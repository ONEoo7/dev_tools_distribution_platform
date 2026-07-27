"""The forge client establishes no trust, and must not be talked into any.

Shapes here are taken from the real GitHub API response for
ONEoo7/ai_tools_git_assistant v0.1.0, so a change in what GitHub sends shows up
as a failure rather than as a silent skip.
"""

from __future__ import annotations

import io
import json

import httpx
import pytest

from dist_ingest.forge import (
    ForgeAsset,
    ForgeError,
    GitHubReleaseSource,
    version_from_tag,
)

PROJECT = "ONEoo7/ai_tools_git_assistant"
DIGEST = "3fd704e32e52adac7e2727a94a26b6a17cc19a5640ad2a879a76268bc1cfd619"
ASSET = "git-assistant-0.1.0-windows-x64.zip"
DOWNLOAD = f"https://github.com/{PROJECT}/releases/download/v0.1.0/{ASSET}"


def release_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "tag_name": "v0.1.0",
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": ASSET,
                "size": 40587850,
                "state": "uploaded",
                "digest": f"sha256:{DIGEST}",
                "browser_download_url": DOWNLOAD,
            }
        ],
    }
    body.update(overrides)
    return body


def source_over(handler: object, **kwargs: object) -> GitHubReleaseSource:
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]
    client = httpx.Client(transport=transport)
    return GitHubReleaseSource(PROJECT, client=client, **kwargs)  # type: ignore[arg-type]


def serving(body: dict[str, object], status: int = 200) -> object:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    return handler


# ------------------------------------------------------------------ releases


def test_the_real_github_release_shape_parses() -> None:
    release = source_over(serving(release_body())).latest_release()

    assert release is not None
    assert release.tag == "v0.1.0"
    assert release.version == "0.1.0"
    asset = release.asset(ASSET)
    assert asset is not None
    assert asset.size == 40587850
    assert asset.declared_sha256 == DIGEST


def test_a_draft_or_prerelease_is_not_a_candidate() -> None:
    assert source_over(serving(release_body(draft=True))).latest_release() is None
    assert source_over(serving(release_body(prerelease=True))).latest_release() is None


def test_a_project_with_no_releases_yields_nothing() -> None:
    assert source_over(serving({}, status=404)).latest_release() is None


def test_an_asset_still_uploading_is_skipped() -> None:
    body = release_body()
    body["assets"][0]["state"] = "starter"  # type: ignore[index]
    release = source_over(serving(body)).latest_release()
    assert release is not None
    assert release.assets == ()


def test_a_missing_forge_digest_is_not_invented() -> None:
    body = release_body()
    del body["assets"][0]["digest"]  # type: ignore[index]
    release = source_over(serving(body)).latest_release()
    assert release is not None
    assert release.assets[0].declared_sha256 is None


# ------------------------------------------------------------------ versions


@pytest.mark.parametrize(
    "tag, expected",
    [("v0.1.0", "0.1.0"), ("v1.2.3-rc.1", "1.2.3-rc.1"), ("2.0", "2.0")],
)
def test_usable_tags_yield_versions(tag: str, expected: str) -> None:
    assert version_from_tag(tag) == expected


@pytest.mark.parametrize(
    "tag",
    [
        "v../../../etc/passwd",  # traversal into the target path
        "v1.0/../2.0",
        "v1.0\\2.0",
        "release-one",
        "v",
        "",
        "v1.0\x00",
    ],
)
def test_a_tag_that_could_alter_a_target_path_is_refused(tag: str) -> None:
    # The version becomes a path segment in a TUF target name. Refusing here
    # as well as there is deliberate duplication.
    with pytest.raises(ForgeError):
        version_from_tag(tag)


# ----------------------------------------------------------------- downloads


def test_a_download_host_outside_the_allowlist_is_refused() -> None:
    # The URL comes from an API response. A forge that can name any host is a
    # request-forgery primitive aimed at whatever this container can reach.
    asset = ForgeAsset(name=ASSET, size=1, download_url="https://attacker.example/payload.zip")
    with pytest.raises(ForgeError, match="allowlisted"):
        source_over(serving({})).download(asset, io.BytesIO())


def test_a_plain_http_download_is_refused() -> None:
    asset = ForgeAsset(name=ASSET, size=1, download_url="http://github.com/x.zip")
    with pytest.raises(ForgeError, match="non-HTTPS"):
        source_over(serving({})).download(asset, io.BytesIO())


def test_a_redirect_to_the_object_store_is_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "github.com":
            return httpx.Response(
                302, headers={"location": "https://objects.githubusercontent.com/blob"}
            )
        return httpx.Response(200, content=b"payload bytes")

    sink = io.BytesIO()
    written = source_over(handler).download(ForgeAsset(ASSET, 13, DOWNLOAD), sink)

    assert written == 13
    assert sink.getvalue() == b"payload bytes"


def test_a_redirect_off_the_allowlist_is_refused() -> None:
    # This is why redirects are followed by hand. `follow_redirects=True` would
    # have sent the request wherever the Location header pointed, and that
    # header is exactly as untrusted as the URL it came from.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "github.com":
            return httpx.Response(302, headers={"location": "https://attacker.example/x"})
        return httpx.Response(200, content=b"never reached")

    sink = io.BytesIO()
    with pytest.raises(ForgeError, match="allowlisted"):
        source_over(handler).download(ForgeAsset(ASSET, 1, DOWNLOAD), sink)
    assert sink.getvalue() == b""


def test_a_redirect_loop_terminates() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": DOWNLOAD})

    with pytest.raises(ForgeError, match="too many redirects"):
        source_over(handler).download(ForgeAsset(ASSET, 1, DOWNLOAD), io.BytesIO())


def test_a_body_over_the_cap_stops_mid_stream() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 4096)

    with pytest.raises(ForgeError, match="cap"):
        source_over(handler, max_asset_bytes=1024).download(
            ForgeAsset(ASSET, 4096, DOWNLOAD), io.BytesIO()
        )


# -------------------------------------------------------------- attestations


def test_the_attestation_is_returned_as_raw_bytes() -> None:
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}
    body: dict[str, object] = {
        "attestations": [{"bundle": bundle, "bundle_url": "https://blob/x?sig=secret"}]
    }

    raw = source_over(serving(body)).attestation(DIGEST)

    assert raw is not None
    assert json.loads(raw) == bundle
    # The API wrapper carries a short-lived signed URL. It is a credential and
    # has no business travelling further into the system.
    assert b"sig=secret" not in raw


def test_an_artifact_with_no_attestation_reports_none() -> None:
    assert source_over(serving({}, status=404)).attestation(DIGEST) is None
    assert source_over(serving({"attestations": []})).attestation(DIGEST) is None
