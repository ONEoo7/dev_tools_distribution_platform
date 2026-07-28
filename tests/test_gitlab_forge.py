"""The GitLab source establishes no trust either, and has more ways to be led.

GitHub release assets are objects GitHub hosts. A GitLab release asset link is
an arbitrary URL somebody typed into a release, which makes the request-forgery
concern in `forge.py`'s module docstring concrete rather than theoretical. Most
of what is asserted here is that the allowlist holds anyway.
"""

from __future__ import annotations

import io

import httpx
import pytest

from dist_ingest.forge import ForgeError, GitLabReleaseSource

PROJECT = "group/subgroup/app"
ENCODED = "group%2Fsubgroup%2Fapp"
HOST = "https://gitlab.example.com"
ASSET = "app-setup-x64.exe"
DOWNLOAD = f"{HOST}/{PROJECT}/-/releases/v1.4.0/downloads/{ASSET}"


def release_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "tag_name": "v1.4.0",
        "upcoming_release": False,
        "assets": {
            "count": 1,
            "links": [
                {
                    "name": ASSET,
                    "url": f"{HOST}/uploads/whatever/{ASSET}",
                    "direct_asset_url": DOWNLOAD,
                }
            ],
            "sources": [
                {"format": "zip", "url": f"{HOST}/{PROJECT}/-/archive/v1.4.0/app-v1.4.0.zip"}
            ],
        },
    }
    body.update(overrides)
    return body


def source_over(handler: object, **kwargs: object) -> GitLabReleaseSource:
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]
    client = httpx.Client(transport=transport)
    return GitLabReleaseSource(PROJECT, client=client, api_base=HOST, **kwargs)  # type: ignore[arg-type]


def serving(body: dict[str, object], status: int = 200) -> object:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    return handler


# ------------------------------------------------------------------ releases


def test_a_gitlab_release_parses() -> None:
    release = source_over(serving(release_body())).latest_release()

    assert release is not None
    assert release.tag == "v1.4.0"
    assert release.version == "1.4.0"
    asset = release.asset(ASSET)
    assert asset is not None
    assert asset.download_url == DOWNLOAD


def test_a_nested_group_path_is_url_encoded() -> None:
    """GitLab addresses `group/subgroup/project` as one encoded id.

    Sending it as path segments reaches a different endpoint entirely, which
    would present as "no such project" for every nested project.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=release_body())

    source_over(handler).latest_release()

    assert f"/api/v4/projects/{ENCODED}/releases/permalink/latest" in seen[0]


def test_an_upcoming_release_is_not_a_candidate() -> None:
    assert source_over(serving(release_body(upcoming_release=True))).latest_release() is None


def test_a_project_with_no_releases_yields_nothing() -> None:
    assert source_over(serving({}, status=404)).latest_release() is None


def test_the_forge_reports_no_digest_and_none_is_invented() -> None:
    release = source_over(serving(release_body())).latest_release()
    assert release is not None
    asset = release.asset(ASSET)
    assert asset is not None
    assert asset.declared_sha256 is None


def test_auto_generated_source_archives_are_not_assets() -> None:
    """`assets.sources` is every tag's tarball, not something anyone published.

    Admitting them would make the artifact selected for ingestion depend on
    ordering in the response.
    """
    release = source_over(serving(release_body())).latest_release()
    assert release is not None
    assert [a.name for a in release.assets] == [ASSET]


# ------------------------------------------------------------------ download


def test_a_release_link_pointing_off_the_instance_is_refused() -> None:
    """The attack this allowlist exists for.

    Anyone able to edit a release can point an asset link at any URL. Without
    the allowlist that is a request-forgery primitive aimed at whatever the
    worker container can reach.
    """
    body = release_body(
        assets={
            "links": [
                {"name": ASSET, "url": "https://attacker.example/x", "direct_asset_url": None}
            ]
        }
    )
    source = source_over(serving(body))
    release = source.latest_release()
    assert release is not None
    asset = release.asset(ASSET)
    assert asset is not None

    with pytest.raises(ForgeError, match="not allowlisted"):
        source.download(asset, io.BytesIO())


def test_the_instance_host_is_allowlisted_without_being_configured() -> None:
    """An unset allowlist means the GitLab host and nothing else.

    PLAN.md 4.1's "allowlist of one", expressed as a default rather than as a
    deployment note somebody has to remember.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v4/"):
            return httpx.Response(200, json=release_body())
        return httpx.Response(200, content=b"installer bytes")

    source = source_over(handler)
    release = source.latest_release()
    assert release is not None
    asset = release.asset(ASSET)
    assert asset is not None

    sink = io.BytesIO()
    assert source.download(asset, sink) == len(b"installer bytes")


def test_a_redirect_off_the_instance_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v4/"):
            return httpx.Response(200, json=release_body())
        return httpx.Response(302, headers={"location": "https://attacker.example/x"})

    source = source_over(handler)
    release = source.latest_release()
    assert release is not None
    asset = release.asset(ASSET)
    assert asset is not None

    with pytest.raises(ForgeError, match="not allowlisted"):
        source.download(asset, io.BytesIO())


def test_a_body_over_the_cap_stops_mid_stream() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v4/"):
            return httpx.Response(200, json=release_body())
        return httpx.Response(200, content=b"x" * 4096)

    source = source_over(handler, max_asset_bytes=1024)
    release = source.latest_release()
    assert release is not None
    asset = release.asset(ASSET)
    assert asset is not None

    with pytest.raises(ForgeError, match="cap"):
        source.download(asset, io.BytesIO())


# --------------------------------------------------------------- attestation


def test_the_attestation_is_fetched_as_a_named_release_asset() -> None:
    """GitLab has no attestations API, so the envelope is an asset.

    Which asset cannot be established from the digest and does not need to be:
    `check_statement` binds the envelope to the artifact bytes, so naming the
    wrong one yields a rejection rather than a substitution.
    """
    envelope = b'{"payloadType":"application/vnd.in-toto+json"}'
    body = release_body(
        assets={
            "links": [
                {"name": ASSET, "url": DOWNLOAD, "direct_asset_url": DOWNLOAD},
                {
                    "name": "provenance.intoto.jsonl",
                    "url": f"{HOST}/p.jsonl",
                    "direct_asset_url": f"{HOST}/p.jsonl",
                },
            ]
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v4/"):
            return httpx.Response(200, json=body)
        return httpx.Response(200, content=envelope)

    assert source_over(handler).attestation("deadbeef") == envelope


def test_a_release_without_the_attestation_asset_reports_none() -> None:
    assert source_over(serving(release_body())).attestation("deadbeef") is None


# ------------------------------------------------------------------ identity


def test_project_identity_reads_the_numeric_ids() -> None:
    body = {"id": 4711, "path_with_namespace": PROJECT, "namespace": {"id": 22}}
    identity = source_over(serving(body)).project_identity()

    assert identity == {
        "repository": PROJECT,
        "repository_id": "4711",
        "repository_owner_id": "22",
    }


def test_a_project_response_without_ids_is_refused() -> None:
    with pytest.raises(ForgeError, match="numeric ids"):
        source_over(serving({"path_with_namespace": PROJECT})).project_identity()


def test_a_missing_project_is_an_error_not_a_silent_default() -> None:
    with pytest.raises(ForgeError, match="no such GitLab project"):
        source_over(serving({}, status=404)).project_identity()
