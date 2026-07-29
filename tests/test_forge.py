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
    MAX_FEED_BYTES,
    ForgeAsset,
    ForgeError,
    GitHubReleaseSource,
    version_from_tag,
)

PROJECT = "ONEoo7/ai_tools_git_assistant"
PROJECT_URL = f"https://github.com/{PROJECT}"
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


# ------------------------------------------------- versioned asset names


def release_with(*names: str, version: str = "0.1.0"):  # type: ignore[no-untyped-def]
    from dist_ingest.forge import ForgeAsset, ForgeRelease

    return ForgeRelease(
        tag=f"v{version}",
        version=version,
        assets=tuple(ForgeAsset(name=n, size=1, download_url=DOWNLOAD) for n in names),
    )


def test_a_versioned_asset_name_follows_the_release() -> None:
    """The reason the placeholder exists.

    An exact name matches one release and then fails every poll afterwards,
    which is a slow, confusing failure: nothing changed on our side, and the
    project looks abandoned rather than misconfigured.
    """
    pattern = "git-assistant-{version}-windows-x64.zip"

    first = release_with("git-assistant-0.1.0-windows-x64.zip", version="0.1.0")
    second = release_with("git-assistant-0.2.0-windows-x64.zip", version="0.2.0")

    assert first.asset(pattern) is not None
    assert second.asset(pattern) is not None


def test_an_exact_name_still_works() -> None:
    # The placeholder is additive; sources registered before it keep resolving.
    release = release_with("installer.zip")
    assert release.asset("installer.zip") is not None
    assert release.asset("other.zip") is None


def test_the_placeholder_does_not_match_a_different_version() -> None:
    # Otherwise a pattern would quietly accept last release's artifact.
    release = release_with("git-assistant-0.1.0-windows-x64.zip", version="0.2.0")
    assert release.asset("git-assistant-{version}-windows-x64.zip") is None


def test_resolution_is_literal_and_survives_other_braces() -> None:
    # str.format would raise on an unrecognised field rather than leaving it
    # alone, turning a odd-but-legal filename into a crash.
    release = release_with("a{b}-1.0.0.zip", version="1.0.0")
    assert release.resolve_asset_name("a{b}-{version}.zip") == "a{b}-1.0.0.zip"
    assert release.asset("a{b}-{version}.zip") is not None


# ------------------------------------------------------- what a refusal says


def refusing(status: int, body: object, headers: dict[str, str] | None = None) -> object:
    def handler(_request: httpx.Request) -> httpx.Response:
        if isinstance(body, str):
            return httpx.Response(status, text=body, headers=headers)
        return httpx.Response(status, json=body, headers=headers)

    return handler


def test_a_rate_limited_poll_says_so() -> None:
    """A bare "HTTP 403" reads as a credential problem and is not one.

    GitHub answers an exhausted unauthenticated quota with 403 and explains
    itself in the body and the headers. Dropping both is what turned a
    one-line diagnosis into a search through container logs.
    """
    forge = source_over(
        refusing(
            403,
            {"message": "API rate limit exceeded for 203.0.113.7."},
            {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1753693200"},
        )
    )

    with pytest.raises(ForgeError) as caught:
        forge.latest_release()

    message = str(caught.value)
    assert "rate limit exhausted" in message
    assert "1753693200" in message
    assert "API rate limit exceeded" in message


def test_a_refusal_with_no_explanation_stays_terse() -> None:
    forge = source_over(refusing(500, ""))

    with pytest.raises(ForgeError, match="HTTP 500"):
        forge.latest_release()


def test_a_forge_error_message_cannot_flood_the_job_record() -> None:
    """The body is forge-controlled text that lands in a record an operator reads."""
    forge = source_over(refusing(403, {"message": "x" * 5000}))

    with pytest.raises(ForgeError) as caught:
        forge.latest_release()

    assert len(str(caught.value)) < 600


def test_control_characters_are_stripped_from_a_forge_message() -> None:
    # It is written to a log and rendered in the admin UI; neither should have
    # to cope with an escape sequence a forge chose.
    forge = source_over(refusing(403, {"message": "bad\x1b[31mred\x00\nthing"}))

    with pytest.raises(ForgeError) as caught:
        forge.latest_release()

    message = str(caught.value)
    assert "\x1b" not in message and "\x00" not in message and "\n" not in message
    # The `[31m` survives, and should: with the escape gone it is inert text,
    # and mangling the rest would make a genuine message harder to read.
    assert "bad[31mredthing" in message


# --------------------------------------------------- the cheap change check


ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Release notes from ai_tools_git_assistant</title>
  <entry>
    <id>tag:github.com,2008:Repository/1310933302/v0.2.0</id>
    <title>v0.2.0</title>
    <updated>2026-07-28T09:39:21Z</updated>
  </entry>
  <entry>
    <id>tag:github.com,2008:Repository/1310933302/v0.1.0</id>
    <title>v0.1.0</title>
    <updated>2026-07-27T12:40:33Z</updated>
  </entry>
</feed>
"""


def feeding(body: str, status: int = 200) -> object:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body)

    return handler


def test_the_real_feed_shape_yields_the_newest_tag() -> None:
    forge = source_over(feeding(ATOM), project_url=PROJECT_URL)
    assert forge.newest_tag_hint() == "v0.2.0"


def test_no_project_url_means_no_opinion() -> None:
    # Not an error. A source registered before this existed simply polls.
    forge = source_over(feeding(ATOM))
    assert forge.newest_tag_hint() is None


def test_an_empty_feed_means_no_opinion() -> None:
    forge = source_over(
        feeding('<feed xmlns="http://www.w3.org/2005/Atom"><title>x</title></feed>'),
        project_url=PROJECT_URL,
    )
    assert forge.newest_tag_hint() is None


def test_a_feed_for_another_repository_is_refused() -> None:
    """The entry id carries the numeric repository id, and the source pins it.

    A feed naming a different repository is either a misconfiguration or
    somebody redirecting this check at a repository they control, and the
    answer to both is to stop rather than to believe it.
    """
    forge = source_over(feeding(ATOM), project_url=PROJECT_URL, repository_id="999")

    with pytest.raises(ForgeError, match="pinned to 999"):
        forge.newest_tag_hint()


def test_the_pinned_repository_id_matching_is_accepted() -> None:
    forge = source_over(feeding(ATOM), project_url=PROJECT_URL, repository_id="1310933302")
    assert forge.newest_tag_hint() == "v0.2.0"


def test_the_structural_id_beats_a_display_title() -> None:
    # The title is editable on the release page; the id is not. A title saying
    # "v9.9.9" must not become the tag this system believes in.
    feed = ATOM.replace("<title>v0.2.0</title>", "<title>v9.9.9 Big Release!</title>")
    forge = source_over(feeding(feed), project_url=PROJECT_URL)
    assert forge.newest_tag_hint() == "v0.2.0"


def test_a_feed_declaring_a_dtd_is_refused() -> None:
    """Entity expansion, refused before the parser sees it.

    A few hundred bytes of nested entity declarations expand to gigabytes in
    ElementTree. A release feed has no reason to carry a DTD, so the whole
    class goes away by refusing one.
    """
    bomb = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE feed [\n'
        '  <!ENTITY a "aaaaaaaaaa">\n'
        '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
        '  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
        ']>\n'
        '<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>&c;</title></entry></feed>'
    )
    forge = source_over(feeding(bomb), project_url=PROJECT_URL)

    with pytest.raises(ForgeError, match="declares a DTD"):
        forge.newest_tag_hint()


def test_an_oversized_feed_is_refused() -> None:
    forge = source_over(feeding("<feed>" + "x" * (MAX_FEED_BYTES + 1)), project_url=PROJECT_URL)

    with pytest.raises(ForgeError, match="over the"):
        forge.newest_tag_hint()


def test_an_unparseable_feed_is_refused() -> None:
    forge = source_over(feeding("this is not xml at all"), project_url=PROJECT_URL)

    with pytest.raises(ForgeError, match="not parseable"):
        forge.newest_tag_hint()


def test_the_feed_host_must_be_allowlisted() -> None:
    """`project_url` comes from the database, so it decides what we connect to."""
    forge = source_over(feeding(ATOM), project_url="https://feeds.evil.example/o/r")

    with pytest.raises(ForgeError, match="not allowlisted"):
        forge.newest_tag_hint()


def test_a_plain_http_feed_is_refused() -> None:
    forge = source_over(feeding(ATOM), project_url="http://github.com/ONEoo7/ai_tools_git_assistant")

    with pytest.raises(ForgeError, match="non-HTTPS"):
        forge.newest_tag_hint()


def test_a_feed_that_errors_is_reported_not_swallowed() -> None:
    # The caller turns this into "poll anyway"; that decision belongs there,
    # not here, so that a feed failing every time is visible.
    forge = source_over(feeding("nope", status=503), project_url=PROJECT_URL)

    with pytest.raises(ForgeError, match="HTTP 503"):
        forge.newest_tag_hint()


def test_gitlab_offers_no_hint() -> None:
    # A self-hosted instance has no quota to protect, so there is nothing to
    # buy with the extra surface.
    from dist_ingest.forge import GitLabReleaseSource

    forge = GitLabReleaseSource("g/p", client=httpx.Client(), api_base="https://gitlab.example")
    assert forge.newest_tag_hint() is None
