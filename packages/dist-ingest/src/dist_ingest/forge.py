"""Retrieving candidate releases from a forge.

Mirrors docs/PLAN.md section 4.1 and 4.2. This layer is deliberately dumb: it
fetches bytes and reports what the forge said. It establishes no trust
whatsoever. Everything it returns is attacker-influenced input if the forge
account, the API, or the network is compromised, and the modules downstream —
`attestation`, `quarantine`, `gates`, `policy` — are what decide whether any of
it may be believed.

Two consequences show up as code rather than as comments:

- **The digest the forge reports is a hint, never an authority.** It is carried
  through so a mismatch can be reported early, but the digest that counts is
  the one `Quarantine.admit` computes over the bytes actually received.
- **URLs from an API response are not addresses we will fetch on request.** A
  compromised forge that can name any URL is a request-forgery primitive
  pointed at whatever the ingest container can reach. Every hop, redirects
  included, must land on an allowlisted host.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import BinaryIO, Protocol
from urllib.parse import urlsplit

import httpx

#: A release download is large; the API responses around it are not.
MAX_API_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_REDIRECTS = 5
_CHUNK = 1024 * 1024

#: Tag to version. Deliberately strict: the version becomes a path segment in a
#: TUF target name, so anything that could alter that path is refused here as
#: well as there.
_VERSION = re.compile(r"\A[0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.]+)?\Z")


class ForgeError(Exception):
    """A forge could not be queried, or answered with something unusable."""


@dataclass(frozen=True, slots=True)
class ForgeAsset:
    """One downloadable file attached to a release."""

    name: str
    size: int
    download_url: str

    #: What the forge claims the digest is. Not trusted; see the module
    #: docstring. `None` when the forge does not report one.
    declared_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ForgeRelease:
    """A release as the forge describes it."""

    tag: str
    version: str
    assets: tuple[ForgeAsset, ...]

    def asset(self, name: str) -> ForgeAsset | None:
        for candidate in self.assets:
            if candidate.name == name:
                return candidate
        return None


class ReleaseSource(Protocol):
    """What ingestion needs from a forge, in forge-neutral terms.

    GitLab and GitHub differ in their JSON and in how they sign, but not in
    what ingestion asks of them, which is why adding a forge is a new
    implementation of this protocol and nothing else (PLAN.md 4.2).
    """

    def latest_release(self) -> ForgeRelease | None:
        """The newest published, non-draft, non-prerelease release."""
        ...

    def download(self, asset: ForgeAsset, sink: BinaryIO) -> int:
        """Stream `asset` into `sink`, returning the byte count written."""
        ...

    def attestation(self, sha256: str) -> bytes | None:
        """The build attestation covering an artifact digest, if published."""
        ...


def version_from_tag(tag: str, *, prefix: str = "v") -> str:
    """Derive a version from a tag name, or raise.

    Raises:
        ForgeError: if the tag does not carry a version we would put in a
            target path.
    """
    version = tag[len(prefix) :] if prefix and tag.startswith(prefix) else tag
    if not _VERSION.match(version):
        raise ForgeError(f"tag {tag!r} does not yield a usable version")
    return version


def _host_of(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ForgeError(f"refusing a non-HTTPS URL: {url!r}")
    if not parts.hostname:
        raise ForgeError(f"URL has no host: {url!r}")
    return parts.hostname.lower()


class GitHubReleaseSource:
    """Reads releases and attestations from a GitHub instance.

    The token, when supplied, needs read access and nothing more. Nothing in
    this system writes to a forge (PLAN.md 8.4), so a write-capable token here
    would be a capability with no corresponding feature.
    """

    def __init__(
        self,
        project: str,
        *,
        client: httpx.Client,
        api_base: str = "https://api.github.com",
        allowed_download_hosts: frozenset[str] = frozenset(
            {"api.github.com", "github.com", "objects.githubusercontent.com"}
        ),
        tag_prefix: str = "v",
        max_asset_bytes: int = DEFAULT_MAX_ASSET_BYTES,
    ) -> None:
        self._project = project
        self._client = client
        self._api_base = api_base.rstrip("/")
        self._allowed_hosts = allowed_download_hosts
        self._tag_prefix = tag_prefix
        self._max_asset_bytes = max_asset_bytes

    # ------------------------------------------------------------- releases

    def latest_release(self) -> ForgeRelease | None:
        body = self._get_json(f"{self._api_base}/repos/{self._project}/releases/latest")
        if body is None:
            return None
        if body.get("draft") or body.get("prerelease"):
            return None

        tag = body.get("tag_name")
        if not isinstance(tag, str) or not tag:
            raise ForgeError("release has no tag_name")

        raw_assets = body.get("assets")
        if not isinstance(raw_assets, list):
            raw_assets = []

        assets: list[ForgeAsset] = []
        for raw in raw_assets:
            if not isinstance(raw, dict) or raw.get("state") != "uploaded":
                continue
            name, url = raw.get("name"), raw.get("browser_download_url")
            if not isinstance(name, str) or not isinstance(url, str):
                continue
            digest = raw.get("digest")
            declared = (
                digest[len("sha256:") :]
                if isinstance(digest, str) and digest.startswith("sha256:")
                else None
            )
            assets.append(
                ForgeAsset(
                    name=name,
                    size=int(raw.get("size") or 0),
                    download_url=url,
                    declared_sha256=declared,
                )
            )

        return ForgeRelease(
            tag=tag,
            version=version_from_tag(tag, prefix=self._tag_prefix),
            assets=tuple(assets),
        )

    def attestation(self, sha256: str) -> bytes | None:
        """The first Sigstore bundle GitHub holds for this digest.

        Returned as raw bytes rather than parsed: it is untrusted until
        `verify_sigstore_provenance` says otherwise, and decoding it here would
        only invite reading it here.
        """
        body = self._get_json(
            f"{self._api_base}/repos/{self._project}/attestations/sha256:{sha256}"
        )
        if body is None:
            return None
        entries = body.get("attestations")
        if not isinstance(entries, list) or not entries:
            return None
        bundle = entries[0].get("bundle") if isinstance(entries[0], dict) else None
        if bundle is None:
            return None
        return json.dumps(bundle).encode("utf-8")

    # ------------------------------------------------------------- download

    def download(self, asset: ForgeAsset, sink: BinaryIO) -> int:
        """Stream an asset, checking the host on every hop.

        Redirects are followed by hand. `follow_redirects=True` would send us
        wherever a `Location` header pointed, and that header is as
        attacker-influenced as the URL we started from.

        Raises:
            ForgeError: on a disallowed host, too many redirects, a non-200
                response, or a body over the size cap.
        """
        url = asset.download_url
        for _ in range(MAX_REDIRECTS + 1):
            host = _host_of(url)
            if host not in self._allowed_hosts:
                raise ForgeError(f"refusing to download from {host!r}, which is not allowlisted")

            with self._client.stream("GET", url, follow_redirects=False) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise ForgeError("redirect without a location header")
                    url = str(httpx.URL(url).join(location))
                    continue
                if response.status_code != httpx.codes.OK:
                    raise ForgeError(f"asset download returned HTTP {response.status_code}")

                written = 0
                for chunk in response.iter_bytes(_CHUNK):
                    written += len(chunk)
                    if written > self._max_asset_bytes:
                        raise ForgeError(f"asset exceeds the {self._max_asset_bytes} byte cap")
                    sink.write(chunk)
                return written

        raise ForgeError(f"too many redirects fetching {asset.name!r}")

    # ------------------------------------------------------------- internals

    def _get_json(self, url: str) -> dict[str, object] | None:
        headers = {"Accept": "application/vnd.github+json"}
        try:
            response = self._client.get(url, headers=headers, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise ForgeError(f"forge request failed: {exc}") from exc

        if response.status_code == httpx.codes.NOT_FOUND:
            return None
        if response.status_code != httpx.codes.OK:
            raise ForgeError(f"forge returned HTTP {response.status_code} for {url}")
        if len(response.content) > MAX_API_RESPONSE_BYTES:
            raise ForgeError("forge response is implausibly large")

        try:
            body = response.json()
        except ValueError as exc:
            raise ForgeError(f"forge response is not JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise ForgeError("forge response is not an object")
        return body
