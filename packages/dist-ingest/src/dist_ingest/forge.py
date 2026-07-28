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

import io
import json
import re
from dataclasses import dataclass
from typing import BinaryIO, Protocol
from urllib.parse import quote, urlsplit

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

_GITHUB_HEADERS = {"Accept": "application/vnd.github+json"}
_JSON = {"Accept": "application/json"}

#: Where github.com actually serves release bytes from. A release download
#: starts on `github.com` and redirects to an asset host, so the allowlist has
#: to name that host too or every download is refused at the first hop.
#:
#: Both asset hosts are listed because GitHub moved: `objects.` was the
#: long-standing one and `release-assets.` is what it serves today. This is the
#: kind of detail a mocked test cannot hold us to — it was found by pointing
#: the worker at a real release and watching the allowlist refuse it — so
#: treat it as a fact with a shelf life rather than a constant.
GITHUB_DOWNLOAD_HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)


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

    def project_identity(self) -> dict[str, str]:
        """The project's immutable numeric identifiers, as the forge reports them.

        Used when a source is registered, so that the identity pinned in policy
        is read from the forge rather than typed by an operator.
        """
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


def _get_json(client: httpx.Client, url: str, headers: dict[str, str]) -> dict[str, object] | None:
    """One API response, or `None` if the forge says it does not exist.

    Shared by both sources because the failure modes are the forge's, not the
    forge vendor's: unreachable, non-200, not JSON, implausibly large.
    """
    try:
        response = client.get(url, headers=headers, follow_redirects=False)
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


def _stream(
    client: httpx.Client,
    url: str,
    sink: BinaryIO,
    *,
    allowed_hosts: frozenset[str],
    max_bytes: int,
    label: str,
) -> int:
    """Stream a URL into `sink`, checking the host on every hop.

    Redirects are followed by hand. `follow_redirects=True` would send us
    wherever a `Location` header pointed, and that header is as
    attacker-influenced as the URL we started from.

    Raises:
        ForgeError: on a disallowed host, too many redirects, a non-200
            response, or a body over the size cap.
    """
    for _ in range(MAX_REDIRECTS + 1):
        host = _host_of(url)
        if host not in allowed_hosts:
            raise ForgeError(f"refusing to download from {host!r}, which is not allowlisted")

        with client.stream("GET", url, follow_redirects=False) as response:
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
                if written > max_bytes:
                    raise ForgeError(f"asset exceeds the {max_bytes} byte cap")
                sink.write(chunk)
            return written

    raise ForgeError(f"too many redirects fetching {label!r}")


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
        allowed_download_hosts: frozenset[str] = GITHUB_DOWNLOAD_HOSTS,
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
        return _stream(
            self._client,
            asset.download_url,
            sink,
            allowed_hosts=self._allowed_hosts,
            max_bytes=self._max_asset_bytes,
            label=asset.name,
        )

    def project_identity(self) -> dict[str, str]:
        """The numeric repository and owner IDs, read from the forge.

        These are what `CertificateIdentity` pins, and they are exactly the
        fields an operator cannot reasonably be asked to type: a repository can
        be renamed, transferred, deleted and its name re-registered by someone
        else, and only the numeric IDs survive that (PLAN.md 4.1). Reading them
        here means the admin plane records what the forge says *today*, and any
        later divergence is a rejected attestation rather than a silent
        substitution.

        Raises:
            ForgeError: if the project does not exist or names no numeric IDs.
        """
        body = _get_json(self._client, f"{self._api_base}/repos/{self._project}", _GITHUB_HEADERS)
        if body is None:
            raise ForgeError(f"no such GitHub project: {self._project!r}")

        owner = body.get("owner")
        owner_id = owner.get("id") if isinstance(owner, dict) else None
        repository_id, full_name = body.get("id"), body.get("full_name")
        if not isinstance(repository_id, int) or not isinstance(owner_id, int):
            raise ForgeError("GitHub project response carries no numeric ids")

        return {
            "repository": full_name if isinstance(full_name, str) else self._project,
            "repository_id": str(repository_id),
            "repository_owner_id": str(owner_id),
        }

    # ------------------------------------------------------------- internals

    def _get_json(self, url: str) -> dict[str, object] | None:
        return _get_json(self._client, url, _GITHUB_HEADERS)


class GitLabReleaseSource:
    """Reads releases from a GitLab instance, self-hosted or gitlab.com.

    The protocol is the same as GitHub's; three things differ and each shows up
    as code rather than as a comment.

    - **Project paths are URL-encoded, not path segments.** GitLab addresses
      `group/subgroup/project` as a single encoded id.
    - **Release links may point anywhere.** A GitLab release asset link is an
      arbitrary operator-supplied URL, not a forge-hosted object as on GitHub.
      That makes the module docstring's request-forgery concern concrete rather
      than theoretical, so the host allowlist defaults to the GitLab host alone
      and `direct_asset_url` — the forge's own redirector — is preferred over
      the raw `url` when GitLab offers it.
    - **There is no attestations API.** GitLab CI signs with a key you control
      (the `TrustedBuilder` path in PLAN.md 4.1), and publishes the attestation
      as a release asset. `attestation()` therefore fetches an asset by name.
      Which asset it is cannot be established from the digest, and does not
      need to be: `check_statement` binds the envelope to the artifact bytes,
      so naming the wrong asset yields a rejection, never a substitution.
    """

    def __init__(
        self,
        project: str,
        *,
        client: httpx.Client,
        api_base: str = "https://gitlab.com",
        allowed_download_hosts: frozenset[str] | None = None,
        tag_prefix: str = "v",
        attestation_asset: str = "provenance.intoto.jsonl",
        max_asset_bytes: int = DEFAULT_MAX_ASSET_BYTES,
    ) -> None:
        self._project = project
        self._client = client
        self._api_base = api_base.rstrip("/")
        # An unset allowlist means the GitLab host and nothing else, which is
        # PLAN.md 4.1's "allowlist of one" expressed as a default rather than
        # as a deployment note someone has to remember.
        self._allowed_hosts = (
            frozenset({_host_of(self._api_base)})
            if allowed_download_hosts is None
            else allowed_download_hosts
        )
        self._tag_prefix = tag_prefix
        self._attestation_asset = attestation_asset
        self._max_asset_bytes = max_asset_bytes

    @property
    def _project_url(self) -> str:
        return f"{self._api_base}/api/v4/projects/{quote(self._project, safe='')}"

    # ------------------------------------------------------------- releases

    def latest_release(self) -> ForgeRelease | None:
        body = _get_json(self._client, f"{self._project_url}/releases/permalink/latest", _JSON)
        if body is None:
            return None
        # GitLab's equivalent of draft. There is no separate prerelease flag;
        # a prerelease is expressed as a tag, which `version_from_tag` and the
        # ref-prefix gate already govern.
        if body.get("upcoming_release"):
            return None

        tag = body.get("tag_name")
        if not isinstance(tag, str) or not tag:
            raise ForgeError("release has no tag_name")

        return ForgeRelease(
            tag=tag,
            version=version_from_tag(tag, prefix=self._tag_prefix),
            assets=self._assets_of(body),
        )

    def attestation(self, sha256: str) -> bytes | None:
        """The attestation asset attached to the latest release, if present.

        `sha256` is unused for lookup — see the class docstring. It is part of
        the protocol because the GitHub path addresses attestations by digest.
        """
        body = _get_json(self._client, f"{self._project_url}/releases/permalink/latest", _JSON)
        if body is None:
            return None
        for asset in self._assets_of(body):
            if asset.name == self._attestation_asset:
                buffer = io.BytesIO()
                _stream(
                    self._client,
                    asset.download_url,
                    buffer,
                    allowed_hosts=self._allowed_hosts,
                    # An attestation is a signature and a small statement. The
                    # asset cap belongs to installers, not to this.
                    max_bytes=MAX_API_RESPONSE_BYTES,
                    label=asset.name,
                )
                return buffer.getvalue()
        return None

    # ------------------------------------------------------------- download

    def download(self, asset: ForgeAsset, sink: BinaryIO) -> int:
        return _stream(
            self._client,
            asset.download_url,
            sink,
            allowed_hosts=self._allowed_hosts,
            max_bytes=self._max_asset_bytes,
            label=asset.name,
        )

    def project_identity(self) -> dict[str, str]:
        """The project's numeric id and its namespace's, read from GitLab.

        Recorded for the same reason as the GitHub equivalent, though the
        GitLab path pins a builder key rather than a certificate: a rename is
        then visible as a changed id rather than as nothing at all.
        """
        body = _get_json(self._client, self._project_url, _JSON)
        if body is None:
            raise ForgeError(f"no such GitLab project: {self._project!r}")

        namespace = body.get("namespace")
        owner_id = namespace.get("id") if isinstance(namespace, dict) else None
        project_id, path = body.get("id"), body.get("path_with_namespace")
        if not isinstance(project_id, int) or not isinstance(owner_id, int):
            raise ForgeError("GitLab project response carries no numeric ids")

        return {
            "repository": path if isinstance(path, str) else self._project,
            "repository_id": str(project_id),
            "repository_owner_id": str(owner_id),
        }

    # ------------------------------------------------------------- internals

    def _assets_of(self, body: dict[str, object]) -> tuple[ForgeAsset, ...]:
        """Release links, as assets.

        `assets.sources` is deliberately ignored: those are the auto-generated
        source archives GitLab attaches to every tag. They are not what anyone
        published as an installer, and admitting them would make the asset
        selected for ingestion depend on ordering.
        """
        assets_field = body.get("assets")
        links = assets_field.get("links") if isinstance(assets_field, dict) else None
        if not isinstance(links, list):
            return ()

        assets: list[ForgeAsset] = []
        for raw in links:
            if not isinstance(raw, dict):
                continue
            name = raw.get("name")
            # `direct_asset_url` is GitLab's own permalink for the link and is
            # therefore on the GitLab host; `url` is whatever the release
            # author typed. Prefer the former, allowlist either.
            url = raw.get("direct_asset_url") or raw.get("url")
            if not isinstance(name, str) or not isinstance(url, str):
                continue
            # GitLab reports neither a size nor a digest for a release link.
            # Both are absent rather than invented: the size cap is enforced
            # while streaming, and the digest that counts is the one
            # `Quarantine.admit` computes.
            assets.append(ForgeAsset(name=name, size=0, download_url=url))
        return tuple(assets)
