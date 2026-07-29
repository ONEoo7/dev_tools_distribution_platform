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
import xml.etree.ElementTree as ElementTree
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


#: Stands in for the release version inside a configured asset name.
#:
#: Release assets are usually named with their version, so that several of them
#: can sit in one directory without becoming a puzzle. That makes the name
#: change every release, which an exact match cannot follow: a source
#: registered against `app-1.0.0.zip` stops resolving the moment 1.0.1 ships,
#: and keeps failing every poll until someone edits it.
VERSION_PLACEHOLDER = "{version}"


@dataclass(frozen=True, slots=True)
class ForgeRelease:
    """A release as the forge describes it."""

    tag: str
    version: str
    assets: tuple[ForgeAsset, ...]

    def resolve_asset_name(self, name: str) -> str:
        """Substitute `{version}` in a configured asset name.

        A name without the placeholder is returned unchanged, so an exact name
        keeps working and this stays additive.

        Substitution is a literal replace rather than `str.format`, because a
        `format` call would also interpret any other brace in the name and
        raise on the ones it did not recognise.
        """
        return name.replace(VERSION_PLACEHOLDER, self.version)

    def asset(self, name: str) -> ForgeAsset | None:
        """Find the asset matching `name`, resolving `{version}` first."""
        resolved = self.resolve_asset_name(name)
        for candidate in self.assets:
            if candidate.name == resolved:
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

    def newest_tag_hint(self) -> str | None:
        """The newest tag the forge advertises, cheaply, or `None`.

        A *hint*, and the name is the contract. It exists only so the scheduler
        can skip an expensive, quota-consuming poll when nothing has changed; it
        is never the basis for ingesting anything. Whatever it says, a release
        is still fetched, hashed, checked against its attestation and run
        through the gates before it can be promoted.

        The distinction matters because this is the one method whose answer may
        come from somewhere cheaper and therefore less trustworthy than the
        API — an unauthenticated feed today, possibly a webhook later. Being
        unable to say anything is normal: `None` means "no opinion", and the
        caller polls.
        """
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


def _require_allowed_host(url: str, allowed_hosts: frozenset[str], *, label: str) -> None:
    """Refuse a URL that does not land on an allowlisted host.

    The module docstring's rule is not only about release downloads: the feed
    URL is built from an operator-supplied `project_url`, so it is one more
    place a value from the database decides what this container connects to.
    """
    host = _host_of(url)
    if host not in allowed_hosts:
        raise ForgeError(f"refusing to fetch the {label} from {host!r}, which is not allowlisted")


# ---------------------------------------------------------------- the feed

#: The release feed is a short document listing recent tags. Anything larger is
#: not one, and reading it into memory to find out would be the bug.
MAX_FEED_BYTES = 512 * 1024

_ATOM = "{http://www.w3.org/2005/Atom}"

#: `tag:github.com,2008:Repository/1310933302/v0.2.0` — the entry id carries
#: the numeric repository id, which is the same value the certificate identity
#: pins, so the feed can be checked against the source rather than trusted.
_FEED_ENTRY_ID = re.compile(r"Repository/(?P<repository_id>[0-9]+)/(?P<tag>.+)\Z")


def _newest_feed_tag(content: bytes, *, expect_repository_id: str | None) -> str | None:
    """The newest tag named by an Atom release feed, or `None` if it names none.

    Everything here treats the document as hostile. It arrives over TLS from a
    host on the allowlist, which makes it *authenticated*, not *trustworthy* —
    a compromised forge serves it too, and this is the one input reached
    without an API token.

    Raises:
        ForgeError: if the document is too large, declares a DTD, is not
            parseable, or describes a different repository than the one pinned.
    """
    if len(content) > MAX_FEED_BYTES:
        raise ForgeError(f"release feed is {len(content)} bytes, over the {MAX_FEED_BYTES} limit")

    # Entity expansion is the attack this forecloses: `ElementTree` resolves
    # internal entities, so a DTD declaring nested ones expands to gigabytes
    # from a few hundred bytes and takes the worker down. A release feed has no
    # legitimate reason to carry a DTD at all, so refusing one outright is both
    # complete against that class and simpler to audit than a parser
    # configuration.
    if b"<!DOCTYPE" in content or b"<!ENTITY" in content:
        raise ForgeError("release feed declares a DTD; refusing to parse it")

    try:
        # Safe given the two checks above: no DTD means no entity expansion,
        # and ElementTree resolves no external references of its own.
        feed = ElementTree.fromstring(content)  # noqa: S314
    except ElementTree.ParseError as exc:
        raise ForgeError(f"release feed is not parseable XML: {exc}") from exc

    for entry in feed.iter(f"{_ATOM}entry"):
        title = entry.findtext(f"{_ATOM}title")
        entry_id = entry.findtext(f"{_ATOM}id") or ""

        match = _FEED_ENTRY_ID.search(entry_id)
        if match and expect_repository_id and match["repository_id"] != expect_repository_id:
            raise ForgeError(
                f"release feed describes repository {match['repository_id']}, "
                f"but this source is pinned to {expect_repository_id}"
            )

        # Prefer the id's tag over the title: the title is a display string an
        # operator can set to anything on the release page, while the id is
        # structural.
        tag = match["tag"] if match else title
        if tag:
            return tag
    return None


#: How much of a forge's error body to quote back. Enough for a sentence,
#: short enough that a hostile forge cannot flood the job record or the log.
MAX_ERROR_DETAIL = 200


def _why(response: httpx.Response) -> str:
    """The forge's own explanation of a refusal, if it gave one.

    Worth the twenty lines. A bare "HTTP 403" sends the reader to check
    credentials and permissions; GitHub had in fact said `rate limit exceeded`
    in the reason phrase and put the reset time in a header, and dropping both
    turned a one-line diagnosis into a search through logs.

    Treated as untrusted text, because it is: truncated, control characters
    stripped, and never interpreted. It goes into a job record an operator
    reads.
    """
    parts: list[str] = []

    remaining = response.headers.get("x-ratelimit-remaining")
    if remaining == "0":
        reset = response.headers.get("x-ratelimit-reset", "")
        # Unauthenticated GitHub allows 60 requests an hour per address, which
        # a poll plus its attestation lookups can exhaust on their own.
        parts.append(f"rate limit exhausted, resets at epoch {reset}" if reset else "rate limited")

    detail = ""
    try:
        body = response.json()
        if isinstance(body, dict) and isinstance(body.get("message"), str):
            detail = body["message"]
    except ValueError:
        detail = response.reason_phrase

    detail = "".join(c for c in detail if c.isprintable())[:MAX_ERROR_DETAIL].strip()
    if detail:
        parts.append(detail)

    return f" ({'; '.join(parts)})" if parts else ""


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
        raise ForgeError(f"forge returned HTTP {response.status_code} for {url}{_why(response)}")
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
        project_url: str = "",
        repository_id: str | None = None,
    ) -> None:
        self._project = project
        self._client = client
        self._api_base = api_base.rstrip("/")
        self._allowed_hosts = allowed_download_hosts
        self._tag_prefix = tag_prefix
        self._max_asset_bytes = max_asset_bytes
        # Used only for the release feed, which lives on the web host rather
        # than the API host. Taken from the operator-supplied project URL
        # instead of being derived from `api_base`, because the relationship
        # between the two is not the same on github.com and on an Enterprise
        # instance, and guessing it wrong means silently never noticing a
        # release.
        self._project_url = project_url.rstrip("/")
        self._repository_id = repository_id

    # ------------------------------------------------------------- releases

    def newest_tag_hint(self) -> str | None:
        """The newest tag, from the release feed. Costs no API quota.

        `releases.atom` is not part of the REST API and is not counted against
        the rate limit — measured, not assumed, and worth measuring because the
        usual advice here is to use conditional requests instead. A `304` from
        `/releases/latest` was observed to consume a request anyway when
        unauthenticated, so ETags do not solve this problem and this does.

        The answer is a hint. `latest_release` still runs before anything is
        ingested; this only decides whether that call is worth making now.

        Raises:
            ForgeError: if the feed describes a different repository than the
                one this source pinned. Not returned as "no opinion", because
                the caller can carry on safely by polling but somebody should
                see it.
        """
        if not self._project_url:
            return None

        url = f"{self._project_url}/releases.atom"
        _require_allowed_host(url, self._allowed_hosts, label="release feed")
        try:
            response = self._client.get(url, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise ForgeError(f"release feed request failed: {exc}") from exc

        if response.status_code != httpx.codes.OK:
            raise ForgeError(
                f"release feed returned HTTP {response.status_code}{_why(response)}"
            )
        return _newest_feed_tag(response.content, expect_repository_id=self._repository_id)

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

    def newest_tag_hint(self) -> str | None:
        """No opinion, so the scheduler polls.

        Deliberately not implemented rather than approximated. The cheap check
        exists to avoid burning an unauthenticated quota, and a self-hosted
        GitLab — which is the deployment PLAN.md targets — has no such quota to
        protect. Adding a second way to learn about releases here would be new
        surface bought with nothing.
        """
        return None

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
