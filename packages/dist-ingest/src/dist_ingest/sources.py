"""Turning a registered source into the objects ingestion already understands.

The admin plane stores what an operator decided. This module is where that
becomes a `ReleaseSource` to fetch with and a `ProvenancePolicy` to judge with.
It is the only place the two halves meet, which is deliberate: everything
downstream of here — `provenance`, `attestation`, `gates`, `policy` — has no
idea a database exists, and keeping it that way is what let the security core
be tested without one.

The egress allowlist is derived here rather than configured, and that is the
security-relevant line in the file. A source can only ever cause requests to
the host an operator typed as its API base, plus GitHub's object store when the
forge is GitHub. A row in the database is not a way to name a new destination.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from dist_ingest.forge import (
    DEFAULT_MAX_ASSET_BYTES,
    GITHUB_DOWNLOAD_HOSTS,
    GitHubReleaseSource,
    GitLabReleaseSource,
    ReleaseSource,
)
from dist_ingest.policy import AppIngestPolicy
from dist_ingest.provenance import CertificateIdentity, ProvenancePolicy, TrustedBuilder
from dist_registry.models import Forge, Source

DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0, read=300.0)


class SourceConfigError(Exception):
    """A stored source cannot be turned into a usable policy."""


def client_for(source: Source, token: str | None) -> httpx.Client:
    """An HTTP client carrying the read-only forge credential, if there is one.

    The header differs per forge; the property does not. Nothing in this system
    writes to a forge (PLAN.md 8.4), so a token with write scopes here would be
    a capability with no corresponding feature.
    """
    headers: dict[str, str] = {}
    if token:
        if source.forge is Forge.GITHUB:
            headers["Authorization"] = f"Bearer {token}"
        else:
            headers["PRIVATE-TOKEN"] = token
    return httpx.Client(headers=headers, timeout=DEFAULT_TIMEOUT, follow_redirects=False)


def release_source(source: Source, client: httpx.Client) -> ReleaseSource:
    if source.forge is Forge.GITHUB:
        return GitHubReleaseSource(
            source.project,
            client=client,
            api_base=source.api_base,
            allowed_download_hosts=_github_hosts(source.api_base),
            tag_prefix=source.tag_prefix,
            max_asset_bytes=source.max_asset_bytes or DEFAULT_MAX_ASSET_BYTES,
        )
    return GitLabReleaseSource(
        source.project,
        client=client,
        api_base=source.api_base,
        # Unset means "the GitLab host and nothing else". A self-hosted
        # instance that serves assets from a separate object store needs that
        # host added here, explicitly, by someone who decided to.
        allowed_download_hosts=None,
        tag_prefix=source.tag_prefix,
        attestation_asset=source.attestation_asset,
        max_asset_bytes=source.max_asset_bytes or DEFAULT_MAX_ASSET_BYTES,
    )


def _github_hosts(api_base: str) -> frozenset[str]:
    """github.com's hosts, or the single host of a GitHub Enterprise install."""
    host = urlsplit(api_base).hostname or ""
    if host == "api.github.com":
        return GITHUB_DOWNLOAD_HOSTS
    return frozenset({host})


def provenance_policy(source: Source) -> ProvenancePolicy:
    """What an attestation must say before this source's artifacts may be signed.

    Raises:
        SourceConfigError: if the source lacks the pins its forge's path needs.
            `ProvenancePolicy` refuses to construct with no trusted builder at
            all, so this is caught at registration rather than at three in the
            morning — but a source that reached here without the numeric ids
            would silently drop the strongest claims, so those are checked too.
    """
    if source.forge is Forge.GITHUB:
        missing = [
            name
            for name, value in (
                ("workflow_uri", source.workflow_uri),
                ("oidc_issuer", source.oidc_issuer),
                ("repository_id", source.repository_id),
                ("repository_owner_id", source.repository_owner_id),
            )
            if not value
        ]
        if missing:
            raise SourceConfigError(
                f"{source.app_id}: certificate identity is incomplete, missing {missing}. "
                "Re-run validation so the numeric ids are read from the forge."
            )
        assert source.workflow_uri and source.oidc_issuer
        assert source.repository_id and source.repository_owner_id
        identity = CertificateIdentity(
            workflow_uri=source.workflow_uri,
            issuer=source.oidc_issuer,
            repository=source.project,
            repository_id=source.repository_id,
            repository_owner_id=source.repository_owner_id,
            runner_environment=source.runner_environment,
        )
        return ProvenancePolicy(
            trusted_builders=(),
            project_url=source.project_url,
            require_tag_ref_prefix=source.require_tag_ref_prefix,
            trusted_identities=(identity,),
        )

    if not (source.builder_id and source.builder_keyid and source.builder_public_key_pem):
        raise SourceConfigError(
            f"{source.app_id}: GitLab sources need a builder id, key id and public key"
        )
    builder = TrustedBuilder(
        builder_id=source.builder_id,
        keyid=source.builder_keyid,
        public_key_pem=source.builder_public_key_pem.encode("utf-8"),
    )
    return ProvenancePolicy(
        trusted_builders=(builder,),
        project_url=source.project_url,
        require_tag_ref_prefix=source.require_tag_ref_prefix,
    )


def ingest_policy(source: Source) -> AppIngestPolicy:
    """The full per-application ingestion policy.

    `critical` carries straight through to `dist_core.roles.app_role_policy`,
    which is what decides between `PROMOTE` and `HOLD_FOR_CEREMONY`. The admin
    plane records that choice; it does not get to override the consequence.
    """
    return AppIngestPolicy(
        app_id=source.app_id,
        critical=source.critical,
        provenance=provenance_policy(source),
    )
