"""The bridge between a stored source and the ingestion policy.

`dist_ingest.sources` is the only place the registry and the security core
meet. Two properties are worth pinning down there, because both are invisible
in the modules on either side:

- a database row cannot name a new egress destination, and
- a source that reached the worker without its pins does not quietly get a
  weaker policy than the operator thought they configured.
"""

from __future__ import annotations

import uuid

import pytest

from dist_ingest.sources import (
    GITHUB_DOWNLOAD_HOSTS,
    SourceConfigError,
    client_for,
    ingest_policy,
    provenance_policy,
    release_source,
)
from dist_registry.models import Forge, Source, SourceStatus

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----"""


def github_source(**overrides: object) -> Source:
    defaults: dict[str, object] = {
        "id": uuid.uuid4(),
        "app_id": "git-assistant",
        "forge": Forge.GITHUB,
        "project": "ONEoo7/ai_tools_git_assistant",
        "api_base": "https://api.github.com",
        "project_url": "https://github.com/ONEoo7/ai_tools_git_assistant",
        "status": SourceStatus.ACTIVE,
        "critical": False,
        "asset_name": "app.zip",
        "tag_prefix": "v",
        "require_tag_ref_prefix": "refs/tags/",
        "max_asset_bytes": 1024,
        "workflow_uri": "https://github.com/ONEoo7/ai_tools_git_assistant/.github/workflows/release.yml",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "repository_id": "123456",
        "repository_owner_id": "654321",
    }
    defaults.update(overrides)
    return Source(**defaults)  # type: ignore[arg-type]


def gitlab_source(**overrides: object) -> Source:
    defaults: dict[str, object] = {
        "id": uuid.uuid4(),
        "app_id": "internal-tool",
        "forge": Forge.GITLAB,
        "project": "platform/internal-tool",
        "api_base": "https://gitlab.example.com",
        "project_url": "https://gitlab.example.com/platform/internal-tool",
        "status": SourceStatus.ACTIVE,
        "critical": False,
        "asset_name": "setup.exe",
        "tag_prefix": "v",
        "require_tag_ref_prefix": "refs/tags/",
        "max_asset_bytes": 1024,
        "builder_id": "https://gitlab.example.com/platform/internal-tool/-/ci",
        "builder_keyid": "a1b2c3",
        "builder_public_key_pem": PUBLIC_KEY,
    }
    defaults.update(overrides)
    return Source(**defaults)  # type: ignore[arg-type]


# ------------------------------------------------------------------- policy


def test_a_github_source_pins_the_certificate_identity() -> None:
    policy = provenance_policy(github_source())

    assert policy.trusted_builders == ()
    (identity,) = policy.trusted_identities
    assert identity.repository_id == "123456"
    assert identity.repository_owner_id == "654321"
    assert identity.runner_environment == "github-hosted"


def test_a_gitlab_source_pins_the_builder_key() -> None:
    policy = provenance_policy(gitlab_source())

    assert policy.trusted_identities == ()
    (builder,) = policy.trusted_builders
    assert builder.keyid == "a1b2c3"
    assert builder.public_key() is not None


@pytest.mark.parametrize(
    "missing", ["repository_id", "repository_owner_id", "workflow_uri", "oidc_issuer"]
)
def test_a_github_source_missing_a_pin_is_refused_rather_than_weakened(missing: str) -> None:
    """The failure mode that matters.

    Dropping an unset claim would build a policy that verifies successfully
    against attestations the operator believed were excluded — a weaker check
    that looks identical from the outside.
    """
    with pytest.raises(SourceConfigError, match="incomplete"):
        provenance_policy(github_source(**{missing: None}))


def test_a_gitlab_source_without_a_key_is_refused() -> None:
    with pytest.raises(SourceConfigError, match="builder"):
        provenance_policy(gitlab_source(builder_public_key_pem=None))


def test_neither_forge_vouches_for_the_other() -> None:
    """Configuring both must not let either forge's identity satisfy the other."""
    github = provenance_policy(github_source())
    gitlab = provenance_policy(gitlab_source())

    assert github.project_url != gitlab.project_url
    assert not github.trusted_builders
    assert not gitlab.trusted_identities


def test_critical_carries_through_to_key_custody() -> None:
    """The admin plane records the choice; it does not get to override it.

    `AppIngestPolicy.keystore` is derived from `dist_core.roles`, so a critical
    application can only ever reach HOLD_FOR_CEREMONY.
    """
    from dist_core.roles import KeyStore

    assert ingest_policy(github_source(critical=True)).keystore is KeyStore.OFFLINE
    assert ingest_policy(github_source(critical=False)).keystore is KeyStore.ONLINE


# ------------------------------------------------------------------- egress


def test_a_github_com_source_allows_the_object_store_and_nothing_else() -> None:
    with client_for(github_source(), None) as client:
        forge = release_source(github_source(), client)
    assert forge._allowed_hosts == GITHUB_DOWNLOAD_HOSTS  # type: ignore[attr-defined]


def test_the_allowlist_names_the_host_github_actually_redirects_to() -> None:
    """Regression: a release download starts on github.com and redirects.

    The allowlist originally named only `objects.githubusercontent.com`, which
    is where GitHub used to serve assets. It serves them from
    `release-assets.githubusercontent.com` now, so every real download was
    refused at the first hop while the mocked tests stayed green. Asserting the
    membership keeps the two hosts from being quietly dropped again; it cannot
    tell us when GitHub adds a third.
    """
    assert "release-assets.githubusercontent.com" in GITHUB_DOWNLOAD_HOSTS
    assert "objects.githubusercontent.com" in GITHUB_DOWNLOAD_HOSTS


def test_a_github_enterprise_source_allows_only_its_own_host() -> None:
    """github.com's object store is not reachable from an enterprise install.

    Carrying the public allowlist over would let a compromised enterprise API
    redirect a download to github.com, which is not a host anybody approved for
    that source.
    """
    source = github_source(api_base="https://github.internal.example/api/v3")
    with client_for(source, None) as client:
        forge = release_source(source, client)
    assert forge._allowed_hosts == frozenset({"github.internal.example"})  # type: ignore[attr-defined]


def test_a_gitlab_source_allows_only_the_instance_host() -> None:
    with client_for(gitlab_source(), None) as client:
        forge = release_source(gitlab_source(), client)
    assert forge._allowed_hosts == frozenset({"gitlab.example.com"})  # type: ignore[attr-defined]


# --------------------------------------------------------------- credential


def test_each_forge_gets_the_header_it_understands() -> None:
    with client_for(github_source(), "tok") as client:
        assert client.headers["authorization"] == "Bearer tok"
    with client_for(gitlab_source(), "tok") as client:
        assert client.headers["private-token"] == "tok"


def test_no_token_means_no_credential_header() -> None:
    with client_for(github_source(), None) as client:
        assert "authorization" not in client.headers


def test_redirects_are_never_followed_by_the_client_itself() -> None:
    """`_stream` checks the host on every hop by hand.

    A client that followed redirects would go wherever a `Location` header
    pointed, before the allowlist ever saw the address.
    """
    with client_for(github_source(), None) as client:
        assert client.follow_redirects is False
