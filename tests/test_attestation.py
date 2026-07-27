"""Certificate-identity provenance, exercised against a real GitHub bundle.

`fixtures/github-attestation.json` is the genuine Sigstore bundle GitHub
produced for ONEoo7/ai_tools_git_assistant v0.1.0. Using the real thing rather
than a synthetic one is the point: a hand-built bundle would encode my
assumptions about the format, and those assumptions are exactly what needs
testing.

The bundle is immutable and its signature covers a fixed artifact digest, so
these tests stay valid indefinitely. What they cannot cover is certificate
expiry semantics -- Fulcio certificates are short-lived, and verification
succeeds because the Rekor entry proves *when* the signature was made.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from dist_ingest.attestation import verify_sigstore_provenance
from dist_ingest.provenance import (
    CertificateIdentity,
    ProvenanceError,
    ProvenancePolicy,
)

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "github-attestation.json"

PROJECT_URL = "https://github.com/ONEoo7/ai_tools_git_assistant"
ARTIFACT_SHA256 = "3fd704e32e52adac7e2727a94a26b6a17cc19a5640ad2a879a76268bc1cfd619"
WORKFLOW = f"{PROJECT_URL}/.github/workflows/release.yml"
ISSUER = "https://token.actions.githubusercontent.com"


def bundle() -> bytes:
    return FIXTURE.read_bytes()


def identity(**overrides: str) -> CertificateIdentity:
    fields: dict[str, str] = {
        "workflow_uri": WORKFLOW,
        "issuer": ISSUER,
        "repository": "ONEoo7/ai_tools_git_assistant",
        "repository_id": "1310933302",
        "repository_owner_id": "1506004",
        "runner_environment": "github-hosted",
    }
    fields.update(overrides)
    return CertificateIdentity(**fields)


def policy(*identities: CertificateIdentity) -> ProvenancePolicy:
    return ProvenancePolicy(
        trusted_builders=(),
        project_url=PROJECT_URL,
        trusted_identities=identities or (identity(),),
    )


@pytest.fixture(scope="session")
def sigstore_available() -> bool:
    """Skip rather than fail where the Sigstore trust root is unreachable."""
    from sigstore.verify import Verifier

    try:
        Verifier.production()
    except Exception as exc:
        pytest.skip(f"sigstore trust root unavailable: {exc}")
    return True


# --------------------------------------------------------- offline behaviour
#
# These need no trust root: they fail before any cryptography happens.


def test_a_policy_trusting_nobody_is_refused_at_construction() -> None:
    # Such a policy rejects everything, which is safe but is always a
    # misconfiguration. Better to hear about it at startup.
    with pytest.raises(ValueError, match="trusts no builder"):
        ProvenancePolicy(trusted_builders=(), project_url=PROJECT_URL)


def test_an_oversized_bundle_is_not_parsed() -> None:
    with pytest.raises(ProvenanceError, match="over the"):
        verify_sigstore_provenance(b"x" * (8 * 1024 * 1024), ARTIFACT_SHA256, policy())


def test_a_malformed_bundle_is_refused() -> None:
    with pytest.raises(ProvenanceError, match="malformed"):
        verify_sigstore_provenance(b"{not json", ARTIFACT_SHA256, policy())


def test_a_workflow_prefix_cannot_be_extended_into_a_different_file() -> None:
    # Anchoring on "@" is what stops release.yml matching release.yml.evil.
    ident = identity()
    assert ident.matches_builder(f"{WORKFLOW}@refs/tags/v0.1.0")
    assert not ident.matches_builder(f"{WORKFLOW}.evil@refs/tags/v0.1.0")
    assert not ident.matches_builder(f"{WORKFLOW}-backup@refs/tags/v0.1.0")


def test_the_policy_resolves_a_builder_to_its_identity() -> None:
    p = policy()
    assert p.identity_for_builder(f"{WORKFLOW}@refs/tags/v0.1.0") is not None
    assert p.identity_for_builder("https://github.com/other/repo/.github/x.yml@r") is None


# ------------------------------------------------------- real verification


@pytest.mark.network
@pytest.mark.usefixtures("sigstore_available")
def test_the_real_github_attestation_verifies() -> None:
    result = verify_sigstore_provenance(bundle(), ARTIFACT_SHA256, policy())

    assert result.subject_name == "git-assistant-0.1.0-windows-x64.zip"
    assert result.subject_sha256 == ARTIFACT_SHA256
    assert result.builder_id == f"{WORKFLOW}@refs/tags/v0.1.0"
    assert result.source_ref == "refs/tags/v0.1.0"
    assert result.source_uri == f"git+{PROJECT_URL}@refs/tags/v0.1.0"


@pytest.mark.network
@pytest.mark.usefixtures("sigstore_available")
def test_a_genuine_attestation_does_not_vouch_for_other_bytes() -> None:
    # Pairing a real attestation with a different artifact is the attack
    # provenance exists to prevent.
    with pytest.raises(ProvenanceError, match="no subject matches"):
        verify_sigstore_provenance(bundle(), "00" * 32, policy())


@pytest.mark.network
@pytest.mark.usefixtures("sigstore_available")
@pytest.mark.parametrize(
    "field, value",
    [
        ("repository_id", "999999"),
        ("repository_owner_id", "999999"),
        ("repository", "attacker/ai_tools_git_assistant"),
        ("issuer", "https://token.actions.example.com"),
        ("runner_environment", "self-hosted"),
        ("workflow_uri", f"{PROJECT_URL}/.github/workflows/other.yml"),
    ],
)
def test_every_pinned_certificate_claim_is_load_bearing(field: str, value: str) -> None:
    """Change any one pinned claim and the bundle must stop verifying.

    Without this, a policy clause that silently matched nothing would look
    exactly like a policy clause that worked.
    """
    with pytest.raises(ProvenanceError):
        verify_sigstore_provenance(bundle(), ARTIFACT_SHA256, policy(identity(**{field: value})))


@pytest.mark.network
@pytest.mark.usefixtures("sigstore_available")
def test_a_build_from_a_branch_would_not_be_promoted() -> None:
    # The fixture is a tag build, so assert the gate the other way: requiring a
    # ref prefix the real ref cannot satisfy must reject it.
    branch_only = ProvenancePolicy(
        trusted_builders=(),
        project_url=PROJECT_URL,
        require_tag_ref_prefix="refs/heads/",
        trusted_identities=(identity(),),
    )
    with pytest.raises(ProvenanceError, match="only tag builds"):
        verify_sigstore_provenance(bundle(), ARTIFACT_SHA256, branch_only)


@pytest.mark.network
@pytest.mark.usefixtures("sigstore_available")
def test_an_attestation_for_a_different_project_is_refused() -> None:
    elsewhere = ProvenancePolicy(
        trusted_builders=(),
        project_url="https://github.com/ONEoo7/some_other_project",
        trusted_identities=(identity(),),
    )
    with pytest.raises(ProvenanceError, match="different project"):
        verify_sigstore_provenance(bundle(), ARTIFACT_SHA256, elsewhere)


def test_the_fixture_is_the_bundle_and_carries_no_signed_url() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert parsed["mediaType"].startswith("application/vnd.dev.sigstore.bundle")
    # The API wrapper's blob URL is SAS-signed. Committing it would put a
    # credential in the repository, short-lived or not.
    assert "bundle_url" not in raw
    assert "sig=" not in raw
