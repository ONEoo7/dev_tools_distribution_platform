"""Phase 3 exit criterion (PLAN.md 12).

An unattested or wrong-pipeline artifact must be rejected, and an application
whose key is offline must never be auto-promoted.

These tests treat GitLab as hostile on purpose: every attestation below is
either absent, signed by the wrong key, or truthful about a *different* build.
Appearing in a release is not evidence of anything.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from dist_ingest.gates import ArchiveLimits, GateError, check_entry_name, inspect_archive
from dist_ingest.policy import AppIngestPolicy, Promotion, ingest, promote
from dist_ingest.provenance import (
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_V1,
    SLSA_PROVENANCE_V1,
    ProvenanceError,
    ProvenancePolicy,
    TrustedBuilder,
    verify_provenance,
)
from dist_ingest.quarantine import Quarantine, QuarantineError

BUILDER_ID = "https://gitlab.corp/builders/shared-runner@v1"
KEYID = "builder-key-1"
PROJECT = "https://gitlab.corp/apps/editor"
PAYLOAD = b"editor release payload"


class AlwaysClean:
    def is_clean(self, path: Path) -> bool:
        return True


class AlwaysMatchingPublisher:
    def matches_expected_publisher(self, path: Path, app_id: str) -> bool:
        return True


@pytest.fixture
def builder_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def provenance_policy(builder_key: ed25519.Ed25519PrivateKey) -> ProvenancePolicy:
    pem = builder_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return ProvenancePolicy(
        trusted_builders=(TrustedBuilder(BUILDER_ID, KEYID, pem),),
        project_url=PROJECT,
    )


def statement(
    digest: str,
    *,
    builder_id: str = BUILDER_ID,
    project: str = PROJECT,
    ref: str = "refs/tags/v1.4.2",
    statement_type: str = IN_TOTO_STATEMENT_V1,
    predicate_type: str = SLSA_PROVENANCE_V1,
) -> dict[str, Any]:
    return {
        "_type": statement_type,
        "predicateType": predicate_type,
        "subject": [{"name": "Editor-1.4.2.zip", "digest": {"sha256": digest}}],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://gitlab.corp/build-types/release",
                "externalParameters": {},
                "resolvedDependencies": [{"uri": f"git+{project}@{ref}"}],
            },
            "runDetails": {"builder": {"id": builder_id}},
        },
    }


def envelope(
    body: dict[str, Any],
    key: ed25519.Ed25519PrivateKey,
    *,
    keyid: str = KEYID,
) -> bytes:
    payload = json.dumps(body).encode()
    encoded_type = DSSE_PAYLOAD_TYPE.encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(encoded_type), encoded_type, len(payload), payload)
    return json.dumps(
        {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": keyid, "sig": base64.b64encode(key.sign(pae)).decode()}],
        }
    ).encode()


@pytest.fixture
def quarantine(tmp_path: Path) -> Quarantine:
    return Quarantine(tmp_path / "quarantine")


def app_policy(provenance: ProvenancePolicy, *, critical: bool) -> AppIngestPolicy:
    from dist_ingest.gates import ContentGates

    return AppIngestPolicy(
        app_id="editor",
        critical=critical,
        provenance=provenance,
        content_gates=ContentGates(
            malware=AlwaysClean(),
            publisher=AlwaysMatchingPublisher(),
        ),
    )


def digest_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------- provenance


def test_valid_provenance_is_accepted(
    builder_key: ed25519.Ed25519PrivateKey, provenance_policy: ProvenancePolicy
) -> None:
    """Baseline. Without it the rejection tests could pass vacuously."""
    digest = digest_of(PAYLOAD)
    result = verify_provenance(envelope(statement(digest), builder_key), digest, provenance_policy)
    assert result.builder_id == BUILDER_ID
    assert result.source_ref == "refs/tags/v1.4.2"


def test_provenance_is_forge_neutral() -> None:
    """The verifier is not GitLab-specific.

    DSSE and SLSA are vendor-neutral, and the source is read from the
    `git+<project>@<ref>` convention both forges follow. Adding GitHub as a
    release source therefore needs no change here — only different
    configuration — provided its attestations are signed with a static builder
    key. See PLAN.md 4.2 for the Sigstore case, which is not this.
    """
    github_key = ed25519.Ed25519PrivateKey.generate()
    pem = github_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    builder = (
        "https://github.com/slsa-framework/slsa-github-generator"
        "/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
    )
    project = "https://github.com/acme/editor"
    policy = ProvenancePolicy(
        trusted_builders=(TrustedBuilder(builder, "gh-key-1", pem),),
        project_url=project,
    )

    digest = digest_of(PAYLOAD)
    result = verify_provenance(
        envelope(
            statement(digest, builder_id=builder, project=project),
            github_key,
            keyid="gh-key-1",
        ),
        digest,
        policy,
    )
    assert result.builder_id == builder
    assert result.source_uri.startswith("git+https://github.com/acme/editor@")


def test_a_forge_cannot_attest_for_another_forge(provenance_policy: ProvenancePolicy) -> None:
    """Configuring both forges must not let either vouch for the other's repos."""
    github_key = ed25519.Ed25519PrivateKey.generate()
    digest = digest_of(PAYLOAD)
    # Signed by a key the GitLab policy does not trust, naming a GitHub project.
    foreign = envelope(
        statement(digest, project="https://github.com/acme/editor"), github_key, keyid="gh-key-1"
    )
    with pytest.raises(ProvenanceError, match="no signature from a trusted builder"):
        verify_provenance(foreign, digest, provenance_policy)


def test_signature_from_an_untrusted_key_is_rejected(
    provenance_policy: ProvenancePolicy,
) -> None:
    attacker = ed25519.Ed25519PrivateKey.generate()
    digest = digest_of(PAYLOAD)
    with pytest.raises(ProvenanceError, match="no signature from a trusted builder"):
        verify_provenance(envelope(statement(digest), attacker), digest, provenance_policy)


def test_tampered_payload_is_rejected(
    builder_key: ed25519.Ed25519PrivateKey, provenance_policy: ProvenancePolicy
) -> None:
    """Swap the payload but keep the genuine signature."""
    digest = digest_of(PAYLOAD)
    raw = json.loads(envelope(statement(digest), builder_key))
    forged = statement(digest, ref="refs/heads/main")
    raw["payload"] = base64.b64encode(json.dumps(forged).encode()).decode()

    with pytest.raises(ProvenanceError, match="no signature from a trusted builder"):
        verify_provenance(json.dumps(raw).encode(), digest, provenance_policy)


def test_attestation_for_different_bytes_is_rejected(
    builder_key: ed25519.Ed25519PrivateKey, provenance_policy: ProvenancePolicy
) -> None:
    """A genuine attestation paired with a different artifact.

    This is the attack provenance exists to stop: the signature verifies, the
    builder is trusted, and the bytes are somebody else's.
    """
    genuine = envelope(statement(digest_of(b"the real release")), builder_key)
    with pytest.raises(ProvenanceError, match="no subject matches the artifact digest"):
        verify_provenance(genuine, digest_of(b"a substituted payload"), provenance_policy)


def test_build_of_another_project_is_rejected(
    builder_key: ed25519.Ed25519PrivateKey, provenance_policy: ProvenancePolicy
) -> None:
    digest = digest_of(PAYLOAD)
    other = envelope(statement(digest, project="https://gitlab.corp/apps/viewer"), builder_key)
    with pytest.raises(ProvenanceError, match="different project"):
        verify_provenance(other, digest, provenance_policy)


def test_branch_build_is_rejected(
    builder_key: ed25519.Ed25519PrivateKey, provenance_policy: ProvenancePolicy
) -> None:
    """Only protected tag builds may be promoted."""
    digest = digest_of(PAYLOAD)
    branch = envelope(statement(digest, ref="refs/heads/main"), builder_key)
    with pytest.raises(ProvenanceError, match="not under"):
        verify_provenance(branch, digest, provenance_policy)


def test_builder_claim_must_match_the_signing_key(
    builder_key: ed25519.Ed25519PrivateKey, provenance_policy: ProvenancePolicy
) -> None:
    digest = digest_of(PAYLOAD)
    lying = envelope(
        statement(digest, builder_id="https://gitlab.corp/builders/other"), builder_key
    )
    with pytest.raises(ProvenanceError, match="claims builder"):
        verify_provenance(lying, digest, provenance_policy)


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        ({"statement_type": "https://in-toto.io/Statement/v0.1"}, "statement type"),
        ({"predicate_type": "https://slsa.dev/provenance/v0.2"}, "predicate type"),
    ],
)
def test_unexpected_types_are_rejected(
    builder_key: ed25519.Ed25519PrivateKey,
    provenance_policy: ProvenancePolicy,
    kwargs: dict[str, str],
    expected: str,
) -> None:
    digest = digest_of(PAYLOAD)
    with pytest.raises(ProvenanceError, match=expected):
        verify_provenance(
            envelope(statement(digest, **kwargs), builder_key), digest, provenance_policy
        )


def test_malformed_envelopes_are_rejected(provenance_policy: ProvenancePolicy) -> None:
    digest = digest_of(PAYLOAD)
    for raw in [b"", b"not json", b"[]", b'{"payloadType":"text/plain"}', b"{}"]:
        with pytest.raises(ProvenanceError):
            verify_provenance(raw, digest, provenance_policy)


# --------------------------------------------------------------------- gates


def make_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


@pytest.mark.parametrize(
    "name",
    [
        "../escape.txt",
        "/etc/passwd",
        "\\\\server\\share",
        "C:evil.exe",
        "sub\\dir.txt",
        "a/../../b.txt",
        "",
        "..",
        "with\x00nul",
    ],
)
def test_unsafe_entry_names_are_rejected(name: str) -> None:
    """Checked directly rather than through a real archive.

    `zipfile` rewrites a backslash to a forward slash on Windows, so several of
    these shapes cannot be round-tripped through an archive on every platform —
    but a hostile archive built elsewhere can still carry them.
    """
    with pytest.raises(GateError):
        check_entry_name(name)


def test_archive_traversal_is_rejected_end_to_end(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "a.zip", {"../escape.txt": b"x"})
    with pytest.raises(GateError, match="traverses"):
        inspect_archive(archive)


def test_decompression_bomb_is_rejected(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "bomb.zip", {"big": b"\0" * 5_000_000})
    with pytest.raises(GateError, match="expands"):
        inspect_archive(archive, ArchiveLimits(max_expansion_ratio=50.0))


def test_entry_count_is_capped(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "many.zip", {f"f{n}": b"x" for n in range(50)})
    with pytest.raises(GateError, match="entries"):
        inspect_archive(archive, ArchiveLimits(max_entries=10))


def test_ordinary_archive_passes(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "ok.zip", {"app/Editor.exe": b"payload" * 100})
    report = inspect_archive(archive)
    assert report is not None
    assert report.entries == 1


def test_non_archive_is_not_a_failure(tmp_path: Path) -> None:
    binary = tmp_path / "Editor.exe"
    binary.write_bytes(b"MZ not an archive")
    assert inspect_archive(binary) is None


# -------------------------------------------------------------------- policy


def test_unattested_artifact_is_rejected(
    provenance_policy: ProvenancePolicy, quarantine: Quarantine
) -> None:
    outcome = ingest(
        io.BytesIO(PAYLOAD),
        app_policy(provenance_policy, critical=False),
        quarantine,
        envelope=None,
    )
    assert outcome.decision is Promotion.REJECT
    assert "no provenance attestation" in outcome.reason


def test_wrong_pipeline_artifact_is_rejected(
    builder_key: ed25519.Ed25519PrivateKey,
    provenance_policy: ProvenancePolicy,
    quarantine: Quarantine,
) -> None:
    wrong = envelope(
        statement(digest_of(PAYLOAD), project="https://gitlab.corp/apps/viewer"), builder_key
    )
    outcome = ingest(
        io.BytesIO(PAYLOAD),
        app_policy(provenance_policy, critical=False),
        quarantine,
        envelope=wrong,
        sbom=b"{}",
    )
    assert outcome.decision is Promotion.REJECT
    assert "different project" in outcome.reason


def test_online_key_application_is_promoted(
    builder_key: ed25519.Ed25519PrivateKey,
    provenance_policy: ProvenancePolicy,
    quarantine: Quarantine,
) -> None:
    outcome = ingest(
        io.BytesIO(PAYLOAD),
        app_policy(provenance_policy, critical=False),
        quarantine,
        envelope=envelope(statement(digest_of(PAYLOAD)), builder_key),
        sbom=b"{}",
    )
    assert outcome.decision is Promotion.PROMOTE
    assert outcome.provenance is not None


def test_offline_key_application_is_never_auto_promoted(
    builder_key: ed25519.Ed25519PrivateKey,
    provenance_policy: ProvenancePolicy,
    quarantine: Quarantine,
) -> None:
    """Automation stops where the offline keys begin (PLAN.md 4.1).

    Every gate passes here. The artifact still may not be promoted, because
    signing it needs a key that is not on this host at all.
    """
    outcome = ingest(
        io.BytesIO(PAYLOAD),
        app_policy(provenance_policy, critical=True),
        quarantine,
        envelope=envelope(statement(digest_of(PAYLOAD)), builder_key),
        sbom=b"{}",
    )
    assert outcome.decision is Promotion.HOLD_FOR_CEREMONY
    assert not outcome.promoted


def test_promote_refuses_anything_not_cleared(
    builder_key: ed25519.Ed25519PrivateKey,
    provenance_policy: ProvenancePolicy,
    quarantine: Quarantine,
    tmp_path: Path,
) -> None:
    outcome = ingest(
        io.BytesIO(PAYLOAD),
        app_policy(provenance_policy, critical=True),
        quarantine,
        envelope=envelope(statement(digest_of(PAYLOAD)), builder_key),
        sbom=b"{}",
    )
    with pytest.raises(GateError, match="refusing to promote"):
        promote(outcome, quarantine, tmp_path / "targets" / "Editor.zip")


def test_missing_sbom_is_rejected(
    builder_key: ed25519.Ed25519PrivateKey,
    provenance_policy: ProvenancePolicy,
    quarantine: Quarantine,
) -> None:
    outcome = ingest(
        io.BytesIO(PAYLOAD),
        app_policy(provenance_policy, critical=False),
        quarantine,
        envelope=envelope(statement(digest_of(PAYLOAD)), builder_key),
        sbom=None,
    )
    assert outcome.decision is Promotion.REJECT
    assert "SBOM" in outcome.reason


def test_unconfigured_scanner_rejects_rather_than_passes(
    builder_key: ed25519.Ed25519PrivateKey,
    provenance_policy: ProvenancePolicy,
    quarantine: Quarantine,
) -> None:
    """A gate that is not running is not a gate that passes."""
    policy = AppIngestPolicy(app_id="editor", critical=False, provenance=provenance_policy)
    outcome = ingest(
        io.BytesIO(PAYLOAD),
        policy,
        quarantine,
        envelope=envelope(statement(digest_of(PAYLOAD)), builder_key),
        sbom=b"{}",
    )
    assert outcome.decision is Promotion.REJECT
    assert "no malware scanner configured" in outcome.reason


# ---------------------------------------------------------------- quarantine


def test_quarantine_is_content_addressed(quarantine: Quarantine) -> None:
    admitted = quarantine.admit(io.BytesIO(PAYLOAD))
    assert admitted.sha256 == digest_of(PAYLOAD)
    assert admitted.length == len(PAYLOAD)
    assert quarantine.contains(admitted.sha256)


def test_quarantine_enforces_a_size_cap(tmp_path: Path) -> None:
    small = Quarantine(tmp_path / "q", max_bytes=16)
    with pytest.raises(QuarantineError, match="exceeds"):
        small.admit(io.BytesIO(b"x" * 1024))
    assert list((tmp_path / "q").iterdir()) == [], "partial transfer was not cleaned up"


def test_promotion_reverifies_the_staged_bytes(quarantine: Quarantine, tmp_path: Path) -> None:
    """Closes the window between admission and promotion.

    Verifying only on the way in would let a local attacker swap the staged
    file before it is copied to the targets store.
    """
    admitted = quarantine.admit(io.BytesIO(PAYLOAD))
    admitted.path.write_bytes(b"swapped after the gates ran")

    with pytest.raises(QuarantineError, match="was modified"):
        quarantine.promote(admitted.sha256, tmp_path / "out.bin")
