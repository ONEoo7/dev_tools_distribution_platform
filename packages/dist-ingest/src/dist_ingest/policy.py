"""Promotion policy: what happens to an artifact once it is in quarantine.

Mirrors docs/PLAN.md section 4.1, "Where automation stops".

The decision is deliberately tied to key custody rather than to a separate
flag. An application whose delegated role is held in `offline.kdbx` can never
be promoted by this service, because promoting it would require a key that is
not on the host at all. Automation ends exactly where the offline keys begin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from dist_core.roles import KeyStore, app_role_policy
from dist_ingest.gates import (
    ArchiveLimits,
    ArchiveReport,
    ContentGates,
    GateError,
    inspect_archive,
    run_content_gates,
)
from dist_ingest.provenance import (
    Provenance,
    ProvenanceError,
    ProvenancePolicy,
    verify_provenance,
)
from dist_ingest.quarantine import Admitted, Quarantine, QuarantineError


class Promotion(StrEnum):
    """What may be done with a candidate."""

    #: Every gate passed and the application's key is online.
    PROMOTE = "promote"
    #: Every gate passed, but signing needs an offline key and a human.
    HOLD_FOR_CEREMONY = "hold_for_ceremony"
    #: A gate failed. The artifact stays in quarantine for inspection.
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class AppIngestPolicy:
    """Per-application ingestion settings."""

    app_id: str
    critical: bool
    provenance: ProvenancePolicy
    archive_limits: ArchiveLimits = field(default_factory=ArchiveLimits)
    content_gates: ContentGates = field(default_factory=ContentGates)

    @property
    def keystore(self) -> KeyStore:
        return app_role_policy(self.app_id, critical=self.critical).keystore


@dataclass(frozen=True, slots=True)
class Outcome:
    decision: Promotion
    reason: str
    admitted: Admitted | None = None
    provenance: Provenance | None = None
    archive: ArchiveReport | None = None

    @property
    def promoted(self) -> bool:
        return self.decision is Promotion.PROMOTE


def _verify(envelope: bytes, sha256: str, policy: ProvenancePolicy) -> Provenance:
    """Verify an attestation by whichever route this policy's forge signs with.

    PLAN.md 4.1 describes two ways of establishing who signed, and which one
    applies is a property of the policy rather than of the caller: a policy
    carrying certificate identities came from a forge that signs with Sigstore,
    and one carrying trusted builders came from a forge that signs with a key
    we pinned. `ProvenancePolicy` refuses to construct with neither, so there
    is no third case.

    Dispatching on the policy rather than sniffing the envelope is deliberate.
    The envelope is attacker-influenced input; letting its shape select the
    verification route would let an attacker choose which check to face.

    The `sigstore` import is local on purpose. `provenance.py` keeps that
    dependency out of the fixed-key path, and importing `attestation` at module
    scope here would undo that for every caller.

    Raises:
        ProvenanceError: on any failure.
    """
    if policy.trusted_identities:
        from dist_ingest.attestation import verify_sigstore_provenance

        return verify_sigstore_provenance(envelope, sha256, policy)
    return verify_provenance(envelope, sha256, policy)


def ingest(
    source: BinaryIO,
    policy: AppIngestPolicy,
    quarantine: Quarantine,
    *,
    envelope: bytes | None,
    sbom: bytes | None = None,
) -> Outcome:
    """Admit a candidate to quarantine and decide what may be done with it.

    Order is deliberate. The artifact is stored and hashed first, so provenance
    is checked against the bytes we actually hold rather than against anything
    the source claimed about them.
    """
    try:
        admitted = quarantine.admit(source)
    except QuarantineError as e:
        return Outcome(Promotion.REJECT, f"not admitted: {e}")

    if not envelope:
        return Outcome(
            Promotion.REJECT,
            "no provenance attestation; appearing in a GitLab release is not evidence",
            admitted=admitted,
        )

    try:
        provenance = _verify(envelope, admitted.sha256, policy.provenance)
    except ProvenanceError as e:
        return Outcome(Promotion.REJECT, f"provenance rejected: {e}", admitted=admitted)

    try:
        archive = inspect_archive(admitted.path, policy.archive_limits)
        run_content_gates(admitted.path, policy.app_id, policy.content_gates, sbom=sbom)
    except GateError as e:
        return Outcome(
            Promotion.REJECT,
            f"gate failed: {e}",
            admitted=admitted,
            provenance=provenance,
        )

    if policy.keystore is KeyStore.OFFLINE:
        return Outcome(
            Promotion.HOLD_FOR_CEREMONY,
            (f"{policy.app_id!r} signs with an offline key; promotion requires a signing ceremony"),
            admitted=admitted,
            provenance=provenance,
            archive=archive,
        )

    return Outcome(
        Promotion.PROMOTE,
        f"all gates passed; built by {provenance.builder_id} at {provenance.source_ref}",
        admitted=admitted,
        provenance=provenance,
        archive=archive,
    )


def promote(outcome: Outcome, quarantine: Quarantine, destination: Path) -> Path:
    """Move a promoted artifact out of quarantine.

    Refuses anything the policy did not clear, so a caller cannot skip the
    decision by calling this directly.
    """
    if outcome.decision is not Promotion.PROMOTE or outcome.admitted is None:
        raise GateError(f"refusing to promote an artifact decided {outcome.decision}")
    return quarantine.promote(outcome.admitted.sha256, destination)
