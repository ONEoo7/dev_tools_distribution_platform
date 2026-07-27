"""Certificate-identity provenance, for forges that sign with Sigstore.

GitHub Actions produces exactly the payload `provenance.py` already knows how
to read — an in-toto Statement v1 carrying a SLSA Provenance v1 predicate, in a
DSSE envelope — but establishes *who signed it* differently. There is no
long-lived builder key to pin. Fulcio issues a certificate for the duration of
one workflow run, bound to the OIDC token that run presented, and the signature
is logged in Rekor.

So this module answers one question — "was this envelope signed by a builder
identity we trust?" — and then hands the statement to
`provenance.check_statement`, which is shared with the fixed-key path. What an
attestation must *say* does not depend on how it was signed.

The verification itself is delegated to `sigstore`. Fulcio chain validation,
signed certificate timestamps, Rekor inclusion proofs and checkpoint signatures
are each easy to implement subtly wrongly, and a subtly wrong implementation
here accepts forged builds. The dependency is the cheaper risk. See PLAN.md
section 4.1.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sigstore.errors import Error as SigstoreError
from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify import policy as sigstore_policy

from dist_ingest.provenance import (
    CertificateIdentity,
    Provenance,
    ProvenanceError,
    ProvenancePolicy,
    check_statement,
)

if TYPE_CHECKING:
    from sigstore.verify.policy import VerificationPolicy

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

#: Refuse to parse a bundle larger than this. A bundle is a certificate, a
#: signature and a small statement; anything bigger is a mistake or an attempt
#: to make us allocate.
MAX_BUNDLE_BYTES = 4 * 1024 * 1024


def _certificate_policy(identity: CertificateIdentity) -> VerificationPolicy:
    """Build the certificate policy for one trusted identity.

    Every clause is an X.509 extension Fulcio wrote from the OIDC token, so
    none of it is under the control of the workflow being verified. The SAN is
    deliberately *not* pinned here — it carries the ref, which changes every
    release. `CertificateIdentity.matches_builder` covers the ref-invariant
    part, and `require_tag_ref_prefix` covers the ref itself.
    """
    return sigstore_policy.AllOf(
        [
            sigstore_policy.OIDCIssuer(identity.issuer),
            sigstore_policy.GitHubWorkflowRepository(identity.repository),
            sigstore_policy.OIDCSourceRepositoryIdentifier(identity.repository_id),
            sigstore_policy.OIDCSourceRepositoryOwnerIdentifier(identity.repository_owner_id),
            sigstore_policy.OIDCRunnerEnvironment(identity.runner_environment),
        ]
    )


def _load_bundle(raw: bytes) -> Bundle:
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ProvenanceError(f"bundle is {len(raw)} bytes, over the {MAX_BUNDLE_BYTES} limit")
    try:
        # Explicit UTF-8: the Rekor checkpoint separator is an em dash, and
        # decoding it under a locale codec silently corrupts the signature
        # block into something that parses to zero signatures.
        return Bundle.from_json(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, SigstoreError) as exc:
        raise ProvenanceError(f"malformed sigstore bundle: {exc}") from exc


def _statement_builder_id(statement: dict[str, Any]) -> str:
    predicate = statement.get("predicate")
    run_details = predicate.get("runDetails") if isinstance(predicate, dict) else None
    builder = run_details.get("builder") if isinstance(run_details, dict) else None
    claimed = builder.get("id") if isinstance(builder, dict) else None
    if not isinstance(claimed, str) or not claimed:
        raise ProvenanceError("statement names no builder")
    return claimed


def verify_sigstore_provenance(
    bundle_json: bytes, artifact_sha256: str, policy: ProvenancePolicy
) -> Provenance:
    """Verify a Sigstore-signed attestation, or raise.

    Checks, in order:

    1. the bundle parses,
    2. for some trusted identity, the certificate chains to Fulcio, the entry
       is in Rekor, and every pinned OIDC claim matches,
    3. the payload is the in-toto media type,
    4. the builder named in the statement is covered by that same identity,
    5. everything `check_statement` requires — statement and predicate types,
       subject digest against these exact bytes, project and tag ref.

    Nothing in the statement is read before step 2 succeeds.

    Trying each trusted identity in turn is not a weakening: an artifact is
    accepted only if some *single* identity satisfies both the certificate
    policy and the builder claim, and each identity independently pins the
    repository, its numeric ID, its owner's numeric ID and the runner
    environment.

    Raises:
        ProvenanceError: on any failure. Never returns a partial result.
    """
    if not policy.trusted_identities:
        raise ProvenanceError("policy trusts no certificate identities")

    bundle = _load_bundle(bundle_json)
    verifier = Verifier.production()

    failures: list[str] = []
    for identity in policy.trusted_identities:
        try:
            payload_type, payload = verifier.verify_dsse(bundle, _certificate_policy(identity))
        except SigstoreError as exc:
            failures.append(f"{identity.workflow_uri}: {exc}")
            continue

        if payload_type != DSSE_PAYLOAD_TYPE:
            raise ProvenanceError(f"unexpected DSSE payload type {payload_type!r}")

        try:
            statement = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ProvenanceError(f"statement is not JSON: {exc}") from exc
        if not isinstance(statement, dict):
            raise ProvenanceError("statement is not an object")

        # The certificate proved which workflow signed. This proves the
        # statement is not claiming some *other* workflow built the artifact.
        builder_id = _statement_builder_id(statement)
        if not identity.matches_builder(builder_id):
            raise ProvenanceError(
                f"certificate authenticated {identity.workflow_uri!r} but the statement "
                f"claims builder {builder_id!r}"
            )

        return check_statement(statement, builder_id, artifact_sha256, policy)

    raise ProvenanceError(
        "no trusted certificate identity verified this bundle: " + "; ".join(failures)
    )
