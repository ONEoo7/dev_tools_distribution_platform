"""Provenance verification for artifacts pulled from a forge.

Mirrors docs/PLAN.md section 4.1. This module is the reason a forge can be a
source of candidate artifacts without becoming an authority to sign:

    "It appeared in a release" is not evidence of anything. "This artifact was
    built by pipeline X on protected tag Y in project Z, attested by a signing
    identity we trust" is.

Everything here answers that second sentence. An artifact that fails any check
never leaves quarantine.

Format: a DSSE envelope (https://github.com/secure-systems-lab/dsse) wrapping
an in-toto Statement v1 whose predicate is SLSA Provenance v1.

Two ways of establishing *who signed* that envelope are supported, because the
two forges do it differently:

- **A fixed public key** (this module). The builder holds a long-lived key and
  we pin it. Used for GitLab, and for anything self-signed.
- **A certificate identity** (`attestation.py`). The builder has no long-lived
  key; a short-lived certificate binds the signature to an OIDC identity. Used
  for GitHub Actions.

Everything downstream of "we now have a trustworthy statement and know which
builder signed it" is shared — see `check_statement`.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

#: Refuse to parse an envelope larger than this. Provenance is small; anything
#: bigger is either a mistake or an attempt to make us allocate.
MAX_ENVELOPE_BYTES = 1024 * 1024


class ProvenanceError(Exception):
    """An artifact's provenance could not be verified. Always fail closed."""


@dataclass(frozen=True, slots=True)
class TrustedBuilder:
    """A builder identity whose attestations we accept.

    `keyid` and `builder_id` are separate identifiers and both are checked.
    The keyid selects the verification key from the DSSE envelope; the
    builder_id is a claim *inside* the signed statement. Requiring them to
    correspond stops one trusted builder's key from attesting a statement that
    claims a different builder produced the artifact.
    """

    builder_id: str
    keyid: str
    public_key_pem: bytes

    def public_key(self) -> PublicKeyTypes:
        return serialization.load_pem_public_key(self.public_key_pem)


@dataclass(frozen=True, slots=True)
class CertificateIdentity:
    """A builder identified by a short-lived certificate, not a pinned key.

    GitHub Actions has no long-lived signing key: Fulcio issues a certificate
    for the duration of one run, bound to the OIDC token that run presented.
    So there is nothing to pin, and the identity in the certificate takes the
    place of `TrustedBuilder.keyid`.

    That turns out to be the stronger position. The fields below are X.509
    extensions asserted by Fulcio from the OIDC token, *not* claims in the
    signed payload. A malicious workflow controls its own predicate; it does
    not control these.

    - `workflow_uri` is the ref-invariant part of the certificate SAN. The SAN
      itself is `<workflow_uri>@<ref>`, so pinning the whole thing would need a
      configuration edit for every release; we pin the workflow and check the
      ref separately against `require_tag_ref_prefix`, which is the property
      actually worth enforcing.
    - `repository_id` and `repository_owner_id` are numeric and immutable.
      Pinning them defeats an attack that comparing `project_url` alone does
      not: a repository can be renamed, transferred, or deleted and its name
      re-registered by someone else. The ID cannot be re-used.
    - `runner_environment` pins the build to GitHub-hosted infrastructure. A
      self-hosted runner is hardware the repository owner controls, so it can
      emit structurally genuine attestations for arbitrary bytes.

    This type carries no `sigstore` import on purpose; it is policy data, and
    keeping it here means the fixed-key path never pays for that dependency.
    """

    workflow_uri: str
    issuer: str
    repository: str
    repository_id: str
    repository_owner_id: str
    runner_environment: str = "github-hosted"

    def matches_builder(self, builder_id: str) -> bool:
        """Does this identity cover the builder named in a statement?

        Prefix match on purpose, and anchored with the `@` so that a workflow
        at `.../release.yml` cannot be satisfied by `.../release.yml.evil@ref`.
        """
        return builder_id.startswith(f"{self.workflow_uri}@")


@dataclass(frozen=True, slots=True)
class ProvenancePolicy:
    """What an attestation must say before an artifact may be promoted.

    `project_url` and `require_tag_ref_prefix` are what stop a valid
    attestation from an unrelated project, or from an unprotected branch build,
    being accepted for this application.

    Exactly one of `trusted_builders` and `trusted_identities` is normally
    populated, according to how the app's forge signs. Both empty would reject
    every artifact — safe, but always a misconfiguration, so it is refused at
    construction rather than at three in the morning.
    """

    trusted_builders: tuple[TrustedBuilder, ...]
    project_url: str
    require_tag_ref_prefix: str = "refs/tags/"
    trusted_identities: tuple[CertificateIdentity, ...] = ()

    def __post_init__(self) -> None:
        if not self.trusted_builders and not self.trusted_identities:
            raise ValueError(
                "provenance policy trusts no builder: set trusted_builders "
                "(fixed key) or trusted_identities (certificate identity)"
            )

    def builder_for_keyid(self, keyid: str) -> TrustedBuilder | None:
        for candidate in self.trusted_builders:
            if candidate.keyid == keyid:
                return candidate
        return None

    def identity_for_builder(self, builder_id: str) -> CertificateIdentity | None:
        for candidate in self.trusted_identities:
            if candidate.matches_builder(builder_id):
                return candidate
        return None


@dataclass(frozen=True, slots=True)
class Provenance:
    """The verified facts about how an artifact was built."""

    builder_id: str
    source_uri: str
    source_ref: str
    subject_name: str
    subject_sha256: str
    statement: dict[str, Any] = field(repr=False, default_factory=dict)


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding.

    The signature covers this, not the raw payload, so that the payload type is
    bound in too and a signature cannot be replayed under a different type.
    """
    encoded_type = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(encoded_type), encoded_type, len(payload), payload)


def _verify_signature(key: PublicKeyTypes, signature: bytes, message: bytes) -> bool:
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            raise ProvenanceError(f"unsupported builder key type {type(key).__name__}")
    except InvalidSignature:
        return False
    return True


def _decode_envelope(raw: bytes) -> tuple[str, bytes, list[dict[str, Any]]]:
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ProvenanceError(f"envelope is {len(raw)} bytes, limit is {MAX_ENVELOPE_BYTES}")

    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ProvenanceError(f"envelope is not valid JSON: {e}") from None
    if not isinstance(envelope, dict):
        raise ProvenanceError("envelope is not a JSON object")

    payload_type = envelope.get("payloadType")
    if payload_type != DSSE_PAYLOAD_TYPE:
        raise ProvenanceError(f"unexpected payloadType {payload_type!r}")

    encoded = envelope.get("payload")
    if not isinstance(encoded, str):
        raise ProvenanceError("envelope has no payload")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ProvenanceError(f"payload is not valid base64: {e}") from None

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise ProvenanceError("envelope carries no signatures")

    return payload_type, payload, signatures


def _verify_envelope(raw: bytes, policy: ProvenancePolicy) -> tuple[dict[str, Any], str]:
    """Check the DSSE signature and return the statement and builder id."""
    payload_type, payload, signatures = _decode_envelope(raw)
    message = _pae(payload_type, payload)

    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        keyid = entry.get("keyid")
        encoded_sig = entry.get("sig")
        if not isinstance(keyid, str) or not isinstance(encoded_sig, str):
            continue

        builder = policy.builder_for_keyid(keyid)
        if builder is None:
            # An untrusted identity's signature carries no weight; keep looking
            # rather than failing, since an envelope may carry several.
            continue

        try:
            signature = base64.b64decode(encoded_sig, validate=True)
        except (binascii.Error, ValueError):
            continue

        if _verify_signature(builder.public_key(), signature, message):
            try:
                statement = json.loads(payload)
            except json.JSONDecodeError as e:
                raise ProvenanceError(f"payload is not valid JSON: {e}") from None
            if not isinstance(statement, dict):
                raise ProvenanceError("statement is not a JSON object")
            return statement, builder.builder_id

    raise ProvenanceError("no signature from a trusted builder")


def _check_builder_claim(statement: dict[str, Any], builder_id: str) -> None:
    """The statement's own builder claim must match the key that signed it."""
    predicate = statement.get("predicate")
    run_details = predicate.get("runDetails") if isinstance(predicate, dict) else None
    builder = run_details.get("builder") if isinstance(run_details, dict) else None
    claimed = builder.get("id") if isinstance(builder, dict) else None

    if claimed != builder_id:
        raise ProvenanceError(
            f"statement claims builder {claimed!r} but was signed by the key for {builder_id!r}"
        )


def _subject_digest(statement: dict[str, Any], artifact_sha256: str) -> tuple[str, str]:
    """Find the subject entry that binds this statement to these exact bytes.

    Without this an attacker could pair a genuine attestation with a different
    artifact, which is the whole attack provenance exists to prevent.
    """
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ProvenanceError("statement has no subject")

    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        digests = subject.get("digest")
        if not isinstance(digests, dict):
            continue
        declared = digests.get("sha256")
        if isinstance(declared, str) and declared.lower() == artifact_sha256.lower():
            name = subject.get("name")
            return (name if isinstance(name, str) else ""), declared.lower()

    raise ProvenanceError(
        f"no subject matches the artifact digest {artifact_sha256}; "
        "the attestation describes different bytes"
    )


def _source(statement: dict[str, Any], policy: ProvenancePolicy) -> tuple[str, str]:
    """Extract and check the source repository and ref.

    SLSA v1 records the source as a resolved dependency with a URI of the form
    `git+<repo>@<ref>`.
    """
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ProvenanceError("statement has no predicate")

    build_definition = predicate.get("buildDefinition")
    if not isinstance(build_definition, dict):
        raise ProvenanceError("predicate has no buildDefinition")

    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list):
        raise ProvenanceError("buildDefinition has no resolvedDependencies")

    expected = f"git+{policy.project_url}"
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        uri = dependency.get("uri")
        if not isinstance(uri, str) or not uri.startswith(f"{expected}@"):
            continue

        ref = uri[len(expected) + 1 :]
        if not ref.startswith(policy.require_tag_ref_prefix):
            raise ProvenanceError(
                f"build ran on {ref!r}, which is not under "
                f"{policy.require_tag_ref_prefix!r}; only tag builds may be promoted"
            )
        return uri, ref

    raise ProvenanceError(
        f"no resolved dependency from {policy.project_url}; "
        "the attestation describes a build of a different project"
    )


def verify_provenance(
    envelope: bytes, artifact_sha256: str, policy: ProvenancePolicy
) -> Provenance:
    """Verify an artifact's provenance, or raise.

    Checks, in order:

    1. the DSSE envelope is signed by a trusted builder identity,
    2. the statement and predicate are the types we expect,
    3. a subject digest matches these exact artifact bytes,
    4. the build resolved the expected project at a tag ref.

    Order matters: nothing in the statement is read until its signature has
    been verified.
    """
    statement, builder_id = _verify_envelope(envelope, policy)
    return check_statement(statement, builder_id, artifact_sha256, policy)


def check_statement(
    statement: dict[str, Any],
    builder_id: str,
    artifact_sha256: str,
    policy: ProvenancePolicy,
) -> Provenance:
    """Check an already-authenticated statement against the policy.

    Split out so the fixed-key and certificate-identity paths cannot drift
    apart: however the signature was established, what the statement has to
    *say* is identical.

    The caller is asserting that `statement` came out of a verified envelope
    and that `builder_id` is the identity that signed it. Passing an
    unauthenticated statement here defeats the entire module.
    """
    if statement.get("_type") != IN_TOTO_STATEMENT_V1:
        raise ProvenanceError(f"unexpected statement type {statement.get('_type')!r}")
    if statement.get("predicateType") != SLSA_PROVENANCE_V1:
        raise ProvenanceError(f"unexpected predicate type {statement.get('predicateType')!r}")

    _check_builder_claim(statement, builder_id)
    subject_name, subject_sha256 = _subject_digest(statement, artifact_sha256)
    source_uri, source_ref = _source(statement, policy)

    return Provenance(
        builder_id=builder_id,
        source_uri=source_uri,
        source_ref=source_ref,
        subject_name=subject_name,
        subject_sha256=subject_sha256,
        statement=statement,
    )
