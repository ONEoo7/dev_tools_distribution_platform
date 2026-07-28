"""The operational store shared by the admin plane and the ingest worker.

This package exists to keep one dependency arrow pointing the right way.

The admin plane (PLAN.md 8) accepts operator input and has no forge credential
and no signing key. The ingest worker (PLAN.md 4.1) holds the forge credential
and has no inbound listener. They have to agree on what a registered source is
and on how work passes between them, and neither may import the other — so the
agreement lives here, and both depend on it.

What passes between them is a job queue rather than a call. That is the same
rule as PLAN.md 8.2: the component facing operators enqueues, and the component
holding the credential decides what it will do about it.
"""

from dist_registry.models import (
    AuditEvent,
    Forge,
    Job,
    JobKind,
    JobState,
    Source,
    SourceStatus,
)

__all__ = [
    "AuditEvent",
    "Forge",
    "Job",
    "JobKind",
    "JobState",
    "Source",
    "SourceStatus",
]
