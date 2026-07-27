"""GitLab release ingestion: quarantine, provenance gates and promotion policy."""

from dist_ingest.gates import (
    ArchiveLimits,
    ArchiveReport,
    ContentGates,
    GateError,
    GateNotConfiguredError,
    MalwareScanner,
    PublisherCheck,
    check_entry_name,
    inspect_archive,
    run_content_gates,
)
from dist_ingest.policy import (
    AppIngestPolicy,
    Outcome,
    Promotion,
    ingest,
    promote,
)
from dist_ingest.provenance import (
    Provenance,
    ProvenanceError,
    ProvenancePolicy,
    TrustedBuilder,
    verify_provenance,
)
from dist_ingest.quarantine import Admitted, Quarantine, QuarantineError

__all__ = [
    "Admitted",
    "AppIngestPolicy",
    "ArchiveLimits",
    "ArchiveReport",
    "ContentGates",
    "GateError",
    "GateNotConfiguredError",
    "MalwareScanner",
    "Outcome",
    "Promotion",
    "Provenance",
    "ProvenanceError",
    "ProvenancePolicy",
    "PublisherCheck",
    "Quarantine",
    "QuarantineError",
    "TrustedBuilder",
    "check_entry_name",
    "ingest",
    "inspect_archive",
    "promote",
    "run_content_gates",
    "verify_provenance",
]
