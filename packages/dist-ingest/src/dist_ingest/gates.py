"""Promotion gates.

Mirrors the gate table in docs/PLAN.md section 4.1. Every gate fails closed:
an artifact is promoted only when all of them pass, never when one is merely
inconclusive.

Gates split into two kinds. Those that are pure computation over the bytes are
implemented here. Those that need an external service — malware scanning,
vulnerability and licence policy, Authenticode publisher checks — are declared
as protocols and must be supplied. `GateNotConfiguredError` is raised if one
is missing, rather than quietly treating "not checked" as "passed".
"""

from __future__ import annotations

import tarfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class GateError(Exception):
    """An artifact failed a promotion gate."""


class GateNotConfiguredError(GateError):
    """A gate the policy requires has no implementation wired in.

    Deliberately an error. A gate that is not running is not a gate that
    passes.
    """


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    """Bounds on what an archive may contain.

    Defaults are deliberately generous for real software and still far below
    what a decompression bomb needs.
    """

    max_entries: int = 100_000
    max_total_uncompressed: int = 8 * 1024 * 1024 * 1024
    max_expansion_ratio: float = 200.0


@dataclass(frozen=True, slots=True)
class ArchiveReport:
    entries: int
    total_uncompressed: int
    expansion_ratio: float


def check_entry_name(name: str) -> None:
    """Reject an archive member whose path could escape the extraction root.

    Checked at ingest even though nothing is extracted here, so a hostile
    archive is stopped before it reaches anything that might extract it.

    Public because some of these shapes cannot be round-tripped through
    `zipfile` on every platform -- Windows rewrites a backslash to a forward
    slash on the way in -- so this has to be testable on its own.
    """
    if not name or name in {".", ".."}:
        raise GateError(f"archive entry has an unusable name {name!r}")
    if name.startswith("/") or name.startswith("\\"):
        raise GateError(f"archive entry {name!r} is an absolute path")
    if "\\" in name:
        raise GateError(f"archive entry {name!r} contains a backslash separator")
    if len(name) > 1 and name[1] == ":":
        raise GateError(f"archive entry {name!r} carries a drive letter")
    if any(part == ".." for part in name.split("/")):
        raise GateError(f"archive entry {name!r} traverses out of the archive root")
    if "\x00" in name:
        raise GateError("archive entry name contains a NUL byte")


def inspect_archive(path: Path, limits: ArchiveLimits | None = None) -> ArchiveReport | None:
    """Check an archive for traversal and decompression bombs.

    Returns `None` if the file is not an archive we recognise; that is not a
    failure, since plenty of artifacts are single binaries.
    """
    limits = limits or ArchiveLimits()
    compressed = path.stat().st_size

    names_and_sizes: list[tuple[str, int]] = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            names_and_sizes = [(info.filename, info.file_size) for info in archive.infolist()]
    elif tarfile.is_tarfile(path):
        # Members are only inspected, never extracted.
        with tarfile.open(path) as archive:
            names_and_sizes = [(member.name, member.size) for member in archive.getmembers()]
    else:
        return None

    if len(names_and_sizes) > limits.max_entries:
        raise GateError(
            f"archive holds {len(names_and_sizes)} entries, limit is {limits.max_entries}"
        )

    total = 0
    for name, size in names_and_sizes:
        check_entry_name(name)
        total += size
        if total > limits.max_total_uncompressed:
            raise GateError(f"archive expands to more than {limits.max_total_uncompressed} bytes")

    ratio = (total / compressed) if compressed else float("inf")
    if ratio > limits.max_expansion_ratio:
        raise GateError(f"archive expands {ratio:.1f}x, limit is {limits.max_expansion_ratio:.1f}x")

    return ArchiveReport(len(names_and_sizes), total, ratio)


class MalwareScanner(Protocol):
    """Scans an artifact. Must raise or return False rather than pass on error."""

    def is_clean(self, path: Path) -> bool: ...


class PublisherCheck(Protocol):
    """Confirms the artifact's platform signature matches the app's publisher.

    PLAN.md 6.4 rule 5: TUF secures the channel, Authenticode secures the file
    at rest. The new binary's publisher must match the installed one.
    """

    def matches_expected_publisher(self, path: Path, app_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class ContentGates:
    """External gates. `None` means not configured, which is an error at run time."""

    malware: MalwareScanner | None = None
    publisher: PublisherCheck | None = None
    require_sbom: bool = True


def run_content_gates(path: Path, app_id: str, gates: ContentGates, *, sbom: bytes | None) -> None:
    """Run the gates that depend on external services.

    Raises `GateNotConfiguredError` when a gate is missing, so a
    misconfigured deployment fails loudly instead of promoting unscanned
    artifacts.
    """
    if gates.malware is None:
        raise GateNotConfiguredError("no malware scanner configured")
    if not gates.malware.is_clean(path):
        raise GateError("malware scan failed")

    if gates.publisher is None:
        raise GateNotConfiguredError("no publisher check configured")
    if not gates.publisher.matches_expected_publisher(path, app_id):
        raise GateError(f"publisher does not match the one already installed for {app_id!r}")

    if gates.require_sbom and not sbom:
        raise GateError("no SBOM accompanies this artifact")


def describe_failures(errors: Sequence[GateError]) -> str:
    return "; ".join(str(e) for e in errors)
