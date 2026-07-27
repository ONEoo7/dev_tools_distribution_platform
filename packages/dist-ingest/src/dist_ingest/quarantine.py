"""Content-addressed quarantine store.

Mirrors docs/PLAN.md section 4.1. Everything pulled from GitLab lands here
first and nothing leaves until every gate has passed, so `dist-ingest` can hold
an artifact without being able to publish one.

Content addressing means the digest is computed from the bytes we actually
stored, not from anything the source told us. A source that lies about a
digest simply gets a different filename.
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO

#: Refuse anything larger before it can fill the volume. Overridable per app.
DEFAULT_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024

_CHUNK = 1024 * 1024


class QuarantineError(Exception):
    """An artifact could not be admitted to quarantine."""


@dataclass(frozen=True, slots=True)
class Admitted:
    """An artifact now sitting in quarantine, not yet promoted."""

    sha256: str
    length: int
    path: Path


class Quarantine:
    def __init__(self, root: Path, max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES) -> None:
        self._root = root
        self._max_bytes = max_bytes
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def admit(self, source: BinaryIO) -> Admitted:
        """Stream `source` into quarantine, returning its digest.

        Streamed and size-capped rather than read into memory: the source is
        remote and its `Content-Length` is not to be believed.
        """
        digest = hashlib.sha256()
        length = 0

        with NamedTemporaryFile(dir=self._root, delete=False, suffix=".part") as handle:
            temp = Path(handle.name)
            try:
                while chunk := source.read(_CHUNK):
                    length += len(chunk)
                    if length > self._max_bytes:
                        raise QuarantineError(
                            f"artifact exceeds {self._max_bytes} bytes; aborted mid-transfer"
                        )
                    digest.update(chunk)
                    handle.write(chunk)
            except BaseException:
                handle.close()
                temp.unlink(missing_ok=True)
                raise

        sha256 = digest.hexdigest()
        destination = self.path(sha256)
        temp.replace(destination)
        return Admitted(sha256=sha256, length=length, path=destination)

    def path(self, sha256: str) -> Path:
        return self._root / f"{sha256}.bin"

    def contains(self, sha256: str) -> bool:
        return self.path(sha256).is_file()

    def promote(self, sha256: str, destination: Path) -> Path:
        """Copy an artifact out of quarantine after every gate has passed.

        The digest is re-derived from the bytes on disk immediately before the
        copy. Verifying only at admission would leave a window in which the
        staged file could be swapped.
        """
        source = self.path(sha256)
        if not source.is_file():
            raise QuarantineError(f"{sha256} is not in quarantine")

        actual = hashlib.sha256()
        with source.open("rb") as handle:
            while chunk := handle.read(_CHUNK):
                actual.update(chunk)
        if actual.hexdigest() != sha256:
            raise QuarantineError(
                f"quarantined bytes for {sha256} now hash to {actual.hexdigest()}; "
                "the staged file was modified"
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=destination.parent, delete=False, suffix=".part") as handle:
            temp = Path(handle.name)
            with source.open("rb") as src:
                shutil.copyfileobj(src, handle)
        temp.replace(destination)
        return destination

    def discard(self, sha256: str) -> None:
        self.path(sha256).unlink(missing_ok=True)
