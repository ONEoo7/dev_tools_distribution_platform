from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest
from harness import Mirror

from dist_core.naming import ReleaseInfo, TargetKey
from dist_core.repository import FileSystemRepository
from dist_core.roles import (
    ROOT,
    SNAPSHOT,
    TARGETS,
    TIMESTAMP,
    TOP_LEVEL_POLICIES,
    app_role_name,
)
from dist_core.signing import InMemorySignerBackend


def _install_symlink_fallback() -> None:
    """Work around python-tuf symlinking root.json to root_history/N.root.json.

    Creating a symlink on Windows needs Developer Mode or elevation, so this
    raises WinError 1314 on a stock machine. The shipped client is the Rust
    core (decision D2) and the services run in Linux containers, so this is a
    developer-machine shim and not a production code path. See PLAN.md 5.4.

    Applied at import rather than as an autouse fixture because it must also
    cover session-scoped fixtures, which are instantiated before any
    function-scoped fixture runs. As a fixture it left `sigstore`'s trust-root
    setup unpatched, and the tests that depend on it skipped -- looking, from
    the summary line, exactly like tests that had passed.

    `Path(dst).parent / src` is the resolution that matters: a symlink target
    is relative to the link's own directory, not the working directory.
    """
    if os.name != "nt":
        return

    real_symlink = os.symlink

    def fallback(src: str, dst: str, **kwargs: object) -> None:
        try:
            real_symlink(src, dst, **kwargs)  # type: ignore[arg-type]
        except OSError:
            shutil.copyfile(Path(dst).parent / src, dst)

    os.symlink = fallback  # type: ignore[assignment]


_install_symlink_fallback()


@pytest.fixture
def backend() -> InMemorySignerBackend:
    """A backend holding enough keys to meet every top-level threshold."""
    b = InMemorySignerBackend()
    for role in (ROOT, TARGETS, SNAPSHOT, TIMESTAMP):
        for _ in range(TOP_LEVEL_POLICIES[role].threshold):
            b.generate(role)
    return b


@pytest.fixture
def repo(tmp_path: Path, backend: InMemorySignerBackend) -> FileSystemRepository:
    r = FileSystemRepository(tmp_path / "repo", backend)
    r.initialize()
    return r


@dataclass
class Published:
    repo: FileSystemRepository
    backend: InMemorySignerBackend
    key: TargetKey
    body: bytes

    @property
    def bootstrap_root(self) -> bytes:
        return (self.repo.metadata_dir / "root.json").read_bytes()


@pytest.fixture
def published(
    repo: FileSystemRepository, backend: InMemorySignerBackend, tmp_path: Path
) -> Published:
    """One application with one published release."""
    backend.generate(app_role_name("editor"))
    repo.add_app("editor")

    body = b"editor release payload"
    payload = tmp_path / "Editor-1.4.2.zip"
    payload.write_bytes(body)

    key = TargetKey("editor", "stable", "windows", "amd64", "1.4.2", "Editor-1.4.2.zip")
    repo.add_release(key, payload, ReleaseInfo(version="1.4.2", rollout_pct=25))
    return Published(repo, backend, key, body)


@pytest.fixture
def mirror(published: Published) -> Mirror:
    return Mirror(published.repo.metadata_dir.parent)
