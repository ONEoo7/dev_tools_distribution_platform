"""Phase 1 exit criterion: a spec-valid repository builds offline (PLAN.md 12)."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import Published
from harness import Mirror, make_client
from tuf.api.metadata import Metadata, Root

from dist_core.naming import ReleaseInfo, TargetKey
from dist_core.repository import FileSystemRepository, PublicationError
from dist_core.roles import ROOT, SNAPSHOT, TARGETS, TIMESTAMP, app_role_name
from dist_core.signing import InMemorySignerBackend


def test_initialize_writes_all_top_level_roles(repo: FileSystemRepository) -> None:
    names = {p.name for p in repo.metadata_dir.glob("*.json")}
    assert {"1.root.json", "1.targets.json", "1.snapshot.json", "timestamp.json"} <= names


def test_root_thresholds_match_policy(repo: FileSystemRepository) -> None:
    root = Metadata.from_bytes((repo.metadata_dir / "root.json").read_bytes()).signed
    assert isinstance(root, Root)
    assert root.consistent_snapshot is True
    assert root.roles[ROOT].threshold == 3
    assert root.roles[TARGETS].threshold == 2
    assert root.roles[SNAPSHOT].threshold == 1
    assert root.roles[TIMESTAMP].threshold == 1


def test_root_is_signed_to_threshold(repo: FileSystemRepository) -> None:
    md = Metadata.from_bytes((repo.metadata_dir / "root.json").read_bytes())
    assert len(md.signatures) >= 3


def test_publication_fails_when_threshold_cannot_be_met(tmp_path: Path) -> None:
    backend = InMemorySignerBackend()
    for role in (ROOT, TARGETS, SNAPSHOT, TIMESTAMP):
        backend.generate(role)  # one key each; root needs three

    repo = FileSystemRepository(tmp_path / "repo", backend)
    with pytest.raises(PublicationError, match="threshold"):
        repo.initialize()


def test_release_before_delegation_is_rejected(repo: FileSystemRepository, tmp_path: Path) -> None:
    payload = tmp_path / "x.zip"
    payload.write_bytes(b"x")
    key = TargetKey("ghost", "stable", "windows", "amd64", "1.0.0", "x.zip")
    with pytest.raises(PublicationError, match="no delegated role"):
        repo.add_release(key, payload, ReleaseInfo(version="1.0.0"))


def test_release_info_version_must_match_target_path(
    repo: FileSystemRepository, backend: InMemorySignerBackend, tmp_path: Path
) -> None:
    backend.generate(app_role_name("editor"))
    repo.add_app("editor")
    payload = tmp_path / "x.zip"
    payload.write_bytes(b"x")
    key = TargetKey("editor", "stable", "windows", "amd64", "1.4.2", "x.zip")
    with pytest.raises(PublicationError, match="does not match"):
        repo.add_release(key, payload, ReleaseInfo(version="9.9.9"))


def test_timestamp_is_written_last(published: Published) -> None:
    """Publication order is delegated role, snapshot, timestamp (PLAN.md 4).

    Timestamp must reference a snapshot version that already exists on disk,
    otherwise a client fetching mid-publish sees a dangling reference.
    """
    metadata_dir = published.repo.metadata_dir
    timestamp = Metadata.from_bytes((metadata_dir / "timestamp.json").read_bytes()).signed
    assert (metadata_dir / f"{timestamp.snapshot_meta.version}.snapshot.json").is_file()


def test_client_verifies_and_downloads_release(
    published: Published, mirror: Mirror, tmp_path: Path
) -> None:
    updater = make_client(mirror, published.bootstrap_root, tmp_path / "client")
    updater.refresh()

    info = updater.get_targetinfo(published.key.path)
    assert info is not None
    assert Path(updater.download_target(info)).read_bytes() == published.body


def test_signed_rollout_metadata_reaches_the_client(
    published: Published, mirror: Mirror, tmp_path: Path
) -> None:
    """Rollout percentage must be signed, or staged rollout is forgeable."""
    updater = make_client(mirror, published.bootstrap_root, tmp_path / "client")
    updater.refresh()

    info = updater.get_targetinfo(published.key.path)
    assert info is not None
    assert ReleaseInfo.from_custom(info.unrecognized_fields["custom"]).rollout_pct == 25


def test_published_files_are_readable_by_the_serving_process(
    repo: FileSystemRepository, backend: InMemorySignerBackend, tmp_path: Path
) -> None:
    """The edge runs as a different user and must be able to read these.

    `NamedTemporaryFile` creates at 0600, which is right for a scratch file and
    wrong for a repository: it produced a signed, correct, and completely
    unserveable set of metadata -- every request answered 403 while the files
    on disk looked fine.
    """
    import stat

    from dist_core.naming import ReleaseInfo, TargetKey
    from dist_core.roles import app_role_name

    backend.generate(app_role_name("editor"))
    repo.add_app("editor")
    payload = tmp_path / "Editor.zip"
    payload.write_bytes(b"payload")
    key = TargetKey("editor", "stable", "windows", "amd64", "1.0.0", "Editor.zip")
    repo.add_release(key, payload, ReleaseInfo(version="1.0.0"))

    written = [*repo.metadata_dir.rglob("*.json"), *repo.targets_dir.rglob("*")]
    assert written
    for path in written:
        if not path.is_file():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode & stat.S_IROTH, f"{path.name} is not world-readable ({oct(mode)})"
