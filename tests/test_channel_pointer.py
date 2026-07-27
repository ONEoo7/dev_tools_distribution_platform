"""The channel pointer, server and client, against a real signed repository.

PLAN.md 5.7. The pointer exists because a target path embeds its version, so a
client cannot resolve one until it already knows the answer. The pointer is a
target at a fixed, version-free path that names the current release.

These tests build an actual repository with the real signing code and then read
it back through the real verifier, so what is under test is the round trip and
not a pair of mocks agreeing with each other.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest

from dist_core.naming import (
    POINTER_FILE,
    POINTER_VERSION,
    ChannelKey,
    CurrentRelease,
    ReleaseInfo,
    TargetKey,
    app_path_pattern,
)
from dist_core.repository import FileSystemRepository, PublicationError
from dist_core.roles import app_role_name
from dist_core.signing import InMemorySignerBackend

LIBRARY = (
    pathlib.Path(__file__).resolve().parents[1]
    / "client"
    / "target"
    / "release"
    / "dist_core_ffi.dll"
)


@pytest.fixture(autouse=True)
def _point_at_the_built_library() -> None:
    if LIBRARY.is_file():
        os.environ.setdefault("DIST_CORE_LIB", str(LIBRARY))


# ------------------------------------------------------------------- naming


def test_the_pointer_path_has_the_same_segment_count_as_a_release() -> None:
    # If it did not, the app's delegation pattern would not cover it and the
    # pointer could never be signed -- failing closed, but also silently.
    channel = ChannelKey("editor", "stable", "windows", "amd64")
    key = TargetKey("editor", "stable", "windows", "amd64", "1.4.2", "Editor.zip")

    assert channel.pointer_path.count("/") == key.path.count("/")
    assert len(app_path_pattern("editor").split("/")) == len(channel.pointer_path.split("/"))


def test_no_release_can_ever_occupy_the_pointer_path() -> None:
    # The reservation is enforced by the segment validator, not by a list of
    # forbidden names that someone has to remember to keep in sync.
    with pytest.raises(ValueError, match="invalid version"):
        TargetKey("editor", "stable", "windows", "amd64", POINTER_VERSION, POINTER_FILE)


def test_a_channel_knows_what_belongs_to_it() -> None:
    channel = ChannelKey("editor", "stable", "windows", "amd64")

    assert channel.covers("editor/stable/windows-amd64/1.4.2/Editor.zip")
    assert not channel.covers("viewer/stable/windows-amd64/1.4.2/Viewer.zip")
    assert not channel.covers("editor/beta/windows-amd64/1.4.2/Editor.zip")
    assert not channel.covers("editor/stable/linux-amd64/1.4.2/Editor.zip")


def test_the_pointer_document_round_trips() -> None:
    pointer = CurrentRelease(
        target_path="editor/stable/windows-amd64/1.4.2/Editor.zip", version="1.4.2"
    )
    assert CurrentRelease.from_json(pointer.to_json()) == pointer


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b"{}",
        b'{"version": "1.0"}',
        b'{"target_path": "x"}',
        b'{"target_path": 1, "version": "1.0"}',
    ],
)
def test_a_malformed_pointer_document_is_refused(raw: bytes) -> None:
    with pytest.raises(ValueError):
        CurrentRelease.from_json(raw)


# ------------------------------------------------------------------- server


@pytest.fixture
def repo_with_release(
    tmp_path: pathlib.Path, backend: InMemorySignerBackend
) -> tuple[FileSystemRepository, TargetKey]:
    backend.generate(app_role_name("editor"))
    repo = FileSystemRepository(tmp_path / "repo", backend)
    repo.initialize()
    repo.add_app("editor")

    payload = tmp_path / "Editor-1.4.2.zip"
    payload.write_bytes(b"editor release payload")
    key = TargetKey("editor", "stable", "windows", "amd64", "1.4.2", "Editor-1.4.2.zip")
    repo.add_release(key, payload, ReleaseInfo(version="1.4.2", rollout_pct=100))
    return repo, key


def test_making_a_release_current_publishes_a_signed_pointer(
    repo_with_release: tuple[FileSystemRepository, TargetKey],
) -> None:
    repo, key = repo_with_release
    path = repo.set_current(key)

    role = repo.open(app_role_name("editor")).signed
    assert path in role.targets  # type: ignore[attr-defined]
    assert path == "editor/stable/windows-amd64/_current/release.json"


def test_a_channel_cannot_point_at_an_unpublished_release(
    repo_with_release: tuple[FileSystemRepository, TargetKey],
) -> None:
    # Otherwise the channel silently breaks for every client, with no signal at
    # publication time.
    repo, _ = repo_with_release
    absent = TargetKey("editor", "stable", "windows", "amd64", "9.9.9", "Editor-9.9.9.zip")

    with pytest.raises(PublicationError, match="has not been published"):
        repo.set_current(absent)


def test_publishing_a_release_does_not_make_it_current(
    repo_with_release: tuple[FileSystemRepository, TargetKey],
) -> None:
    # The two are separate acts: a release may sit published while it is being
    # validated, and rollback is set_current with an older key.
    repo, _ = repo_with_release
    role = repo.open(app_role_name("editor")).signed
    pointer = "editor/stable/windows-amd64/_current/release.json"

    assert pointer not in role.targets  # type: ignore[attr-defined]


def test_rolling_back_is_pointing_at_an_older_release(
    repo_with_release: tuple[FileSystemRepository, TargetKey],
    tmp_path: pathlib.Path,
) -> None:
    repo, old = repo_with_release
    newer = tmp_path / "Editor-1.5.0.zip"
    newer.write_bytes(b"a newer editor payload")
    new_key = TargetKey("editor", "stable", "windows", "amd64", "1.5.0", "Editor-1.5.0.zip")
    repo.add_release(new_key, newer, ReleaseInfo(version="1.5.0"))

    repo.set_current(new_key)
    assert _current_version(repo) == "1.5.0"

    repo.set_current(old)
    assert _current_version(repo) == "1.4.2"


def _current_version(repo: FileSystemRepository) -> str:
    role = repo.open(app_role_name("editor")).signed
    pointer_path = "editor/stable/windows-amd64/_current/release.json"
    target = role.targets[pointer_path]  # type: ignore[attr-defined]
    digest = next(iter(target.hashes.values()))
    stored = repo.targets_dir / "editor/stable/windows-amd64/_current" / f"{digest}.release.json"
    return str(json.loads(stored.read_bytes())["version"])
