"""The signing worker, against a real repository and real keys.

This is the component that turns an approved artifact into signed metadata, so
what matters is not only that it publishes but what it refuses to publish. Each
refusal below corresponds to a way the thing it signs could differ from the
thing ingestion approved.
"""

from __future__ import annotations

import pathlib
import uuid

import pytest

from dist_core.naming import ReleaseInfo, TargetKey
from dist_core.repository import FileSystemRepository, PublicationError
from dist_core.roles import app_role_name
from dist_core.signing import InMemorySignerBackend
from dist_registry.models import Forge, Source, SourceStatus
from dist_sign.worker import do_publish, quarantine_path

APP = "git-assistant"
PAYLOAD_BYTES = b"a stand-in for the PyInstaller onedir zip" * 64


def a_source(**overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": uuid.uuid4(),
        "app_id": APP,
        "forge": Forge.GITHUB,
        "project": "ONEoo7/ai_tools_git_assistant",
        "api_base": "https://api.github.com",
        "project_url": "https://github.com/ONEoo7/ai_tools_git_assistant",
        "status": SourceStatus.ACTIVE,
        "critical": False,
        "asset_name": "git-assistant-{version}-windows-x64.zip",
        "tag_prefix": "v",
        "require_tag_ref_prefix": "refs/tags/",
        "max_asset_bytes": 2 * 1024 * 1024 * 1024,
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


@pytest.fixture
def repo(tmp_path: pathlib.Path, backend: InMemorySignerBackend) -> FileSystemRepository:
    backend.generate(app_role_name(APP))
    r = FileSystemRepository(tmp_path / "repo", backend)
    r.initialize()
    r.add_app(APP)
    return r


@pytest.fixture
def quarantined(tmp_path: pathlib.Path) -> tuple[pathlib.Path, str, dict[str, object]]:
    """An artifact sitting in quarantine, and the payload naming it."""
    import hashlib

    root = tmp_path / "quarantine"
    root.mkdir()
    sha256 = hashlib.sha256(PAYLOAD_BYTES).hexdigest()
    quarantine_path(root, sha256).write_bytes(PAYLOAD_BYTES)

    payload: dict[str, object] = {
        "sha256": sha256,
        "version": "0.2.0",
        "filename": "git-assistant-0.2.0-windows-x64.zip",
        "tag": "v0.2.0",
    }
    return root, sha256, payload


# ------------------------------------------------------------- the layout


def test_the_quarantine_layout_matches_the_ingest_worker() -> None:
    """`dist-sign` duplicates this path rather than importing it.

    Depending on `dist-ingest` would put an HTTP client and a forge client
    inside the process holding the signing keys. The duplication is the lesser
    cost, but only while the two agree -- so they are compared here.
    """
    from dist_ingest.quarantine import Quarantine

    digest = "a" * 64
    root = pathlib.Path("/srv/quarantine")
    assert quarantine_path(root, digest) == Quarantine(root).path(digest)


# ------------------------------------------------------------- publishing


def test_an_approved_artifact_is_published_and_made_current(
    repo: FileSystemRepository,
    quarantined: tuple[pathlib.Path, str, dict[str, object]],
) -> None:
    root, sha256, payload = quarantined

    result = do_publish(None, a_source(), payload, repo, root)  # type: ignore[arg-type]

    assert result["target"] == "git-assistant/stable/windows-amd64/0.2.0/" + str(
        payload["filename"]
    )
    assert result["pointer"] == "git-assistant/stable/windows-amd64/_current/release.json"
    assert result["sha256"] == sha256

    role = repo.open(app_role_name(APP)).signed
    assert result["target"] in role.targets  # type: ignore[attr-defined]
    assert result["pointer"] in role.targets  # type: ignore[attr-defined]


def test_the_source_decides_the_channel_and_platform(
    repo: FileSystemRepository,
    quarantined: tuple[pathlib.Path, str, dict[str, object]],
) -> None:
    # Not hardcoded in the signer: an app publishing a Linux build on beta must
    # land in its own slot rather than overwrite the Windows stable one.
    root, _, payload = quarantined
    source = a_source(channel="beta", platform="linux", arch="arm64")

    result = do_publish(None, source, payload, repo, root)  # type: ignore[arg-type]

    assert result["target"].startswith("git-assistant/beta/linux-arm64/0.2.0/")


# --------------------------------------------------------------- refusals


def test_an_artifact_missing_from_quarantine_is_refused(
    repo: FileSystemRepository, tmp_path: pathlib.Path
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    payload = {"sha256": "b" * 64, "version": "0.2.0", "filename": "x.zip"}

    with pytest.raises(PublicationError, match="no quarantined artifact"):
        do_publish(None, a_source(), payload, repo, empty)  # type: ignore[arg-type]


def test_an_artifact_whose_bytes_changed_is_refused(
    repo: FileSystemRepository,
    quarantined: tuple[pathlib.Path, str, dict[str, object]],
) -> None:
    """The check that makes content-addressed storage mean something.

    Quarantine names a file by its digest, so the name is a claim about the
    bytes. Re-hashing before signing is what stops a file swapped after
    admission from being signed under the digest that was approved.
    """
    root, sha256, payload = quarantined
    quarantine_path(root, sha256).write_bytes(PAYLOAD_BYTES + b"appended")

    with pytest.raises(PublicationError, match="refusing to sign"):
        do_publish(None, a_source(), payload, repo, root)  # type: ignore[arg-type]


def test_an_application_without_a_delegation_is_refused(
    tmp_path: pathlib.Path,
    backend: InMemorySignerBackend,
    quarantined: tuple[pathlib.Path, str, dict[str, object]],
) -> None:
    """The ceremony is what grants this, and it has not happened.

    The signer holds online keys only. Publishing for an app with no `app-<id>`
    delegation would mean creating one, which needs the offline `targets` key
    it does not have -- so this must be a refusal rather than an attempt.
    """
    bare = FileSystemRepository(tmp_path / "bare", backend)
    bare.initialize()
    root, _, payload = quarantined

    with pytest.raises(PublicationError, match="no delegated role"):
        do_publish(None, a_source(), payload, bare, root)  # type: ignore[arg-type]


@pytest.mark.parametrize("missing", ["sha256", "version", "filename"])
def test_an_incomplete_payload_is_refused(
    repo: FileSystemRepository,
    quarantined: tuple[pathlib.Path, str, dict[str, object]],
    missing: str,
) -> None:
    root, _, payload = quarantined
    incomplete = {k: v for k, v in payload.items() if k != missing}

    with pytest.raises(PublicationError, match=missing):
        do_publish(None, a_source(), incomplete, repo, root)  # type: ignore[arg-type]


def test_publishing_twice_is_not_an_error(
    repo: FileSystemRepository,
    quarantined: tuple[pathlib.Path, str, dict[str, object]],
) -> None:
    # A retried job -- after a crash, or a requeued stale job -- must converge
    # rather than fail, or a transient error becomes a stuck source.
    root, _, payload = quarantined
    first = do_publish(None, a_source(), payload, repo, root)  # type: ignore[arg-type]
    second = do_publish(None, a_source(), payload, repo, root)  # type: ignore[arg-type]
    assert first["target"] == second["target"]


def test_the_published_release_carries_its_version(
    repo: FileSystemRepository,
    quarantined: tuple[pathlib.Path, str, dict[str, object]],
) -> None:
    root, _, payload = quarantined
    do_publish(None, a_source(), payload, repo, root)  # type: ignore[arg-type]

    role = repo.open(app_role_name(APP)).signed
    target = role.targets[  # type: ignore[attr-defined]
        "git-assistant/stable/windows-amd64/0.2.0/" + str(payload["filename"])
    ]
    assert ReleaseInfo.from_custom(target.unrecognized_fields["custom"]).version == "0.2.0"
    # And the key the client resolves is the one the pointer names.
    assert TargetKey(APP, "stable", "windows", "amd64", "0.2.0", str(payload["filename"])).path in (
        role.targets  # type: ignore[attr-defined]
    )
