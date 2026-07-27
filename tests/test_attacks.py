"""TUF attack simulations — Phase 2 exit criterion (PLAN.md 12).

Each test hands the attacker full control of the mirror, and in several cases a
valid signing key as well, then asserts that a conforming client still refuses.

The property under test is that **a valid signature is never sufficient on its
own**: version, expiry, cross-role consistency and payload hashes all have to
hold too. These are the guarantees §3.2 claims, expressed as executable checks
so they cannot quietly regress.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import Published
from harness import Mirror, make_client, resign
from tuf.api.exceptions import (
    BadVersionNumberError,
    ExpiredMetadataError,
    RepositoryError,
    UnsignedMetadataError,
)
from tuf.api.metadata import Metadata, TargetFile

from dist_core.naming import TargetKey
from dist_core.repository import FileSystemRepository
from dist_core.roles import TARGETS, TIMESTAMP, app_role_name
from dist_core.signing import InMemorySignerBackend

_VERSIONED = re.compile(r"^(\d+)\.(.+)\.json$")


def current_version(published: Published, role: str) -> int:
    versions = [
        int(m.group(1))
        for path in published.repo.metadata_dir.glob("*.json")
        if (m := _VERSIONED.match(path.name)) and m.group(2) == role
    ]
    return max(versions)


def client_for(published: Published, mirror: Mirror, tmp_path: Path):
    return make_client(mirror, published.bootstrap_root, tmp_path / "client")


def test_honest_mirror_succeeds(published: Published, mirror: Mirror, tmp_path: Path) -> None:
    """Baseline. Without this the attack tests below could pass vacuously."""
    client = client_for(published, mirror, tmp_path)
    client.refresh()
    info = client.get_targetinfo(published.key.path)
    assert info is not None
    assert Path(client.download_target(info)).read_bytes() == published.body


def test_rollback_attack_is_rejected(published: Published, mirror: Mirror, tmp_path: Path) -> None:
    """A mirror replaying older, validly-signed metadata must not be believed.

    Without this the attacker reverts clients to a release with a known
    vulnerability, using nothing but metadata the repository itself once signed.
    """
    client = client_for(published, mirror, tmp_path)
    client.refresh()

    timestamp = Metadata.from_bytes(mirror.read("metadata/timestamp.json"))
    older = timestamp.signed.version - 1
    assert older >= 1, "fixture must publish enough versions to roll back from"

    mirror.overrides["metadata/timestamp.json"] = resign(
        published.backend, TIMESTAMP, timestamp, version=older
    )

    # A second client over the same cache directory: it already trusts the
    # newer version from disk, which is what makes the regression detectable.
    returning = client_for(published, mirror, tmp_path)
    with pytest.raises(BadVersionNumberError):
        returning.refresh()


def test_freeze_attack_is_rejected(published: Published, mirror: Mirror, tmp_path: Path) -> None:
    """Expired metadata must be refused even though its signature is valid.

    Expiry is the only thing that stops a mirror pinning clients to a stale
    view forever, which is why the short timestamp lifetime in §3.1 is a
    security control rather than a tuning knob.
    """
    timestamp = Metadata.from_bytes(mirror.read("metadata/timestamp.json"))
    mirror.overrides["metadata/timestamp.json"] = resign(
        published.backend,
        TIMESTAMP,
        timestamp,
        version=timestamp.signed.version + 1,
        expires=datetime.now(UTC) - timedelta(days=1),
    )

    client = client_for(published, mirror, tmp_path)
    with pytest.raises(ExpiredMetadataError):
        client.refresh()


def test_mix_and_match_attack_is_rejected(
    published: Published, mirror: Mirror, tmp_path: Path
) -> None:
    """Metadata from different snapshots must not be combinable.

    Snapshot pins the version of every targets role, so serving an older
    delegated role alongside a current snapshot is detected. This is what stops
    an attacker assembling a set of individually-valid files that never existed
    together as a release.
    """
    role = app_role_name("editor")
    version = current_version(published, role)
    assert version >= 2, "fixture must publish more than one version of the app role"

    mirror.overrides[f"metadata/{version}.{role}.json"] = mirror.read(
        f"metadata/{version - 1}.{role}.json"
    )

    client = client_for(published, mirror, tmp_path)
    client.refresh()

    with pytest.raises(RepositoryError):
        client.get_targetinfo(published.key.path)


def test_malicious_mirror_cannot_alter_payload(
    published: Published, mirror: Mirror, tmp_path: Path
) -> None:
    """Tampering with the artifact bytes must fail the hash check.

    This is the case where TLS has already failed, or the edge itself is
    hostile. TUF is what makes that survivable.
    """
    client = client_for(published, mirror, tmp_path)
    client.refresh()

    info = client.get_targetinfo(published.key.path)
    assert info is not None

    digest = next(iter(info.hashes.values()))
    dirname, sep, basename = published.key.path.rpartition("/")
    mirror.overrides[f"targets/{dirname}{sep}{digest}.{basename}"] = b"malicious payload"

    with pytest.raises(RepositoryError):
        client.download_target(info)


def test_metadata_signed_by_untrusted_key_is_rejected(
    published: Published, mirror: Mirror, tmp_path: Path
) -> None:
    """A key that root does not delegate carries no authority."""
    attacker = InMemorySignerBackend()
    attacker.generate(TIMESTAMP)

    timestamp = Metadata.from_bytes(mirror.read("metadata/timestamp.json"))
    mirror.overrides["metadata/timestamp.json"] = resign(
        attacker, TIMESTAMP, timestamp, version=timestamp.signed.version + 1
    )

    client = client_for(published, mirror, tmp_path)
    with pytest.raises(UnsignedMetadataError):
        client.refresh()


def test_signature_threshold_is_enforced(
    published: Published, mirror: Mirror, tmp_path: Path
) -> None:
    """One targets key is not enough when the policy requires two.

    Thresholds are the reason a single stolen offline key does not compromise
    the repository (§3.1).
    """
    version = current_version(published, TARGETS)
    targets = Metadata.from_bytes(mirror.read(f"metadata/{version}.targets.json"))

    one_key = published.backend.keyids(TARGETS)[:1]
    assert len(one_key) < 2

    mirror.overrides[f"metadata/{version}.targets.json"] = resign(
        published.backend, TARGETS, targets, keyids=one_key
    )

    client = client_for(published, mirror, tmp_path)
    with pytest.raises(UnsignedMetadataError, match="1/2 keys"):
        client.refresh()


def test_delegated_role_cannot_sign_outside_its_path(
    repo: FileSystemRepository,
    backend: InMemorySignerBackend,
    tmp_path: Path,
) -> None:
    """Per-app delegation isolation (PLAN.md 3.1).

    Simulates a compromise of one application's signing key: the attacker
    inserts a target belonging to a *different* application into the role they
    control, and signs it legitimately. A conforming client must not resolve
    it, because the delegation only covers that application's own path prefix.

    This is the property that makes one compromised application's key a
    contained incident rather than a fleet-wide one.
    """
    for app in ("editor", "viewer"):
        backend.generate(app_role_name(app))
        repo.add_app(app)

    payload = tmp_path / "Viewer-9.9.9.zip"
    payload.write_bytes(b"forged viewer release")

    forged = TargetKey("viewer", "stable", "windows", "amd64", "9.9.9", "Viewer-9.9.9.zip")
    entry = TargetFile.from_file(forged.path, str(payload))
    repo.store_payload(forged.path, entry, payload)
    with repo.edit(app_role_name("editor")) as editor_targets:
        editor_targets.targets[forged.path] = entry
    repo.publish()

    mirror = Mirror(repo.metadata_dir.parent)
    client = make_client(
        mirror, (repo.metadata_dir / "root.json").read_bytes(), tmp_path / "client"
    )
    client.refresh()
    assert client.get_targetinfo(forged.path) is None
