"""TUF repository state machine over a filesystem layout.

Mirrors docs/PLAN.md sections 3.1-3.5 and 4. Two rules from the plan are
enforced structurally here:

* Publication order is delegated role, then snapshot, then timestamp. A client
  fetching mid-publish must never see a snapshot referencing metadata that is
  not yet on disk.
* Every metadata write is atomic (temp file plus replace), so a crashed worker
  leaves the previous consistent state rather than a truncated file.

Serialising concurrent publication is the caller's responsibility; the plan
specifies a Postgres advisory lock in `dist-worker`.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from shutil import copyfileobj
from tempfile import NamedTemporaryFile
from typing import Any

from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.repository import Repository

from dist_core.naming import (
    ChannelKey,
    CurrentRelease,
    ReleaseInfo,
    TargetKey,
    app_path_pattern,
)
from dist_core.roles import (
    ROOT,
    SNAPSHOT,
    TARGETS,
    TIMESTAMP,
    TOP_LEVEL_POLICIES,
    RolePolicy,
    app_role_name,
    app_role_policy,
)
from dist_core.signing import SignerBackend

_VERSIONED = re.compile(r"^(\d+)\.(.+)\.json$")

_INITIAL: dict[str, type[Root] | type[Targets] | type[Snapshot] | type[Timestamp]] = {
    ROOT: Root,
    TARGETS: Targets,
    SNAPSHOT: Snapshot,
    TIMESTAMP: Timestamp,
}


class PublicationError(RuntimeError):
    """Raised when the repository cannot be published as specified."""


class FileSystemRepository(Repository):
    def __init__(self, root_dir: Path, backend: SignerBackend) -> None:
        self._root_dir = root_dir
        self._metadata_dir = root_dir / "metadata"
        self._targets_dir = root_dir / "targets"
        self._metadata_dir.mkdir(parents=True, exist_ok=True)
        self._targets_dir.mkdir(parents=True, exist_ok=True)

        self._backend = backend
        self._policies: dict[str, RolePolicy] = dict(TOP_LEVEL_POLICIES)
        self._versions: dict[str, int] = {}
        self._app_roles: set[str] = set()

        self._scan()

    # ---------------------------------------------------------------- scanning

    def _scan(self) -> None:
        for path in self._metadata_dir.glob("*.json"):
            match = _VERSIONED.match(path.name)
            if match:
                version, role = int(match.group(1)), match.group(2)
                self._versions[role] = max(self._versions.get(role, 0), version)
            elif path.name == "timestamp.json":
                md = Metadata.from_bytes(path.read_bytes())
                self._versions[TIMESTAMP] = md.signed.version

        if self._versions.get(TARGETS):
            targets = self.open(TARGETS).signed
            assert isinstance(targets, Targets)
            if targets.delegations and targets.delegations.roles:
                for name in targets.delegations.roles:
                    self._app_roles.add(name)
                    self._policies.setdefault(name, self._policy_from_role_name(name))

    @staticmethod
    def _policy_from_role_name(role: str) -> RolePolicy:
        # Criticality is not recoverable from metadata alone; assume the
        # conservative default and let callers re-register via add_app().
        app_id = role.removeprefix("app-")
        return app_role_policy(app_id, critical=False)

    # ------------------------------------------------------- Repository hooks

    def open(self, role: str) -> Metadata[Any]:
        version = self._versions.get(role, 0)
        if version == 0:
            initial = _INITIAL.get(role, Targets)
            return Metadata(initial())
        return Metadata.from_bytes(
            (self._metadata_dir / self._filename(role, version)).read_bytes()
        )

    def close(self, role: str, md: Metadata[Any]) -> None:
        policy = self._policies.get(role)
        if policy is None:
            raise PublicationError(f"no policy registered for role {role!r}")

        version = self._versions.get(role, 0) + 1
        md.signed.version = version
        md.signed.expires = datetime.now(UTC) + policy.expiry

        keyids = self._backend.keyids(role)
        if len(keyids) < policy.threshold:
            raise PublicationError(
                f"role {role!r} needs {policy.threshold} keys to meet its threshold, "
                f"backend holds {len(keyids)}"
            )

        md.signatures.clear()
        for keyid in keyids:
            md.sign(self._backend.signer(keyid), append=True)

        self._write(role, version, md)
        self._versions[role] = version

    @property
    def targets_infos(self) -> dict[str, MetaFile]:
        roles = [TARGETS, *sorted(self._app_roles)]
        return {
            f"{role}.json": MetaFile(version=self._versions[role])
            for role in roles
            if self._versions.get(role)
        }

    @property
    def snapshot_info(self) -> MetaFile:
        return MetaFile(version=self._versions.get(SNAPSHOT, 1))

    # ------------------------------------------------------------------ writes

    def _filename(self, role: str, version: int) -> str:
        if role == TIMESTAMP:
            return "timestamp.json"
        return f"{version}.{role}.json"

    def _write(self, role: str, version: int, md: Metadata[Any]) -> None:
        data = md.to_bytes(JSONSerializer())
        self._atomic_write(self._metadata_dir / self._filename(role, version), data)
        if role == ROOT:
            # Unversioned alias so operators can fetch the current root for
            # client bootstrap without first knowing its version.
            self._atomic_write(self._metadata_dir / "root.json", data)

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        with NamedTemporaryFile(dir=path.parent, delete=False, suffix=".tmp") as handle:
            handle.write(data)
            handle.flush()
            temp = Path(handle.name)
        temp.replace(path)

    def store_payload(self, target_path: str, target_file: TargetFile, source: Path) -> None:
        """Place the payload where a consistent-snapshot client will look for it.

        Storage is content-addressed, so republishing identical bytes is
        idempotent and two releases can never collide on a filename.
        """
        digest = next(iter(target_file.hashes.values()))
        dirname, sep, basename = target_path.rpartition("/")
        destination = self._targets_dir / f"{dirname}{sep}{digest}.{basename}"
        destination.parent.mkdir(parents=True, exist_ok=True)

        with NamedTemporaryFile(dir=destination.parent, delete=False, suffix=".tmp") as handle:
            temp = Path(handle.name)
            with source.open("rb") as src:
                copyfileobj(src, handle)
        temp.replace(destination)

    # ------------------------------------------------------------- operations

    def initialize(self) -> None:
        """Create root, targets, snapshot and timestamp from scratch."""
        if self._versions.get(ROOT):
            raise PublicationError("repository is already initialised")

        with self.edit_root() as root:
            root.consistent_snapshot = True
            for role, policy in TOP_LEVEL_POLICIES.items():
                keyids = self._backend.keyids(role)
                if not keyids:
                    raise PublicationError(f"no signing key available for role {role!r}")
                for keyid in keyids:
                    root.add_key(self._backend.public_key(keyid), role)
                root.roles[role].threshold = policy.threshold

        with self.edit_targets():
            pass

        self.publish()

    def add_app(self, app_id: str, *, critical: bool = False) -> str:
        """Delegate `<app_id>/*` to that application's own role.

        One delegated role per application is what stops a compromise of one
        application's signing key from forging releases for another
        (PLAN.md 3.1).
        """
        policy = app_role_policy(app_id, critical=critical)
        role = policy.name
        self._policies[role] = policy

        keyids = self._backend.keyids(role)
        if not keyids:
            raise PublicationError(f"no signing key available for delegated role {role!r}")

        with self.edit_targets() as targets:
            if targets.delegations is None:
                targets.delegations = Delegations(keys={}, roles={})
            if targets.delegations.roles is None:
                targets.delegations.roles = {}
            for keyid in keyids:
                targets.delegations.keys[keyid] = self._backend.public_key(keyid)
            targets.delegations.roles[role] = DelegatedRole(
                name=role,
                keyids=keyids,
                threshold=policy.threshold,
                terminating=False,
                paths=[app_path_pattern(app_id)],
            )

        self._app_roles.add(role)
        with self.edit(role):
            pass

        self.publish()
        return role

    def add_release(self, key: TargetKey, payload: Path, info: ReleaseInfo) -> str:
        """Publish one artifact under its application's delegated role."""
        if info.version != key.version:
            raise PublicationError(
                f"release info version {info.version!r} does not match target path "
                f"version {key.version!r}"
            )

        role = app_role_name(key.app_id)
        if role not in self._app_roles:
            raise PublicationError(
                f"application {key.app_id!r} has no delegated role; call add_app"
            )

        target_file = TargetFile.from_file(key.path, str(payload))
        target_file.unrecognized_fields["custom"] = info.to_custom()
        self.store_payload(key.path, target_file, payload)

        with self.edit(role) as app_targets:
            assert isinstance(app_targets, Targets)
            app_targets.targets[key.path] = target_file

        self.publish()
        return key.path

    def set_current(self, key: TargetKey) -> str:
        """Point a channel at an already-published release (PLAN.md 5.7).

        Deliberately a separate operation from `add_release`. Publishing a
        release and declaring it current are different acts: a release can sit
        published and unreferenced while it is being validated, and rolling
        back is this call with an older key rather than an unpublish.

        The pointer is an ordinary target, so it inherits the whole trust
        chain — it cannot be forged without the application's delegated key,
        and snapshot plus timestamp stop it being rolled back or frozen
        independently of the release it names.

        Raises:
            PublicationError: if the application has no delegated role, or if
                the release being pointed at was never published. Pointing a
                channel at a target that does not exist would leave every
                client unable to update, with no signal at publication time.
        """
        role = app_role_name(key.app_id)
        if role not in self._app_roles:
            raise PublicationError(
                f"application {key.app_id!r} has no delegated role; call add_app"
            )

        channel = ChannelKey(key.app_id, key.channel, key.platform, key.arch)
        published = self.open(role).signed
        assert isinstance(published, Targets)
        if key.path not in published.targets:
            raise PublicationError(f"cannot make {key.path!r} current: it has not been published")

        pointer = CurrentRelease(target_path=key.path, version=key.version)
        body = pointer.to_json()

        with NamedTemporaryFile(dir=self._targets_dir, delete=False, suffix=".tmp") as handle:
            temp = Path(handle.name)
            handle.write(body)

        try:
            target_file = TargetFile.from_file(channel.pointer_path, str(temp))
            # Every target carries signed release info; a client rejects one
            # that does not. The pointer's rollout is always 100: it must be
            # readable by every install, because rollout is decided on the
            # release it names, not on the pointer that names it.
            target_file.unrecognized_fields["custom"] = ReleaseInfo(
                version=key.version, rollout_pct=100
            ).to_custom()
            self.store_payload(channel.pointer_path, target_file, temp)
        finally:
            temp.unlink(missing_ok=True)

        with self.edit(role) as app_targets:
            assert isinstance(app_targets, Targets)
            app_targets.targets[channel.pointer_path] = target_file

        self.publish()
        return channel.pointer_path

    def publish(self) -> None:
        """Re-sign snapshot then timestamp. Timestamp is always written last."""
        self.do_snapshot()
        self.do_timestamp()

    @property
    def metadata_dir(self) -> Path:
        return self._metadata_dir

    @property
    def targets_dir(self) -> Path:
        return self._targets_dir
