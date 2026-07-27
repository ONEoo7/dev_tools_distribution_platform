"""Deciding whether an update exists, and fetching it safely.

This is the layer an application actually calls. It owns the sequence — fetch
metadata in TUF's order, resolve the channel pointer, resolve the release it
names, decide on rollout — and delegates every trust decision to the verifier.

The transport is injected rather than imported. `dist_client` has no
dependencies, and an application that already has an HTTP client should not be
made to carry a second one.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from dist_client import TargetInfo, UnknownTargetError, Verifier, in_rollout

#: Fetches one path under the repository root, or raises. Mirrors what an
#: application's existing HTTP client already does.
Fetch = Callable[[str], bytes]

POINTER_VERSION = "_current"
POINTER_FILE = "release.json"

#: A pointer document is two short strings. Anything larger is not one.
MAX_POINTER_BYTES = 64 * 1024


class UpdateError(Exception):
    """An update check could not be completed."""


class RedirectRefusedError(UpdateError):
    """A channel pointer named a target outside its own channel.

    Worth its own type because it is not a transport failure or a stale cache:
    a pointer that points elsewhere is the one way this design could be abused,
    and it should be visible in logs as itself.
    """


@dataclass(frozen=True, slots=True)
class Channel:
    """What the application knows about itself before it asks anything."""

    app_id: str
    channel: str
    platform: str
    arch: str

    @property
    def prefix(self) -> str:
        return f"{self.app_id}/{self.channel}/{self.platform}-{self.arch}/"

    @property
    def pointer_path(self) -> str:
        return f"{self.prefix}{POINTER_VERSION}/{POINTER_FILE}"

    @property
    def role(self) -> str:
        return f"app-{self.app_id}"


@dataclass(frozen=True, slots=True)
class Available:
    """A release that exists, verified, and applies to this install."""

    version: str
    target_path: str
    info: TargetInfo

    @property
    def mandatory(self) -> bool:
        return self.info.mandatory


def stored_target_path(target_path: str, sha256_hex: str) -> str:
    """Where a consistent-snapshot repository keeps a target's bytes."""
    dirname, sep, basename = target_path.rpartition("/")
    return f"{dirname}{sep}{sha256_hex}.{basename}"


def _parse_pointer(raw: bytes) -> tuple[str, str]:
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError(f"channel pointer is not JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise UpdateError("channel pointer is not an object")

    target_path, version = body.get("target_path"), body.get("version")
    if not isinstance(target_path, str) or not isinstance(version, str):
        raise UpdateError("channel pointer must carry target_path and version strings")
    return target_path, version


class UpdateCheck:
    """One check against the repository.

    Construct, call `run`, discard. The verifier underneath is a one-shot state
    machine and is not thread-safe, so a check belongs entirely to the thread
    that made it.
    """

    def __init__(
        self,
        *,
        root: bytes,
        channel: Channel,
        fetch: Fetch,
        install_id: str,
        now: int | None = None,
    ) -> None:
        self._root = root
        self._channel = channel
        self._fetch = fetch
        self._install_id = install_id
        self._now = now

    def run(self) -> Available | None:
        """Return the release this install should be offered, if any.

        `None` means "nothing to offer" — either the channel has no pointer
        yet, or the named release is outside this install's rollout slice.
        Neither is an error.

        Raises:
            UpdateError: the check could not be completed.
            RedirectRefusedError: the pointer named another channel's target.
            DistError: metadata failed verification. Distinct from UpdateError
                on purpose — this one means something did not verify.
        """
        with Verifier(self._root, now=self._now) as verifier:
            # Each role names the version of the one below, and the repository
            # serves `<version>.<role>.json`. Following that chain -- rather
            # than fetching an unversioned alias -- is what stops a cache from
            # serving one role from one publish and another from the next,
            # which is the mismatched-set attack consistent snapshots exist to
            # prevent.
            verifier.update_timestamp(self._fetch("timestamp.json"))

            snapshot = verifier.snapshot_version()
            if snapshot is None:
                raise UpdateError("timestamp named no snapshot version")
            verifier.update_snapshot(self._fetch(f"{snapshot}.snapshot.json"))

            targets = verifier.targets_version("targets")
            if targets is None:
                raise UpdateError("snapshot named no targets version")
            verifier.update_targets(self._fetch(f"{targets}.targets.json"))

            role = self._channel.role
            delegated = verifier.targets_version(role)
            if delegated is None:
                # The snapshot does not describe this application at all, which
                # is what a client sees before its first release is published.
                return None
            verifier.update_delegated_targets(role, self._fetch(f"{delegated}.{role}.json"))

            try:
                pointer_info = verifier.target(self._channel.pointer_path)
            except UnknownTargetError:
                return None  # channel published nothing yet

            pointer = self._fetch_verified(pointer_info, self._channel.pointer_path)
            if len(pointer) > MAX_POINTER_BYTES:
                raise UpdateError("channel pointer is implausibly large")

            target_path, version = _parse_pointer(pointer)

            # The pointer's *contents* are signed, but they are still just a
            # string chosen by whoever holds the app key. Without this check it
            # could name another application's target, which the verifier would
            # resolve happily because a different role legitimately owns it.
            if not target_path.startswith(self._channel.prefix):
                raise RedirectRefusedError(
                    f"channel {self._channel.prefix!r} pointed at {target_path!r}"
                )

            try:
                info = verifier.target(target_path)
            except UnknownTargetError as exc:
                raise UpdateError(
                    f"channel points at {target_path!r}, which no trusted role describes"
                ) from exc

            if info.version != version:
                raise UpdateError(
                    f"pointer says version {version!r} but the target says {info.version!r}"
                )

            if not in_rollout(self._install_id, self._channel.app_id, info.rollout_pct):
                return None

            return Available(version=version, target_path=target_path, info=info)

    def _fetch_verified(self, info: TargetInfo, path: str) -> bytes:
        """Fetch a target and check it against its signed description.

        The stored name carries the digest — `<dir>/<sha256>.<file>` — because
        the repository uses consistent snapshots. That is not decoration: it
        means a cache can never serve bytes from one release under another
        release's name, since the name *is* the content.
        """
        from dist_client import verify_payload

        body = self._fetch(f"targets/{stored_target_path(path, info.sha256_hex)}")
        verify_payload(info, body)
        return body


def is_newer(candidate: str, installed: str) -> bool:
    """Compare two dotted versions numerically, longest-wins on a tie.

    Deliberately not a full semver implementation: pre-release ordering is
    subtle, and a client that guesses wrongly either offers a downgrade or
    hides a security release. Anything this cannot parse as numeric segments
    sorts as *not newer*, so an unparseable version fails closed.
    """

    def parts(value: str) -> list[int] | None:
        out: list[int] = []
        for segment in value.split("."):
            if not segment.isdigit():
                return None
            out.append(int(segment))
        return out

    left, right = parts(candidate), parts(installed)
    if left is None or right is None:
        return False
    return left > right
