"""Python binding for the dist-core verifier.

An application embeds this to answer one question safely: *is there a newer
version of me, and are these bytes really it?* The answer comes from TUF
metadata verified in Rust; this package marshals arguments and turns status
codes into exceptions.

Typical use::

    with Verifier(root=Path("root.json").read_bytes()) as v:
        v.update_timestamp(fetch("timestamp.json"))
        v.update_snapshot(fetch("snapshot.json"))
        v.update_targets(fetch("targets.json"))
        v.update_delegated_targets("app-editor", fetch("app-editor.json"))
        target = v.target("editor/stable/windows-amd64/1.4.2/Editor-1.4.2.zip")
        verify_payload(target, downloaded_bytes)

The metadata order is TUF's and is not negotiable: timestamp bounds freshness,
snapshot binds the set, targets and its delegations describe the files. Feeding
them out of order is rejected rather than reordered, because a client that
quietly repairs the order is a client an attacker can steer.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from types import TracebackType
from typing import Any, Self

from dist_client._ffi import DistTargetInfo, as_bytes, load_library

__all__ = [
    "DigestMismatchError",
    "DistError",
    "LengthMismatchError",
    "PanicError",
    "RejectedError",
    "Status",
    "TargetInfo",
    "UnknownTargetError",
    "Verifier",
    "core_version",
    "in_rollout",
    "verify_payload",
]


class Status(IntEnum):
    """Mirrors `DistStatus` in dist_core.h."""

    OK = 0
    NULL_ARGUMENT = 1
    REJECTED = 2
    UNKNOWN_TARGET = 3
    MALFORMED = 4
    LENGTH = 5
    DIGEST = 6
    CLOCK = 7
    INVALID_ARGUMENT = 8
    OVERFLOW = 9
    PANIC = 10


class DistError(Exception):
    """A call into the verifier failed."""

    def __init__(self, status: Status, detail: str = "") -> None:
        self.status = status
        super().__init__(f"{status.name}{f': {detail}' if detail else ''}")


class RejectedError(DistError):
    """Metadata refused: bad signature, threshold, rollback or expiry.

    This is the interesting one. It does not mean the network glitched; it
    means something presented metadata that did not verify, which is what an
    attack looks like from here.
    """


class UnknownTargetError(DistError):
    """No trusted metadata describes the requested target."""


class LengthMismatchError(DistError):
    """Payload length did not match the signed description."""


class DigestMismatchError(DistError):
    """Payload digest did not match the signed description."""


class PanicError(DistError):
    """A panic was caught at the boundary. The verifier is unusable."""


_EXCEPTIONS: dict[Status, type[DistError]] = {
    Status.REJECTED: RejectedError,
    Status.UNKNOWN_TARGET: UnknownTargetError,
    Status.LENGTH: LengthMismatchError,
    Status.DIGEST: DigestMismatchError,
    Status.PANIC: PanicError,
}


def _raise(status: int, detail: str = "") -> None:
    if status == Status.OK:
        return
    code = Status(status)
    raise _EXCEPTIONS.get(code, DistError)(code, detail)


_LIB = None


def _lib() -> ctypes.CDLL:
    global _LIB
    if _LIB is None:
        _LIB = load_library()
    return _LIB


@dataclass(frozen=True, slots=True)
class TargetInfo:
    """A verified description of one release artifact.

    Every field here came out of signed metadata. Nothing on this object was
    reported by a server in an unsigned response.
    """

    version: str
    length: int
    sha256: bytes
    rollout_pct: int
    mandatory: bool

    @property
    def sha256_hex(self) -> str:
        return self.sha256.hex()


def _to_target_info(raw: DistTargetInfo) -> TargetInfo:
    version = bytes(raw.version).split(b"\x00", 1)[0].decode("utf-8", "strict")
    return TargetInfo(
        version=version,
        length=int(raw.length),
        sha256=bytes(raw.sha256),
        rollout_pct=int(raw.rollout_pct),
        mandatory=bool(raw.mandatory),
    )


class Verifier:
    """A TUF client anchored on a root shipped with the application.

    The root is embedded in the application, not fetched, so there is no
    trust-on-first-use window for an attacker to occupy.

    Not thread-safe: the underlying handle must not be used from two threads at
    once. An application checking for updates on a worker thread should keep
    the verifier on that thread.
    """

    def __init__(self, root: bytes, *, now: int | None = None) -> None:
        status = ctypes.c_int(Status.OK)
        buffer, length = as_bytes(root)
        ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))

        if now is None:
            handle = _lib().dist_verifier_new(ptr, length, ctypes.byref(status))
        else:
            handle = _lib().dist_verifier_new_at(ptr, length, now, ctypes.byref(status))

        if not handle:
            _raise(status.value, "the embedded root did not verify")
        self._handle: int | None = handle

    # ------------------------------------------------------------ lifecycle

    def close(self) -> None:
        if self._handle is not None:
            _lib().dist_verifier_free(ctypes.c_void_p(self._handle))
            self._handle = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        # Best effort. Interpreter shutdown can retire the library first, and a
        # leaked handle at exit is harmless next to an exception in __del__.
        try:
            self.close()
        except Exception:  # noqa: S110 - see the comment above
            pass

    def _live(self) -> ctypes.c_void_p:
        if self._handle is None:
            raise DistError(Status.NULL_ARGUMENT, "verifier is closed")
        return ctypes.c_void_p(self._handle)

    def _feed(self, fn_name: str, raw: bytes) -> None:
        handle = self._live()
        buffer, length = as_bytes(raw)
        ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))
        status = getattr(_lib(), fn_name)(handle, ptr, length)
        if status == Status.PANIC:
            # The ABI declares the handle unusable after a panic. Release it
            # here so a caller that catches the exception cannot keep using it.
            self.close()
        _raise(status)

    # -------------------------------------------------------------- metadata

    def update_timestamp(self, raw: bytes) -> None:
        """Feed `timestamp.json`. Bounds how stale the rest may be."""
        self._feed("dist_verifier_update_timestamp", raw)

    def update_snapshot(self, raw: bytes) -> None:
        """Feed `snapshot.json`. Binds the set of targets metadata together."""
        self._feed("dist_verifier_update_snapshot", raw)

    def update_targets(self, raw: bytes) -> None:
        """Feed `targets.json`, the top-level targets role."""
        self._feed("dist_verifier_update_targets", raw)

    def update_delegated_targets(self, role: str, raw: bytes) -> None:
        """Feed one delegated role, e.g. `app-editor`."""
        handle = self._live()
        buffer, length = as_bytes(raw)
        ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))
        status = _lib().dist_verifier_update_delegated_targets(
            handle, role.encode("utf-8"), ptr, length
        )
        if status == Status.PANIC:
            self.close()
        _raise(status)

    # -------------------------------------------------------------- versions

    def snapshot_version(self) -> int | None:
        """Version of `snapshot` named by the trusted timestamp.

        A repository with consistent snapshots serves `<version>.<role>.json`,
        so a client has to know a role's version before it can fetch it — and
        it learns that from the role above. `None` before a timestamp has been
        accepted; guessing, or defaulting to 1, would fetch a stale file.
        """
        return self._version(lambda out: _lib().dist_verifier_snapshot_version(self._live(), out))

    def targets_version(self, role: str) -> int | None:
        """Version of a targets role named by the trusted snapshot.

        Pass `"targets"` for the top-level role, or a delegated name such as
        `"app-editor"`. `None` before a snapshot has been accepted, or if the
        snapshot does not describe `role`.
        """
        encoded = role.encode("utf-8")
        return self._version(
            lambda out: _lib().dist_verifier_targets_version(self._live(), encoded, out)
        )

    def _version(self, call: Callable[[Any], int]) -> int | None:
        out = ctypes.c_uint32(0)
        status = call(ctypes.byref(out))
        if status == Status.MALFORMED:
            return None  # the role above has not been accepted yet
        if status == Status.PANIC:
            self.close()
        _raise(status)
        return int(out.value)

    # ---------------------------------------------------------------- lookup

    def target(self, path: str) -> TargetInfo:
        """Resolve a target path against trusted metadata.

        Raises:
            UnknownTargetError: if no trusted role is permitted to describe it.
                A delegated role that tries to describe another application's
                path lands here, which is the isolation §3.1 exists for.
        """
        handle = self._live()
        out = DistTargetInfo()
        status = _lib().dist_verifier_target(handle, path.encode("utf-8"), ctypes.byref(out))
        if status == Status.PANIC:
            self.close()
        _raise(status, path)
        return _to_target_info(out)


def verify_payload(target: TargetInfo, payload: bytes) -> None:
    """Check downloaded bytes against a verified description.

    Call this on the bytes as they sit on disk, immediately before installing,
    and not only when they finish downloading. Verifying once at download time
    leaves a window in which the staged file can be replaced.

    Raises:
        LengthMismatch, DigestMismatch: if the bytes are not what was signed.
    """
    raw = DistTargetInfo()
    raw.length = target.length
    raw.sha256 = (ctypes.c_uint8 * 32)(*target.sha256)
    raw.rollout_pct = target.rollout_pct
    raw.mandatory = 1 if target.mandatory else 0
    encoded = target.version.encode("utf-8")[:63]
    raw.version = (ctypes.c_uint8 * 64)(*encoded, *([0] * (64 - len(encoded))))

    buffer, length = as_bytes(payload)
    ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))
    _raise(_lib().dist_verify_payload(ctypes.byref(raw), ptr, length))


def in_rollout(install_id: str, app_id: str, rollout_pct: int) -> bool:
    """Decide whether this install is inside a staged rollout.

    The decision is made here, from signed metadata, rather than asked of a
    server — so there is no per-client answer for a network attacker to forge
    in order to push a release at someone early.
    """
    out = ctypes.c_uint8(0)
    _raise(
        _lib().dist_in_rollout(
            install_id.encode("utf-8"),
            app_id.encode("utf-8"),
            rollout_pct,
            ctypes.byref(out),
        )
    )
    return bool(out.value)


def core_version() -> str:
    """The version of the loaded verifier library."""
    raw = _lib().dist_core_version()
    return raw.decode("utf-8") if raw else ""
