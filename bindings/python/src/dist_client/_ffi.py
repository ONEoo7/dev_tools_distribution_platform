"""ctypes declarations for the dist-core C ABI.

`ctypes` rather than cffi or a compiled extension, for two reasons that matter
in this system specifically:

- **No compiler at install time.** The binding is consumed by desktop
  applications, not by developers with a toolchain.
- **It survives freezing.** PyInstaller bundles a `.dll` as data and a ctypes
  `CDLL` call finds it at runtime; a compiled extension would need to match the
  frozen interpreter's ABI.

Nothing in this module interprets metadata. Every security decision happens on
the far side of the boundary, in Rust (PLAN.md decision D2). A defect here can
fail to *call* the verifier correctly, which the tests are aimed at; it cannot
weaken what the verifier decides.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

VERSION_CAPACITY = 64

#: The C header pins this layout, and `dist-core-ffi/tests/abi.rs` asserts it
#: on the Rust side. Asserted again here at import: a silent disagreement about
#: field offsets would be read as garbage digests and versions, not as an error.
_EXPECTED_SIZE = 112
_EXPECTED_OFFSETS = {
    "length": 0,
    "sha256": 8,
    "rollout_pct": 40,
    "mandatory": 44,
    "version": 45,
}


class DistTargetInfo(ctypes.Structure):
    """Mirrors `DistTargetInfo` in dist_core.h."""

    _fields_ = (
        ("length", ctypes.c_uint64),
        ("sha256", ctypes.c_uint8 * 32),
        ("rollout_pct", ctypes.c_uint32),
        ("mandatory", ctypes.c_uint8),
        ("version", ctypes.c_uint8 * VERSION_CAPACITY),
    )


def _check_layout() -> None:
    actual = ctypes.sizeof(DistTargetInfo)
    if actual != _EXPECTED_SIZE:
        raise RuntimeError(
            f"DistTargetInfo is {actual} bytes here but {_EXPECTED_SIZE} in the C ABI"
        )
    for name, offset in _EXPECTED_OFFSETS.items():
        found = getattr(DistTargetInfo, name).offset
        if found != offset:
            raise RuntimeError(
                f"DistTargetInfo.{name} is at offset {found} here but {offset} in the C ABI"
            )


_check_layout()


def _library_name() -> str:
    if sys.platform == "win32":
        return "dist_core_ffi.dll"
    if sys.platform == "darwin":
        return "libdist_core_ffi.dylib"
    return "libdist_core_ffi.so"


def _candidates() -> list[Path]:
    """Where to look for the shared library, most specific first.

    `sys._MEIPASS` is PyInstaller's extraction directory; checking it first is
    what makes a frozen application find its own bundled copy rather than
    whatever happens to be installed on the machine.
    """
    name = _library_name()
    found: list[Path] = []

    override = os.environ.get("DIST_CORE_LIB")
    if override:
        found.append(Path(override))

    frozen = getattr(sys, "_MEIPASS", None)
    if frozen:
        found.append(Path(frozen) / name)

    found.append(Path(__file__).resolve().parent / name)
    found.append(Path(sys.argv[0]).resolve().parent / name)
    return found


def load_library() -> ctypes.CDLL:
    """Load the verifier, or raise with every path that was tried.

    Raises:
        OSError: if the library is not found or cannot be loaded.
    """
    tried: list[str] = []
    for candidate in _candidates():
        if candidate.is_file():
            return _bind(ctypes.CDLL(str(candidate)))
        tried.append(str(candidate))

    raise OSError(
        f"{_library_name()} not found. Tried:\n  " + "\n  ".join(tried) + "\n"
        "Set DIST_CORE_LIB to its path, or ship it beside the application."
    )


def _bind(lib: ctypes.CDLL) -> ctypes.CDLL:
    """Declare every signature.

    ctypes defaults to `int` for arguments and results. On 64-bit Windows that
    silently truncates a pointer, so leaving any of these undeclared produces a
    crash that looks like a bug in the verifier.
    """
    u8p = ctypes.POINTER(ctypes.c_uint8)

    lib.dist_verifier_new.argtypes = [u8p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int)]
    lib.dist_verifier_new.restype = ctypes.c_void_p

    lib.dist_verifier_new_at.argtypes = [
        u8p,
        ctypes.c_size_t,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.dist_verifier_new_at.restype = ctypes.c_void_p

    lib.dist_verifier_free.argtypes = [ctypes.c_void_p]
    lib.dist_verifier_free.restype = None

    for name in (
        "dist_verifier_update_timestamp",
        "dist_verifier_update_snapshot",
        "dist_verifier_update_targets",
    ):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_void_p, u8p, ctypes.c_size_t]
        fn.restype = ctypes.c_int

    lib.dist_verifier_update_delegated_targets.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        u8p,
        ctypes.c_size_t,
    ]
    lib.dist_verifier_update_delegated_targets.restype = ctypes.c_int

    lib.dist_verifier_target.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(DistTargetInfo),
    ]
    lib.dist_verifier_target.restype = ctypes.c_int

    lib.dist_verifier_snapshot_version.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    lib.dist_verifier_snapshot_version.restype = ctypes.c_int

    lib.dist_verifier_targets_version.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    lib.dist_verifier_targets_version.restype = ctypes.c_int

    lib.dist_verify_payload.argtypes = [
        ctypes.POINTER(DistTargetInfo),
        u8p,
        ctypes.c_size_t,
    ]
    lib.dist_verify_payload.restype = ctypes.c_int

    lib.dist_in_rollout.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.dist_in_rollout.restype = ctypes.c_int

    lib.dist_core_version.argtypes = []
    lib.dist_core_version.restype = ctypes.c_char_p

    return lib


def as_bytes(data: bytes) -> tuple[ctypes.Array[ctypes.c_uint8], int]:
    """Borrow `data` as a (pointer-compatible buffer, length) pair.

    An empty input still yields a valid non-null pointer, because the ABI
    rejects null and "no metadata" should surface as a verification failure
    rather than as an argument error.
    """
    buffer = (ctypes.c_uint8 * max(len(data), 1))()
    buffer[: len(data)] = list(data)
    return buffer, len(data)
