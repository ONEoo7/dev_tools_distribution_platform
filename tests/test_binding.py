"""The Python binding, against the same signed metadata the Rust suite uses.

Sharing `client/dist-core-rs/tests/fixtures` is deliberate. If the binding
passed against fixtures of its own, the two could agree with each other and
both be wrong about what the server produces.

What is being tested is *marshalling*, not verification: the binding cannot
weaken a signature check, but it can pass the wrong pointer, misread a struct,
or swallow a rejection. Each of those looks like working software until the day
it matters.
"""

from __future__ import annotations

import ctypes
import json
import os
import pathlib

import pytest

from dist_client._ffi import _library_name

FIXTURES = (
    pathlib.Path(__file__).resolve().parents[1] / "client" / "dist-core-rs" / "tests" / "fixtures"
)
# Resolved per platform rather than hardcoded: a hardcoded `.dll` makes every
# test in this file skip on Linux and macOS, and a skipped test is
# indistinguishable from a passing one in a CI summary.
LIBRARY = (
    pathlib.Path(__file__).resolve().parents[1] / "client" / "target" / "release" / _library_name()
)

pytestmark = pytest.mark.skipif(
    not LIBRARY.is_file(),
    reason=f"{LIBRARY.name} not built; run: cargo build -p dist-core-ffi --release",
)


@pytest.fixture(scope="session", autouse=True)
def _point_at_the_built_library() -> None:
    os.environ.setdefault("DIST_CORE_LIB", str(LIBRARY))


@pytest.fixture(scope="session")
def meta() -> dict[str, object]:
    return json.loads((FIXTURES / "meta.json").read_text(encoding="utf-8"))


def raw(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fresh_verifier(meta: dict[str, object]):  # type: ignore[no-untyped-def]
    """A verifier wound to the moment the fixtures were generated.

    The fixtures carry real expiry timestamps, so a verifier using the wall
    clock would start failing on its own once they lapse -- and a test that
    rots into a failure teaches nothing about the code.
    """
    from dist_client import Verifier

    return Verifier(raw("root.json"), now=int(meta["generated_at"]))  # type: ignore[arg-type]


def loaded(meta: dict[str, object]):  # type: ignore[no-untyped-def]
    v = fresh_verifier(meta)
    v.update_timestamp(raw("timestamp.json"))
    v.update_snapshot(raw("snapshot.json"))
    v.update_targets(raw("targets.json"))
    v.update_delegated_targets(str(meta["delegated_role"]), raw("app-editor.json"))
    return v


# ------------------------------------------------------------------- the ABI


def test_the_struct_layout_matches_the_c_header() -> None:
    # A disagreement about field offsets is not a crash; it is a digest read
    # from the wrong bytes. dist-core-ffi/tests/abi.rs pins the same numbers.
    from dist_client._ffi import DistTargetInfo

    assert ctypes.sizeof(DistTargetInfo) == 112
    assert DistTargetInfo.length.offset == 0
    assert DistTargetInfo.sha256.offset == 8
    assert DistTargetInfo.rollout_pct.offset == 40
    assert DistTargetInfo.mandatory.offset == 44
    assert DistTargetInfo.version.offset == 45


def test_the_library_loads_and_reports_a_version() -> None:
    from dist_client import core_version

    assert core_version() == "0.1.0"


# --------------------------------------------------------------- happy path


def test_a_real_release_resolves_from_signed_metadata(meta: dict[str, object]) -> None:
    from dist_client import verify_payload

    with loaded(meta) as v:
        target = v.target(str(meta["target_path"]))

    assert target.version == meta["version"]
    assert target.length == meta["payload_length"]
    assert target.rollout_pct == meta["rollout_pct"]
    verify_payload(target, raw("payload.bin"))


def test_the_signed_digest_is_read_correctly(meta: dict[str, object]) -> None:
    import hashlib

    with loaded(meta) as v:
        target = v.target(str(meta["target_path"]))

    # If the struct were misread this would be 32 bytes of something else, and
    # verify_payload would still agree with it. Compare against the payload.
    assert target.sha256_hex == hashlib.sha256(raw("payload.bin")).hexdigest()


# --------------------------------------------- consistent-snapshot versions


def test_versions_are_none_until_the_role_above_is_accepted(
    meta: dict[str, object],
) -> None:
    # None, not 0 and not 1. A client that defaulted to a number would fetch a
    # stale file and blame the server.
    v = fresh_verifier(meta)
    assert v.snapshot_version() is None
    assert v.targets_version("targets") is None

    v.update_timestamp(raw("timestamp.json"))
    assert v.snapshot_version() is not None
    assert v.targets_version("targets") is None
    v.close()


def test_the_reported_versions_are_the_ones_the_server_published(
    meta: dict[str, object],
) -> None:
    published: dict[str, int] = meta["published_versions"]  # type: ignore[assignment]

    with loaded(meta) as v:
        assert v.snapshot_version() == published["snapshot"]
        assert v.targets_version("targets") == published["targets"]
        role = str(meta["delegated_role"])
        assert v.targets_version(role) == published[role]


def test_an_unknown_role_reports_no_version(meta: dict[str, object]) -> None:
    with loaded(meta) as v:
        assert v.targets_version("app-nonexistent") is None
        assert v.targets_version("") is None


def test_the_channel_pointer_resolves(meta: dict[str, object]) -> None:
    with loaded(meta) as v:
        info = v.target(str(meta["pointer_path"]))

    assert info.version == meta["version"]
    # Readable by every install: rollout is decided on the release it names.
    assert info.rollout_pct == 100


# ------------------------------------------------------------- the refusals


def test_metadata_out_of_order_is_refused_not_reordered(meta: dict[str, object]) -> None:
    from dist_client import DistError

    with fresh_verifier(meta) as v, pytest.raises(DistError):
        v.update_snapshot(raw("snapshot.json"))


def test_a_delegated_role_cannot_describe_another_application(
    meta: dict[str, object],
) -> None:
    # app-editor is delegated `editor/*`. The fixture generator signs a target
    # outside that namespace with the same key; it must not resolve.
    from dist_client import UnknownTargetError

    with loaded(meta) as v, pytest.raises(UnknownTargetError):
        v.target(str(meta["forged_target_path"]))


def test_tampered_metadata_is_rejected(meta: dict[str, object]) -> None:
    from dist_client import RejectedError

    corrupt = bytearray(raw("timestamp.json"))
    corrupt[len(corrupt) // 2] ^= 0xFF

    with fresh_verifier(meta) as v, pytest.raises(RejectedError):
        v.update_timestamp(bytes(corrupt))


def test_a_payload_of_the_wrong_length_is_refused(meta: dict[str, object]) -> None:
    from dist_client import LengthMismatchError, verify_payload

    with loaded(meta) as v:
        target = v.target(str(meta["target_path"]))

    with pytest.raises(LengthMismatchError):
        verify_payload(target, raw("payload.bin") + b"!")


def test_a_payload_of_the_right_length_but_wrong_bytes_is_refused(
    meta: dict[str, object],
) -> None:
    from dist_client import DigestMismatchError, verify_payload

    with loaded(meta) as v:
        target = v.target(str(meta["target_path"]))

    swapped = bytearray(raw("payload.bin"))
    swapped[0] ^= 0xFF
    with pytest.raises(DigestMismatchError):
        verify_payload(target, bytes(swapped))


def test_an_unsafe_target_path_never_reaches_the_filesystem(
    meta: dict[str, object],
) -> None:
    from dist_client import DistError

    for hostile in [
        "editor/stable/windows-amd64/../../../etc/passwd",
        "editor/stable/windows-amd64/1.4.2/..\\..\\evil.exe",
        "/absolute/path",
    ]:
        with loaded(meta) as v, pytest.raises(DistError):
            v.target(hostile)


# ---------------------------------------------------------------- lifecycle


def test_using_a_closed_verifier_raises_rather_than_crashing(
    meta: dict[str, object],
) -> None:
    # Use-after-free across an FFI boundary is a crash at best. The binding
    # must notice on the Python side.
    from dist_client import DistError

    v = fresh_verifier(meta)
    v.close()
    with pytest.raises(DistError):
        v.update_timestamp(raw("timestamp.json"))


def test_closing_twice_is_harmless(meta: dict[str, object]) -> None:
    v = fresh_verifier(meta)
    v.close()
    v.close()


# ------------------------------------------------------------------ rollout


def test_rollout_agrees_with_the_shared_test_vector() -> None:
    # The same eight install ids, at the same 50%, that
    # `rollout.rs::matches_python_vectors` and
    # `test_naming.py::test_rollout_vectors_are_stable` both pin. Three
    # implementations agreeing is the only reason to believe any of them.
    from dist_client import in_rollout

    got = [in_rollout(f"install-{i}", "editor", 50) for i in range(8)]
    assert got == [False, False, True, False, False, False, True, False]


def test_a_zero_rollout_includes_nobody_and_a_full_one_includes_everybody() -> None:
    from dist_client import in_rollout

    assert not any(in_rollout(f"install-{i}", "editor", 0) for i in range(32))
    assert all(in_rollout(f"install-{i}", "editor", 100) for i in range(32))
