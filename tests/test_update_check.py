"""The full client round trip: real repository, real verifier, real pointer.

An application asks one question — *is there a newer version of me?* — and this
is the whole path that answers it. Nothing here is mocked: the repository is
built by the signing code, served from disk, and read back through the Rust
verifier over the C ABI.

`fetch_from` below is a strict file server: it resolves nothing and guesses
nothing. Every metadata path the client asks for must exist verbatim, so the
client is forced to follow the consistent-snapshot chain properly -- timestamp
names snapshot's version, snapshot names the targets versions -- rather than
being handed an unversioned alias by a helpful harness.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from dist_client._ffi import _library_name
from dist_core.naming import ReleaseInfo, TargetKey
from dist_core.repository import FileSystemRepository
from dist_core.roles import app_role_name
from dist_core.signing import InMemorySignerBackend

LIBRARY = (
    pathlib.Path(__file__).resolve().parents[1] / "client" / "target" / "release" / _library_name()
)

pytestmark = pytest.mark.skipif(
    not LIBRARY.is_file(),
    reason=f"{LIBRARY.name} not built; run: cargo build -p dist-core-ffi --release",
)

APP = "editor"
INSTALL_IN_ROLLOUT = "install-2"  # in the 50% slice, per the shared vectors
INSTALL_OUT_OF_ROLLOUT = "install-0"


@pytest.fixture(autouse=True)
def _point_at_the_built_library() -> None:
    os.environ.setdefault("DIST_CORE_LIB", str(LIBRARY))


@pytest.fixture
def served(
    tmp_path: pathlib.Path, backend: InMemorySignerBackend
) -> tuple[FileSystemRepository, TargetKey]:
    backend.generate(app_role_name(APP))
    repo = FileSystemRepository(tmp_path / "repo", backend)
    repo.initialize()
    repo.add_app(APP)

    payload = tmp_path / "Editor-1.4.2.zip"
    payload.write_bytes(b"the editor release payload")
    key = TargetKey(APP, "stable", "windows", "amd64", "1.4.2", "Editor-1.4.2.zip")
    repo.add_release(key, payload, ReleaseInfo(version="1.4.2", rollout_pct=100))
    return repo, key


def fetch_from(repo: FileSystemRepository):  # type: ignore[no-untyped-def]
    """Serve the repository byte for byte, resolving nothing.

    Deliberately dumb. An earlier version of this helper resolved the newest
    versioned file when asked for a bare `snapshot.json`, which let the client
    pass without ever following the version chain -- the harness was doing the
    client's job. Now an unversioned request for a versioned role is a 404,
    exactly as the edge would answer.
    """

    def fetch(path: str) -> bytes:
        root = repo.targets_dir if path.startswith("targets/") else repo.metadata_dir
        full = root / path.removeprefix("targets/")
        if not full.is_file():
            raise FileNotFoundError(path)
        return full.read_bytes()

    return fetch


def check(repo: FileSystemRepository, *, install_id: str = INSTALL_IN_ROLLOUT):  # type: ignore[no-untyped-def]
    from dist_client.update import Channel, UpdateCheck

    return UpdateCheck(
        root=(repo.metadata_dir / "root.json").read_bytes(),
        channel=Channel(APP, "stable", "windows", "amd64"),
        fetch=fetch_from(repo),
        install_id=install_id,
    ).run()


# ------------------------------------------------------------------ the flow


def test_a_channel_with_no_pointer_offers_nothing(
    served: tuple[FileSystemRepository, TargetKey],
) -> None:
    # A published release that has not been made current is not on offer. This
    # is the whole reason the two operations are separate.
    repo, _ = served
    assert check(repo) is None


def test_a_current_release_is_offered(
    served: tuple[FileSystemRepository, TargetKey],
) -> None:
    repo, key = served
    repo.set_current(key)

    available = check(repo)

    assert available is not None
    assert available.version == "1.4.2"
    assert available.target_path == key.path
    assert available.info.length == len(b"the editor release payload")


def test_an_install_outside_the_rollout_is_not_offered(
    tmp_path: pathlib.Path, backend: InMemorySignerBackend
) -> None:
    backend.generate(app_role_name(APP))
    repo = FileSystemRepository(tmp_path / "repo", backend)
    repo.initialize()
    repo.add_app(APP)
    payload = tmp_path / "Editor.zip"
    payload.write_bytes(b"payload")
    key = TargetKey(APP, "stable", "windows", "amd64", "1.4.2", "Editor.zip")
    repo.add_release(key, payload, ReleaseInfo(version="1.4.2", rollout_pct=50))
    repo.set_current(key)

    # The decision is made locally from signed metadata, so there is no
    # per-client server response for an attacker to forge.
    assert check(repo, install_id=INSTALL_OUT_OF_ROLLOUT) is None
    assert check(repo, install_id=INSTALL_IN_ROLLOUT) is not None


def test_rolling_the_pointer_back_offers_the_older_release(
    served: tuple[FileSystemRepository, TargetKey], tmp_path: pathlib.Path
) -> None:
    repo, old = served
    newer = tmp_path / "Editor-1.5.0.zip"
    newer.write_bytes(b"a newer editor payload")
    new_key = TargetKey(APP, "stable", "windows", "amd64", "1.5.0", "Editor-1.5.0.zip")
    repo.add_release(new_key, newer, ReleaseInfo(version="1.5.0"))

    repo.set_current(new_key)
    first = check(repo)
    assert first is not None and first.version == "1.5.0"

    repo.set_current(old)
    after = check(repo)
    assert after is not None and after.version == "1.4.2"


# ------------------------------------------------------------- the refusals


def test_a_swapped_pointer_body_is_caught_by_its_digest(
    served: tuple[FileSystemRepository, TargetKey],
) -> None:
    # A mirror that rewrites the pointer never gets as far as the redirect
    # check: the pointer is a signed target, so its bytes are pinned.
    from dist_client import DigestMismatchError
    from dist_client.update import Channel, UpdateCheck

    repo, key = served
    repo.set_current(key)

    real = fetch_from(repo)
    pointer_prefix = f"targets/{APP}/stable/windows-amd64/_current/"

    genuine = next(
        real(f"targets/{p.relative_to(repo.targets_dir).as_posix()}")
        for p in repo.targets_dir.rglob("*.release.json")
    )
    # Padded to the genuine length so this exercises the digest check rather
    # than stopping at the length check, which would pass for the wrong reason.
    body = b'{"target_path":"viewer/stable/windows-amd64/9.9.9/Viewer.zip","version":"9.9.9"}'
    forged = body.ljust(len(genuine), b" ")[: len(genuine)]
    assert len(forged) == len(genuine)

    def fetch(path: str) -> bytes:
        return forged if path.startswith(pointer_prefix) else real(path)

    checker = UpdateCheck(
        root=(repo.metadata_dir / "root.json").read_bytes(),
        channel=Channel(APP, "stable", "windows", "amd64"),
        fetch=fetch,
        install_id=INSTALL_IN_ROLLOUT,
    )
    with pytest.raises(DigestMismatchError):
        checker.run()


def test_a_validly_signed_redirect_is_still_refused(
    tmp_path: pathlib.Path, backend: InMemorySignerBackend
) -> None:
    """The one way this design could be abused, so it gets its own test.

    `set_current` refuses to point at an unpublished target, so a cross-app
    pointer requires the app's signing key. Model exactly that: publish a
    correctly-signed pointer, indistinguishable from a real one, whose contents
    name another application. Without the prefix check the verifier resolves it
    happily -- a different role legitimately owns that path -- and the user is
    handed someone else's binary.
    """
    from tuf.api.metadata import TargetFile, Targets

    from dist_client.update import Channel, RedirectRefusedError, UpdateCheck
    from dist_core.naming import ChannelKey

    backend.generate(app_role_name(APP))
    repo = FileSystemRepository(tmp_path / "repo", backend)
    repo.initialize()
    repo.add_app(APP)

    hostile = tmp_path / "release.json"
    hostile.write_bytes(
        b'{"target_path":"viewer/stable/windows-amd64/9.9.9/Viewer.zip","version":"9.9.9"}'
    )

    channel = ChannelKey(APP, "stable", "windows", "amd64")
    target_file = TargetFile.from_file(channel.pointer_path, str(hostile))
    target_file.unrecognized_fields["custom"] = ReleaseInfo(
        version="9.9.9", rollout_pct=100
    ).to_custom()
    repo.store_payload(channel.pointer_path, target_file, hostile)
    with repo.edit(app_role_name(APP)) as targets:
        assert isinstance(targets, Targets)
        targets.targets[channel.pointer_path] = target_file
    repo.publish()

    checker = UpdateCheck(
        root=(repo.metadata_dir / "root.json").read_bytes(),
        channel=Channel(APP, "stable", "windows", "amd64"),
        fetch=fetch_from(repo),
        install_id=INSTALL_IN_ROLLOUT,
    )
    with pytest.raises(RedirectRefusedError):
        checker.run()


# ---------------------------------------------------------------- versioning


@pytest.mark.parametrize(
    "candidate, installed, expected",
    [
        ("1.4.3", "1.4.2", True),
        ("1.5.0", "1.4.9", True),
        ("2.0", "1.9.9", True),
        ("1.4.2", "1.4.2", False),
        ("1.4.1", "1.4.2", False),
        ("1.4", "1.4.0", False),
        ("1.4.2-rc1", "1.4.1", False),  # unparseable fails closed
        ("", "1.0.0", False),
    ],
)
def test_version_comparison_fails_closed(candidate: str, installed: str, expected: bool) -> None:
    from dist_client.update import is_newer

    assert is_newer(candidate, installed) is expected
