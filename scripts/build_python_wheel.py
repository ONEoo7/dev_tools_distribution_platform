"""Build a self-contained `dist-client` wheel.

The wheel carries the compiled verifier beside `_ffi.py`, which is the first
place `load_library` looks. An application then depends on `dist-client` and
gets the verifier with it, instead of having to locate a native library and
bundle it by hand — a step that is easy to forget and whose failure mode is an
application that cannot check for updates.

    uv run python scripts/build_python_wheel.py

The wheel is platform-specific by construction: it contains one library, for
the machine it was built on. Publishing for several platforms means running
this on each.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "client"
PACKAGE = ROOT / "bindings" / "python" / "src" / "dist_client"

LIBRARY_NAMES = {
    "win32": "dist_core_ffi.dll",
    "darwin": "libdist_core_ffi.dylib",
}
DEFAULT_LIBRARY = "libdist_core_ffi.so"


def library_name() -> str:
    return LIBRARY_NAMES.get(sys.platform, DEFAULT_LIBRARY)


def build_library() -> Path:
    """Compile the cdylib, or raise if cargo is unavailable or fails."""
    # S603/S607: a developer build tool resolved from PATH, with a fixed
    # argument list and no untrusted input. Pinning an absolute path would tie
    # the script to one machine's toolchain layout.
    subprocess.run(
        ["cargo", "build", "-p", "dist-core-ffi", "--release"],  # noqa: S607
        cwd=CRATE,
        check=True,
    )
    built = CRATE / "target" / "release" / library_name()
    if not built.is_file():
        raise SystemExit(f"cargo reported success but {built} is missing")
    return built


def main() -> None:
    built = build_library()
    staged = PACKAGE / library_name()
    shutil.copyfile(built, staged)
    print(f"staged {staged.name} ({staged.stat().st_size:,} bytes)")

    subprocess.run(  # noqa: S603 - see build_library
        ["uv", "build", "--wheel", "--out-dir", str(ROOT / "dist")],  # noqa: S607
        cwd=ROOT / "bindings" / "python",
        check=True,
    )

    # Fail loudly rather than publish a wheel with no verifier in it. The
    # .gitignore excludes compiled libraries, so a missing `artifacts` entry in
    # pyproject.toml produces exactly that, and it is invisible until an
    # application tries to load it.
    import zipfile

    wheels = sorted((ROOT / "dist").glob("dist_client-*.whl"))
    if not wheels:
        raise SystemExit("no wheel was produced")
    wheel = wheels[-1]
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    if f"dist_client/{library_name()}" not in names:
        raise SystemExit(
            f"{wheel.name} does not contain the verifier; check `artifacts` in "
            "bindings/python/pyproject.toml"
        )

    print(f"built {wheel.name} containing {library_name()}")


if __name__ == "__main__":
    main()
