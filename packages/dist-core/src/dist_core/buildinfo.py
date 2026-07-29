"""Which code is actually running.

A container keeps whatever it was built with. Rebuild one service and forget
another that shares the image, and the stale one goes on behaving like the
source tree of an hour ago — reporting failures that describe code no longer on
disk, which is a genuinely disorienting thing to debug.

So each service says, at startup, what it is running:

    dist-ingest.worker starting; source 4f2a1c9e, built ce856bc at 2026-07-28T04:26:10Z

Two identifiers, because they answer different questions and neither is enough
alone:

- **`source`** is a digest over the installed `dist_*` package files. It needs
  no build plumbing and is comparable against the same computation on a
  checkout, so "is this container running my working tree?" has an answer even
  for an image built with no arguments at all.
- **`built`** is whatever the build was told — a git ref and a timestamp. It is
  the human-legible one, and it is absent unless the build passed it.

Run it against a checkout to get the value to compare with:

    uv run python -m dist_core.buildinfo
"""

from __future__ import annotations

import hashlib
import os
from importlib import util
from pathlib import Path

#: The packages whose contents define "the code this service runs". Bindings
#: and vendored crates are deliberately absent: neither is imported by a
#: service, so neither can explain a service behaving unexpectedly.
TRACKED_PACKAGES = ("dist_core", "dist_ingest", "dist_registry", "dist_admin")

#: Long enough to distinguish, short enough to read off a log line.
_DIGEST_CHARS = 8

UNKNOWN = "unknown"


def _package_dir(name: str) -> Path | None:
    try:
        spec = util.find_spec(name)
    except (ImportError, ValueError):
        return None
    if spec is None or spec.origin is None:
        return None
    return Path(spec.origin).parent


def source_digest() -> str:
    """A digest over the `.py` files of every installed tracked package.

    Content only: no paths, no timestamps, no file ownership. A checkout and an
    image built from it must produce the same value despite living at different
    paths, or the number answers a question nobody asked.

    Packages that are not installed are skipped rather than treated as empty,
    so the worker and the admin — which install different subsets — still each
    produce a stable value.
    """
    digest = hashlib.sha256()
    for name in TRACKED_PACKAGES:
        directory = _package_dir(name)
        if directory is None:
            continue
        # Sorted, and relative to the package root, so the order and the names
        # do not depend on where the package was installed.
        for path in sorted(
            directory.rglob("*.py"), key=lambda p: p.relative_to(directory).as_posix()
        ):
            if "__pycache__" in path.parts:
                continue
            digest.update(path.relative_to(directory).as_posix().encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()[:_DIGEST_CHARS]


def build_ref() -> str:
    """The git ref the image was built from, if the build was told."""
    return os.environ.get("DIST_BUILD_REF", "").strip() or UNKNOWN


def build_time() -> str:
    """When the image was built, if the build was told."""
    return os.environ.get("DIST_BUILD_TIME", "").strip() or UNKNOWN


def describe(service: str) -> str:
    """One line naming the service and the code it is running."""
    parts = [f"{service} starting", f"source {source_digest()}"]
    if build_ref() != UNKNOWN:
        parts.append(f"built {build_ref()} at {build_time()}")
    return "; ".join(parts)


def main() -> None:
    print(f"source   {source_digest()}")
    print(f"built    {build_ref()}")
    print(f"at       {build_time()}")
    for name in TRACKED_PACKAGES:
        directory = _package_dir(name)
        print(f"  {name:<14} {'-' if directory is None else directory}")


if __name__ == "__main__":
    main()
