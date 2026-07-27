"""Tag the wheel for the platform whose verifier it contains.

Without this the wheel is tagged `py3-none-any` — a claim that it runs
anywhere. It does not: it carries one compiled library, for one operating
system and architecture. Installed on the wrong platform it resolves happily
and then fails at import, which is a considerably worse experience than pip
declining to install it.

The tag is `py3-none-<platform>` rather than the interpreter-specific tag
hatchling would infer. The Python side is pure and loads the library through
ctypes, so there is no ABI dependency on a particular CPython build — only on
the platform. One wheel per platform, not one per platform per interpreter.
"""

from __future__ import annotations

import sysconfig
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def platform_tag() -> str:
    """`win-amd64` -> `win_amd64`, `macosx-14.0-arm64` -> `macosx_14_0_arm64`."""
    return sysconfig.get_platform().replace("-", "_").replace(".", "_")


class CustomBuildHook(BuildHookInterface):  # type: ignore[misc]
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{platform_tag()}"
