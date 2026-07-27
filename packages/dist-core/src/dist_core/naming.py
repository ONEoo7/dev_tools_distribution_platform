"""Target naming and the signed custom metadata carried with each release.

Mirrors docs/PLAN.md sections 3.4 and 3.5.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Self

CHANNELS = frozenset({"stable", "beta", "canary"})

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _check_segment(name: str, value: str) -> str:
    if not _SEGMENT.match(value):
        raise ValueError(f"invalid {name} {value!r}: must match {_SEGMENT.pattern}")
    return value


@dataclass(frozen=True, slots=True)
class TargetKey:
    """Identifies one published artifact.

    Renders to `<app-id>/<channel>/<platform>-<arch>/<version>/<file>`.
    """

    app_id: str
    channel: str
    platform: str
    arch: str
    version: str
    filename: str

    def __post_init__(self) -> None:
        if self.channel not in CHANNELS:
            raise ValueError(
                f"unknown channel {self.channel!r}, expected one of {sorted(CHANNELS)}"
            )
        for field in ("app_id", "platform", "arch", "version", "filename"):
            _check_segment(field, getattr(self, field))

    @property
    def path(self) -> str:
        return (
            f"{self.app_id}/{self.channel}/{self.platform}-{self.arch}/"
            f"{self.version}/{self.filename}"
        )


#: Segment count of the rendered target path. `app_path_pattern` depends on it.
TARGET_PATH_SEGMENTS = 5


def app_path_pattern(app_id: str) -> str:
    """Delegation pattern covering exactly the paths `TargetKey` renders.

    TUF path patterns are matched segment by segment and there is no recursive
    wildcard, so a pattern must carry the same segment count as the paths it is
    meant to cover. `app_id/*` silently matches nothing, which fails closed but
    also means no release ever resolves. Deriving the pattern here keeps it in
    lockstep with `TargetKey.path`; `tests/test_naming.py` fails if they drift.

    Note for client implementations: a delegated role could still name a target
    such as `app/../../x` that satisfies the segment count. Never join a target
    path onto a local directory without validating each segment.
    """
    return "/".join([app_id, *["*"] * (TARGET_PATH_SEGMENTS - 1)])


#: Version segment of the channel pointer (PLAN.md 5.7).
#:
#: It begins with an underscore, which `_SEGMENT` forbids, so no `TargetKey`
#: can ever render this path. A release therefore cannot shadow the pointer and
#: the pointer cannot shadow a release — the reservation is enforced by the
#: existing validator rather than by a list of forbidden names someone has to
#: remember to update.
POINTER_VERSION = "_current"
POINTER_FILE = "release.json"


@dataclass(frozen=True, slots=True)
class ChannelKey:
    """One application's update channel for one platform.

    This is everything a client knows about itself before it has spoken to the
    server, which is what makes the pointer resolvable: the client can build
    this path unaided, whereas a release path needs a version it does not yet
    have.
    """

    app_id: str
    channel: str
    platform: str
    arch: str

    def __post_init__(self) -> None:
        if self.channel not in CHANNELS:
            raise ValueError(
                f"unknown channel {self.channel!r}, expected one of {sorted(CHANNELS)}"
            )
        for field in ("app_id", "platform", "arch"):
            _check_segment(field, getattr(self, field))

    @property
    def prefix(self) -> str:
        """The path prefix every target for this channel must sit under."""
        return f"{self.app_id}/{self.channel}/{self.platform}-{self.arch}/"

    @property
    def pointer_path(self) -> str:
        """Target path of the channel pointer. Five segments, so the app's
        delegation pattern covers it without change."""
        return f"{self.prefix}{POINTER_VERSION}/{POINTER_FILE}"

    def covers(self, target_path: str) -> bool:
        """Is `target_path` inside this channel?

        Clients must check this on the path a pointer names. A compromised app
        key can only sign targets under its own delegation, but a *pointer* is
        just a string, so without this check it could redirect the client to
        another application's artifact — which the verifier would happily
        resolve, because some other role legitimately owns that path.
        """
        return target_path.startswith(self.prefix)


@dataclass(frozen=True, slots=True)
class CurrentRelease:
    """Contents of the channel pointer: which release is current.

    Kept minimal on purpose. Everything a client needs in order to *decide* —
    rollout percentage, mandatory, minimum versions — already travels in the
    signed `custom` field of the target this points at, and duplicating it here
    would create two signed sources that can disagree.
    """

    target_path: str
    version: str

    def __post_init__(self) -> None:
        _check_segment("version", self.version)
        if not self.target_path or "\\" in self.target_path:
            raise ValueError(f"invalid target_path {self.target_path!r}")

    def to_json(self) -> bytes:
        return json.dumps(
            {"target_path": self.target_path, "version": self.version},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> Self:
        """Parse a pointer document.

        Raises:
            ValueError: if it is not a JSON object with the two string fields.
                The bytes have already been verified against signed metadata by
                the time this runs, so a failure here means the server
                published something malformed, not that anyone was attacked.
        """
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"channel pointer is not JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise ValueError("channel pointer is not an object")

        target_path, version = body.get("target_path"), body.get("version")
        if not isinstance(target_path, str) or not isinstance(version, str):
            raise ValueError("channel pointer must carry target_path and version strings")
        return cls(target_path=target_path, version=version)


@dataclass(frozen=True, slots=True)
class ReleaseInfo:
    """Signed `custom` metadata attached to a target (PLAN.md 3.3).

    This travels inside the delegated role's signed metadata, so a client can
    trust it to exactly the degree it trusts the release itself. Rollout
    percentage in particular must be signed: it is what makes staged rollout
    unforgeable by a network attacker (PLAN.md 3.5).
    """

    version: str
    notes_url: str | None = None
    min_os: str | None = None
    min_from_version: str | None = None
    mandatory: bool = False
    rollout_pct: int = 100

    def __post_init__(self) -> None:
        _check_segment("version", self.version)
        if not 0 <= self.rollout_pct <= 100:
            raise ValueError(f"rollout_pct must be 0..100, got {self.rollout_pct}")

    def to_custom(self) -> dict[str, Any]:
        custom: dict[str, Any] = {
            "version": self.version,
            "mandatory": self.mandatory,
            "rollout_pct": self.rollout_pct,
        }
        for key in ("notes_url", "min_os", "min_from_version"):
            value = getattr(self, key)
            if value is not None:
                custom[key] = value
        return custom

    @classmethod
    def from_custom(cls, custom: dict[str, Any]) -> Self:
        return cls(
            version=custom["version"],
            notes_url=custom.get("notes_url"),
            min_os=custom.get("min_os"),
            min_from_version=custom.get("min_from_version"),
            mandatory=bool(custom.get("mandatory", False)),
            rollout_pct=int(custom.get("rollout_pct", 100)),
        )


def in_rollout(install_id: str, app_id: str, rollout_pct: int) -> bool:
    """Deterministic client-side rollout selection (PLAN.md 3.5).

    Reference implementation. The Rust client in `dist-core-rs` must produce
    identical results; `tests/test_naming.py` holds the shared vectors.

    The client decides for itself rather than asking the server, so there is no
    per-client server decision for a network attacker or a compromised edge to
    manipulate.
    """
    if not 0 <= rollout_pct <= 100:
        raise ValueError(f"rollout_pct must be 0..100, got {rollout_pct}")
    if rollout_pct == 0:
        return False
    if rollout_pct == 100:
        return True
    digest = hashlib.sha256(f"{install_id}:{app_id}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % 100 < rollout_pct
