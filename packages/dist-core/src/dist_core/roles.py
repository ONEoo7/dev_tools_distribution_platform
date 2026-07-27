"""Role, threshold and expiry policy.

Mirrors docs/PLAN.md section 3.1. Every value here is a security property of
the deployed repository: shortening an expiry weakens freeze protection,
lowering a threshold weakens compromise resilience. Treat edits as security
review material, not configuration tuning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

ROOT = "root"
TARGETS = "targets"
SNAPSHOT = "snapshot"
TIMESTAMP = "timestamp"

TOP_LEVEL_ROLES = (ROOT, TARGETS, SNAPSHOT, TIMESTAMP)

# Delegated role names become filenames, so the character set is deliberately
# narrow. `app-` prefixed rather than `apps/` so no path separator can appear.
APP_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
APP_ROLE_PREFIX = "app-"


class KeyStore(StrEnum):
    """Which KeePass database holds a role's private keys (PLAN.md 3.3).

    OFFLINE keys never exist on the service host. ONLINE keys are assumed
    stealable by TUF's own threat model, which is why they sign only the
    short-lived roles.
    """

    OFFLINE = "offline"
    ONLINE = "online"


@dataclass(frozen=True, slots=True)
class RolePolicy:
    name: str
    keystore: KeyStore
    threshold: int
    expiry: timedelta

    #: How many keys a ceremony issues for this role. Distinct from
    #: `threshold`, and the difference is what makes a lost key survivable:
    #: issuing exactly `threshold` keys means every one of them is load-bearing
    #: forever. Lose one root key under 3-of-3 and root can never be re-signed,
    #: so once it expires every installed client is permanently unable to
    #: accept anything -- with no recovery, because recovery is signed by the
    #: keys you no longer have.
    key_count: int = 1

    def __post_init__(self) -> None:
        if self.key_count < self.threshold:
            raise ValueError(
                f"{self.name}: key_count {self.key_count} is below threshold {self.threshold}"
            )


# PLAN.md 3.1. The spare keys are the point: root tolerates losing two,
# targets one.
ROOT_POLICY = RolePolicy(ROOT, KeyStore.OFFLINE, 3, timedelta(days=365), key_count=5)
TARGETS_POLICY = RolePolicy(TARGETS, KeyStore.OFFLINE, 2, timedelta(days=90), key_count=3)
SNAPSHOT_POLICY = RolePolicy(SNAPSHOT, KeyStore.ONLINE, 1, timedelta(days=7), key_count=1)
TIMESTAMP_POLICY = RolePolicy(TIMESTAMP, KeyStore.ONLINE, 1, timedelta(days=1), key_count=1)

TOP_LEVEL_POLICIES: dict[str, RolePolicy] = {
    p.name: p for p in (ROOT_POLICY, TARGETS_POLICY, SNAPSHOT_POLICY, TIMESTAMP_POLICY)
}

APP_ROLE_EXPIRY = timedelta(days=14)


def app_role_name(app_id: str) -> str:
    if not APP_ID_PATTERN.match(app_id):
        raise ValueError(
            f"invalid app id {app_id!r}: must match {APP_ID_PATTERN.pattern} "
            "so it is safe as both a role name and a filename"
        )
    return f"{APP_ROLE_PREFIX}{app_id}"


def app_role_policy(app_id: str, *, critical: bool) -> RolePolicy:
    """Policy for one application's delegated role.

    `critical` selects offline key custody, which is the only control that
    survives a full compromise of the service host or of GitLab (PLAN.md 13).
    """
    return RolePolicy(
        name=app_role_name(app_id),
        keystore=KeyStore.OFFLINE if critical else KeyStore.ONLINE,
        threshold=1,
        expiry=APP_ROLE_EXPIRY,
    )
