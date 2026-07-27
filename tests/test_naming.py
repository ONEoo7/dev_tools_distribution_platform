from __future__ import annotations

import pytest
from tuf.api.metadata import DelegatedRole

from dist_core.naming import ReleaseInfo, TargetKey, app_path_pattern, in_rollout


def _delegation(app_id: str) -> DelegatedRole:
    return DelegatedRole(f"app-{app_id}", [], 1, False, paths=[app_path_pattern(app_id)])


def test_delegation_pattern_covers_rendered_target_paths() -> None:
    """Guards against `TargetKey.path` and `app_path_pattern` drifting apart.

    TUF matches path patterns segment by segment with no recursive wildcard, so
    a pattern with the wrong segment count matches nothing at all.
    """
    key = TargetKey("editor", "stable", "windows", "amd64", "1.4.2", "Editor-1.4.2.zip")
    assert _delegation("editor").is_delegated_path(key.path)


def test_delegation_pattern_excludes_other_applications() -> None:
    other = TargetKey("viewer", "stable", "windows", "amd64", "9.9.9", "Viewer.zip")
    assert not _delegation("editor").is_delegated_path(other.path)


def test_delegation_pattern_excludes_prefix_collisions() -> None:
    """`editor` must not be delegated paths belonging to `editor-pro`."""
    other = TargetKey("editor-pro", "stable", "windows", "amd64", "1.0.0", "Pro.zip")
    assert not _delegation("editor").is_delegated_path(other.path)


def test_target_path_follows_plan_convention() -> None:
    key = TargetKey("editor", "stable", "windows", "amd64", "1.4.2", "Editor-1.4.2.zip")
    assert key.path == "editor/stable/windows-amd64/1.4.2/Editor-1.4.2.zip"


@pytest.mark.parametrize(
    "field,value",
    [
        ("app_id", "../etc"),
        ("platform", "win/dows"),
        ("filename", "a b.zip"),
        ("version", ""),
    ],
)
def test_target_key_rejects_path_traversal_and_separators(field: str, value: str) -> None:
    parts = {
        "app_id": "editor",
        "channel": "stable",
        "platform": "windows",
        "arch": "amd64",
        "version": "1.4.2",
        "filename": "Editor.zip",
    }
    parts[field] = value
    with pytest.raises(ValueError):
        TargetKey(**parts)


def test_unknown_channel_rejected() -> None:
    with pytest.raises(ValueError, match="unknown channel"):
        TargetKey("editor", "nightly", "windows", "amd64", "1.4.2", "Editor.zip")


def test_release_info_round_trips_through_custom() -> None:
    info = ReleaseInfo(
        version="1.4.2",
        notes_url="https://example.invalid/notes",
        min_os="10.0.19045",
        min_from_version="1.2.0",
        mandatory=True,
        rollout_pct=25,
    )
    assert ReleaseInfo.from_custom(info.to_custom()) == info


def test_release_info_omits_absent_optional_fields() -> None:
    assert ReleaseInfo(version="1.0.0").to_custom() == {
        "version": "1.0.0",
        "mandatory": False,
        "rollout_pct": 100,
    }


@pytest.mark.parametrize("pct", [-1, 101])
def test_rollout_pct_bounds_enforced(pct: int) -> None:
    with pytest.raises(ValueError, match="rollout_pct"):
        ReleaseInfo(version="1.0.0", rollout_pct=pct)


def test_rollout_extremes() -> None:
    assert in_rollout("any-install", "editor", 100) is True
    assert in_rollout("any-install", "editor", 0) is False


def test_rollout_is_deterministic_and_app_scoped() -> None:
    assert in_rollout("install-a", "editor", 50) == in_rollout("install-a", "editor", 50)
    # An install unlucky for one app is selected independently for another.
    differing = [
        app
        for app in ("alpha", "beta", "gamma", "delta")
        if in_rollout("install-a", app, 50) != in_rollout("install-a", "editor", 50)
    ]
    assert differing


def test_rollout_is_monotonic_in_percentage() -> None:
    install = "install-a"
    selected = [pct for pct in range(0, 101) if in_rollout(install, "editor", pct)]
    # Once an install is inside the rollout it stays inside as the percentage grows,
    # so raising the percentage never removes anyone mid-rollout.
    assert selected == list(range(min(selected), 101))


def test_rollout_vectors_are_stable() -> None:
    """Shared with the Rust client; both implementations must agree (PLAN.md 3.5)."""
    assert [in_rollout(f"install-{n}", "editor", 50) for n in range(8)] == [
        False,
        False,
        True,
        False,
        False,
        False,
        True,
        False,
    ]


# ---------------------------------------------------- key counts vs thresholds


def test_every_role_issues_at_least_its_threshold() -> None:
    from dist_core.roles import TOP_LEVEL_POLICIES

    for name, policy in TOP_LEVEL_POLICIES.items():
        assert policy.key_count >= policy.threshold, name


def test_the_offline_roles_carry_spare_keys() -> None:
    """PLAN.md 3.1: root is 3-of-5 and targets 2-of-3.

    The spares are the whole point. Issuing exactly `threshold` keys makes
    every key load-bearing forever: lose one root key under 3-of-3 and root can
    never be re-signed, so once it expires every installed client is stranded
    with no way back -- recovery would have to be signed by the keys that are
    gone.
    """
    from dist_core.roles import ROOT, TARGETS, TOP_LEVEL_POLICIES

    root = TOP_LEVEL_POLICIES[ROOT]
    assert (root.threshold, root.key_count) == (3, 5)

    targets = TOP_LEVEL_POLICIES[TARGETS]
    assert (targets.threshold, targets.key_count) == (2, 3)


def test_a_policy_that_cannot_meet_its_own_threshold_is_refused() -> None:
    from datetime import timedelta

    from dist_core.roles import KeyStore, RolePolicy

    with pytest.raises(ValueError, match="below threshold"):
        RolePolicy("root", KeyStore.OFFLINE, 3, timedelta(days=1), key_count=2)
