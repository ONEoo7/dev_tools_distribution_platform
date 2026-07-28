"""Activate a source whose delegation now exists.

This is the reconciliation step between the two halves of "add a repo". The web
application registers a source and stops; a signing ceremony creates the
`app-<id>` delegation in `targets.json`; this command notices that it happened
and lets the worker start polling.

It deliberately does no signing. Its only input from the operator is an
application id, and it refuses to activate anything whose delegation it cannot
*see* in the published metadata:

    uv run python -m dist_registry.delegate my-app --repo ./repo

That check is the reason this is a separate command rather than a button. A
button would record an operator's claim that the ceremony happened. This
records that the metadata says so.

Creating the delegation itself is `dist_core.repository.Repository.add_app`,
run on the machine holding `offline.kdbx` — see `scripts/ceremony.py` for how
that keystore is opened.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dist_core.roles import app_role_name
from dist_registry import db, store
from dist_registry.store import StoreError


class DelegationMissingError(Exception):
    """The metadata does not carry the delegation this source needs."""


def current_targets(metadata_dir: Path) -> Path:
    """The targets metadata file in force.

    Under consistent snapshots — which this repository uses — only `root` gets
    an unversioned alias. `targets` is written as `<N>.targets.json`, so the
    current one is the highest N present rather than a fixed filename. The
    unversioned form is still accepted, because a repository built without
    consistent snapshots writes that instead.

    Raises:
        DelegationMissingError: if there is no targets metadata at all.
    """
    plain = metadata_dir / "targets.json"
    if plain.is_file():
        return plain

    versioned: list[tuple[int, Path]] = []
    for path in metadata_dir.glob("*.targets.json"):
        head = path.name.split(".", 1)[0]
        if head.isdigit():
            versioned.append((int(head), path))

    if not versioned:
        raise DelegationMissingError(f"no targets metadata in {metadata_dir}")
    return max(versioned)[1]


def delegated_roles(targets_json: Path) -> set[str]:
    """Role names delegated by a targets metadata file.

    Accepts both shapes the metadata can take: the spec serialises
    `delegations.roles` as a list of role objects, and some tooling keeps it as
    a mapping keyed by name.
    """
    try:
        document = json.loads(targets_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DelegationMissingError(f"cannot read {targets_json}: {exc}") from exc

    signed = document.get("signed")
    delegations = signed.get("delegations") if isinstance(signed, dict) else None
    roles = delegations.get("roles") if isinstance(delegations, dict) else None

    if isinstance(roles, dict):
        return set(roles)
    if isinstance(roles, list):
        return {r["name"] for r in roles if isinstance(r, dict) and isinstance(r.get("name"), str)}
    return set()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("app_id", help="application id, as registered in the admin UI")
    parser.add_argument(
        "--repo",
        default=os.environ.get("DIST_REPO_DIR", "./repo"),
        help="repository directory containing the metadata/ tree",
    )
    parser.add_argument(
        "--critical",
        action="store_true",
        help="accepted for symmetry with the ceremony; custody is recorded on the source",
    )
    args = parser.parse_args(argv)

    role = app_role_name(args.app_id)

    try:
        targets_json = current_targets(Path(args.repo) / "metadata")
        roles = delegated_roles(targets_json)
    except DelegationMissingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if role not in roles:
        print(
            f"error: {targets_json} does not delegate {role!r}.\n"
            f"       Run the signing ceremony for {args.app_id!r} first — this command "
            f"only records a delegation that already exists.",
            file=sys.stderr,
        )
        return 1

    with db.connect() as conn:
        try:
            source = store.mark_delegated(conn, args.app_id)
        except StoreError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        store.audit(
            conn,
            actor=os.environ.get("USER") or os.environ.get("USERNAME") or "ceremony",
            action="source.activated",
            source_id=source.id,
            detail={"app_id": source.app_id, "role": role},
        )

    print(f"{source.app_id} is active; the worker will poll {source.project}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
