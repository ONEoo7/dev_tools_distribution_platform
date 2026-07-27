"""Key ceremony: create the keystores and initialise a repository.

PLAN.md 3.3 and phase 0. This is the act that creates the trust anchor every
installed application will carry, so what it does and does not do is deliberate.

Two keystores, because the split is what makes the compromise-resilience claim
in 3.2 real:

- **offline.kdbx** — `root` (3-of-5) and `targets` (2-of-3). Belongs on offline
  media and must never sit on the service host. Compromising the running
  service does not yield these.
- **online.kdbx** — `snapshot`, `timestamp` and per-application roles. Lives in
  a Docker volume and is used continuously.

Usage::

    # Development: one operator, one machine, keys that persist.
    uv run python scripts/ceremony.py --dev --out ./repo

    # Production: refuses to proceed without a composite master key, and the
    # key file must be on a different mount from the database.
    ENV=production uv run python scripts/ceremony.py \\
        --out /mnt/offline/repo \\
        --offline-db /mnt/offline/offline.kdbx --offline-keyfile /mnt/token/offline.key \\
        --online-db /srv/volumes/keys/online.kdbx --online-keyfile /mnt/token/online.key

Passwords are read interactively, or piped in with `--passwords-from-stdin` for
an automated ceremony. Never from the command line and never from the
environment: argv is world-readable in a process listing and both linger in
shell history and CI logs.

What this does NOT do, and must not be mistaken for:

- It generates all five root keys in one place. A real production ceremony
  splits custody so that no single person or machine ever holds a threshold.
  Doing that needs several people and hardware this script cannot drive; use it
  to establish the layout, then rotate each root key to its holder.
- It does not back anything up. An `offline.kdbx` that exists in one copy is a
  single disk failure away from every installed client being unable to accept a
  new root.
"""

from __future__ import annotations

import argparse
import getpass
import shutil
import sys
from pathlib import Path

from dist_core.repository import FileSystemRepository
from dist_core.roles import ROOT, SNAPSHOT, TARGETS, TIMESTAMP, TOP_LEVEL_POLICIES, KeyStore
from dist_core.signing import (
    KeePassConfig,
    KeePassSignerBackend,
    KeyMaterialError,
    create_keystore,
    generate_key,
    is_production,
)

#: Which store holds which role. Mirrors TOP_LEVEL_POLICIES rather than
#: restating it, so a change to the policy cannot silently leave a role in the
#: wrong database.
OFFLINE_ROLES = (ROOT, TARGETS)
ONLINE_ROLES = (SNAPSHOT, TIMESTAMP)

DEV_PASSWORD = "dev-only-not-a-secret"  # noqa: S105 - refused when ENV=production


def _password(label: str, *, dev: bool, stdin: list[str] | None) -> str:
    """Obtain one keystore password.

    Three sources, in descending order of how much they should be trusted:

    - interactive, the default;
    - stdin, for an automated ceremony (a staging environment, a test). Piping
      keeps the secret out of argv and out of the environment, both of which
      are readable by other processes;
    - a known constant under `--dev`, refused when ENV=production.
    """
    if stdin is not None:
        if not stdin:
            raise SystemExit("stdin ran out of passwords")
        value = stdin.pop(0)
        if not value:
            raise SystemExit(f"empty password for {label}")
        return value
    if dev:
        return DEV_PASSWORD
    first = getpass.getpass(f"Password for {label}: ")
    if first != getpass.getpass(f"Repeat password for {label}: "):
        raise SystemExit("passwords did not match")
    if not first:
        raise SystemExit("empty password")
    return first


def _check_role_placement() -> None:
    """Fail if a role's declared keystore disagrees with where we put it."""
    for role in OFFLINE_ROLES:
        if TOP_LEVEL_POLICIES[role].keystore is not KeyStore.OFFLINE:
            raise SystemExit(f"{role} is not declared OFFLINE; refusing to write it there")
    for role in ONLINE_ROLES:
        if TOP_LEVEL_POLICIES[role].keystore is not KeyStore.ONLINE:
            raise SystemExit(f"{role} is not declared ONLINE; refusing to write it there")


def build(args: argparse.Namespace) -> int:
    _check_role_placement()

    if args.dev and is_production():
        raise SystemExit("--dev refused with ENV=production")
    if not args.dev and not is_production():
        print("warning: not running with ENV=production; the composite-key rules are relaxed")

    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"{out} already exists and is not empty; refusing to overwrite a keyset")

    piped = None
    if args.passwords_from_stdin:
        piped = sys.stdin.read().splitlines()

    offline = KeePassConfig(
        database=Path(args.offline_db),
        password=_password("offline.kdbx (root and targets)", dev=args.dev, stdin=piped),
        keyfile=Path(args.offline_keyfile) if args.offline_keyfile else None,
    )
    online = KeePassConfig(
        database=Path(args.online_db),
        password=_password("online.kdbx (snapshot, timestamp, apps)", dev=args.dev, stdin=piped),
        keyfile=Path(args.online_keyfile) if args.online_keyfile else None,
    )

    # Validate before generating anything: discovering the key file is on the
    # wrong mount after writing five root keys is a ceremony you have to redo.
    for config in (offline, online):
        config.validate()

    create_keystore(offline)
    create_keystore(online)
    print(f"created {offline.database}")
    print(f"created {online.database}")

    for store, roles in ((offline, OFFLINE_ROLES), (online, ONLINE_ROLES)):
        for role in roles:
            policy = TOP_LEVEL_POLICIES[role]
            # key_count, not threshold. Issuing exactly `threshold` keys makes
            # every key load-bearing forever; the spares are what let one be
            # lost without stranding every installed client.
            for n in range(policy.key_count):
                keyid = generate_key(store, role, f"{role}-{n + 1}")
                print(
                    f"  {role:<10} key {n + 1}/{policy.key_count} "
                    f"(threshold {policy.threshold})  {keyid[:16]}..."
                )

    # One backend over both stores: the repository needs every role to sign the
    # initial metadata, which is the one moment offline and online keys meet.
    backend = _CombinedBackend(
        KeePassSignerBackend(offline),
        KeePassSignerBackend(online),
    )
    repo = FileSystemRepository(out, backend)
    repo.initialize()
    print(f"initialised repository at {out}")

    root = repo.metadata_dir / "root.json"
    if args.export_root:
        destination = Path(args.export_root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root, destination)
        print(f"exported trusted root to {destination}")

    print()
    print("Next:")
    print(f"  1. Move {offline.database} to offline media. It must not stay here.")
    print("  2. Back up both databases. One copy is not a backup.")
    print(f"  3. Embed {root.name} in each application that will accept updates.")
    if args.dev:
        print()
        print("  This is a DEVELOPMENT keyset: one operator, one machine, a known")
        print("  password, and all five root keys generated together. Do not ship it.")
    return 0


class _CombinedBackend:
    """Presents two keystores as one, for the moment they must both sign.

    Only used during the ceremony. At runtime the signing worker holds the
    online store alone -- that separation is the whole point of 3.3, and a
    long-lived combined backend would quietly undo it.
    """

    def __init__(self, *backends: KeePassSignerBackend) -> None:
        self._backends = backends

    def _owner(self, keyid: str) -> KeePassSignerBackend:
        for backend in self._backends:
            try:
                backend.public_key(keyid)
            except KeyMaterialError:
                continue
            return backend
        raise KeyMaterialError(f"no keystore holds {keyid}")

    def keyids(self, role: str) -> list[str]:
        return sorted(k for b in self._backends for k in b.keyids(role))

    def public_key(self, keyid: str):  # type: ignore[no-untyped-def]
        return self._owner(keyid).public_key(keyid)

    def signer(self, keyid: str):  # type: ignore[no-untyped-def]
        return self._owner(keyid).signer(keyid)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="./repo", help="repository directory to create")
    parser.add_argument("--offline-db", default="./offline.kdbx")
    parser.add_argument("--online-db", default="./online.kdbx")
    parser.add_argument("--offline-keyfile", default=None)
    parser.add_argument("--online-keyfile", default=None)
    parser.add_argument(
        "--export-root",
        default=None,
        help="copy the trusted root here for embedding in an application",
    )
    parser.add_argument(
        "--passwords-from-stdin",
        action="store_true",
        help="read the offline then online password, one per line, from stdin. "
        "For automated ceremonies; keeps secrets out of argv and the environment.",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="development keyset: known password, no key file. Refused with ENV=production.",
    )
    return build(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
