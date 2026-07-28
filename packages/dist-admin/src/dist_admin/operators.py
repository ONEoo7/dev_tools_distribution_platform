"""Manage operator accounts.

    uv run python -m dist_admin.operators add alice
    uv run python -m dist_admin.operators passwd alice

The password is read interactively or from stdin, never from argv and never
from the environment — argv is world-readable in a process listing, and both
linger in shell history and CI logs. Same rule as `scripts/ceremony.py`.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from dist_admin import auth
from dist_registry import db, store

MIN_PASSWORD_LENGTH = 12


def _read_password(from_stdin: bool) -> str | None:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat: "):
            print("error: passwords do not match", file=sys.stderr)
            return None
    if len(password) < MIN_PASSWORD_LENGTH:
        print(
            f"error: password must be at least {MIN_PASSWORD_LENGTH} characters",
            file=sys.stderr,
        )
        return None
    return password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["add", "passwd", "list"])
    parser.add_argument("username", nargs="?")
    parser.add_argument(
        "--password-from-stdin",
        action="store_true",
        help="read the password from stdin rather than prompting",
    )
    args = parser.parse_args(argv)

    with db.connect() as conn:
        db.migrate(conn)

        if args.command == "list":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT username, disabled, created_at FROM operators ORDER BY username"
                )
                for row in cur.fetchall():
                    flag = " (disabled)" if row["disabled"] else ""
                    print(f"{row['username']}{flag}\t{row['created_at']:%Y-%m-%d}")
            return 0

        if not args.username:
            parser.error(f"{args.command} needs a username")

        exists = store.get_operator(conn, args.username) is not None
        if args.command == "add" and exists:
            print(f"error: {args.username!r} already exists; use passwd", file=sys.stderr)
            return 1
        if args.command == "passwd" and not exists:
            print(f"error: no such operator {args.username!r}", file=sys.stderr)
            return 1

        password = _read_password(args.password_from_stdin)
        if password is None:
            return 1

        digest, salt = auth.hash_password(password)
        store.put_operator(conn, args.username, digest, salt)
        store.audit(
            conn, actor="cli", action=f"operator.{args.command}", detail={"username": args.username}
        )

    print(f"{args.username} updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
