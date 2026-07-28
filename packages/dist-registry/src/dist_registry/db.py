"""Connection handling and schema application.

Both services call `migrate` at startup. It takes an advisory lock first, so
the admin plane and the worker racing to start cannot interleave DDL.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources

import psycopg
from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

#: Every connection in this package yields mapping rows. Spelling it once means
#: the store's `Conn` alias and the pool cannot drift apart.
Conn = psycopg.Connection[DictRow]
Pool = ConnectionPool[Conn]

#: Bumped when `schema.sql` changes in a way that is not idempotent on its own.
SCHEMA_VERSION = 1

#: Arbitrary but fixed. Any two processes applying this schema must pick the
#: same number or the lock does not serialise anything.
_MIGRATION_LOCK = 0x64_69_73_74_00_01


def database_url() -> str:
    """The DSN, from the environment.

    Raises:
        RuntimeError: if unset. Defaulting to a local database would mean a
            misconfigured container silently writing somewhere unintended.
    """
    url = os.environ.get("DIST_DATABASE_URL")
    if not url:
        raise RuntimeError("DIST_DATABASE_URL is not set")
    return url


def pool(url: str | None = None, *, min_size: int = 1, max_size: int = 8) -> Pool:
    """A connection pool that survives the database restarting under it.

    `check` costs one round trip per checkout and buys the difference between
    "Postgres was restarted" and "the admin plane returns 500 until someone
    restarts it too". Pooled connections are broken by a restart, a failover or
    an idle-timeout, and a pool that hands one out discovers this inside the
    request rather than before it.
    """
    return ConnectionPool[Conn](
        url or database_url(),
        min_size=min_size,
        max_size=max_size,
        kwargs={"row_factory": dict_row},
        check=ConnectionPool.check_connection,
        open=True,
    )


@contextmanager
def connect(url: str | None = None) -> Iterator[Conn]:
    """One short-lived connection. For migrations and for CLI use."""
    with psycopg.connect(url or database_url(), row_factory=dict_row) as conn:
        yield conn


def schema_sql() -> str:
    return resources.files("dist_registry").joinpath("schema.sql").read_text(encoding="utf-8")


def migrate(conn: Conn) -> bool:
    """Apply the schema if it has not been applied. Returns whether it ran.

    Serialised with a session advisory lock rather than with `IF NOT EXISTS`
    alone: the statements are individually idempotent, but two transactions
    running them at once still deadlock against each other on catalog locks.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK,))
        try:
            cur.execute("""
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = current_schema() AND table_name = 'schema_migrations'
            """)
            if cur.fetchone() is not None:
                cur.execute(
                    "SELECT 1 FROM schema_migrations WHERE version >= %s",
                    (SCHEMA_VERSION,),
                )
                if cur.fetchone() is not None:
                    return False

            cur.execute(schema_sql())
            cur.execute(
                "INSERT INTO schema_migrations (version) VALUES (%s) ON CONFLICT DO NOTHING",
                (SCHEMA_VERSION,),
            )
            conn.commit()
            return True
        finally:
            cur.execute("SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK,))
