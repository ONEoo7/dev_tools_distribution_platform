"""Every read and write either service makes.

Kept as plain SQL and dataclasses rather than an ORM, for the same reason the
rest of this codebase is written that way: the security-relevant statements —
which rows a worker may claim, which transition activates a source — should be
readable as the statements they are.

Two invariants are enforced here rather than by convention:

- **A source cannot be activated from this module.** `mark_delegated` is the
  only transition into `ACTIVE`, it is not reachable from the web application,
  and it requires the caller to have observed the `app-<id>` delegation.
- **The pinned identity is written once, by the worker, from what the forge
  said.** The web application never writes `repository_id` or its owner.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import Any

import psycopg

from dist_registry.db import Conn
from dist_registry.models import (
    AuditEvent,
    Forge,
    Job,
    JobKind,
    JobState,
    Source,
    SourceStatus,
)

__all__ = ["Conn", "StoreError"]

_SOURCE_COLUMNS = """
    id, app_id, forge, project, api_base, project_url, status, critical,
    asset_name, tag_prefix, require_tag_ref_prefix, max_asset_bytes,
    workflow_uri, oidc_issuer, repository_id, repository_owner_id,
    runner_environment, builder_id, builder_keyid, builder_public_key_pem,
    attestation_asset, created_at, updated_at, created_by, last_error
"""


class StoreError(Exception):
    """A write the store refused."""


def _source(row: dict[str, Any]) -> Source:
    return Source(
        id=row["id"],
        app_id=row["app_id"],
        forge=Forge(row["forge"]),
        project=row["project"],
        api_base=row["api_base"],
        project_url=row["project_url"],
        status=SourceStatus(row["status"]),
        critical=row["critical"],
        asset_name=row["asset_name"],
        tag_prefix=row["tag_prefix"],
        require_tag_ref_prefix=row["require_tag_ref_prefix"],
        max_asset_bytes=row["max_asset_bytes"],
        workflow_uri=row["workflow_uri"],
        oidc_issuer=row["oidc_issuer"],
        repository_id=row["repository_id"],
        repository_owner_id=row["repository_owner_id"],
        runner_environment=row["runner_environment"],
        builder_id=row["builder_id"],
        builder_keyid=row["builder_keyid"],
        builder_public_key_pem=row["builder_public_key_pem"],
        attestation_asset=row["attestation_asset"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        created_by=row["created_by"],
        last_error=row["last_error"],
    )


def _job(row: dict[str, Any]) -> Job:
    return Job(
        id=row["id"],
        source_id=row["source_id"],
        kind=JobKind(row["kind"]),
        state=JobState(row["state"]),
        requested_by=row["requested_by"],
        requested_at=row["requested_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        attempts=row["attempts"],
        result=row["result"],
        error=row["error"],
    )


# ----------------------------------------------------------------- sources


def add_source(conn: Conn, source: Source) -> Source:
    """Insert a source. Always lands in `DRAFT`, whatever the caller passed.

    The status argument is ignored on purpose. A caller that could choose the
    initial status could choose `ACTIVE`, and the whole point of the state
    machine is that one transition is not reachable from the web application.
    """
    with conn.cursor() as cur:
        try:
            cur.execute(
                f"""
                INSERT INTO sources (
                    id, app_id, forge, project, api_base, project_url, status,
                    critical, asset_name, tag_prefix, require_tag_ref_prefix,
                    max_asset_bytes, workflow_uri, oidc_issuer,
                    runner_environment, builder_id, builder_keyid,
                    builder_public_key_pem, attestation_asset, created_by
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, 'draft',
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s
                ) RETURNING {_SOURCE_COLUMNS}
                """,  # noqa: S608 - _SOURCE_COLUMNS is a module constant, not input
                (
                    source.id,
                    source.app_id,
                    str(source.forge),
                    source.project,
                    source.api_base,
                    source.project_url,
                    source.critical,
                    source.asset_name,
                    source.tag_prefix,
                    source.require_tag_ref_prefix,
                    source.max_asset_bytes,
                    source.workflow_uri,
                    source.oidc_issuer,
                    source.runner_environment,
                    source.builder_id,
                    source.builder_keyid,
                    source.builder_public_key_pem,
                    source.attestation_asset,
                    source.created_by,
                ),
            )
        except psycopg.errors.UniqueViolation as exc:
            conn.rollback()
            raise StoreError(f"application id {source.app_id!r} is already registered") from exc
        except psycopg.errors.CheckViolation as exc:
            conn.rollback()
            raise StoreError(f"the store refused this source: {exc}") from exc
        row = cur.fetchone()
    conn.commit()
    assert row is not None
    return _source(row)


def get_source(conn: Conn, source_id: uuid.UUID) -> Source | None:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_SOURCE_COLUMNS} FROM sources WHERE id = %s", (source_id,))  # noqa: S608
        row = cur.fetchone()
    return _source(row) if row else None


def list_sources(conn: Conn) -> list[Source]:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_SOURCE_COLUMNS} FROM sources ORDER BY app_id")  # noqa: S608
        return [_source(row) for row in cur.fetchall()]


def pollable_sources(conn: Conn) -> list[Source]:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_SOURCE_COLUMNS} FROM sources WHERE status = 'active'")  # noqa: S608
        return [_source(row) for row in cur.fetchall()]


def sources_due_for_poll(conn: Conn, interval: timedelta) -> list[Source]:
    """Active sources with no recent and no open poll.

    "Recent" is measured from when a poll last *finished*, not from when it was
    requested, so a slow forge stretches the interval rather than queueing
    behind itself.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT {_SOURCE_COLUMNS} FROM sources s
             WHERE s.status = 'active'
               AND NOT EXISTS (
                    SELECT 1 FROM jobs j
                     WHERE j.source_id = s.id AND j.state IN ('queued', 'running'))
               AND NOT EXISTS (
                    SELECT 1 FROM jobs j
                     WHERE j.source_id = s.id AND j.kind = 'poll'
                       AND j.finished_at > now() - %s)
            """,  # noqa: S608
            (interval,),
        )
        return [_source(row) for row in cur.fetchall()]


def set_status(
    conn: Conn, source_id: uuid.UUID, status: SourceStatus, *, error: str | None = None
) -> None:
    """Move a source between states the web application is allowed to choose.

    `ACTIVE` is refused here. It is reachable only through `mark_delegated`,
    which requires the delegation to exist.
    """
    if status is SourceStatus.ACTIVE:
        raise StoreError(
            "a source becomes active only when its app-<id> delegation exists; "
            "run the signing ceremony and use mark_delegated"
        )
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE sources SET status = %s, last_error = %s, updated_at = now() WHERE id = %s",
            (str(status), error, source_id),
        )
    conn.commit()


def record_identity(conn: Conn, source_id: uuid.UUID, identity: dict[str, str]) -> None:
    """Write the numeric ids the forge reported, and mark the source validated.

    Only the worker calls this, because only the worker talks to the forge.
    Landing in `PENDING_DELEGATION` rather than `ACTIVE` is the whole shape of
    this feature: validation establishes that the project is real and that its
    releases are usable, and establishes nothing at all about whether this
    system should sign for it.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sources
               SET repository_id = %s,
                   repository_owner_id = %s,
                   status = 'pending_delegation',
                   last_error = NULL,
                   updated_at = now()
             WHERE id = %s
            """,
            (identity.get("repository_id"), identity.get("repository_owner_id"), source_id),
        )
    conn.commit()


def mark_delegated(conn: Conn, app_id: str) -> Source:
    """Activate a source whose `app-<id>` delegation now exists.

    Called by the ceremony tooling after `Repository.add_app` has published a
    targets metadata file carrying the delegation — that is, after somebody
    opened the offline KeePass database and signed. It is not importable by the
    web application's process in any deployment described in
    `deploy/compose/README.md`.

    Raises:
        StoreError: if the source is not waiting for a delegation.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE sources SET status = 'active', last_error = NULL, updated_at = now()
             WHERE app_id = %s AND status IN ('pending_delegation', 'paused')
            RETURNING {_SOURCE_COLUMNS}
            """,  # noqa: S608
            (app_id,),
        )
        row = cur.fetchone()
    if row is None:
        conn.rollback()
        raise StoreError(f"no source for {app_id!r} is waiting for a delegation")
    conn.commit()
    return _source(row)


def delete_source(conn: Conn, source_id: uuid.UUID) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM sources WHERE id = %s", (source_id,))
    conn.commit()


# -------------------------------------------------------------------- jobs


def enqueue(conn: Conn, source_id: uuid.UUID, kind: JobKind, *, requested_by: str) -> Job | None:
    """Queue a job, or return `None` if this source already has one open.

    The partial unique index does the excluding. Two "check now" clicks in the
    same second are the ordinary case, not the adversarial one, and neither
    should produce a second download.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO jobs (id, source_id, kind, state, requested_by)
            VALUES (%s, %s, %s, 'queued', %s)
            ON CONFLICT DO NOTHING
            RETURNING id, source_id, kind, state, requested_by, requested_at,
                      started_at, finished_at, attempts, result, error
            """,
            (uuid.uuid4(), source_id, str(kind), requested_by),
        )
        row = cur.fetchone()
    conn.commit()
    return _job(row) if row else None


def claim_job(conn: Conn) -> Job | None:
    """Take the oldest queued job, or `None`.

    `SKIP LOCKED` so that more than one worker is a scaling decision rather
    than a correctness problem.
    """
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE jobs SET state = 'running', started_at = now(), attempts = attempts + 1
             WHERE id = (
                SELECT id FROM jobs WHERE state = 'queued'
                 ORDER BY requested_at
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
             )
            RETURNING id, source_id, kind, state, requested_by, requested_at,
                      started_at, finished_at, attempts, result, error
        """)
        row = cur.fetchone()
    conn.commit()
    return _job(row) if row else None


def finish_job(
    conn: Conn,
    job_id: uuid.UUID,
    state: JobState,
    *,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE jobs SET state = %s, finished_at = now(), result = %s, error = %s
             WHERE id = %s
            """,
            (str(state), json.dumps(result) if result is not None else None, error, job_id),
        )
    conn.commit()


def recent_jobs(conn: Conn, source_id: uuid.UUID, limit: int = 10) -> list[Job]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, source_id, kind, state, requested_by, requested_at,
                   started_at, finished_at, attempts, result, error
              FROM jobs WHERE source_id = %s ORDER BY requested_at DESC LIMIT %s
            """,
            (source_id, limit),
        )
        return [_job(row) for row in cur.fetchall()]


def reset_stale_jobs(conn: Conn, older_than: timedelta) -> int:
    """Requeue jobs a worker claimed and never finished.

    A worker killed mid-job leaves a row in `running` that the partial unique
    index then treats as an open job forever, which would make the source
    permanently unpollable.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE jobs SET state = 'queued', started_at = NULL
             WHERE state = 'running' AND started_at < now() - %s
            """,
            (older_than,),
        )
        count = cur.rowcount
    conn.commit()
    return count


# ------------------------------------------------------------------- audit


def audit(
    conn: Conn,
    *,
    actor: str,
    action: str,
    source_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO audit_log (actor, action, source_id, detail) VALUES (%s, %s, %s, %s)",
            (actor, action, source_id, json.dumps(detail or {})),
        )
    conn.commit()


def recent_audit(conn: Conn, limit: int = 100) -> list[AuditEvent]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, at, actor, action, source_id, detail FROM audit_log "
            "ORDER BY at DESC, id DESC LIMIT %s",
            (limit,),
        )
        return [
            AuditEvent(
                id=row["id"],
                at=row["at"],
                actor=row["actor"],
                action=row["action"],
                source_id=row["source_id"],
                detail=row["detail"],
            )
            for row in cur.fetchall()
        ]


# --------------------------------------------------------- operators, sessions


def put_operator(conn: Conn, username: str, password_hash: bytes, salt: bytes) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO operators (username, password_hash, salt) VALUES (%s, %s, %s)
            ON CONFLICT (username) DO UPDATE
                SET password_hash = EXCLUDED.password_hash, salt = EXCLUDED.salt
            """,
            (username, password_hash, salt),
        )
    conn.commit()


def get_operator(conn: Conn, username: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT username, password_hash, salt, disabled FROM operators WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def operator_count(conn: Conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM operators")
        row = cur.fetchone()
    return int(row["n"]) if row else 0


def create_session(
    conn: Conn, token_sha256: bytes, username: str, csrf_token: str, expires_at: datetime
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO sessions (token_sha256, username, csrf_token, expires_at) "
            "VALUES (%s, %s, %s, %s)",
            (token_sha256, username, csrf_token, expires_at),
        )
    conn.commit()


def get_session(conn: Conn, token_sha256: bytes) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.username, s.csrf_token, s.expires_at
              FROM sessions s JOIN operators o ON o.username = s.username
             WHERE s.token_sha256 = %s AND s.expires_at > now() AND NOT o.disabled
            """,
            (token_sha256,),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def delete_session(conn: Conn, token_sha256: bytes) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM sessions WHERE token_sha256 = %s", (token_sha256,))
    conn.commit()


def purge_expired_sessions(conn: Conn) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM sessions WHERE expires_at <= now()")
    conn.commit()
