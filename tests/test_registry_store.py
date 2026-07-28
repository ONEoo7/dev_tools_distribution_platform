"""The store, against a real Postgres.

Skipped unless `DIST_TEST_DATABASE_URL` points at a database this suite may
create tables in and truncate. There is no in-memory substitute worth having:
what is being asserted here is mostly constraints and a `FOR UPDATE SKIP
LOCKED` claim, and a fake would assert that the fake works.

The transitions matter more than the CRUD. Registering a source must not be
able to make it trusted, and the only path to `active` has to run through
metadata somebody signed.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from dist_admin import auth
from dist_registry import db, store
from dist_registry.models import Forge, JobKind, JobState, Source, SourceStatus
from dist_registry.store import StoreError

DSN = os.environ.get("DIST_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(not DSN, reason="set DIST_TEST_DATABASE_URL to run the store tests")


@pytest.fixture
def conn():  # type: ignore[no-untyped-def]
    with db.connect(DSN) as connection:
        db.migrate(connection)
        with connection.cursor() as cur:
            cur.execute("TRUNCATE sources, jobs, audit_log, operators, sessions CASCADE")
        connection.commit()
        yield connection


def a_source(**overrides: object) -> Source:
    defaults: dict[str, object] = {
        "id": uuid.uuid4(),
        "app_id": "git-assistant",
        "forge": Forge.GITHUB,
        "project": "ONEoo7/ai_tools_git_assistant",
        "api_base": "https://api.github.com",
        "project_url": "https://github.com/ONEoo7/ai_tools_git_assistant",
        "status": SourceStatus.DRAFT,
        "critical": False,
        "asset_name": "app.zip",
        "tag_prefix": "v",
        "require_tag_ref_prefix": "refs/tags/",
        "max_asset_bytes": 1024,
        "workflow_uri": "https://github.com/ONEoo7/x/.github/workflows/release.yml",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "created_by": "alice",
    }
    defaults.update(overrides)
    return Source(**defaults)  # type: ignore[arg-type]


# ------------------------------------------------------------- transitions


def test_a_source_always_lands_in_draft(conn) -> None:  # type: ignore[no-untyped-def]
    """Whatever status the caller passed.

    A caller that could choose the initial status could choose `active`, and
    one transition not being reachable from the web application is the whole
    shape of this feature.
    """
    created = store.add_source(conn, a_source(status=SourceStatus.ACTIVE))
    assert created.status is SourceStatus.DRAFT


def test_the_store_refuses_to_activate_a_source(conn) -> None:  # type: ignore[no-untyped-def]
    created = store.add_source(conn, a_source())
    with pytest.raises(StoreError, match="delegation"):
        store.set_status(conn, created.id, SourceStatus.ACTIVE)


def test_validation_stops_at_pending_delegation(conn) -> None:  # type: ignore[no-untyped-def]
    """Validation establishes that a project is real, and nothing else."""
    created = store.add_source(conn, a_source())
    store.record_identity(conn, created.id, {"repository_id": "1", "repository_owner_id": "2"})

    after = store.get_source(conn, created.id)
    assert after is not None
    assert after.status is SourceStatus.PENDING_DELEGATION
    assert after.repository_id == "1"


def test_mark_delegated_activates_a_waiting_source(conn) -> None:  # type: ignore[no-untyped-def]
    created = store.add_source(conn, a_source())
    store.record_identity(conn, created.id, {"repository_id": "1", "repository_owner_id": "2"})

    activated = store.mark_delegated(conn, created.app_id)
    assert activated.status is SourceStatus.ACTIVE
    assert activated.pollable


def test_mark_delegated_refuses_a_source_that_never_validated(conn) -> None:  # type: ignore[no-untyped-def]
    store.add_source(conn, a_source())
    with pytest.raises(StoreError, match="waiting for a delegation"):
        store.mark_delegated(conn, "git-assistant")


def test_a_github_source_cannot_be_activated_without_its_pins(conn) -> None:  # type: ignore[no-untyped-def]
    """Enforced by the schema, not only by Python.

    A second writer to this table must not be able to produce an active source
    whose certificate identity is half configured.
    """
    created = store.add_source(conn, a_source())
    with conn.cursor() as cur:
        cur.execute("UPDATE sources SET status = 'pending_delegation' WHERE id = %s", (created.id,))
    conn.commit()

    with pytest.raises(Exception, match="github_active_needs_certificate_identity"):
        store.mark_delegated(conn, created.app_id)


def test_an_app_id_can_only_be_registered_once(conn) -> None:  # type: ignore[no-untyped-def]
    store.add_source(conn, a_source())
    with pytest.raises(StoreError, match="already registered"):
        store.add_source(conn, a_source(id=uuid.uuid4()))


def test_an_app_id_that_is_not_a_role_name_is_refused_by_the_schema(conn) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(StoreError):
        store.add_source(conn, a_source(app_id="Not A Role Name"))


# -------------------------------------------------------------------- jobs


def test_a_source_has_at_most_one_open_job(conn) -> None:  # type: ignore[no-untyped-def]
    """Two 'check now' clicks in the same second are ordinary, not adversarial.

    Neither should produce a second download.
    """
    created = store.add_source(conn, a_source())

    first = store.enqueue(conn, created.id, JobKind.VALIDATE, requested_by="alice")
    second = store.enqueue(conn, created.id, JobKind.POLL, requested_by="alice")

    assert first is not None
    assert second is None


def test_a_finished_job_frees_the_source_for_another(conn) -> None:  # type: ignore[no-untyped-def]
    created = store.add_source(conn, a_source())
    first = store.enqueue(conn, created.id, JobKind.VALIDATE, requested_by="alice")
    assert first is not None
    store.finish_job(conn, first.id, JobState.DONE, result={"ok": True})

    assert store.enqueue(conn, created.id, JobKind.POLL, requested_by="alice") is not None


def test_claiming_takes_the_oldest_queued_job_and_marks_it_running(conn) -> None:  # type: ignore[no-untyped-def]
    created = store.add_source(conn, a_source())
    store.enqueue(conn, created.id, JobKind.VALIDATE, requested_by="alice")

    claimed = store.claim_job(conn)
    assert claimed is not None
    assert claimed.state is JobState.RUNNING
    assert claimed.attempts == 1
    # Nothing left to claim.
    assert store.claim_job(conn) is None


def test_a_job_a_dead_worker_left_running_is_requeued(conn) -> None:  # type: ignore[no-untyped-def]
    """Otherwise the partial unique index treats it as open forever."""
    created = store.add_source(conn, a_source())
    store.enqueue(conn, created.id, JobKind.VALIDATE, requested_by="alice")
    store.claim_job(conn)

    assert store.reset_stale_jobs(conn, timedelta(seconds=0)) == 1
    assert store.claim_job(conn) is not None


def test_only_active_sources_come_due_for_polling(conn) -> None:  # type: ignore[no-untyped-def]
    created = store.add_source(conn, a_source())
    store.record_identity(conn, created.id, {"repository_id": "1", "repository_owner_id": "2"})
    assert store.sources_due_for_poll(conn, timedelta(minutes=15)) == []

    store.mark_delegated(conn, created.app_id)
    assert [s.app_id for s in store.sources_due_for_poll(conn, timedelta(minutes=15))] == [
        "git-assistant"
    ]


def test_deleting_a_source_takes_its_jobs_but_not_its_audit_trail(conn) -> None:  # type: ignore[no-untyped-def]
    created = store.add_source(conn, a_source())
    store.audit(conn, actor="alice", action="source.added", source_id=created.id)
    store.enqueue(conn, created.id, JobKind.VALIDATE, requested_by="alice")

    store.delete_source(conn, created.id)

    assert store.get_source(conn, created.id) is None
    assert store.claim_job(conn) is None
    assert [e.action for e in store.recent_audit(conn)] == ["source.added"]


# ---------------------------------------------------------------- sessions


def test_a_password_round_trips_and_a_wrong_one_does_not(conn) -> None:  # type: ignore[no-untyped-def]
    digest, salt = auth.hash_password("correct horse battery staple")
    store.put_operator(conn, "alice", digest, salt)

    assert auth.authenticate(conn, "alice", "correct horse battery staple")
    assert not auth.authenticate(conn, "alice", "wrong")
    assert not auth.authenticate(conn, "bob", "correct horse battery staple")


def test_only_the_hash_of_a_session_cookie_is_stored(conn) -> None:  # type: ignore[no-untyped-def]
    """A read of this table is not enough to mint a cookie."""
    digest, salt = auth.hash_password("correct horse battery staple")
    store.put_operator(conn, "alice", digest, salt)
    token, _ = auth.begin_session(conn, "alice")

    with conn.cursor() as cur:
        cur.execute("SELECT token_sha256 FROM sessions")
        row = cur.fetchone()
    assert row is not None
    assert bytes(row["token_sha256"]) != token.encode()
    assert bytes(row["token_sha256"]) == auth.token_digest(token)


def test_signing_out_ends_the_session_server_side(conn) -> None:  # type: ignore[no-untyped-def]
    digest, salt = auth.hash_password("correct horse battery staple")
    store.put_operator(conn, "alice", digest, salt)
    token, _ = auth.begin_session(conn, "alice")

    assert auth.session_for(conn, token) is not None
    auth.end_session(conn, token)
    assert auth.session_for(conn, token) is None


def test_an_expired_session_is_not_accepted(conn) -> None:  # type: ignore[no-untyped-def]
    digest, salt = auth.hash_password("correct horse battery staple")
    store.put_operator(conn, "alice", digest, salt)
    store.create_session(
        conn, auth.token_digest("stale"), "alice", "csrf", datetime.now(UTC) - timedelta(hours=1)
    )

    assert auth.session_for(conn, "stale") is None
