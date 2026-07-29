"""When the scheduler is allowed to skip a poll.

Skipped unless `DIST_TEST_DATABASE_URL` is set, like the store tests, because
the thing under test is a decision made from job history and a fake would
assert that the fake works.

The failure this guards against is quiet. A poll that runs when it need not
costs a request; a poll that is skipped when it should have run means the
source stops updating and nothing says so. Every uncertain path here has to
resolve towards polling.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

from dist_ingest import worker
from dist_ingest.forge import ForgeError
from dist_registry import db, store
from dist_registry.models import Forge, JobKind, JobState, Source, SourceStatus

DSN = os.environ.get("DIST_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(not DSN, reason="set DIST_TEST_DATABASE_URL to run these")


@pytest.fixture
def conn():  # type: ignore[no-untyped-def]
    with db.connect(DSN) as connection:
        db.migrate(connection)
        with connection.cursor() as cur:
            cur.execute("TRUNCATE sources, jobs, audit_log, operators, sessions CASCADE")
        connection.commit()
        yield connection


class FakeForge:
    """Stands in for the forge's cheap change check."""

    def __init__(self, hint: str | None = None, raises: Exception | None = None) -> None:
        self._hint = hint
        self._raises = raises
        self.calls = 0

    def newest_tag_hint(self) -> str | None:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return self._hint


@pytest.fixture
def source(conn: Any) -> Source:
    return store.add_source(
        conn,
        Source(
            id=uuid.uuid4(),
            app_id="git-assistant",
            forge=Forge.GITHUB,
            project="ONEoo7/ai_tools_git_assistant",
            api_base="https://api.github.com",
            project_url="https://github.com/ONEoo7/ai_tools_git_assistant",
            status=SourceStatus.DRAFT,
            critical=False,
            asset_name="git-assistant-{version}-windows-x64.zip",
            tag_prefix="v",
            require_tag_ref_prefix="refs/tags/",
            max_asset_bytes=1024,
        ),
    )


def a_finished_poll(conn: Any, source: Source, result: dict[str, Any]) -> None:
    job = store.enqueue(conn, source.id, JobKind.POLL, requested_by="test")
    assert job is not None
    store.finish_job(conn, job.id, JobState.DONE, result=result)


def ask(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source, forge: FakeForge
) -> dict[str, Any] | None:
    monkeypatch.setattr(worker, "release_source", lambda *_a, **_k: forge)
    return worker._unchanged_since_last_poll(conn, source, None)


# ------------------------------------------------------------ skipping is on


def test_an_unchanged_tag_skips_the_poll(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    a_finished_poll(conn, source, {"tag": "v0.2.0", "decision": "promote"})

    record = ask(monkeypatch, conn, source, FakeForge("v0.2.0"))

    assert record is not None
    assert record["outcome"] == "unchanged"
    assert record["tag"] == "v0.2.0"
    assert record["consecutive_skips"] == 1


def test_consecutive_skips_accumulate(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    a_finished_poll(conn, source, {"outcome": "unchanged", "tag": "v0.2.0", "consecutive_skips": 7})

    record = ask(monkeypatch, conn, source, FakeForge("v0.2.0"))

    assert record is not None
    assert record["consecutive_skips"] == 8


def test_a_real_poll_resets_the_run(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    # A poll that actually ran records no skip count, so the next skip starts
    # the clock again rather than inheriting an old one.
    a_finished_poll(conn, source, {"outcome": "unchanged", "tag": "v0.2.0", "consecutive_skips": 9})
    a_finished_poll(conn, source, {"tag": "v0.2.0", "decision": "promote"})

    record = ask(monkeypatch, conn, source, FakeForge("v0.2.0"))

    assert record is not None
    assert record["consecutive_skips"] == 1


# --------------------------------------------------------- skipping is off


def test_a_new_tag_polls(monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source) -> None:
    a_finished_poll(conn, source, {"tag": "v0.2.0", "decision": "promote"})

    assert ask(monkeypatch, conn, source, FakeForge("v0.3.0")) is None


def test_no_previous_poll_polls(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    """Nothing to compare against, and the feed is not the authority."""
    forge = FakeForge("v0.2.0")

    assert ask(monkeypatch, conn, source, forge) is None
    # And the feed is not even consulted: there is no question it could settle.
    assert forge.calls == 0


def test_a_forge_with_no_opinion_polls(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    a_finished_poll(conn, source, {"tag": "v0.2.0", "decision": "promote"})

    assert ask(monkeypatch, conn, source, FakeForge(None)) is None


def test_a_failing_feed_polls_rather_than_stopping(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    """The cheap check is an optimisation, and one that can halt ingestion is not."""
    a_finished_poll(conn, source, {"tag": "v0.2.0", "decision": "promote"})

    assert ask(monkeypatch, conn, source, FakeForge(raises=ForgeError("feed is gone"))) is None


def test_too_many_skips_forces_a_poll(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    """A feed that has quietly stopped reflecting reality must not hide forever."""
    a_finished_poll(
        conn,
        source,
        {
            "outcome": "unchanged",
            "tag": "v0.2.0",
            "consecutive_skips": worker.MAX_CONSECUTIVE_SKIPS,
        },
    )
    forge = FakeForge("v0.2.0")

    assert ask(monkeypatch, conn, source, forge) is None
    assert forge.calls == 0, "the reconcile must not depend on the feed answering"


def test_a_poll_that_found_no_release_leaves_nothing_to_compare(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    # `{"outcome": "no release"}` carries no tag, so there is no prior fact.
    a_finished_poll(conn, source, {"outcome": "no release"})

    assert ask(monkeypatch, conn, source, FakeForge("v0.1.0")) is None


def test_a_corrupt_skip_count_polls(
    monkeypatch: pytest.MonkeyPatch, conn: Any, source: Source
) -> None:
    # The result column is JSON and nothing constrains its shape. A value that
    # is not an integer must not become a comparison that silently succeeds.
    a_finished_poll(
        conn, source, {"outcome": "unchanged", "tag": "v0.2.0", "consecutive_skips": "lots"}
    )

    assert ask(monkeypatch, conn, source, FakeForge("v0.2.0")) is None
