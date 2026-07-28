"""The service that holds the forge credential.

    uv run python -m dist_ingest.worker

It has no inbound listener. It takes work from the `jobs` table, reaches the
forge, and writes results back — which is what lets PLAN.md 2's invariant hold
with a web UI in the picture: the component operators can reach has no
credential, and the component with the credential cannot be reached.

Two kinds of work:

- **validate** — ask the forge what it knows about a project. Read-only, no
  download, no ingestion. It resolves the numeric ids the certificate identity
  pins, and confirms the release and the named asset exist. Success moves the
  source to `pending_delegation`, never further.
- **poll** — fetch the latest release, admit it to quarantine, and run the
  promotion policy. Only ever for a source that already has a delegation.

Everything a forge says is untrusted input, so a job that fails records why and
the source stays where it was. There is no failure mode here that promotes.
"""

from __future__ import annotations

import hashlib
import logging
import os
import signal
import sys
import time
import types
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import httpx

from dist_ingest.forge import ForgeError, ReleaseSource
from dist_ingest.policy import Outcome, Promotion, ingest
from dist_ingest.quarantine import Quarantine
from dist_ingest.sources import SourceConfigError, client_for, ingest_policy, release_source
from dist_registry import db, store
from dist_registry.models import Job, JobKind, JobState, Source, SourceStatus
from dist_registry.store import Conn

log = logging.getLogger("dist_ingest.worker")

#: How often to look for work when there was none.
IDLE_SLEEP = 5.0
#: How often an active source is polled, absent an operator asking sooner.
POLL_INTERVAL = timedelta(minutes=15)
#: A job claimed and not finished within this is assumed to belong to a worker
#: that died, and is requeued.
STALE_AFTER = timedelta(minutes=30)


class _Stopping:
    """Finish the job in hand, then exit."""

    def __init__(self) -> None:
        self.requested = False
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._handle)

    def _handle(self, _signum: int, _frame: types.FrameType | None) -> None:
        log.info("stop requested; finishing the current job")
        self.requested = True


def forge_token() -> str | None:
    """The read-only forge credential.

    Read from a file when `DIST_FORGE_TOKEN_FILE` is set, so that a compose
    secret does not have to become an environment variable that every child
    process and every crash dump inherits.
    """
    path = os.environ.get("DIST_FORGE_TOKEN_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip() or None
    return os.environ.get("DIST_FORGE_TOKEN") or None


# --------------------------------------------------------------- job kinds


def do_validate(source: Source, client: httpx.Client) -> dict[str, Any]:
    """Read what the forge knows. Establishes nothing about trust.

    Raises:
        ForgeError: if the project, the release or the named asset is not there.
    """
    forge = release_source(source, client)
    identity = forge.project_identity()

    release = forge.latest_release()
    if release is None:
        raise ForgeError("the project has no published release; there is nothing to ingest yet")
    asset = release.asset(source.asset_name)
    if asset is None:
        available = ", ".join(a.name for a in release.assets) or "none"
        raise ForgeError(
            f"release {release.tag} has no asset named {source.asset_name!r} (it has: {available})"
        )

    return {
        **identity,
        "latest_tag": release.tag,
        "latest_version": release.version,
        "asset": asset.name,
        "asset_bytes": asset.size,
    }


def do_poll(source: Source, client: httpx.Client, quarantine: Quarantine) -> dict[str, Any]:
    """Fetch the latest release and run it through the promotion policy.

    The artifact is streamed to a temporary file and then handed to `ingest`,
    which admits it to quarantine and hashes it there. Provenance is checked
    against the digest computed over the bytes we actually received, never
    against what the forge said they would be.
    """
    policy = ingest_policy(source)
    forge: ReleaseSource = release_source(source, client)

    release = forge.latest_release()
    if release is None:
        return {"outcome": "no release"}
    asset = release.asset(source.asset_name)
    if asset is None:
        raise ForgeError(f"release {release.tag} has no asset named {source.asset_name!r}")

    with TemporaryDirectory() as scratch:
        staged = Path(scratch) / "asset"
        with staged.open("wb") as sink:
            written = forge.download(asset, sink)

        # The attestation is addressed by the digest of the bytes on disk, so
        # quarantine has to hash them first. `ingest` does that; this pre-pass
        # exists only to look the envelope up.
        digest = _sha256_of(staged)
        try:
            envelope = forge.attestation(digest)
        except ForgeError as exc:
            # A missing attestation is a rejection, not an error: it is the
            # ordinary case for a project that has not set up provenance.
            log.info("no attestation for %s: %s", source.app_id, exc)
            envelope = None

        with staged.open("rb") as handle:
            outcome = ingest(handle, policy, quarantine, envelope=envelope)

    return _outcome_record(release.tag, release.version, written, outcome)


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _outcome_record(tag: str, version: str, written: int, outcome: Outcome) -> dict[str, Any]:
    record: dict[str, Any] = {
        "tag": tag,
        "version": version,
        "bytes": written,
        "decision": str(outcome.decision),
        "reason": outcome.reason,
    }
    if outcome.admitted is not None:
        record["sha256"] = outcome.admitted.sha256
    if outcome.decision is Promotion.HOLD_FOR_CEREMONY:
        record["note"] = "offline key; a human must sign this release"
    return record


# ------------------------------------------------------------------- loop


def run_job(conn: Conn, job: Job, quarantine: Quarantine, token: str | None) -> None:
    source = store.get_source(conn, job.source_id)
    if source is None:
        store.finish_job(conn, job.id, JobState.FAILED, error="source was deleted")
        return

    try:
        with client_for(source, token) as client:
            if job.kind is JobKind.VALIDATE:
                result = do_validate(source, client)
                # Only the pins are written back. The rest of the result is a
                # snapshot of what the forge said at this moment and belongs in
                # the job record, not in policy.
                store.record_identity(
                    conn,
                    source.id,
                    {
                        "repository_id": str(result["repository_id"]),
                        "repository_owner_id": str(result["repository_owner_id"]),
                    },
                )
                store.audit(
                    conn,
                    actor="worker",
                    action="source.validated",
                    source_id=source.id,
                    detail=result,
                )
            else:
                if not source.pollable:
                    raise SourceConfigError(
                        f"{source.app_id} has no delegation yet; refusing to fetch artifacts "
                        "that could not be promoted"
                    )
                result = do_poll(source, client, quarantine)
                store.audit(
                    conn,
                    actor="worker",
                    action="source.polled",
                    source_id=source.id,
                    detail=result,
                )
        store.finish_job(conn, job.id, JobState.DONE, result=result)

    # Deliberately broad. The narrow list above it is what this code expects to
    # go wrong; anything else is a bug, and a bug that escapes here leaves the
    # job in `running` forever. The partial unique index then treats that as an
    # open job, so the source stops being pollable until `reset_stale_jobs`
    # notices half an hour later. Recording the failure is what keeps one
    # unexpected exception from wedging a source.
    except Exception as exc:
        expected = (ForgeError, SourceConfigError, httpx.HTTPError, OSError)
        message = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, expected):
            log.warning("job %s for %s failed: %s", job.kind, source.app_id, message)
        else:
            log.exception("job %s for %s raised unexpectedly", job.kind, source.app_id)
        store.finish_job(conn, job.id, JobState.FAILED, error=message)
        if job.kind is JobKind.VALIDATE:
            store.set_status(conn, source.id, SourceStatus.INVALID, error=message)


def tick(conn: Conn, quarantine: Quarantine, token: str | None) -> bool:
    """One pass. Returns whether any work was done."""
    store.reset_stale_jobs(conn, STALE_AFTER)

    for source in store.sources_due_for_poll(conn, POLL_INTERVAL):
        store.enqueue(conn, source.id, JobKind.POLL, requested_by="schedule")

    job = store.claim_job(conn)
    if job is None:
        return False
    run_job(conn, job, quarantine, token)
    return True


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("DIST_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    quarantine = Quarantine(Path(os.environ.get("DIST_QUARANTINE_DIR", "/srv/quarantine")))
    token = forge_token()
    if token is None:
        log.warning(
            "no forge token configured; only public projects will be reachable "
            "and rate limits will be low"
        )

    stopping = _Stopping()
    pool = db.pool(min_size=1, max_size=2)
    with pool.connection() as conn:
        db.migrate(conn)
    log.info("worker ready; polling active sources every %s", POLL_INTERVAL)

    try:
        while not stopping.requested:
            try:
                with pool.connection() as conn:
                    worked = tick(conn, quarantine, token)
            except Exception:
                # A worker that exits on a transient database error is a worker
                # that stops polling until somebody notices.
                log.exception("tick failed; retrying")
                worked = False
            if not worked:
                time.sleep(IDLE_SLEEP)
    finally:
        pool.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
