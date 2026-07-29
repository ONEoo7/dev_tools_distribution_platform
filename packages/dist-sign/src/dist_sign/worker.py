"""The service that holds the online signing keys.

    uv run python -m dist_sign.worker

It has no inbound listener and no network client. It takes `publish` jobs from
the queue, reads the named artifact out of quarantine, and signs it into the
repository. That is the whole of it, and the narrowness is the point: this is
the only component that can write TUF metadata, so the smaller its reachable
surface the better.

What it deliberately cannot do:

- **Reach a forge.** It joins no network that does. The artifact it signs was
  fetched, verified and quarantined by the ingest worker; if this service could
  also fetch, a compromise here would be able to sign bytes it chose itself.
- **Decide what to sign.** The digest comes from the job payload, written when
  ingestion approved that specific artifact. It signs what was approved, not
  whatever is newest in quarantine when it happens to run.
- **Touch `root` or `targets`.** Those keys live in `offline.kdbx` and are not
  mounted here. This process can publish releases for applications that already
  have a delegation; it cannot create one, which is what keeps the ceremony
  meaningful.
- **Write to quarantine.** Mounted read-only, so it cannot remove the evidence
  of what it signed.

An artifact whose digest no longer matches is refused rather than re-hashed.
Quarantine is content-addressed, so a mismatch means the file changed under a
name that says it cannot have.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
import types
from datetime import timedelta
from pathlib import Path
from typing import Any

from dist_core.buildinfo import describe
from dist_core.naming import ReleaseInfo, TargetKey
from dist_core.repository import FileSystemRepository, PublicationError
from dist_core.roles import app_role_name
from dist_core.signing import KeePassConfig, KeePassSignerBackend, KeyMaterialError
from dist_registry import db, store
from dist_registry.models import Job, JobKind, JobState, Source
from dist_registry.store import Conn

log = logging.getLogger("dist_sign.worker")

IDLE_SLEEP = 5.0
STALE_AFTER = timedelta(minutes=30)

#: This worker claims only its own kind. `claim_job` requires the list rather
#: than defaulting to everything, so a poll job can never be executed by the
#: process holding the signing keys.
CLAIMS = (JobKind.PUBLISH,)


class SigningConfigError(Exception):
    """The signing worker is not configured to sign anything."""


class _Stopping:
    """Finish the job in hand, then exit.

    Interrupting a publish half-way would leave metadata referring to a target
    that snapshot does not describe, so a signal is a request to stop *after*
    the current job rather than during it.
    """

    def __init__(self) -> None:
        self.requested = False
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._handle)

    def _handle(self, _signum: int, _frame: types.FrameType | None) -> None:
        log.info("stop requested; finishing the current job")
        self.requested = True


def keystore() -> KeePassConfig:
    """The online keystore, from the environment.

    The password is read from a file when `DIST_ONLINE_KDBX_PASSWORD_FILE` is
    set. Prefer that: an environment variable is inherited by every child
    process and lands in a crash dump, and this one unlocks the keys that sign
    everything clients accept.
    """
    database = Path(os.environ.get("DIST_ONLINE_KDBX", "/srv/keys/online.kdbx"))
    if not database.is_file():
        raise SigningConfigError(f"no keystore at {database}")

    password_file = os.environ.get("DIST_ONLINE_KDBX_PASSWORD_FILE")
    password = (
        Path(password_file).read_text(encoding="utf-8").strip()
        if password_file
        else os.environ.get("DIST_ONLINE_KDBX_PASSWORD") or None
    )
    keyfile = os.environ.get("DIST_ONLINE_KDBX_KEYFILE")
    return KeePassConfig(
        database=database,
        password=password,
        keyfile=Path(keyfile) if keyfile else None,
    )


def quarantine_path(root: Path, sha256: str) -> Path:
    """Where quarantine keeps an artifact, by digest.

    Mirrors `dist_ingest.quarantine.Quarantine.path`, and there is a test that
    fails if the two disagree. Duplicated rather than imported: depending on
    `dist-ingest` would put an HTTP client and a forge client inside the
    process holding the signing keys, which is the one place they should not
    be.
    """
    return root / f"{sha256}.bin"


def do_publish(
    conn: Conn,
    source: Source,
    payload: dict[str, Any],
    repo: FileSystemRepository,
    quarantine_root: Path,
) -> dict[str, Any]:
    """Sign one approved artifact into the repository and make it current.

    Raises:
        PublicationError: if the artifact is missing, its digest disagrees with
            the job, or the application has no delegation.
    """
    for required in ("sha256", "version", "filename"):
        if not payload.get(required):
            raise PublicationError(f"publish job carries no {required}")

    sha256 = str(payload["sha256"])
    artifact = quarantine_path(quarantine_root, sha256)
    if not artifact.is_file():
        raise PublicationError(f"no quarantined artifact {sha256}")

    # Content-addressed storage means the name is a claim about the bytes.
    # Checking it here is what stops a file swapped after admission from being
    # signed under the digest that was approved.
    actual = _sha256_of(artifact)
    if actual != sha256:
        raise PublicationError(
            f"quarantined artifact {sha256} now hashes to {actual}; refusing to sign it"
        )

    role = app_role_name(source.app_id)
    if role not in repo.app_roles:
        raise PublicationError(
            f"{source.app_id} has no delegated role in the published metadata; "
            "the ceremony has not happened"
        )

    key = TargetKey(
        app_id=source.app_id,
        channel=source.channel,
        platform=source.platform,
        arch=source.arch,
        version=str(payload["version"]),
        filename=str(payload["filename"]),
    )
    repo.add_release(key, artifact, ReleaseInfo(version=key.version))
    pointer = repo.set_current(key)

    log.info("published %s %s and made it current", source.app_id, key.version)
    return {
        "target": key.path,
        "pointer": pointer,
        "version": key.version,
        "sha256": sha256,
    }


def _sha256_of(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


# ------------------------------------------------------------------- loop


def run_job(conn: Conn, job: Job, repo: FileSystemRepository, quarantine_root: Path) -> None:
    source = store.get_source(conn, job.source_id)
    if source is None:
        store.finish_job(conn, job.id, JobState.FAILED, error="source was deleted")
        return

    try:
        result = do_publish(conn, source, job.payload, repo, quarantine_root)
        store.audit(
            conn,
            actor="signer",
            action="release.published",
            source_id=source.id,
            detail=result,
        )
        store.finish_job(conn, job.id, JobState.DONE, result=result)

    # As in the ingest worker: the narrow list is what this code expects to go
    # wrong, and anything else is a bug. A bug that escapes here leaves the job
    # `running` forever, and the partial unique index then blocks every further
    # job for that source until `reset_stale_jobs` notices.
    except Exception as exc:
        expected = (PublicationError, KeyMaterialError, OSError, ValueError)
        message = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, expected):
            log.warning("publish for %s failed: %s", source.app_id, message)
        else:
            log.exception("publish for %s raised unexpectedly", source.app_id)
        store.finish_job(conn, job.id, JobState.FAILED, error=message)


def tick(conn: Conn, repo: FileSystemRepository, quarantine_root: Path) -> bool:
    """One pass. Returns whether any work was done."""
    store.reset_stale_jobs(conn, STALE_AFTER)

    job = store.claim_job(conn, CLAIMS)
    if job is None:
        return False
    run_job(conn, job, repo, quarantine_root)
    return True


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("DIST_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log.info(describe("dist-sign.worker"))

    repo_dir = Path(os.environ.get("DIST_REPO_DIR", "/srv/repo"))
    quarantine_root = Path(os.environ.get("DIST_QUARANTINE_DIR", "/srv/quarantine"))

    try:
        config = keystore()
        backend = KeePassSignerBackend(config)
    except (SigningConfigError, KeyMaterialError) as exc:
        # Refuse to start rather than run and fail every job. A signing worker
        # that cannot open its keystore has nothing to offer, and a container
        # restarting loudly is easier to notice than one quietly failing work.
        log.error("cannot open the online keystore: %s", exc)
        return 1

    repo = FileSystemRepository(repo_dir, backend)
    log.info(
        "signing worker ready; repo %s, %d delegated role(s)",
        repo_dir,
        len(repo.app_roles),
    )

    stopping = _Stopping()
    pool = db.pool(min_size=1, max_size=2)
    with pool.connection() as conn:
        db.migrate(conn)

    try:
        while not stopping.requested:
            try:
                with pool.connection() as conn:
                    worked = tick(conn, repo, quarantine_root)
            except Exception:
                log.exception("tick failed; retrying")
                worked = False
            if not worked:
                time.sleep(IDLE_SLEEP)
    finally:
        pool.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
