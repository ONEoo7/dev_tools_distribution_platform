"""Generate TUF fixtures for the Rust verifier's interop test.

Builds a real repository with `dist-core` and flattens the metadata into
`client/dist-core-rs/tests/fixtures/`, so the Rust verifier is tested against
bytes the Python server actually produces rather than against hand-written
metadata that only resembles them.

Metadata expires, so `meta.json` records the generation time and the Rust test
pins its clock to it via `TufVerifier::bootstrap_at`. Regenerate with:

    uv run python scripts/gen_rust_fixtures.py
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from tuf.api.metadata import TargetFile

from dist_core.naming import ChannelKey, ReleaseInfo, TargetKey
from dist_core.repository import FileSystemRepository
from dist_core.roles import ROOT, SNAPSHOT, TARGETS, TIMESTAMP, TOP_LEVEL_POLICIES, app_role_name
from dist_core.signing import InMemorySignerBackend

FIXTURES = Path(__file__).resolve().parent.parent / "client/dist-core-rs/tests/fixtures"
APP_ID = "editor"
VERSION = "1.4.2"
ROLLOUT_PCT = 25
PAYLOAD = b"editor release payload for the rust interop test"

_VERSIONED = re.compile(r"^(\d+)\.(.+)\.json$")


def latest(metadata_dir: Path, role: str) -> Path:
    versions = [
        (int(m.group(1)), path)
        for path in metadata_dir.glob("*.json")
        if (m := _VERSIONED.match(path.name)) and m.group(2) == role
    ]
    return max(versions)[1]


def main() -> None:
    generated_at = datetime.now(UTC)

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        backend = InMemorySignerBackend()
        for role in (ROOT, TARGETS, SNAPSHOT, TIMESTAMP):
            for _ in range(TOP_LEVEL_POLICIES[role].threshold):
                backend.generate(role)
        role_name = app_role_name(APP_ID)
        backend.generate(role_name)

        repo = FileSystemRepository(work / "repo", backend)
        repo.initialize()
        repo.add_app(APP_ID)

        payload = work / f"Editor-{VERSION}.zip"
        payload.write_bytes(PAYLOAD)

        key = TargetKey(APP_ID, "stable", "windows", "amd64", VERSION, payload.name)
        repo.add_release(key, payload, ReleaseInfo(version=VERSION, rollout_pct=ROLLOUT_PCT))

        # Delegation escalation: the editor role signs a target belonging to a
        # different application. A conforming client must not resolve it, since
        # the delegation only covers `editor/...` (PLAN.md 3.1).
        forged = TargetKey("viewer", "stable", "windows", "amd64", "9.9.9", "Viewer-9.9.9.zip")
        forged_payload = work / forged.filename
        forged_payload.write_bytes(b"forged viewer release")
        entry = TargetFile.from_file(forged.path, str(forged_payload))
        repo.store_payload(forged.path, entry, forged_payload)
        with repo.edit(role_name) as editor_targets:
            editor_targets.targets[forged.path] = entry
        repo.publish()

        # Make the release current, so the fixtures carry a channel pointer as
        # a real repository would (PLAN.md 5.7).
        repo.set_current(key)

        if FIXTURES.exists():
            shutil.rmtree(FIXTURES)
        FIXTURES.mkdir(parents=True)

        metadata = repo.metadata_dir
        shutil.copyfile(metadata / "root.json", FIXTURES / "root.json")
        shutil.copyfile(metadata / "timestamp.json", FIXTURES / "timestamp.json")
        # Recorded so the interop test can assert the ABI reports the versions
        # the server actually published, rather than merely reporting *a*
        # number. The fixture filenames are flattened, so without this the
        # cross-language contract would be untestable.
        published_versions = {
            role: int(latest(metadata, role).name.split(".", 1)[0])
            for role in (SNAPSHOT, TARGETS, role_name)
        }
        for role in (SNAPSHOT, TARGETS, role_name):
            shutil.copyfile(latest(metadata, role), FIXTURES / f"{role}.json")
        shutil.copyfile(payload, FIXTURES / "payload.bin")

        (FIXTURES / "meta.json").write_text(
            json.dumps(
                {
                    "generated_at": int(generated_at.timestamp()),
                    "delegated_role": role_name,
                    "target_path": key.path,
                    "forged_target_path": forged.path,
                    "version": VERSION,
                    "rollout_pct": ROLLOUT_PCT,
                    "payload_length": len(PAYLOAD),
                    "pointer_path": ChannelKey(
                        APP_ID, key.channel, key.platform, key.arch
                    ).pointer_path,
                    "published_versions": published_versions,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    print(f"wrote fixtures to {FIXTURES}")


if __name__ == "__main__":
    main()
