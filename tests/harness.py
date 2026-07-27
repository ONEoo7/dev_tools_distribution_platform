"""Test harness for driving a real TUF client against the repository.

`Mirror` stands in for the edge (§4). Because tests can seed it with arbitrary
responses, it also stands in for a *compromised* edge, which is what the attack
simulations in `test_attacks.py` need.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from tuf.api.exceptions import DownloadHTTPError
from tuf.api.metadata import Metadata
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient import Updater
from tuf.ngclient.fetcher import FetcherInterface

from dist_core.signing import SignerBackend

BASE_URL = "http://local/"


class Mirror(FetcherInterface):
    """Serves the on-disk repository, with per-path overrides.

    Overrides are keyed by repository-relative path, e.g. `metadata/timestamp.json`.
    An override models an attacker who controls the mirror but not the keys.
    """

    def __init__(self, repo_dir: Path) -> None:
        self._repo_dir = repo_dir
        self.overrides: dict[str, bytes] = {}

    def read(self, relative: str) -> bytes:
        return (self._repo_dir / relative).read_bytes()

    def _fetch(self, url: str) -> Iterator[bytes]:
        relative = unquote(url.removeprefix(BASE_URL))
        if relative in self.overrides:
            yield self.overrides[relative]
            return
        path = self._repo_dir / relative
        if not path.is_file():
            raise DownloadHTTPError(f"not found: {url}", 404)
        yield path.read_bytes()


def make_client(mirror: Mirror, bootstrap_root: bytes, client_dir: Path) -> Updater:
    client_dir.mkdir(parents=True, exist_ok=True)
    return Updater(
        metadata_dir=str(client_dir),
        metadata_base_url=f"{BASE_URL}metadata/",
        target_dir=str(client_dir / "targets"),
        target_base_url=f"{BASE_URL}targets/",
        fetcher=mirror,
        bootstrap=bootstrap_root,
    )


def resign(
    backend: SignerBackend,
    role: str,
    md: Metadata[Any],
    *,
    version: int | None = None,
    expires: datetime | None = None,
    keyids: list[str] | None = None,
) -> bytes:
    """Re-sign metadata after tampering with it.

    Models an attacker who has obtained a signing key, or an operator error
    that produces validly-signed but unacceptable metadata. The point of each
    attack test is that a valid signature is *not* sufficient on its own.
    """
    if version is not None:
        md.signed.version = version
    if expires is not None:
        md.signed.expires = expires

    md.signatures.clear()
    for keyid in keyids if keyids is not None else backend.keyids(role):
        md.sign(backend.signer(keyid), append=True)
    return md.to_bytes(JSONSerializer())
