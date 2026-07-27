"""Signer backends.

Mirrors docs/PLAN.md section 3.3. All signing reaches the rest of the system
through `SignerBackend`, so migrating from KeePass to an HSM or KMS later is a
configuration change rather than a rewrite (decision D4).

Note on what KDBX encryption buys: for `online.kdbx` it protects against theft
of the volume or a backup. It does not protect against host compromise, because
the worker must unseal the database in order to sign. That is tolerable for the
online roles by design, and is why `root` and `targets` live in a separate
database that never reaches the service host.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from pykeepass import PyKeePass, create_database
from securesystemslib.signer import CryptoSigner, Key, Signer, SSlibKey

GROUP_NAME = "tuf"
ROLE_PROPERTY = "tuf_role"
PEM_PROPERTY = "tuf_private_key_pem"


class KeyMaterialError(RuntimeError):
    """Raised when key custody rules are violated or key material is unusable."""


class SignerBackend(Protocol):
    def keyids(self, role: str) -> list[str]: ...

    def public_key(self, keyid: str) -> Key: ...

    def signer(self, keyid: str) -> Signer: ...


def is_production() -> bool:
    return os.environ.get("ENV", "").strip().lower() == "production"


@dataclass(frozen=True, slots=True)
class KeePassConfig:
    """Location and unsealing material for one KeePass database."""

    database: Path
    password: str | None = None
    keyfile: Path | None = None

    def validate(self) -> None:
        if self.password is None and self.keyfile is None:
            raise KeyMaterialError(f"no unsealing material supplied for {self.database}")

        if not is_production():
            return

        # PLAN.md 3.3: composite master key, key file on a separate mount.
        if self.password is None or self.keyfile is None:
            raise KeyMaterialError(
                "production requires a composite master key: both a password and a key file"
            )
        if self.keyfile.resolve().parent == self.database.resolve().parent:
            raise KeyMaterialError(
                "key file must not sit beside the database; PLAN.md 3.3 requires it on a "
                "separate mount so that disclosure of one volume is not sufficient"
            )


@dataclass(frozen=True, slots=True)
class _KeyEntry:
    role: str
    private_key: PrivateKeyTypes
    public_key: SSlibKey


class KeePassSignerBackend:
    """Reads TUF signing keys from a KDBX database.

    Entries live in a `tuf` group, each carrying two custom properties:
    `tuf_role` naming the role it signs for, and `tuf_private_key_pem` holding
    a PKCS#8 PEM private key.
    """

    def __init__(self, config: KeePassConfig) -> None:
        config.validate()
        self._config = config
        self._keys: dict[str, _KeyEntry] = {}
        self._kp = PyKeePass(
            str(config.database),
            password=config.password,
            keyfile=str(config.keyfile) if config.keyfile else None,
        )
        self._load()

    def _load(self) -> None:
        group = self._kp.find_groups(name=GROUP_NAME, first=True)
        if group is None:
            raise KeyMaterialError(f"database {self._config.database} has no {GROUP_NAME!r} group")
        for entry in group.entries:
            role = entry.get_custom_property(ROLE_PROPERTY)
            pem = entry.get_custom_property(PEM_PROPERTY)
            if role is None or pem is None:
                continue
            private_key = serialization.load_pem_private_key(pem.encode(), password=None)
            public_key = SSlibKey.from_crypto(private_key.public_key())
            self._keys[public_key.keyid] = _KeyEntry(role, private_key, public_key)

    def keyids(self, role: str) -> list[str]:
        return sorted(k for k, v in self._keys.items() if v.role == role)

    def public_key(self, keyid: str) -> Key:
        return self._entry(keyid).public_key

    def signer(self, keyid: str) -> Signer:
        entry = self._entry(keyid)
        return CryptoSigner(entry.private_key, entry.public_key)

    def _entry(self, keyid: str) -> _KeyEntry:
        try:
            return self._keys[keyid]
        except KeyError:
            raise KeyMaterialError(f"no key {keyid} in {self._config.database}") from None


def create_keystore(config: KeePassConfig) -> None:
    """Create an empty KDBX database with the `tuf` group present."""
    if config.database.exists():
        raise KeyMaterialError(f"refusing to overwrite existing database {config.database}")
    config.database.parent.mkdir(parents=True, exist_ok=True)
    kp = create_database(
        str(config.database),
        password=config.password,
        keyfile=str(config.keyfile) if config.keyfile else None,
    )
    kp.add_group(kp.root_group, GROUP_NAME)
    kp.save()


def generate_key(config: KeePassConfig, role: str, name: str, algorithm: str = "ed25519") -> str:
    """Generate a signing key for `role` and store it in the database.

    Intended for ceremonies and for tests. Returns the TUF keyid.
    """
    private_key: PrivateKeyTypes
    if algorithm == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif algorithm == "ecdsa":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"unsupported algorithm {algorithm!r}")

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    kp = PyKeePass(
        str(config.database),
        password=config.password,
        keyfile=str(config.keyfile) if config.keyfile else None,
    )
    group = kp.find_groups(name=GROUP_NAME, first=True)
    if group is None:
        raise KeyMaterialError(f"database {config.database} has no {GROUP_NAME!r} group")
    entry = kp.add_entry(group, title=name, username=role, password="")
    entry.set_custom_property(ROLE_PROPERTY, role)
    entry.set_custom_property(PEM_PROPERTY, pem, protect=True)
    kp.save()

    return SSlibKey.from_crypto(private_key.public_key()).keyid


class Pkcs11SignerBackend:
    """Specified in PLAN.md 3.3, not implemented. KeePass is the current backend."""

    def __init__(self, *_: object, **__: object) -> None:
        raise NotImplementedError(
            "PKCS#11 backend is not implemented; decision D4 selects KeePass. "
            "Implement against SignerBackend to migrate."
        )


class KmsSignerBackend:
    """Specified in PLAN.md 3.3, not implemented. KeePass is the current backend."""

    def __init__(self, *_: object, **__: object) -> None:
        raise NotImplementedError(
            "KMS backend is not implemented; decision D4 selects KeePass. "
            "Implement against SignerBackend to migrate."
        )


class InMemorySignerBackend:
    """Unencrypted in-process keys. Development and unit tests only."""

    def __init__(self) -> None:
        if is_production():
            raise KeyMaterialError("InMemorySignerBackend must never be used with ENV=production")
        self._keys: dict[str, _KeyEntry] = {}

    def generate(self, role: str) -> str:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = SSlibKey.from_crypto(private_key.public_key())
        self._keys[public_key.keyid] = _KeyEntry(role, private_key, public_key)
        return public_key.keyid

    def keyids(self, role: str) -> list[str]:
        return sorted(k for k, v in self._keys.items() if v.role == role)

    def public_key(self, keyid: str) -> Key:
        return self._keys[keyid].public_key

    def signer(self, keyid: str) -> Signer:
        entry = self._keys[keyid]
        return CryptoSigner(entry.private_key, entry.public_key)
