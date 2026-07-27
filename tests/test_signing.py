from __future__ import annotations

from pathlib import Path

import pytest

from dist_core.signing import (
    InMemorySignerBackend,
    KeePassConfig,
    KeePassSignerBackend,
    KeyMaterialError,
    KmsSignerBackend,
    Pkcs11SignerBackend,
    create_keystore,
    generate_key,
)


@pytest.fixture
def keystore(tmp_path: Path) -> KeePassConfig:
    keyfile = tmp_path / "unseal" / "online.key"
    keyfile.parent.mkdir()
    keyfile.write_bytes(b"unsealing-key-file-material")
    config = KeePassConfig(
        database=tmp_path / "keys" / "online.kdbx",
        password="correct horse battery staple",
        keyfile=keyfile,
    )
    create_keystore(config)
    return config


def test_keepass_round_trip_signs_and_verifies(keystore: KeePassConfig) -> None:
    keyid = generate_key(keystore, "timestamp", "timestamp-1")

    backend = KeePassSignerBackend(keystore)
    assert backend.keyids("timestamp") == [keyid]

    signature = backend.signer(keyid).sign(b"payload")
    backend.public_key(keyid).verify_signature(signature, b"payload")


def test_keepass_rejects_tampered_payload(keystore: KeePassConfig) -> None:
    from securesystemslib.exceptions import UnverifiedSignatureError

    keyid = generate_key(keystore, "snapshot", "snapshot-1")
    backend = KeePassSignerBackend(keystore)
    signature = backend.signer(keyid).sign(b"payload")

    with pytest.raises(UnverifiedSignatureError):
        backend.public_key(keyid).verify_signature(signature, b"tampered")


def test_keys_are_partitioned_by_role(keystore: KeePassConfig) -> None:
    root_key = generate_key(keystore, "root", "root-1")
    generate_key(keystore, "timestamp", "timestamp-1")

    backend = KeePassSignerBackend(keystore)
    assert backend.keyids("root") == [root_key]
    assert root_key not in backend.keyids("timestamp")


def test_unknown_keyid_is_rejected(keystore: KeePassConfig) -> None:
    generate_key(keystore, "root", "root-1")
    backend = KeePassSignerBackend(keystore)
    with pytest.raises(KeyMaterialError, match="no key"):
        backend.signer("not-a-real-keyid")


def test_create_keystore_refuses_to_overwrite(keystore: KeePassConfig) -> None:
    with pytest.raises(KeyMaterialError, match="refusing to overwrite"):
        create_keystore(keystore)


def test_wrong_unsealing_material_fails(keystore: KeePassConfig) -> None:
    from pykeepass.exceptions import CredentialsError

    generate_key(keystore, "root", "root-1")
    wrong = KeePassConfig(
        database=keystore.database,
        password="wrong password",
        keyfile=keystore.keyfile,
    )
    with pytest.raises(CredentialsError):
        KeePassSignerBackend(wrong)


def test_no_unsealing_material_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(KeyMaterialError, match="no unsealing material"):
        KeePassConfig(database=tmp_path / "online.kdbx").validate()


class TestProductionGuards:
    """PLAN.md 3.3 requires a composite master key with the key file separated."""

    def test_password_alone_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENV", "production")
        config = KeePassConfig(database=tmp_path / "online.kdbx", password="p")
        with pytest.raises(KeyMaterialError, match="composite master key"):
            config.validate()

    def test_keyfile_beside_database_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ENV", "production")
        config = KeePassConfig(
            database=tmp_path / "online.kdbx",
            password="p",
            keyfile=tmp_path / "online.key",
        )
        with pytest.raises(KeyMaterialError, match="separate mount"):
            config.validate()

    def test_separated_keyfile_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ENV", "production")
        config = KeePassConfig(
            database=tmp_path / "keys" / "online.kdbx",
            password="p",
            keyfile=tmp_path / "unseal" / "online.key",
        )
        config.validate()

    def test_in_memory_backend_refuses_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENV", "production")
        with pytest.raises(KeyMaterialError, match="never be used with ENV=production"):
            InMemorySignerBackend()


@pytest.mark.parametrize("backend", [Pkcs11SignerBackend, KmsSignerBackend])
def test_unimplemented_backends_fail_loudly(backend: type) -> None:
    with pytest.raises(NotImplementedError, match="D4"):
        backend()
