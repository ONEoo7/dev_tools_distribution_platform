"""TUF metadata operations, signer abstraction and publication policy."""

from dist_core.naming import CHANNELS, ReleaseInfo, TargetKey, in_rollout
from dist_core.repository import FileSystemRepository, PublicationError
from dist_core.roles import KeyStore, RolePolicy, app_role_name, app_role_policy
from dist_core.signing import (
    InMemorySignerBackend,
    KeePassConfig,
    KeePassSignerBackend,
    KeyMaterialError,
    SignerBackend,
    create_keystore,
    generate_key,
)

__all__ = [
    "CHANNELS",
    "FileSystemRepository",
    "InMemorySignerBackend",
    "KeePassConfig",
    "KeePassSignerBackend",
    "KeyMaterialError",
    "KeyStore",
    "PublicationError",
    "ReleaseInfo",
    "RolePolicy",
    "SignerBackend",
    "TargetKey",
    "app_role_name",
    "app_role_policy",
    "create_keystore",
    "generate_key",
    "in_rollout",
]
