"""Operator login: password hashing, server-side sessions, CSRF.

This is the single-operator loopback deployment described in
`deploy/compose/README.md`, not PLAN.md 8.3's OIDC SSO with MFA. The seam is
`current_operator`: everything above it takes a username and does not care how
it was established, so replacing this module with an OIDC front-end changes no
route.

Three things are done deliberately rather than by default:

- **scrypt, not a bare digest.** A password digested with SHA-256 is a
  wordlist away from recovered. The parameters below are the interactive-login
  end of RFC 7914's guidance.
- **Sessions are server-side and only their hash is stored.** Logging out ends
  a session rather than asking the browser to forget it, and a read of the
  `sessions` table is not enough to mint a cookie.
- **CSRF tokens are per session and checked on every mutating route.**
  SameSite=Strict is set as well, but it is a browser behaviour, not an
  enforcement point in this process.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from dist_registry import store
from dist_registry.store import Conn

#: RFC 7914 interactive-login parameters. n is the cost; raising it is a
#: one-line change that invalidates no stored hash, because n is not encoded in
#: the hash — which is also why it must not be lowered without a reset.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 64
_SALT_LEN = 16

SESSION_COOKIE = "dist_admin_session"
SESSION_LIFETIME = timedelta(hours=12)

#: Length of the session cookie value, before hashing. 32 bytes of
#: `secrets.token_urlsafe` is 256 bits of entropy.
_TOKEN_BYTES = 32


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Return `(hash, salt)`. Generates a salt when not given one."""
    if salt is None:
        salt = secrets.token_bytes(_SALT_LEN)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_KEY_LEN,
        maxmem=64 * 1024 * 1024,
    )
    return digest, salt


def verify_password(password: str, expected: bytes, salt: bytes) -> bool:
    candidate, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate, expected)


def token_digest(token: str) -> bytes:
    """What is stored for a session cookie.

    A plain SHA-256 is right here and would be wrong for the password above:
    the input is 256 bits of `secrets` output, so there is no wordlist to run
    and nothing for a slow hash to buy.
    """
    return hashlib.sha256(token.encode("utf-8")).digest()


def authenticate(conn: Conn, username: str, password: str) -> bool:
    """Check a password, in constant time whether or not the operator exists.

    An unknown username still pays for a scrypt call. Skipping it would make
    "no such operator" measurably faster than "wrong password", which is how a
    login form tells an attacker which usernames are real.
    """
    record = store.get_operator(conn, username)
    if record is None:
        hash_password(password, b"\x00" * _SALT_LEN)
        return False
    if record["disabled"]:
        return False
    return verify_password(password, bytes(record["password_hash"]), bytes(record["salt"]))


def begin_session(conn: Conn, username: str) -> tuple[str, str]:
    """Create a session. Returns `(cookie_value, csrf_token)`."""
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    csrf = secrets.token_urlsafe(_TOKEN_BYTES)
    store.create_session(
        conn,
        token_digest(token),
        username,
        csrf,
        datetime.now(UTC) + SESSION_LIFETIME,
    )
    return token, csrf


def end_session(conn: Conn, token: str | None) -> None:
    if token:
        store.delete_session(conn, token_digest(token))


def session_for(conn: Conn, token: str | None) -> dict[str, object] | None:
    if not token:
        return None
    return store.get_session(conn, token_digest(token))


def csrf_ok(expected: str, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(expected, supplied or "")
