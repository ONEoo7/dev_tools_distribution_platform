"""Deployment settings, from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    #: Set only where the admin plane is behind TLS. It is off by default
    #: because the documented deployment is loopback HTTP, and a `Secure`
    #: cookie is simply never sent there — which presents as a login form that
    #: accepts the password and then returns you to the login form.
    secure_cookie: bool
    #: Creates the `admin` operator on first start when no operator exists.
    #: Ignored once one does, so leaving it set does not reset a password.
    bootstrap_password: str | None

    @classmethod
    def from_env(cls) -> Settings:
        url = os.environ.get("DIST_DATABASE_URL")
        if not url:
            raise RuntimeError("DIST_DATABASE_URL is not set")
        return cls(
            database_url=url,
            secure_cookie=os.environ.get("DIST_ADMIN_SECURE_COOKIE", "").lower()
            in {"1", "true", "yes"},
            bootstrap_password=os.environ.get("DIST_ADMIN_BOOTSTRAP_PASSWORD") or None,
        )
