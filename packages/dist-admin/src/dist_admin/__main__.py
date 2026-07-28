"""Run the admin plane.

    uv run python -m dist_admin

Binds loopback by default. PLAN.md 2 gives the admin plane no inbound path from
clients at all, so exposing it means putting an authenticating TLS terminator
in front, not changing this default.
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "dist_admin.app:create_app",
        factory=True,
        host=os.environ.get("DIST_ADMIN_HOST", "127.0.0.1"),
        port=int(os.environ.get("DIST_ADMIN_PORT", "8081")),
        # This service sits behind nothing by default, so it must not believe
        # X-Forwarded-* headers. Turning this on without a trusted proxy in
        # front lets a client dictate the address that lands in the log.
        proxy_headers=False,
        access_log=True,
    )


if __name__ == "__main__":
    main()
