# Distribution plane — Compose stack

Implements the serving half of PLAN.md section 4. See section 10.1 for the
volume model.

## What is here

| Service | State |
|---|---|
| `edge` | Implemented. nginx serving `/metadata` and `/targets` as static files. |
| `dist-worker` | Pending. Signing worker; mounts the repository volumes read-write and has no inbound listener. |
| `dist-api`, `dist-ingest` | Pending — phases 1 and 3. |
| `postgres`, `redis`, `minio` | Pending; added with the services that use them. |

Volumes are declared as the services that need them land, so that
`docker compose up` never starts a datastore nothing talks to.

## Running against a locally built repository

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

Set `REPO_DIR` to a repository built by `dist-core` (default `../../repo`).
Both mounts are read-only, so the edge behaves exactly as it does in
production.

Verify with `curl http://127.0.0.1:8080/healthz`.

## Security properties encoded here

- **Read-only by mount, not by configuration.** The repository volumes are
  mounted `:ro`. Even a full compromise of the edge cannot alter metadata,
  regardless of whether `edge.conf` is correct.
- **Bound to loopback by default.** `EDGE_BIND` defaults to `127.0.0.1`; put a
  TLS terminator in front rather than exposing this directly.
- **`timestamp.json` and `root.json` are `no-store`.** Everything else is
  version-numbered or content-addressed and therefore immutable. Caching the
  freshness signal defeats the short expiry in section 3.1 and is
  indistinguishable from a freeze attack.
- **No Docker socket is mounted anywhere.** Socket access is host root, and
  host root is every volume including the keys.
- Container runs unprivileged, read-only root filesystem, all capabilities
  dropped, `no-new-privileges`.

## Not yet verified

`edge.conf` has not been checked with `nginx -t` — it was written without a
running Docker daemon available. Run this before deploying:

```bash
docker run --rm -v "$PWD/nginx/edge.conf:/etc/nginx/conf.d/default.conf:ro" -v "$PWD/nginx/security-headers.conf:/etc/nginx/security-headers.conf:ro" nginxinc/nginx-unprivileged:1.27-alpine nginx -t
```
