# Distribution and admin planes — Compose stack

Implements the serving half of PLAN.md section 4, and the source-registry slice
of the admin plane in section 8. See section 10.1 for the volume model.

## What is here

| Service | Network | Listens | Holds | State |
|---|---|---|---|---|
| `edge` | `edge` | 8080 (loopback) | nothing | Implemented. nginx serving `/metadata` and `/targets` as static files. |
| `admin` | `front`, `control` | 8081 (loopback) | nothing | Implemented. Operator UI for the forge source registry. |
| `worker` | `control`, `forge` | **nothing** | read-only forge token | Implemented. Drains the job queue: validates sources, polls releases, runs ingestion. |
| `postgres` | `control` | not published | registry, queue, audit log | Implemented. |
| `dist-worker` (signing) | — | — | signing keys | Pending. Mounts the repository volumes read-write. |
| `dist-api` | — | — | — | Pending — phase 1. |
| `redis`, `minio` | — | — | — | Pending; added with the services that use them. |

## Running it

```bash
cp .env.example .env      # set POSTGRES_PASSWORD and ADMIN_BOOTSTRAP_PASSWORD
docker compose up -d --build
```

The admin UI is then on <http://127.0.0.1:8081>. Sign in as `admin` with the
bootstrap password, or create an operator without putting a password in a file:

```bash
docker compose run --rm admin python -m dist_admin.operators add alice
```

Verify the edge with `curl http://127.0.0.1:8080/healthz`.

### Upgrading Postgres, 17 to 18

A fresh deployment needs nothing here. An existing one does, because this is a
major version bump and the on-disk format is not compatible — and because the
18 image moved where that format lives.

Two changes landed together upstream. `PGDATA` became version specific
(`/var/lib/postgresql/18/docker`), and the declared VOLUME became its parent
(`/var/lib/postgresql`). The compose file now mounts the parent, and mounts a
**new** volume, `postgres-data`.

The old `pgdata` volume is deliberately left alone rather than reused. A 17
volume holds its cluster at the volume root; mounted at the 18 location those
files would sit beside a freshly initialised empty cluster, and the stack would
start, pass its healthcheck and serve an empty registry. Nothing would report
an error. The rename is what makes that impossible instead of merely unlikely.

Dump from 17 and restore into 18:

```bash
docker compose stop admin worker signer
docker run --rm -v dist-platform_pgdata:/var/lib/postgresql/data postgres:17-alpine \
  pg_dumpall -U dist > dist-17.sql
docker compose up -d postgres
docker compose exec -T postgres psql -U dist -d dist < dist-17.sql
docker compose up -d
```

Keep `dist-17.sql` and the `pgdata` volume until the registry, the job history
and the operator accounts have all been checked. Only then:

```bash
docker volume rm dist-platform_pgdata
```

This database holds the source registry, the queue and the audit log — no
signing keys and no TUF metadata — so a botched migration costs the registry
and not the trust root. That is the one part of this worth being relaxed about.

### Knowing which code is running

**Rebuild everything, not one service.** `admin` and `worker` are two targets of
one image and share `dist-core`, `dist-registry` and `dist-ingest`, so
`docker compose build admin` after editing shared code leaves the worker on the
older tree — where it goes on reporting failures that describe code no longer on
disk. Plain `docker compose build` rebuilds both.

Each service says what it is running, as its first log line:

```
dist-ingest.worker starting; source 8f6a080b; built ce856bc at 2026-07-28T06:20:59Z
```

`source` is a digest over the installed `dist_*` package files, so it needs no
build arguments and can be compared directly against a checkout:

```bash
uv run python -m dist_core.buildinfo     # the tree
curl -s http://127.0.0.1:8081/healthz    # what the admin container is running
docker compose logs worker | head -1     # what the worker container is running
```

Three matching values mean the containers are running your tree. A worker that
disagrees with the other two is the case that is otherwise invisible.

`built` is optional and only appears when the build was told:

```bash
DIST_BUILD_REF=$(git rev-parse --short HEAD) \
DIST_BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) docker compose build
```

### Running against a locally built repository

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

Set `REPO_DIR` to a repository built by `dist-core` (default `../../repo`).
Both mounts are read-only, so the edge behaves exactly as it does in
production.

## Adding a repository, and where it stops

This is the part worth reading before using the UI.

**Registering a source is not the same as trusting it.** Adding a GitHub or
GitLab project records a decision about where candidate installers come from.
It creates nothing in TUF and grants nothing.

### The four fields that are easy to get wrong

Each of these is accepted as typed and fails somewhere else, later, so they are
worth getting right the first time. A worked example, for an application whose
GitHub repository is `ONEoo7/ai_tools_git_assistant`:

| Field | Value | Why not the obvious thing |
|---|---|---|
| Application id | `git-assistant` | **Not the repository name.** It must be the id the *application* asks for — `APP_ID` in its updater configuration. They are often different, and a mismatch is silent: the app requests a channel that does not exist and reports "no updates" indefinitely. It becomes a TUF role name and a path segment, so it cannot be changed afterwards |
| Project path | `ONEoo7/ai_tools_git_assistant` | The path alone, not the URL you copied from the browser. The host is the API base field, and pasting a full URL would otherwise discard the host it carries |
| Installer asset | `git-assistant-{version}-windows-x64.zip` | `{version}` is substituted from the tag. A literal version matches exactly one release and then fails every poll — with nothing to suggest the cause is a field nobody has looked at since registration |
| Release workflow URI | *leave blank* | Derives to `<project>/.github/workflows/release.yml`. Fill it in only if your release workflow is named something else |

Two further notes on that table:

- **Tag prefix** applies to the git *tag*, not the filename. With `v` the tag
  `v1.2.3` yields version `1.2.3`, and that is what `{version}` becomes. An
  asset named without a `v` is correct and expected.
- **The artifact should be an archive, not a setup `.exe`.** The installer
  stages a directory and promotes it to an A/B slot (PLAN.md 6.1); an `.exe`
  that installs itself defeats rollback, and the archive gates that check for
  traversal and decompression bombs have nothing to inspect.

The form suggests corrections for the first two rather than applying them —
these values cannot be edited after registration, so a silent fix would remove
the one moment an operator would notice the stored value is not what they meant.

A source moves through:

```
draft ── validate ──▶ pending_delegation ── signing ceremony ──▶ active
             │                                                     │
             └──▶ invalid                                     poll ─┘
```

`pending_delegation` is where a web form has to stop. Serving an application
requires an `app-<id>` delegation in `targets.json`, `targets` signs with a
2-of-3 offline key (`dist_core.roles.TARGETS_POLICY`), and PLAN.md 8.2 forbids
this web application from mutating TUF metadata at all. So the ceremony happens
on the machine holding `offline.kdbx`, and then:

```bash
uv run python -m dist_registry.delegate <app-id> --repo ./repo
```

That command signs nothing. It reads `targets.json`, refuses unless the
delegation is actually there, and only then lets the worker start polling — so
what activates a source is the published metadata, not an operator's assertion
that the ceremony happened.

One ceremony per **application**, not per release. After it, releases for an
online-key app flow through without a human. An app registered as *critical*
gets offline key custody and every release stops at `HOLD_FOR_CEREMONY`, which
is the point of marking it critical.

## Security properties encoded here

- **Read-only by mount, not by configuration.** The repository volumes are
  mounted `:ro`. Even a full compromise of the edge cannot alter metadata,
  regardless of whether `edge.conf` is correct.
- **The credential and the listener are in different containers.** `admin`
  accepts operator input and has no forge token and no signing key. `worker`
  holds the forge token and publishes no port at all. Adding a web UI did not
  weaken PLAN.md 2's invariant, because the UI enqueues and the worker decides.

  This separation is **capability-shaped, not network-shaped**, and it is worth
  being precise about which. Publishing a port requires a non-internal network,
  and a non-internal network also gives that container ordinary outbound
  access — so `admin` is not egress-isolated and this stack does not claim it
  is. What holds is that `admin` is given no forge token, no signing key, and
  no code path that reaches a forge: `dist_admin` does not import
  `dist_ingest`, and its only way to learn anything about a repository is to
  queue a job.
- **`control` is an internal network.** Postgres has no route off the host and
  publishes no port. The only ways into the stack are the two loopback ports.
- **Bound to loopback by default.** `EDGE_BIND` and `ADMIN_BIND` both default
  to `127.0.0.1`; put a TLS terminator in front rather than exposing either.
- **`timestamp.json` and `root.json` are `no-store`.** Everything else is
  version-numbered or content-addressed and therefore immutable. Caching the
  freshness signal defeats the short expiry in section 3.1 and is
  indistinguishable from a freeze attack.
- **No Docker socket is mounted anywhere.** Socket access is host root, and
  host root is every volume including the keys.
- **The admin UI ships no JavaScript.** CSP is `default-src 'none'` with
  `style-src 'self'`; there is no script to allow. Section 8.3 requires every
  telemetry and forge string to render as untrusted text, and the cheapest way
  to mean that is to have no client-side code at all.
- Containers run unprivileged with read-only root filesystems, all capabilities
  dropped, `no-new-privileges`.

## Egress, which is a decision and not a detail

The `worker` joins a `forge` network with outbound access. For a self-hosted
GitLab that stays inside the perimeter, as PLAN.md 4.1 intends. **Registering a
github.com source puts public internet egress into the publish path**, which
retires the "egress allowlist of one internal host" property that section 4.1
claims. That does not make the design unsound — provenance establishes trust,
not the network — but section 4.2 flags it as something the threat model has to
be updated to say, and this stack is where it becomes real.

The allowlist is still per source and still narrow: `dist_ingest.sources`
derives it from the API base an operator typed, so a database row cannot name a
new destination.

## Why most polls say "unchanged"

A source's job history will mostly read:

```json
{"outcome": "unchanged", "tag": "v0.2.0", "via": "release feed", "consecutive_skips": 3}
```

That is a poll that ran and decided not to call the API. Before spending
quota, the worker reads the project's release feed — `releases.atom`, which is
not part of the REST API and, measured, is not counted against the rate limit.
If the newest tag matches the one the last poll actually ingested, there is
nothing to fetch.

Three things about it are deliberate:

- **The feed is a hint, never an authority.** Nothing is ingested on its say-so.
  When it reports something new, the ordinary poll runs and the release is
  fetched, hashed, checked against its Sigstore attestation and put through the
  gates exactly as before.
- **The comparison is against what was ingested, not against what the feed said
  last time.** A wrong hint then costs one wasted cycle rather than wedging the
  source.
- **It gives up after `MAX_CONSECUTIVE_SKIPS` (about six hours).** A feed that
  has quietly stopped reflecting reality — repository renamed, document stale —
  would otherwise stop a source updating with nothing in the log to say so.

Every uncertain path polls: no previous poll, a feed that errors, a feed for a
repository whose numeric id does not match the one pinned at validation.

This does not replace a token. Unauthenticated GitHub allows 60 requests an
hour per address and a single poll spends two of them, so a burst of real
releases can still exhaust it. Set `FORGE_TOKEN_FILE`; see `.env.example`.

## What a fully configured source still needs

A source can be `active` and still refuse every release, on purpose. Ingestion
runs the content gates after provenance, and `ContentGates` fails closed: with
no malware scanner configured, every artifact is rejected with

```
gate failed: no malware scanner configured
```

That is correct behaviour rather than a misconfiguration of this stack — it is
PLAN.md 4.1's content gate declining to pretend it ran. Wiring a scanner is
outstanding Phase 3 work.

## Verified against live services

Run end to end against the real `ONEoo7/ai_tools_git_assistant` v0.1.0 release,
with no forge token configured:

- source registered through the UI, validated, and left in `pending_delegation`
- activated only after a real `app-git-assistant` delegation was signed
- 40,587,850 bytes downloaded through GitHub's redirect, digest `3fd704e3…`
  matching the offline fixture the ingest suite already carried
- **Sigstore certificate-identity verification passed** against GitHub's live
  attestation: Fulcio chain, Rekor entry, and the pinned issuer, repository id
  `1310933302`, owner id `1506004`, workflow URI and `github-hosted` runner
- rejected at the content gate, as above

Three things this found that the mocked suite could not, all now fixed:

1. GitHub serves release assets from `release-assets.githubusercontent.com`.
   The download allowlist named only `objects.githubusercontent.com`, so every
   real download was refused at the first hop.
2. `policy.ingest` verified every attestation through the fixed-key DSSE path,
   so a GitHub Sigstore bundle could never verify. It failed as
   `unexpected payloadType None`, which reads like a bad attestation rather
   than an unwired branch.
3. `sigstore` needs writable `XDG_CACHE_HOME` **and** `XDG_DATA_HOME` for its
   TUF trust root. With a read-only root filesystem and only one of them it
   reports `failed to refresh TUF metadata` rather than a permission error.

Note the second one in particular: the GitHub certificate-identity path had
unit tests and a real attestation fixture, and was still not reachable from the
function that ingestion actually calls.

## Not yet verified

`edge.conf` was checked with `nginx -t` against
`nginxinc/nginx-unprivileged:1.27-alpine` and passes.

The GitLab release source is implemented against the documented API shapes but
**has not been run against a live GitLab instance**, and PLAN.md 4.1 records a
related open assumption: the exact shape of GitLab's own SLSA provenance has
not been confirmed against a real pipeline. Two of the three bugs above were
exactly this class of "mocked shape differs from live shape", so expect the
GitLab path to need the same treatment before it is trusted.

The failure mode is safe — an attestation whose source cannot be located is
rejected — so this shows up as releases refusing to promote rather than as
unverified artifacts getting through.
