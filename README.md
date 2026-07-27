# dev_tools_distribution_platform

A self-hosted service that distributes signed application updates to installed
desktop applications, and the client-side updater those applications embed.
Integrity and authenticity are enforced with
[The Update Framework](https://theupdateframework.io).

The flow it implements:

1. An application asks the service whether a newer version of itself exists.
2. If one does, it shows a small in-app notification.
3. The user decides whether to install.
4. On consent the updater downloads and verifies the new version, closes the
   running application, installs, and relaunches it.

No package manager is involved at any point. Applications are distributed as
their own artifacts, not as `pip` or `npm` packages.

> **Status: not production ready.** The trust core is built and tested; the
> installer's last mile and the telemetry and admin planes are not. See
> [Status](#status).

## Why it is shaped this way

**A forge is a source of candidates, never an authority to sign.** If the
service signed whatever appeared in a GitHub or GitLab release, anyone able to
create a release — a leaked token, a compromised account, the forge itself —
could have arbitrary code signed and delivered to every user. Everything pulled
from a forge lands in quarantine and is promoted only against a verified SLSA
provenance attestation.

**Verification happens once, in Rust, behind a C ABI.** Five language bindings
would otherwise mean five security-critical verifiers of uneven maturity. A
binding marshals arguments; it cannot weaken a signature check.

**The keys that matter are never on the service host.** `root` (3-of-5) and
`targets` (2-of-3) live in an offline KeePass database. Compromising the running
service yields `snapshot`, `timestamp` and per-application keys — enough to
disrupt, not enough to forge a release for an application whose delegated key is
held offline.

**Staged rollout is decided by the client.** The percentage is signed metadata
and the client evaluates it locally, so there is no per-client server response
for a network attacker to forge in order to push a release at someone early.

## Layout

| Path | What it is |
|---|---|
| `packages/dist-core` | TUF metadata core: roles, signing backends, repository |
| `packages/dist-ingest` | Forge ingestion: provenance, quarantine, gates, promotion |
| `bindings/python` | `dist_client` — ctypes binding, ships the verifier in its wheel |
| `client/dist-core-rs` | The verifier, installer and privileged broker |
| `client/dist-core-ffi` | C ABI over the verifier, for all bindings |
| `client/dist-conformance` | Client-under-test CLI for the TUF conformance suite |
| `client/vendor/tuf` | Vendored fork of the `tuf` crate — see below |
| `deploy/compose` | Read-only nginx edge and the Compose stack |
| `scripts/ceremony.py` | Key ceremony: creates the keystores and a repository |
| `docs/PLAN.md` | The design. Authoritative; this README summarises it |

## Getting started

```bash
uv sync --all-packages
```

```bash
cd client && cargo build -p dist-core-ffi --release && cd ..
```

```bash
uv run pytest
```

The Rust build is not optional for the test suite: the binding tests exercise
the real C ABI, and without the library they skip — which reads exactly like
passing.

Create a development keyset and an initialised repository:

```bash
uv run python scripts/ceremony.py --dev --out ./repo
```

For a real one, `ENV=production` requires a composite master key with the key
file on separate media, and refuses to proceed otherwise:

```bash
ENV=production uv run python scripts/ceremony.py --out /mnt/offline/repo --offline-db /mnt/offline/offline.kdbx --offline-keyfile /mnt/token/offline.key --online-db /srv/keys/online.kdbx --online-keyfile /mnt/token/online.key
```

The script cannot enforce the part that matters most — splitting custody so no
single person or machine ever holds a threshold of root keys. Read its docstring
before running it for real.

## Embedding the updater in an application

Install the binding; the wheel carries the compiled verifier, so there is no
native library to locate and bundle separately.

```bash
uv pip install dist_client-0.1.0-py3-none-win_amd64.whl
```

```python
from dist_client.update import Channel, UpdateCheck

available = UpdateCheck(
    root=embedded_root_bytes,          # shipped in the build, never fetched
    channel=Channel("my-app", "stable", "windows", "amd64"),
    fetch=my_http_get,                 # your existing HTTP client
    install_id=stable_local_id,        # never transmitted; rollout is local
).run()
```

The root is embedded rather than fetched: fetching it would open a
trust-on-first-use window in which a network attacker could supply a root of
their own.

Wheels are published per platform by
[`release-dist-client.yml`](.github/workflows/release-dist-client.yml), each
carrying SLSA provenance:

```bash
gh attestation verify <wheel> --repo ONEoo7/dev_tools_distribution_platform
```

## Status

| Phase | State |
|---|---|
| 0. Foundations | Workspace, lint and type gates, CI, key ceremony. Threat model still outstanding |
| 1. Metadata core | Complete — a spec-valid repository builds offline and verifies against a real TUF client |
| 2. Serve + verify | Complete — rollback, freeze, mix-and-match and malicious-mirror attacks all provably fail |
| 3. Forge ingestion | Security core complete, verified against a real GitHub attestation. GitLab release source outstanding |
| 4. Windows per-user | A/B slots and auto-rollback complete. **Launcher shim not built** |
| 5. Windows system-wide | Broker and LPE suite complete for §6.4 rules 1–5. **Rules 6–9 need a SYSTEM host** |
| 6. Bindings | Python check path complete. JavaScript, C#, C/C++ not started |
| 7+ | Telemetry, admin, failure clustering, crash correlation — not started |

171 Python tests and 76 Rust tests, with `ruff`, `mypy --strict`, `rustfmt` and
`clippy -D warnings` enforced in CI.

**What this means in practice:** the platform can publish a signed release, and
an application can find, verify and download it. It cannot yet close itself,
install the update and relaunch — that needs the launcher shim.

`docs/PLAN.md` §0 carries the detailed status and is kept current.

## The vendored `tuf` fork

`client/vendor/tuf` is a fork of `tuf` 0.3.0-beta9 carrying six patches, all
marked `FORK PATCH <n>` and documented in
[`PATCHES.md`](client/vendor/tuf/PATCHES.md). Three are spec-conformance fixes
without which the crate cannot parse metadata that `python-tuf` produces. One is
a security fix:

> **Patch 4 — delegation paths were never enforced.** A delegated role could
> describe targets outside the paths delegated to it, defeating the
> per-application isolation the delegation exists to provide.

Patches 4 and 6 should be reported upstream.

The TUF conformance suite runs in CI and is currently non-gating: the remaining
failures are untriaged, and reporting a real number is more useful than a green
tick that means nothing. See PLAN.md §11.2.

## Security

Report vulnerabilities privately rather than in a public issue.

Nothing in this system writes to a forge. The ingestion credential is read-only,
and telemetry — the one component anonymous clients can write to — holds no
credentials at all.

Key material never enters this repository: `*.kdbx`, `*.key`, `keys/` and the
repository output directories are excluded, and the exclusions are deliberate
enough to be worth reading before adding a path.

## Licence

See [LICENSE](LICENSE).
