# Fork patches — `tuf` 0.3.0-beta9

Vendored from crates.io at version `0.3.0-beta9`, unmodified except for the
six changes below. Upstream licences (`LICENSE-MIT`, `LICENSE-APACHE`) are
preserved as published.

Decision D1 in `docs/PLAN.md` selected this crate because it is the only Rust
TUF implementation with delegated-role support, and per-application key
isolation (§3.1) depends on delegations. D1 also required vendoring and
budgeted for upstream defects. These are those defects.

**All six patches make the crate agree with the TUF specification.** None
introduce project-specific behaviour, so all six are upstreamable as-is.

Every patch site is marked `FORK PATCH <n>` in the source. Upstream's own test
suite passes: 189 tests, one of which was updated (patch 3).

Regenerate the interop fixtures with `uv run python scripts/gen_rust_fixtures.py`;
`client/dist-core-rs/tests/interop.rs` is what proves these patches work
against metadata the Python server actually publishes.

---

## Patch 1 — `spec_version` compared by exact string

`src/interchange/cjson/shims.rs`

Upstream compared the whole `spec_version` string against the constant `"1.0"`
and rejected anything else. The TUF specification requires clients to check
that the **major** version is compatible. `python-tuf` emits the precise
specification version, currently `1.0.31`, so no metadata from the reference
implementation could be parsed at all.

Replaced the four inline comparisons with `check_spec_version`, which compares
the major component.

## Patch 2 — glob delegation paths were not implemented

`src/metadata.rs`, `src/client.rs`, `src/interchange/cjson/shims.rs`

The specification matches a delegation PATHPATTERN against a target path
segment by segment, with `*` matching any run of characters inside one segment.
Upstream implemented only directory-prefix matching (`TargetPath::is_child`),
and additionally listed `*` in `PATH_ILLEGAL_STRINGS`, so metadata containing a
pattern such as `app/*/*/*/*` was rejected at parse time.

There is no pattern both implementations accept, and a client-side workaround
is impossible because `paths` is inside the signed payload.

- **2a** — `safe_pattern` / `TargetPath::new_pattern`: same validation as
  `TargetPath::new`, but permits `*` and `?`, because a delegation path is a
  pattern rather than a filename.
- **2b** — `TargetPath::matches_pattern` plus `glob_segment`: specification
  matching, iterative with backtracking so a wildcard-heavy pattern cannot blow
  the stack. Upstream's prefix form is still accepted, so existing metadata
  keeps working.
- **2c** — `src/client.rs` delegation lookup uses `matches_pattern`.
- **2d** — the deserialisation shim reads `paths` as raw strings and builds
  them with `new_pattern`, so patterns survive parsing.

## Patch 3 — delegation role field named `role` instead of `name`

`src/interchange/cjson/shims.rs`, `src/metadata.rs`

The specification names this field `name` in `delegations.roles[]`. Upstream
serialised and expected `role`, so it could not read delegations from any
conforming implementation.

Renamed via `#[serde(rename = "name")]`. Upstream's
`serde_targets_with_delegations_metadata` test asserted the old spelling and
was updated.

## Patch 4 — SECURITY: delegation paths were never enforced

`src/database.rs`

Upstream guarded the delegation path check with `current_depth > 0`, so at the
first delegation level **no path check ran at all**. At greater depths it
checked `parents`, which excludes the current delegation's own paths. The net
effect is that a delegated role's `paths` were never enforced against its own
targets, at any depth.

Any delegated role could therefore sign **any target path**, which removes the
isolation that delegated roles exist to provide. For this project it would have
meant a compromise of one application's signing key could forge releases for
every other application — the exact property §3.1 claims and D1 chose this
crate to obtain.

Fixed by checking `new_parents`, which includes the current delegation's paths,
at every depth.

Found by `delegated_role_cannot_sign_outside_its_path` in
`client/dist-core-rs/tests/interop.rs`. **This should be reported upstream.**

## Patch 5 — no ECDSA support

`src/crypto.rs`

Upstream implemented only ed25519 and RSA-PSS. The TUF conformance suite
generates ECDSA (`ecdsa-sha2-nistp256`) keys, so every one of its tests failed
at root verification with "signature threshold not met: 0/1".

Added `KeyType::Ecdsa` and `SignatureScheme::EcdsaSha2Nistp256`, verified with
`ring`'s `ECDSA_P256_SHA256_ASN1`. Verification only; this crate still cannot
sign with ECDSA, and `as_oid` returns an error for it.

Two details worth keeping in mind when reviewing:

- **The PEM is stored verbatim.** A key ID is the SHA-256 of the canonical JSON
  of the key object, so re-encoding the key would change its ID and every
  signature reference would stop matching. The point is extracted at
  verification time instead.
- **Both OIDs are checked**, `id-ecPublicKey` and `prime256v1`. Accepting the
  point without confirming the curve would let a key on a different curve be
  verified as though it were P-256.

## Patch 6 — canonical JSON escaped too much

`src/interchange/cjson/mod.rs`, `src/verify.rs`

Canonical JSON escapes exactly two characters, `"` and `\`. Every other
character, control characters such as newline included, is emitted literally.
Upstream delegated string encoding to `serde_json`, which escapes far more —
its own comment called this "abusing serde_json to get json escaping".

Canonical JSON is the input to both key-ID computation and signature
verification, so **for any metadata containing a control character inside a
string the crate computed the wrong key ID and could not verify the
signature.** In practice that means any repository whose keys are PEM-encoded,
since PEM contains newlines. Both `python-tuf` and `go-tuf` produce such
repositories.

This is why patch 5 alone did not help: ECDSA keys arrive as PEM, so the key
IDs still disagreed and every key was silently dropped by the filter in
`shims.rs` that discards keys whose ID does not match.

A second change follows from the first. `verify_signatures` re-parsed
`canonical_bytes` after verifying them, deliberately, so that only signed data
is interpreted. A strict JSON parser rejects literal control characters, so
that re-parse could no longer succeed. It now deserializes from the parsed
value the canonical bytes were produced from. **The security property is
unchanged**: canonicalization is a pure function of that value, so this is
exactly the data whose canonical form was verified, and no unsigned bytes from
the raw document can leak in.

Upstream's `write_obj` test asserted the escaped output and was updated.

### Effect

Conformance suite results moved from 90 failed / 22 passed to **43 failed /
69 passed**. Our own suites were unaffected in both directions, because our
metadata uses ed25519 keys in hex and contains no control characters.
