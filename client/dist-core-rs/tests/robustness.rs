//! Mutation harness over the metadata parser (PLAN.md D1 mitigation).
//!
//! Metadata is attacker-reachable input on every client: anything that can
//! answer a request can hand the verifier arbitrary bytes. D1 requires fuzzing
//! this surface. `cargo-fuzz` needs a nightly toolchain, so this is the
//! stable-toolchain equivalent that runs on every CI build — deterministic,
//! seeded mutation rather than coverage-guided search. The two are
//! complementary.
//!
//! Two properties are asserted for every mutant:
//!
//! 1. **No panic.** A panic in the verifier is a denial of service on the
//!    update path, and across the C ABI it would be undefined behaviour.
//! 2. **No acceptance of a semantically changed document.** Silent acceptance
//!    of altered metadata is the worst possible outcome, and is what this file
//!    exists to rule out.
//!
//! Mutants whose parsed JSON is unchanged are skipped. TUF signs *canonical
//! JSON*, not raw bytes, so a mutation confined to insignificant whitespace is
//! a no-op by design and accepting it is correct rather than a defect. The
//! fixtures are pretty-printed, so those mutations do occur.

// Truncation is deliberate here: the generator's output is reduced to an index
// or a byte, and losing the high bits is exactly what is wanted.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dist_core::verifier::{TufVerifier, Verifier};

/// Mutants per file per strategy. Deterministic, so any failure reproduces
/// exactly from the reported seed.
const MUTANTS: u64 = 150;

struct Harness {
    dir: PathBuf,
    now: SystemTime,
    delegated_role: String,
}

impl Harness {
    fn load() -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let meta: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("meta.json")).unwrap()).unwrap();
        Self {
            now: UNIX_EPOCH + Duration::from_secs(meta["generated_at"].as_u64().unwrap()),
            delegated_role: meta["delegated_role"].as_str().unwrap().to_owned(),
            dir,
        }
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.dir.join(name)).unwrap()
    }

    /// Feed the chain in TUF's required order, substituting `mutant` at
    /// `role`, and report whether that step was accepted.
    ///
    /// Earlier steps use the genuine fixtures: a role cannot be verified in
    /// isolation, since snapshot needs a trusted timestamp and so on.
    fn feed(&self, role: &str, mutant: &[u8]) -> bool {
        let Ok(mut verifier) = TufVerifier::bootstrap_at(&self.read("root.json"), self.now) else {
            return false;
        };

        let delegated = self.delegated_role.clone();
        let chain: [&str; 4] = ["timestamp", "snapshot", "targets", &delegated];

        for step in chain {
            let is_target = step == role;
            let raw = if is_target {
                mutant.to_vec()
            } else {
                self.read(&format!("{step}.json"))
            };

            let accepted = match step {
                "timestamp" => verifier.update_timestamp(&raw).is_ok(),
                "snapshot" => verifier.update_snapshot(&raw).is_ok(),
                "targets" => verifier.update_targets(&raw).is_ok(),
                other => verifier.update_delegated_targets(other, &raw).is_ok(),
            };

            if is_target {
                return accepted;
            }
            assert!(accepted, "harness error: genuine {step} was refused");
        }

        unreachable!("role {role} is not part of the chain")
    }
}

/// Deterministic pseudo-random sequence. A named constant beats a `rand`
/// dependency here: every failure reproduces exactly from its seed.
fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state >> 33
}

fn flip(original: &[u8], seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut bytes = original.to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    let index = (next(&mut state) as usize) % bytes.len();
    let delta = (next(&mut state) as u8) | 1; // never a no-op
    bytes[index] ^= delta;
    bytes
}

fn truncate(original: &[u8], seed: u64) -> Vec<u8> {
    let mut state = seed;
    if original.is_empty() {
        return Vec::new();
    }
    original[..(next(&mut state) as usize) % original.len()].to_vec()
}

fn splice(original: &[u8], seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut bytes = original.to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    let index = (next(&mut state) as usize) % bytes.len();
    let byte = next(&mut state) as u8;
    bytes.insert(index, byte);
    bytes
}

/// Whether two byte strings parse to the same JSON document.
fn same_document(a: &[u8], b: &[u8]) -> bool {
    match (
        serde_json::from_slice::<serde_json::Value>(a),
        serde_json::from_slice::<serde_json::Value>(b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn check_role(file: &str, role: &str) {
    let harness = Harness::load();
    let original = harness.read(file);

    // Without this the assertions below could hold vacuously.
    assert!(
        harness.feed(role, &original),
        "{file} was refused unmutated; the harness would prove nothing"
    );

    let mut skipped = 0u32;
    for (name, mutate) in [
        ("flip", flip as fn(&[u8], u64) -> Vec<u8>),
        ("truncate", truncate),
        ("splice", splice),
    ] {
        for seed in 0..MUTANTS {
            let mutant = mutate(&original, seed);
            if same_document(&original, &mutant) {
                skipped += 1;
                continue;
            }
            assert!(
                !harness.feed(role, &mutant),
                "{file}: {name} mutant seed {seed} was ACCEPTED as valid {role} metadata"
            );
        }
    }

    // Guards against the mutators degenerating into no-ops and the test
    // silently checking nothing.
    let total = MUTANTS * 3;
    assert!(
        u64::from(skipped) < total / 2,
        "{file}: {skipped}/{total} mutants were semantically identical"
    );
}

#[test]
fn mutated_timestamp_is_never_accepted() {
    check_role("timestamp.json", "timestamp");
}

#[test]
fn mutated_snapshot_is_never_accepted() {
    check_role("snapshot.json", "snapshot");
}

#[test]
fn mutated_targets_is_never_accepted() {
    check_role("targets.json", "targets");
}

#[test]
fn mutated_delegated_targets_is_never_accepted() {
    let role = Harness::load().delegated_role;
    check_role(&format!("{role}.json"), &role);
}

#[test]
fn mutated_root_never_panics() {
    // Root is the trust anchor the client ships with, so `bootstrap` treats it
    // as already trusted and does not verify it against anything. Acceptance
    // is therefore expected, and only the no-panic property is meaningful. The
    // root's security comes from how it is embedded and distributed.
    let harness = Harness::load();
    let original = harness.read("root.json");

    for seed in 0..MUTANTS {
        for mutate in [flip as fn(&[u8], u64) -> Vec<u8>, truncate, splice] {
            let _ = TufVerifier::bootstrap_at(&mutate(&original, seed), harness.now);
        }
    }
}

#[test]
fn arbitrary_bytes_are_never_accepted() {
    // Input that is not derived from a real file, and mostly not JSON at all.
    let harness = Harness::load();
    let delegated = harness.delegated_role.clone();
    let mut state = 0x5eed_1234_u64;

    for length in [0usize, 1, 2, 7, 64, 512] {
        for _ in 0..50 {
            let raw: Vec<u8> = (0..length).map(|_| next(&mut state) as u8).collect();
            for role in ["timestamp", "snapshot", "targets", delegated.as_str()] {
                assert!(
                    !harness.feed(role, &raw),
                    "random {length}-byte input accepted as {role}"
                );
            }
        }
    }
}
