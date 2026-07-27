//! Cross-implementation test: the Rust verifier against real server output.
//!
//! Fixtures are produced by `scripts/gen_rust_fixtures.py` from the Python
//! `dist-core` repository, so this exercises bytes the server actually
//! publishes rather than hand-written metadata that merely resembles them. A
//! divergence between the two implementations shows up here and nowhere else.
//!
//! Metadata expires, so the clock is pinned to the fixtures' generation time.

// The crate's panic-denying lints exist to protect the verifier at runtime.
// Test code is allowed to panic on a bad fixture -- that is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dist_core::verifier::{Role, TufVerifier, Verifier, VerifyError, verify_payload};
use dist_core::{TargetInfo, TargetPath};

struct Fixtures {
    dir: PathBuf,
    generated_at: SystemTime,
    delegated_role: String,
    target_path: String,
    forged_target_path: String,
    rollout_pct: u32,
    payload_length: u64,
    pointer_path: String,
    published_versions: serde_json::Value,
}

impl Fixtures {
    fn load() -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let meta: serde_json::Value = serde_json::from_slice(
            &fs::read(dir.join("meta.json"))
                .expect("fixtures missing; run scripts/gen_rust_fixtures.py"),
        )
        .unwrap();

        let secs = meta["generated_at"].as_u64().unwrap();
        Self {
            generated_at: UNIX_EPOCH + Duration::from_secs(secs),
            delegated_role: meta["delegated_role"].as_str().unwrap().to_owned(),
            target_path: meta["target_path"].as_str().unwrap().to_owned(),
            forged_target_path: meta["forged_target_path"].as_str().unwrap().to_owned(),
            rollout_pct: u32::try_from(meta["rollout_pct"].as_u64().unwrap()).unwrap(),
            payload_length: meta["payload_length"].as_u64().unwrap(),
            pointer_path: meta["pointer_path"].as_str().unwrap().to_owned(),
            published_versions: meta["published_versions"].clone(),
            dir,
        }
    }

    /// The version the Python server actually assigned to a role.
    fn published_version(&self, role: &str) -> u32 {
        u32::try_from(self.published_versions[role].as_u64().unwrap()).unwrap()
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.dir.join(name)).unwrap()
    }

    /// A verifier that has consumed the full metadata chain.
    fn verified(&self) -> TufVerifier {
        let mut verifier =
            TufVerifier::bootstrap_at(&self.read("root.json"), self.generated_at).unwrap();
        verifier
            .update_timestamp(&self.read("timestamp.json"))
            .unwrap();
        verifier
            .update_snapshot(&self.read("snapshot.json"))
            .unwrap();
        verifier.update_targets(&self.read("targets.json")).unwrap();
        verifier
            .update_delegated_targets(
                &self.delegated_role,
                &self.read(&format!("{}.json", self.delegated_role)),
            )
            .unwrap();
        verifier
    }

    fn target(&self) -> (TufVerifier, TargetInfo) {
        let verifier = self.verified();
        let path = TargetPath::parse(&self.target_path).unwrap();
        let info = verifier.target(&path).unwrap();
        (verifier, info)
    }
}

#[test]
fn accepts_the_full_metadata_chain_from_the_python_server() {
    let fixtures = Fixtures::load();
    let _ = fixtures.verified();
}

// -------------------------------------------- consistent-snapshot fetch order
//
// A repository with consistent snapshots serves `<version>.<role>.json`, so a
// client must know a role's version before it can fetch it, and it learns that
// from the role above. These assert the numbers reported match what the Python
// server actually published -- reporting *a* number is not the contract.

#[test]
fn reports_the_snapshot_version_the_server_published() {
    let fixtures = Fixtures::load();
    let mut verifier =
        TufVerifier::bootstrap_at(&fixtures.read("root.json"), fixtures.generated_at).unwrap();

    // Nothing to report before a timestamp has been accepted. Guessing a
    // version here, or defaulting to 1, would send the client to a stale file.
    assert_eq!(verifier.snapshot_version(), None);

    verifier
        .update_timestamp(&fixtures.read("timestamp.json"))
        .unwrap();
    assert_eq!(
        verifier.snapshot_version(),
        Some(fixtures.published_version("snapshot"))
    );
}

#[test]
fn reports_the_targets_versions_the_server_published() {
    let fixtures = Fixtures::load();
    let mut verifier =
        TufVerifier::bootstrap_at(&fixtures.read("root.json"), fixtures.generated_at).unwrap();
    verifier
        .update_timestamp(&fixtures.read("timestamp.json"))
        .unwrap();

    // Snapshot is what names the targets versions, so before it is accepted
    // there is nothing to report.
    assert_eq!(verifier.targets_version("targets"), None);

    verifier
        .update_snapshot(&fixtures.read("snapshot.json"))
        .unwrap();

    assert_eq!(
        verifier.targets_version("targets"),
        Some(fixtures.published_version("targets"))
    );
    assert_eq!(
        verifier.targets_version(&fixtures.delegated_role),
        Some(fixtures.published_version(&fixtures.delegated_role))
    );
}

#[test]
fn reports_nothing_for_a_role_the_snapshot_does_not_describe() {
    let fixtures = Fixtures::load();
    let verifier = fixtures.verified();

    assert_eq!(verifier.targets_version("app-nonexistent"), None);
    assert_eq!(verifier.targets_version(""), None);
}

#[test]
fn the_reported_versions_differ_from_each_other() {
    // Guard against an accessor that returns the same number for everything,
    // which would pass the assertions above only because the fixture happened
    // to publish matching versions.
    let fixtures = Fixtures::load();
    assert_ne!(
        fixtures.published_version("snapshot"),
        fixtures.published_version("targets"),
        "fixture no longer distinguishes the roles; regenerate it"
    );

    let verifier = fixtures.verified();
    assert_ne!(
        verifier.snapshot_version(),
        verifier.targets_version("targets")
    );
}

#[test]
fn resolves_the_channel_pointer() {
    // The pointer is what lets a client discover a version it does not know
    // (PLAN.md 5.7). It must resolve like any other target.
    let fixtures = Fixtures::load();
    let verifier = fixtures.verified();
    let path = TargetPath::parse(&fixtures.pointer_path).unwrap();

    let info = verifier.target(&path).expect("pointer must resolve");
    assert_eq!(info.release.version, "1.4.2");
    assert_eq!(
        info.release.rollout_pct, 100,
        "the pointer must be readable by every install"
    );
}

#[test]
fn resolves_the_published_target() {
    let fixtures = Fixtures::load();
    let (_verifier, info) = fixtures.target();
    assert_eq!(info.length, fixtures.payload_length);
    assert_eq!(info.release.version, "1.4.2");
}

#[test]
fn signed_rollout_percentage_survives_the_round_trip() {
    // Rollout must arrive from signed metadata, or staged rollout is forgeable
    // by anyone who can answer a request (PLAN.md 3.5).
    let fixtures = Fixtures::load();
    let (_verifier, info) = fixtures.target();
    assert_eq!(info.release.rollout_pct, fixtures.rollout_pct);
    assert!(!info.release.mandatory);
}

#[test]
fn accepts_the_genuine_payload() {
    let fixtures = Fixtures::load();
    let (_verifier, info) = fixtures.target();
    assert_eq!(verify_payload(&info, &fixtures.read("payload.bin")), Ok(()));
}

#[test]
fn rejects_a_tampered_payload() {
    // The malicious-mirror case: TLS has failed or the edge is hostile, and
    // the hash check is what remains.
    let fixtures = Fixtures::load();
    let (_verifier, info) = fixtures.target();

    let mut tampered = fixtures.read("payload.bin");
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;

    assert_eq!(verify_payload(&info, &tampered), Err(VerifyError::Digest));
}

#[test]
fn rejects_a_truncated_payload() {
    let fixtures = Fixtures::load();
    let (_verifier, info) = fixtures.target();

    let mut truncated = fixtures.read("payload.bin");
    truncated.pop();

    assert!(matches!(
        verify_payload(&info, &truncated),
        Err(VerifyError::Length { .. })
    ));
}

#[test]
fn rejects_metadata_signed_by_an_untrusted_key() {
    // Root delegates to specific keys; a valid signature from any other key
    // carries no authority.
    let fixtures = Fixtures::load();
    let mut verifier =
        TufVerifier::bootstrap_at(&fixtures.read("root.json"), fixtures.generated_at).unwrap();

    // The delegated role's metadata is validly signed, but not by a timestamp key.
    let wrong_role = fixtures.read(&format!("{}.json", fixtures.delegated_role));

    assert!(matches!(
        verifier.update_timestamp(&wrong_role),
        Err(VerifyError::Rejected {
            role: Role::Timestamp,
            ..
        })
    ));
}

#[test]
fn rejects_expired_metadata() {
    // The freeze case. Timestamp expires after one day (PLAN.md 3.1), so a
    // clock well past generation must refuse it even though it is validly
    // signed.
    let fixtures = Fixtures::load();
    let much_later = fixtures.generated_at + Duration::from_secs(60 * 60 * 24 * 30);

    let mut verifier = TufVerifier::bootstrap_at(&fixtures.read("root.json"), much_later).unwrap();

    assert!(matches!(
        verifier.update_timestamp(&fixtures.read("timestamp.json")),
        Err(VerifyError::Rejected {
            role: Role::Timestamp,
            ..
        })
    ));
}

#[test]
fn delegated_role_cannot_sign_outside_its_path() {
    // Delegation escalation. The fixture's editor role legitimately signs a
    // target belonging to `viewer`, simulating a compromise of one
    // application's key. The delegation only covers `editor/...`, so a
    // conforming client must refuse to resolve it.
    //
    // This is the property that makes one compromised application key a
    // contained incident rather than a fleet-wide one (PLAN.md 3.1), and it is
    // the reason D1 chose a crate with delegation support at all. The matching
    // it depends on is FORK PATCH 2b.
    let fixtures = Fixtures::load();
    let verifier = fixtures.verified();

    let forged = TargetPath::parse(&fixtures.forged_target_path).unwrap();
    assert_eq!(verifier.target(&forged), Err(VerifyError::UnknownTarget));
}

#[test]
fn unknown_targets_are_not_resolved() {
    let fixtures = Fixtures::load();
    let verifier = fixtures.verified();
    let absent = TargetPath::parse("editor/stable/windows-amd64/9.9.9/Nope.zip").unwrap();
    assert_eq!(verifier.target(&absent), Err(VerifyError::UnknownTarget));
}
