//! Exercises the C ABI the way a foreign caller does: raw pointers, including
//! the misuse cases.
//!
//! The happy path is covered more thoroughly by the Rust interop suite. What
//! this file is for is the boundary itself — null handling, string validation
//! and buffer limits — because that is where FFI defects live, and a defect
//! here is reachable from every one of the five language bindings.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::ffi::{CStr, CString, c_char};
use std::fs;
use std::path::PathBuf;
use std::ptr;

use dist_core_ffi::{
    DistStatus, DistTargetInfo, DistVerifier, dist_core_version, dist_in_rollout,
    dist_verifier_free, dist_verifier_new_at, dist_verifier_target,
    dist_verifier_update_delegated_targets, dist_verifier_update_snapshot,
    dist_verifier_update_targets, dist_verifier_update_timestamp, dist_verify_payload,
};

struct Fixtures {
    dir: PathBuf,
    generated_at: u64,
    delegated_role: String,
    target_path: String,
    forged_target_path: String,
}

impl Fixtures {
    fn load() -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist-core-rs/tests/fixtures");
        let meta: serde_json::Value = serde_json::from_slice(
            &fs::read(dir.join("meta.json"))
                .expect("fixtures missing; run scripts/gen_rust_fixtures.py"),
        )
        .unwrap();
        Self {
            generated_at: meta["generated_at"].as_u64().unwrap(),
            delegated_role: meta["delegated_role"].as_str().unwrap().to_owned(),
            target_path: meta["target_path"].as_str().unwrap().to_owned(),
            forged_target_path: meta["forged_target_path"].as_str().unwrap().to_owned(),
            dir,
        }
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.dir.join(name)).unwrap()
    }

    /// A handle that has consumed the full metadata chain.
    fn verifier(&self) -> *mut DistVerifier {
        let root = self.read("root.json");
        let mut status = DistStatus::Panic;
        let handle = unsafe {
            dist_verifier_new_at(
                root.as_ptr(),
                root.len(),
                self.generated_at,
                &raw mut status,
            )
        };
        assert_eq!(status, DistStatus::Ok);
        assert!(!handle.is_null());

        for (name, update) in [
            ("timestamp.json", dist_verifier_update_timestamp as UpdateFn),
            ("snapshot.json", dist_verifier_update_snapshot),
            ("targets.json", dist_verifier_update_targets),
        ] {
            let raw = self.read(name);
            assert_eq!(
                unsafe { update(handle, raw.as_ptr(), raw.len()) },
                DistStatus::Ok,
                "{name} was refused"
            );
        }

        let role = CString::new(self.delegated_role.clone()).unwrap();
        let raw = self.read(&format!("{}.json", self.delegated_role));
        assert_eq!(
            unsafe {
                dist_verifier_update_delegated_targets(
                    handle,
                    role.as_ptr(),
                    raw.as_ptr(),
                    raw.len(),
                )
            },
            DistStatus::Ok
        );

        handle
    }
}

fn resolve(handle: *mut DistVerifier, path: &str) -> (DistStatus, DistTargetInfo) {
    let c_path = CString::new(path).unwrap();
    let mut info = ZEROED;
    let status = unsafe { dist_verifier_target(handle, c_path.as_ptr(), &raw mut info) };
    (status, info)
}

type UpdateFn = unsafe extern "C" fn(*mut DistVerifier, *const u8, usize) -> DistStatus;

const ZEROED: DistTargetInfo = DistTargetInfo {
    length: 0,
    sha256: [0; 32],
    rollout_pct: 0,
    mandatory: 0,
    version: [0; 64],
};

#[test]
fn full_chain_resolves_and_verifies_a_payload() {
    let fixtures = Fixtures::load();
    let handle = fixtures.verifier();

    let (status, info) = resolve(handle, &fixtures.target_path);
    assert_eq!(status, DistStatus::Ok);
    assert_eq!(info.rollout_pct, 25);
    assert_eq!(info.mandatory, 0);

    let version = CStr::from_bytes_until_nul(&info.version).unwrap();
    assert_eq!(version.to_str().unwrap(), "1.4.2");

    let payload = fixtures.read("payload.bin");
    assert_eq!(
        unsafe { dist_verify_payload(&raw const info, payload.as_ptr(), payload.len()) },
        DistStatus::Ok
    );

    unsafe { dist_verifier_free(handle) };
}

#[test]
fn tampered_payload_is_rejected_through_the_abi() {
    let fixtures = Fixtures::load();
    let handle = fixtures.verifier();
    let (_, info) = resolve(handle, &fixtures.target_path);

    let mut payload = fixtures.read("payload.bin");
    payload[0] ^= 0xff;
    assert_eq!(
        unsafe { dist_verify_payload(&raw const info, payload.as_ptr(), payload.len()) },
        DistStatus::Digest
    );

    let truncated = &payload[..payload.len() - 1];
    assert_eq!(
        unsafe { dist_verify_payload(&raw const info, truncated.as_ptr(), truncated.len()) },
        DistStatus::Length
    );

    unsafe { dist_verifier_free(handle) };
}

#[test]
fn delegation_isolation_holds_through_the_abi() {
    // The security property from PLAN.md 3.1, checked at the boundary the
    // bindings actually use rather than only in Rust.
    let fixtures = Fixtures::load();
    let handle = fixtures.verifier();

    let (status, _) = resolve(handle, &fixtures.forged_target_path);
    assert_eq!(status, DistStatus::UnknownTarget);

    unsafe { dist_verifier_free(handle) };
}

#[test]
fn target_paths_are_validated_before_use() {
    // Traversal that satisfies the delegation segment count must not reach the
    // verifier, let alone a filesystem.
    let fixtures = Fixtures::load();
    let handle = fixtures.verifier();

    for path in ["editor/../../etc/passwd", "editor/stable", ""] {
        let (status, _) = resolve(handle, path);
        assert_eq!(status, DistStatus::InvalidArgument, "accepted {path:?}");
    }

    unsafe { dist_verifier_free(handle) };
}

#[test]
fn null_arguments_are_rejected_rather_than_dereferenced() {
    let mut status = DistStatus::Panic;
    let handle = unsafe { dist_verifier_new_at(ptr::null(), 0, 0, &raw mut status) };
    assert!(handle.is_null());
    assert_eq!(status, DistStatus::NullArgument);

    assert_eq!(
        unsafe { dist_verifier_update_timestamp(ptr::null_mut(), ptr::null(), 0) },
        DistStatus::NullArgument
    );
    assert_eq!(
        unsafe { dist_verify_payload(ptr::null(), ptr::null(), 0) },
        DistStatus::NullArgument
    );

    let mut out = 0u8;
    assert_eq!(
        unsafe { dist_in_rollout(ptr::null(), ptr::null(), 50, &raw mut out) },
        DistStatus::InvalidArgument
    );

    // A null status pointer must not be written through.
    let handle = unsafe { dist_verifier_new_at(ptr::null(), 0, 0, ptr::null_mut()) };
    assert!(handle.is_null());
}

#[test]
fn freeing_null_is_a_no_op() {
    unsafe { dist_verifier_free(ptr::null_mut()) };
}

#[test]
fn invalid_utf8_strings_are_rejected() {
    let fixtures = Fixtures::load();
    let handle = fixtures.verifier();

    let invalid: [c_char; 3] = [-1, -2, 0];
    let mut info = ZEROED;
    assert_eq!(
        unsafe { dist_verifier_target(handle, invalid.as_ptr(), &raw mut info) },
        DistStatus::InvalidArgument
    );

    unsafe { dist_verifier_free(handle) };
}

#[test]
fn rollout_matches_the_python_vectors_through_the_abi() {
    let app = CString::new("editor").unwrap();
    let expected = [false, false, true, false, false, false, true, false];

    for (n, want) in expected.iter().enumerate() {
        let install = CString::new(format!("install-{n}")).unwrap();
        let mut out = 0u8;
        assert_eq!(
            unsafe { dist_in_rollout(install.as_ptr(), app.as_ptr(), 50, &raw mut out) },
            DistStatus::Ok
        );
        assert_eq!(out == 1, *want, "install-{n}");
    }
}

#[test]
fn out_of_range_rollout_is_rejected() {
    let app = CString::new("editor").unwrap();
    let install = CString::new("install-0").unwrap();
    let mut out = 0u8;
    assert_eq!(
        unsafe { dist_in_rollout(install.as_ptr(), app.as_ptr(), 101, &raw mut out) },
        DistStatus::InvalidArgument
    );
}

#[test]
fn target_info_layout_is_pinned_to_the_c_header() {
    // include/dist_core.h declares this struct field for field, by hand. If
    // the Rust layout shifts without the header following, every binding reads
    // misaligned memory and the failure is silent. Pin it here so the drift is
    // a test failure instead.
    use std::mem::{align_of, offset_of, size_of};

    assert_eq!(size_of::<DistTargetInfo>(), 112);
    assert_eq!(align_of::<DistTargetInfo>(), 8);
    assert_eq!(offset_of!(DistTargetInfo, length), 0);
    assert_eq!(offset_of!(DistTargetInfo, sha256), 8);
    assert_eq!(offset_of!(DistTargetInfo, rollout_pct), 40);
    assert_eq!(offset_of!(DistTargetInfo, mandatory), 44);
    assert_eq!(offset_of!(DistTargetInfo, version), 45);

    // The C enum must stay int-sized.
    assert_eq!(size_of::<DistStatus>(), 4);
}

#[test]
fn version_is_a_nul_terminated_string() {
    let version = unsafe { CStr::from_ptr(dist_core_version()) };
    assert_eq!(version.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
}
