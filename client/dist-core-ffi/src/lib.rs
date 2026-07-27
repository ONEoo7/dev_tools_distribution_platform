//! C ABI over the shared TUF verifier.
//!
//! This is the boundary the JavaScript, Python, C# and C/C++ bindings call
//! through (PLAN.md decision D2). It is a separate crate from `dist-core` so
//! the verifier itself keeps `#![forbid(unsafe_code)]`: all the unsafe code in
//! the client lives here, in one small auditable file, and none of it makes
//! security decisions.
//!
//! # Rules this file follows
//!
//! * **Nothing unwinds across the boundary.** Every entry point is wrapped in
//!   `catch_unwind`; unwinding into a foreign frame is undefined behaviour.
//! * **Every pointer is checked before use**, including for zero-length
//!   slices, since `slice::from_raw_parts` is undefined behaviour on a null
//!   pointer even when the length is zero.
//! * **No allocation crosses the boundary.** Results are written into
//!   caller-owned storage, so there is no matching free function to get wrong
//!   and no allocator mismatch between languages.
//!
//! # Thread safety
//!
//! A [`DistVerifier`] handle must not be used from two threads at once. It is
//! a plain mutable object; callers that share one must serialise access.

use std::ffi::{CStr, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::time::{Duration, UNIX_EPOCH};

use dist_core::rollout::in_rollout;
use dist_core::verifier::{TufVerifier, Verifier, VerifyError};
use dist_core::{TargetInfo, TargetPath, verify_payload};

/// Result of every entry point.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistStatus {
    /// Operation succeeded.
    Ok = 0,
    /// A required pointer argument was null.
    NullArgument = 1,
    /// Metadata was refused: bad signature, threshold, rollback or expiry.
    Rejected = 2,
    /// No trusted metadata describes the requested target.
    UnknownTarget = 3,
    /// Metadata verified but did not carry what the client needs.
    Malformed = 4,
    /// Payload length did not match the signed description.
    Length = 5,
    /// Payload digest did not match the signed description.
    Digest = 6,
    /// The system clock is before the Unix epoch.
    Clock = 7,
    /// A string argument was not valid UTF-8, or a target path was unsafe.
    InvalidArgument = 8,
    /// A value did not fit its fixed-size field.
    Overflow = 9,
    /// A panic was caught at the boundary. Treat the handle as unusable.
    Panic = 10,
}

impl From<VerifyError> for DistStatus {
    fn from(error: VerifyError) -> Self {
        match error {
            VerifyError::Rejected { .. } => Self::Rejected,
            VerifyError::UnknownTarget => Self::UnknownTarget,
            VerifyError::Malformed(_) => Self::Malformed,
            VerifyError::Length { .. } => Self::Length,
            VerifyError::Digest => Self::Digest,
            VerifyError::Clock => Self::Clock,
        }
    }
}

/// Longest release version string the ABI carries.
pub const DIST_VERSION_CAPACITY: usize = 64;

/// A verified target description.
///
/// Fixed-size by design: the caller owns the storage, so nothing has to be
/// freed across the boundary.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DistTargetInfo {
    /// Signed payload length in bytes.
    pub length: u64,
    /// Signed SHA-256 digest.
    pub sha256: [u8; 32],
    /// Signed staged-rollout percentage, 0..=100.
    pub rollout_pct: u32,
    /// Non-zero if the release is flagged security-critical.
    pub mandatory: u8,
    /// NUL-padded release version.
    pub version: [u8; DIST_VERSION_CAPACITY],
}

impl DistTargetInfo {
    fn zeroed() -> Self {
        Self {
            length: 0,
            sha256: [0; 32],
            rollout_pct: 0,
            mandatory: 0,
            version: [0; DIST_VERSION_CAPACITY],
        }
    }

    fn fill_from(&mut self, info: &TargetInfo) -> Result<(), DistStatus> {
        let version = info.release.version.as_bytes();
        // Leave room for the terminating NUL so C callers can treat it as a
        // string without copying.
        let room = self.version.len().saturating_sub(1);
        let slot = self
            .version
            .get_mut(..version.len())
            .ok_or(DistStatus::Overflow)?;
        if version.len() > room {
            return Err(DistStatus::Overflow);
        }
        slot.copy_from_slice(version);

        self.length = info.length;
        self.sha256 = info.sha256;
        self.rollout_pct = info.release.rollout_pct;
        self.mandatory = u8::from(info.release.mandatory);
        Ok(())
    }

    fn to_target_info(self) -> TargetInfo {
        TargetInfo {
            length: self.length,
            sha256: self.sha256,
            // Only length and digest take part in payload verification; the
            // release fields are informational and are not reconstructed.
            release: dist_core::ReleaseInfo {
                version: String::new(),
                rollout_pct: self.rollout_pct,
                mandatory: self.mandatory != 0,
                notes_url: None,
                min_os: None,
                min_from_version: None,
            },
        }
    }
}

/// Opaque verifier handle.
pub struct DistVerifier {
    inner: TufVerifier,
}

/// Run `body` with unwinding contained at the boundary.
fn guard<F: FnOnce() -> DistStatus>(body: F) -> DistStatus {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(DistStatus::Panic)
}

/// Borrow a caller-provided byte slice.
///
/// # Safety
/// `ptr` must be null, or valid for `len` bytes.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // Safe by the contract above; the null case has already returned.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Borrow a caller-provided C string as UTF-8.
///
/// # Safety
/// `ptr` must be null, or a valid NUL-terminated string.
unsafe fn utf8<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Create a verifier from a trusted root shipped with the application.
///
/// Returns null on failure and writes the reason to `status` when it is
/// non-null. Free the result with [`dist_verifier_free`].
///
/// # Safety
/// `root` must be valid for `root_len` bytes. `status` must be null or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_verifier_new(
    root: *const u8,
    root_len: usize,
    status: *mut DistStatus,
) -> *mut DistVerifier {
    let mut result = std::ptr::null_mut();

    let code = guard(|| {
        let Some(root) = (unsafe { bytes(root, root_len) }) else {
            return DistStatus::NullArgument;
        };
        match TufVerifier::bootstrap(root) {
            Ok(inner) => {
                result = Box::into_raw(Box::new(DistVerifier { inner }));
                DistStatus::Ok
            }
            Err(e) => e.into(),
        }
    });

    if !status.is_null() {
        unsafe { *status = code };
    }
    result
}

/// Create a verifier with a fixed notion of "now", in seconds since the Unix
/// epoch. For tests and for callers with a trusted external clock.
///
/// # Safety
/// As [`dist_verifier_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_verifier_new_at(
    root: *const u8,
    root_len: usize,
    unix_seconds: u64,
    status: *mut DistStatus,
) -> *mut DistVerifier {
    let mut result = std::ptr::null_mut();

    let code = guard(|| {
        let Some(root) = (unsafe { bytes(root, root_len) }) else {
            return DistStatus::NullArgument;
        };
        let now = UNIX_EPOCH + Duration::from_secs(unix_seconds);
        match TufVerifier::bootstrap_at(root, now) {
            Ok(inner) => {
                result = Box::into_raw(Box::new(DistVerifier { inner }));
                DistStatus::Ok
            }
            Err(e) => e.into(),
        }
    });

    if !status.is_null() {
        unsafe { *status = code };
    }
    result
}

/// Release a verifier. Null is accepted and ignored.
///
/// # Safety
/// `handle` must be null, or a pointer returned by `dist_verifier_new*` that
/// has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_verifier_free(handle: *mut DistVerifier) {
    if handle.is_null() {
        return;
    }
    let _ = guard(|| {
        drop(unsafe { Box::from_raw(handle) });
        DistStatus::Ok
    });
}

macro_rules! update_fn {
    ($name:ident, $method:ident, $doc:literal) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// `handle` must be a live verifier and `raw` valid for `raw_len` bytes.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            handle: *mut DistVerifier,
            raw: *const u8,
            raw_len: usize,
        ) -> DistStatus {
            guard(|| {
                if handle.is_null() {
                    return DistStatus::NullArgument;
                }
                let Some(raw) = (unsafe { bytes(raw, raw_len) }) else {
                    return DistStatus::NullArgument;
                };
                let verifier = unsafe { &mut *handle };
                match verifier.inner.$method(raw) {
                    Ok(()) => DistStatus::Ok,
                    Err(e) => e.into(),
                }
            })
        }
    };
}

update_fn!(
    dist_verifier_update_timestamp,
    update_timestamp,
    "Accept a new timestamp."
);
update_fn!(
    dist_verifier_update_snapshot,
    update_snapshot,
    "Accept a new snapshot."
);
update_fn!(
    dist_verifier_update_targets,
    update_targets,
    "Accept new top-level targets."
);

/// Accept a delegated role's targets.
///
/// # Safety
/// `handle` must be a live verifier, `role` a valid NUL-terminated string, and
/// `raw` valid for `raw_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_verifier_update_delegated_targets(
    handle: *mut DistVerifier,
    role: *const c_char,
    raw: *const u8,
    raw_len: usize,
) -> DistStatus {
    guard(|| {
        if handle.is_null() {
            return DistStatus::NullArgument;
        }
        let Some(role) = (unsafe { utf8(role) }) else {
            return DistStatus::InvalidArgument;
        };
        let Some(raw) = (unsafe { bytes(raw, raw_len) }) else {
            return DistStatus::NullArgument;
        };
        let verifier = unsafe { &mut *handle };
        match verifier.inner.update_delegated_targets(role, raw) {
            Ok(()) => DistStatus::Ok,
            Err(e) => e.into(),
        }
    })
}

/// Resolve a target path against trusted metadata.
///
/// The path is validated segment by segment before use, so a delegated role
/// cannot smuggle a traversal component through a pattern that TUF accepts.
///
/// # Safety
/// `handle` must be a live verifier, `path` a valid NUL-terminated string, and
/// `out` a valid, writable [`DistTargetInfo`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_verifier_target(
    handle: *const DistVerifier,
    path: *const c_char,
    out: *mut DistTargetInfo,
) -> DistStatus {
    guard(|| {
        if handle.is_null() || out.is_null() {
            return DistStatus::NullArgument;
        }
        let Some(path) = (unsafe { utf8(path) }) else {
            return DistStatus::InvalidArgument;
        };
        let Ok(path) = TargetPath::parse(path) else {
            return DistStatus::InvalidArgument;
        };

        let verifier = unsafe { &*handle };
        let info = match verifier.inner.target(&path) {
            Ok(info) => info,
            Err(e) => return e.into(),
        };

        let mut filled = DistTargetInfo::zeroed();
        if let Err(status) = filled.fill_from(&info) {
            return status;
        }
        unsafe { *out = filled };
        DistStatus::Ok
    })
}

/// Version of `snapshot` named by the trusted timestamp.
///
/// A repository with consistent snapshots serves `<version>.<role>.json`, so a
/// client must know a role's version before it can fetch it. It learns that
/// from the role above, and this is how it reads it out. The number comes from
/// verified metadata, never from a filename or an unsigned response.
///
/// Returns `DIST_MALFORMED` before a timestamp has been accepted.
///
/// # Safety
/// `handle` must be a live verifier and `out` a valid, writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_verifier_snapshot_version(
    handle: *const DistVerifier,
    out: *mut u32,
) -> DistStatus {
    guard(|| {
        if handle.is_null() || out.is_null() {
            return DistStatus::NullArgument;
        }
        let verifier = unsafe { &*handle };
        match verifier.inner.snapshot_version() {
            Some(version) => {
                unsafe { *out = version };
                DistStatus::Ok
            }
            None => DistStatus::Malformed,
        }
    })
}

/// Version of a targets role — top-level or delegated — named by the trusted
/// snapshot.
///
/// Pass `"targets"` for the top-level role, or a delegated role name such as
/// `"app-editor"`.
///
/// Returns `DIST_MALFORMED` before a snapshot has been accepted, or if the
/// snapshot does not describe `role`.
///
/// # Safety
/// `handle` must be a live verifier, `role` a valid NUL-terminated string, and
/// `out` a valid, writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_verifier_targets_version(
    handle: *const DistVerifier,
    role: *const c_char,
    out: *mut u32,
) -> DistStatus {
    guard(|| {
        if handle.is_null() || out.is_null() {
            return DistStatus::NullArgument;
        }
        let Some(role) = (unsafe { utf8(role) }) else {
            return DistStatus::InvalidArgument;
        };
        let verifier = unsafe { &*handle };
        match verifier.inner.targets_version(role) {
            Some(version) => {
                unsafe { *out = version };
                DistStatus::Ok
            }
            None => DistStatus::Malformed,
        }
    })
}

/// Check downloaded bytes against a verified target description.
///
/// # Safety
/// `info` must be a valid [`DistTargetInfo`] and `payload` valid for
/// `payload_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_verify_payload(
    info: *const DistTargetInfo,
    payload: *const u8,
    payload_len: usize,
) -> DistStatus {
    guard(|| {
        if info.is_null() {
            return DistStatus::NullArgument;
        }
        let Some(payload) = (unsafe { bytes(payload, payload_len) }) else {
            return DistStatus::NullArgument;
        };
        let info = unsafe { *info }.to_target_info();
        match verify_payload(&info, payload) {
            Ok(()) => DistStatus::Ok,
            Err(e) => e.into(),
        }
    })
}

/// Decide whether this install is inside a staged rollout.
///
/// Writes 0 or 1 to `out`.
///
/// # Safety
/// `install_id` and `app_id` must be valid NUL-terminated strings and `out` a
/// valid, writable `u8`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dist_in_rollout(
    install_id: *const c_char,
    app_id: *const c_char,
    rollout_pct: u32,
    out: *mut u8,
) -> DistStatus {
    guard(|| {
        if out.is_null() {
            return DistStatus::NullArgument;
        }
        let (Some(install_id), Some(app_id)) =
            (unsafe { utf8(install_id) }, unsafe { utf8(app_id) })
        else {
            return DistStatus::InvalidArgument;
        };
        match in_rollout(install_id, app_id, rollout_pct) {
            Some(inside) => {
                unsafe { *out = u8::from(inside) };
                DistStatus::Ok
            }
            None => DistStatus::InvalidArgument,
        }
    })
}

/// Library version as a static NUL-terminated string.
#[unsafe(no_mangle)]
pub extern "C" fn dist_core_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}
