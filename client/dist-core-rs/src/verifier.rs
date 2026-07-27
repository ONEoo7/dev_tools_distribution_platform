//! TUF verification, wrapped so the rest of the client never sees the `tuf` crate.
//!
//! Decision D1 selects the `tuf` crate because it supports delegated roles,
//! which per-application key isolation depends on (PLAN.md 3.1) and which
//! `tough` does not provide. The crate is pre-1.0 and documents its API as
//! unstable, so nothing outside this module may name a `tuf` or `chrono` type.
//! That is what bounds the cost if the crate churns or stalls.

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, TimeZone as _, Utc};
use sha2::{Digest as _, Sha256};
use tuf::crypto::HashAlgorithm;
use tuf::database::Database;
use tuf::interchange::Json;
use tuf::metadata::{
    MetadataDescription, MetadataPath, RawSignedMetadata, RootMetadata,
    TargetPath as TufTargetPath, TargetsMetadata, TimestampMetadata,
};

use crate::TargetPath;

/// Which role's metadata was being verified when a check failed.
///
/// Carried on errors because the telemetry plane reports the failing stage
/// rather than a message (PLAN.md 7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Trust root.
    Root,
    /// Freshness signal.
    Timestamp,
    /// Pins the version of every targets role.
    Snapshot,
    /// Top-level targets.
    Targets,
    /// A per-application delegated role.
    Delegated,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Root => "root",
            Self::Timestamp => "timestamp",
            Self::Snapshot => "snapshot",
            Self::Targets => "targets",
            Self::Delegated => "delegated",
        };
        f.write_str(name)
    }
}

/// Why verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Metadata was refused. Covers bad signatures, failed thresholds,
    /// rollback and expiry alike -- all the cases the attack suite exercises.
    Rejected {
        /// Role whose metadata was refused.
        role: Role,
        /// Diagnostic detail from the underlying verifier.
        reason: String,
    },
    /// No trusted metadata describes this target.
    UnknownTarget,
    /// Metadata verified but did not carry what the client needs.
    Malformed(&'static str),
    /// Payload length did not match the signed description.
    Length {
        /// Length the signed metadata promised.
        expected: u64,
        /// Length actually received.
        actual: u64,
    },
    /// Payload digest did not match the signed description.
    Digest,
    /// The system clock is before the Unix epoch.
    Clock,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { role, reason } => write!(f, "{role} metadata rejected: {reason}"),
            Self::UnknownTarget => f.write_str("no trusted metadata describes this target"),
            Self::Malformed(what) => write!(f, "malformed metadata: {what}"),
            Self::Length { expected, actual } => {
                write!(
                    f,
                    "payload length {actual} does not match signed {expected}"
                )
            }
            Self::Digest => f.write_str("payload digest does not match signed description"),
            Self::Clock => f.write_str("system clock is before the Unix epoch"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Signed release metadata attached to a target (PLAN.md 3.4).
///
/// Mirrors `dist_core.naming.ReleaseInfo` on the server. `rollout_pct` in
/// particular is signed, which is what makes staged rollout unforgeable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// Version of this release.
    pub version: String,
    /// Percentage of installs the release is offered to.
    pub rollout_pct: u32,
    /// Security-critical release; the client may shorten its deferral window.
    pub mandatory: bool,
    /// Release notes shown in the in-app prompt.
    pub notes_url: Option<String>,
    /// Minimum supported OS build.
    pub min_os: Option<String>,
    /// Oldest version that may upgrade directly to this one.
    pub min_from_version: Option<String>,
}

/// A verified description of one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    /// Signed payload length.
    pub length: u64,
    /// Signed SHA-256 digest.
    pub sha256: [u8; 32],
    /// Signed release metadata.
    pub release: ReleaseInfo,
}

/// Verifies TUF metadata and resolves targets.
///
/// Implementations must never trust input that has not passed every check;
/// the update path is a remote code execution channel by design.
pub trait Verifier {
    /// Accept a new timestamp.
    ///
    /// # Errors
    /// [`VerifyError::Rejected`] if the metadata fails any check.
    fn update_timestamp(&mut self, raw: &[u8]) -> Result<(), VerifyError>;

    /// Accept a new snapshot.
    ///
    /// # Errors
    /// [`VerifyError::Rejected`] if the metadata fails any check.
    fn update_snapshot(&mut self, raw: &[u8]) -> Result<(), VerifyError>;

    /// Accept new top-level targets.
    ///
    /// # Errors
    /// [`VerifyError::Rejected`] if the metadata fails any check.
    fn update_targets(&mut self, raw: &[u8]) -> Result<(), VerifyError>;

    /// Accept a delegated role's targets.
    ///
    /// # Errors
    /// [`VerifyError::Rejected`] if the metadata fails any check, including
    /// the delegation not covering the role.
    fn update_delegated_targets(&mut self, role: &str, raw: &[u8]) -> Result<(), VerifyError>;

    /// Resolve a target against trusted metadata.
    ///
    /// # Errors
    /// [`VerifyError::UnknownTarget`] if no trusted role describes it.
    fn target(&self, path: &TargetPath) -> Result<TargetInfo, VerifyError>;

    /// Version of `snapshot` named by the trusted timestamp.
    ///
    /// A repository with consistent snapshots serves metadata as
    /// `<version>.<role>.json`, so a client has to know each role's version
    /// before it can fetch it — and it learns that from the role above.
    /// Without this, a client can only guess, and the usual guess is an
    /// unversioned alias, which reintroduces precisely the mismatched-set race
    /// consistent snapshots exist to prevent.
    ///
    /// Returns `None` before a timestamp has been accepted. The value comes
    /// from verified metadata, never from a filename or a server response.
    fn snapshot_version(&self) -> Option<u32>;

    /// Version of a targets role — top-level or delegated — named by the
    /// trusted snapshot.
    ///
    /// Returns `None` before a snapshot has been accepted, or if the snapshot
    /// does not describe `role`.
    fn targets_version(&self, role: &str) -> Option<u32>;
}

/// Where the verifier gets the current time.
enum Clock {
    System,
    Fixed(DateTime<Utc>),
}

/// [`Verifier`] backed by the `tuf` crate.
pub struct TufVerifier {
    database: Database<Json>,
    clock: Clock,
}

impl TufVerifier {
    /// Bootstrap from a trusted root shipped with the application.
    ///
    /// The root is embedded in the client rather than fetched, so there is no
    /// trust-on-first-use window.
    ///
    /// # Errors
    /// [`VerifyError::Rejected`] if the root cannot be parsed or verified.
    pub fn bootstrap(trusted_root: &[u8]) -> Result<Self, VerifyError> {
        Self::build(trusted_root, Clock::System)
    }

    /// Bootstrap with a fixed notion of "now", for deterministic tests.
    ///
    /// # Errors
    /// As [`Self::bootstrap`], plus [`VerifyError::Clock`] if `now` predates
    /// the Unix epoch.
    pub fn bootstrap_at(trusted_root: &[u8], now: SystemTime) -> Result<Self, VerifyError> {
        Self::build(trusted_root, Clock::Fixed(to_utc(now)?))
    }

    fn build(trusted_root: &[u8], clock: Clock) -> Result<Self, VerifyError> {
        let raw: RawSignedMetadata<Json, RootMetadata> =
            RawSignedMetadata::new(trusted_root.to_vec());
        let database = Database::from_trusted_root(&raw).map_err(|e| rejected(Role::Root, &e))?;
        Ok(Self { database, clock })
    }

    fn now(&self) -> Result<DateTime<Utc>, VerifyError> {
        match &self.clock {
            Clock::System => to_utc(SystemTime::now()),
            Clock::Fixed(t) => Ok(*t),
        }
    }
}

fn to_utc(time: SystemTime) -> Result<DateTime<Utc>, VerifyError> {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VerifyError::Clock)?
        .as_secs();
    let secs = i64::try_from(secs).map_err(|_| VerifyError::Clock)?;
    Utc.timestamp_opt(secs, 0)
        .single()
        .ok_or(VerifyError::Clock)
}

fn rejected(role: Role, error: &tuf::Error) -> VerifyError {
    VerifyError::Rejected {
        role,
        reason: error.to_string(),
    }
}

impl Verifier for TufVerifier {
    fn update_timestamp(&mut self, raw: &[u8]) -> Result<(), VerifyError> {
        let now = self.now()?;
        let raw: RawSignedMetadata<Json, TimestampMetadata> = RawSignedMetadata::new(raw.to_vec());
        self.database
            .update_timestamp(&now, &raw)
            .map(|_| ())
            .map_err(|e| rejected(Role::Timestamp, &e))
    }

    fn update_snapshot(&mut self, raw: &[u8]) -> Result<(), VerifyError> {
        let now = self.now()?;
        let raw = RawSignedMetadata::new(raw.to_vec());
        self.database
            .update_snapshot(&now, &raw)
            .map(|_| ())
            .map_err(|e| rejected(Role::Snapshot, &e))
    }

    fn update_targets(&mut self, raw: &[u8]) -> Result<(), VerifyError> {
        let now = self.now()?;
        let raw: RawSignedMetadata<Json, TargetsMetadata> = RawSignedMetadata::new(raw.to_vec());
        self.database
            .update_targets(&now, &raw)
            .map(|_| ())
            .map_err(|e| rejected(Role::Targets, &e))
    }

    fn update_delegated_targets(&mut self, role: &str, raw: &[u8]) -> Result<(), VerifyError> {
        let now = self.now()?;
        let parent = MetadataPath::targets();
        let role = MetadataPath::new(role.to_owned()).map_err(|e| rejected(Role::Delegated, &e))?;
        let raw: RawSignedMetadata<Json, TargetsMetadata> = RawSignedMetadata::new(raw.to_vec());
        self.database
            .update_delegated_targets(&now, &parent, &role, &raw)
            .map(|_| ())
            .map_err(|e| rejected(Role::Delegated, &e))
    }

    fn snapshot_version(&self) -> Option<u32> {
        self.database
            .trusted_timestamp()
            .map(|timestamp| timestamp.snapshot().version())
    }

    fn targets_version(&self, role: &str) -> Option<u32> {
        let snapshot = self.database.trusted_snapshot()?;
        // Snapshot keys are role names without the `.json` suffix; the
        // interchange layer strips it on the way in.
        let path = MetadataPath::new(role.to_owned()).ok()?;
        snapshot.meta().get(&path).map(MetadataDescription::version)
    }

    fn target(&self, path: &TargetPath) -> Result<TargetInfo, VerifyError> {
        let now = self.now()?;
        let tuf_path =
            TufTargetPath::new(path.as_str().to_owned()).map_err(|_| VerifyError::UnknownTarget)?;
        let description = self
            .database
            .target_description_with_start_time(&now, &tuf_path)
            .map_err(|_| VerifyError::UnknownTarget)?;

        let digest = description
            .hashes()
            .get(&HashAlgorithm::Sha256)
            .ok_or(VerifyError::Malformed("target has no sha256 hash"))?;
        let sha256: [u8; 32] = digest
            .value()
            .try_into()
            .map_err(|_| VerifyError::Malformed("sha256 digest is not 32 bytes"))?;

        Ok(TargetInfo {
            length: description.length(),
            sha256,
            release: release_info(description.custom())?,
        })
    }
}

fn release_info(custom: &HashMap<String, serde_json::Value>) -> Result<ReleaseInfo, VerifyError> {
    let version = custom
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerifyError::Malformed("release metadata has no version"))?
        .to_owned();

    let rollout_pct = custom
        .get("rollout_pct")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(100);
    let rollout_pct = u32::try_from(rollout_pct)
        .map_err(|_| VerifyError::Malformed("rollout_pct out of range"))?;
    if rollout_pct > 100 {
        return Err(VerifyError::Malformed("rollout_pct out of range"));
    }

    let optional = |key: &str| {
        custom
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    };

    Ok(ReleaseInfo {
        version,
        rollout_pct,
        mandatory: custom
            .get("mandatory")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        notes_url: optional("notes_url"),
        min_os: optional("min_os"),
        min_from_version: optional("min_from_version"),
    })
}

/// Check downloaded bytes against a verified target description.
///
/// Length is checked before the digest so an oversized response is rejected
/// without hashing it.
///
/// # Errors
/// [`VerifyError::Length`] or [`VerifyError::Digest`] on mismatch.
pub fn verify_payload(info: &TargetInfo, payload: &[u8]) -> Result<(), VerifyError> {
    let actual = u64::try_from(payload.len()).map_err(|_| VerifyError::Length {
        expected: info.length,
        actual: u64::MAX,
    })?;
    if actual != info.length {
        return Err(VerifyError::Length {
            expected: info.length,
            actual,
        });
    }

    let digest: [u8; 32] = Sha256::digest(payload).into();
    if digest == info.sha256 {
        Ok(())
    } else {
        Err(VerifyError::Digest)
    }
}
