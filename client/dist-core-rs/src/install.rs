//! A/B slot installation.
//!
//! Mirrors docs/PLAN.md sections 6.1 and 6.2. The shape is platform-agnostic;
//! [`InstallLayout`] is the seam that §6.6 keeps free of Windows vocabulary so
//! macOS and Linux are additive.
//!
//! # Why slots
//!
//! A running `.exe` or `.dll` cannot be overwritten on Windows. Because a new
//! version is written to its own directory and activated by flipping a pointer,
//! the running version's files are never touched and that entire class of
//! failure disappears. Installation is also decoupled from restart: staging can
//! finish in the background while the application runs.
//!
//! # Crash consistency
//!
//! Every step is ordered so that an interruption leaves a usable install:
//!
//! 1. stage into a temporary directory,
//! 2. rename it into place as a version slot,
//! 3. atomically replace the pointer.
//!
//! Interrupted before 2, the old version is still active and the staging
//! directory is garbage that [`Installer::clean_staging`] removes. Interrupted
//! between 2 and 3, a complete but inactive slot exists, which is harmless.
//! Step 3 is a single rename, so a client sees either the old pointer or the
//! new one and never a torn file.
//!
//! # Health probation
//!
//! A freshly activated version starts on probation. Each launch attempt is
//! recorded before the process starts; a version that never confirms itself is
//! rolled back automatically after [`MAX_LAUNCH_ATTEMPTS`] tries. That is what
//! stops a bad release turning into an unbootable install with no way to ship
//! the fix.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Launch attempts allowed before an unconfirmed version is rolled back.
///
/// More than one because a first launch can fail for reasons unrelated to the
/// update — a machine shutting down, a transient antivirus lock (§6.5).
pub const MAX_LAUNCH_ATTEMPTS: u32 = 3;

/// Version slots retained. One spare is what rollback needs.
pub const SLOTS_RETAINED: usize = 2;

/// Where an installation keeps its files.
///
/// Deliberately free of platform vocabulary: no "junction", no "service". A
/// macOS or Linux implementation supplies different paths and nothing above
/// this trait changes.
pub trait InstallLayout {
    /// Root of the installation.
    fn root(&self) -> &Path;

    /// Directory holding the version slots.
    fn versions_dir(&self) -> PathBuf {
        self.root().join("versions")
    }

    /// Slot for one version.
    fn slot(&self, version: &str) -> PathBuf {
        self.versions_dir().join(version)
    }

    /// Where a download is assembled before it becomes a slot.
    fn staging_dir(&self) -> PathBuf {
        self.root().join("staging")
    }

    /// The pointer naming the active version.
    fn pointer_path(&self) -> PathBuf {
        self.root().join("current.json")
    }
}

/// Per-user installation root.
///
/// On Windows this sits under `%LOCALAPPDATA%`, which needs no elevation and
/// therefore no privileged helper at all (§6.1).
#[derive(Debug, Clone)]
pub struct PerUserLayout {
    root: PathBuf,
}

impl PerUserLayout {
    /// Use an explicit root. Tests and portable installs need this.
    #[must_use]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl InstallLayout for PerUserLayout {
    fn root(&self) -> &Path {
        &self.root
    }
}

/// Whether the active version has proved it can start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// Activated but not yet confirmed. Rolls back if it never confirms.
    Probation,
    /// Started successfully at least once.
    Confirmed,
}

/// The pointer file: the whole of the installation's mutable state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pointer {
    /// Version that should run.
    pub active: String,
    /// Version to fall back to. `None` on a first install.
    pub previous: Option<String>,
    /// Whether `active` has confirmed itself.
    pub health: Health,
    /// Launches attempted since activation.
    pub attempts: u32,
}

impl Pointer {
    fn first(version: &str) -> Self {
        Self {
            active: version.to_owned(),
            previous: None,
            health: Health::Confirmed,
            attempts: 0,
        }
    }
}

/// Why an installation operation failed.
#[derive(Debug)]
pub enum InstallError {
    /// The installation has no pointer; nothing has been installed yet.
    NotInstalled,
    /// The pointer exists but could not be understood.
    ///
    /// Writes are atomic, so this means damage rather than a torn write, and
    /// it is reported instead of guessed at: picking a version by scanning the
    /// slots could silently re-activate one that was rolled back.
    CorruptPointer(String),
    /// The slot the pointer names is absent or incomplete.
    MissingSlot(String),
    /// A version string that is not safe to use as a directory name.
    InvalidVersion(String),
    /// Nothing to roll back to.
    NoPreviousVersion,
    /// Underlying filesystem failure.
    Io(io::Error),
}

impl From<io::Error> for InstallError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => f.write_str("no installation found"),
            Self::CorruptPointer(why) => write!(f, "pointer file is unusable: {why}"),
            Self::MissingSlot(v) => {
                write!(f, "version {v} is named by the pointer but not present")
            }
            Self::InvalidVersion(v) => write!(f, "unsafe version string {v:?}"),
            Self::NoPreviousVersion => f.write_str("no previous version to roll back to"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InstallError {}

/// Reject a version that could escape the versions directory.
///
/// Versions arrive from signed metadata, but a delegated role could still name
/// something hostile, so this is checked before it ever reaches a path.
fn check_version(version: &str) -> Result<(), InstallError> {
    let invalid = version.is_empty()
        || version == "."
        || version == ".."
        || version.contains('/')
        || version.contains('\\')
        || version.contains(':')
        || version.contains('\0');
    if invalid {
        return Err(InstallError::InvalidVersion(version.to_owned()));
    }
    Ok(())
}

/// Drives staging, activation, health and rollback for one installation.
pub struct Installer<L: InstallLayout> {
    layout: L,
}

impl<L: InstallLayout> Installer<L> {
    /// Drive an installation at `layout`.
    pub const fn new(layout: L) -> Self {
        Self { layout }
    }

    /// The layout this installer operates on.
    #[must_use]
    pub const fn layout(&self) -> &L {
        &self.layout
    }

    /// Read the pointer.
    ///
    /// # Errors
    /// [`InstallError::NotInstalled`] if there is no pointer,
    /// [`InstallError::CorruptPointer`] if it cannot be parsed.
    pub fn pointer(&self) -> Result<Pointer, InstallError> {
        let path = self.layout.pointer_path();
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(InstallError::NotInstalled);
            }
            Err(e) => return Err(e.into()),
        };
        serde_json::from_slice(&raw).map_err(|e| InstallError::CorruptPointer(e.to_string()))
    }

    /// Replace the pointer atomically.
    ///
    /// Written to a temporary file in the same directory and renamed over the
    /// old one, so a reader sees one complete pointer or the other.
    fn write_pointer(&self, pointer: &Pointer) -> Result<(), InstallError> {
        let path = self.layout.pointer_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("json.tmp");
        let encoded = serde_json::to_vec_pretty(pointer)
            .map_err(|e| InstallError::CorruptPointer(e.to_string()))?;
        fs::write(&temp, encoded)?;
        fs::rename(&temp, &path)?;
        Ok(())
    }

    /// Create an empty staging directory for `version`.
    ///
    /// # Errors
    /// [`InstallError::InvalidVersion`] or a filesystem failure.
    pub fn stage(&self, version: &str) -> Result<PathBuf, InstallError> {
        check_version(version)?;
        let staging = self.layout.staging_dir().join(version);
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        fs::create_dir_all(&staging)?;
        Ok(staging)
    }

    /// Turn a completed staging directory into a version slot.
    ///
    /// A single rename, so the slot appears complete or not at all. Does not
    /// activate anything: an interruption here leaves an unused slot.
    ///
    /// # Errors
    /// [`InstallError::MissingSlot`] if the staging directory is absent.
    pub fn commit_slot(&self, version: &str) -> Result<PathBuf, InstallError> {
        check_version(version)?;
        let staging = self.layout.staging_dir().join(version);
        if !staging.is_dir() {
            return Err(InstallError::MissingSlot(version.to_owned()));
        }

        let slot = self.layout.slot(version);
        fs::create_dir_all(self.layout.versions_dir())?;
        if slot.exists() {
            fs::remove_dir_all(&slot)?;
        }
        fs::rename(&staging, &slot)?;
        Ok(slot)
    }

    /// Make `version` active, keeping the current one as the rollback target.
    ///
    /// The new version starts on probation.
    ///
    /// # Errors
    /// [`InstallError::MissingSlot`] if the version was never committed.
    pub fn activate(&self, version: &str) -> Result<Pointer, InstallError> {
        check_version(version)?;
        if !self.layout.slot(version).is_dir() {
            return Err(InstallError::MissingSlot(version.to_owned()));
        }

        let pointer = match self.pointer() {
            Ok(current) if current.active == version => Pointer {
                health: Health::Confirmed,
                attempts: 0,
                ..current
            },
            Ok(current) => Pointer {
                active: version.to_owned(),
                previous: Some(current.active),
                health: Health::Probation,
                attempts: 0,
            },
            Err(InstallError::NotInstalled) => Pointer::first(version),
            Err(e) => return Err(e),
        };

        self.write_pointer(&pointer)?;
        Ok(pointer)
    }

    /// Decide what to launch, recording the attempt.
    ///
    /// Called by the launcher on every start. If the active version has used
    /// up its probation attempts, this rolls back and returns the previous
    /// version instead. The attempt is recorded *before* the process starts,
    /// so a version that hangs or crashes still burns an attempt.
    ///
    /// # Errors
    /// [`InstallError::NotInstalled`], [`InstallError::CorruptPointer`] or
    /// [`InstallError::MissingSlot`].
    pub fn begin_launch(&self) -> Result<PathBuf, InstallError> {
        let pointer = self.pointer()?;

        if pointer.health == Health::Probation && pointer.attempts >= MAX_LAUNCH_ATTEMPTS {
            let rolled_back = self.rollback()?;
            return self.resolve(&rolled_back.active);
        }

        let next = Pointer {
            attempts: pointer.attempts.saturating_add(1),
            ..pointer
        };
        self.write_pointer(&next)?;
        self.resolve(&next.active)
    }

    /// Record that the active version started successfully.
    ///
    /// # Errors
    /// As [`Self::pointer`].
    pub fn confirm_healthy(&self) -> Result<Pointer, InstallError> {
        let pointer = self.pointer()?;
        let confirmed = Pointer {
            health: Health::Confirmed,
            attempts: 0,
            ..pointer
        };
        self.write_pointer(&confirmed)?;
        Ok(confirmed)
    }

    /// Return to the previous version.
    ///
    /// The rolled-back-to version is marked confirmed: it ran before, and
    /// putting it on probation could roll back past it into nothing.
    ///
    /// # Errors
    /// [`InstallError::NoPreviousVersion`] if there is nothing to return to.
    pub fn rollback(&self) -> Result<Pointer, InstallError> {
        let pointer = self.pointer()?;
        let Some(previous) = pointer.previous.clone() else {
            return Err(InstallError::NoPreviousVersion);
        };
        if !self.layout.slot(&previous).is_dir() {
            return Err(InstallError::MissingSlot(previous));
        }

        let rolled_back = Pointer {
            active: previous,
            previous: None,
            health: Health::Confirmed,
            attempts: 0,
        };
        self.write_pointer(&rolled_back)?;
        Ok(rolled_back)
    }

    /// Path to the slot for `version`, checking that it exists.
    fn resolve(&self, version: &str) -> Result<PathBuf, InstallError> {
        let slot = self.layout.slot(version);
        if slot.is_dir() {
            Ok(slot)
        } else {
            Err(InstallError::MissingSlot(version.to_owned()))
        }
    }

    /// Remove staging left behind by an interrupted update.
    ///
    /// # Errors
    /// Filesystem failures other than the directory being absent.
    pub fn clean_staging(&self) -> Result<(), InstallError> {
        let staging = self.layout.staging_dir();
        match fs::remove_dir_all(&staging) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete slots that are neither active nor the rollback target.
    ///
    /// # Errors
    /// Filesystem failures. A slot that cannot be removed — antivirus holding
    /// a handle, say (§6.5) — is skipped rather than failing the update.
    pub fn prune(&self) -> Result<Vec<String>, InstallError> {
        let pointer = self.pointer()?;
        let keep: Vec<&str> = [Some(pointer.active.as_str()), pointer.previous.as_deref()]
            .into_iter()
            .flatten()
            .collect();

        let versions_dir = self.layout.versions_dir();
        let entries = match fs::read_dir(&versions_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut removed = Vec::new();
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if keep.contains(&name.as_str()) || !entry.path().is_dir() {
                continue;
            }
            if fs::remove_dir_all(entry.path()).is_ok() {
                removed.push(name);
            }
        }
        removed.sort();
        Ok(removed)
    }
}
