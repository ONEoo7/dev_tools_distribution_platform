//! The privileged broker: system-wide installs without a local privilege
//! escalation.
//!
//! Mirrors docs/PLAN.md section 6.4. A privileged updater that an unprivileged
//! process can talk to is a permanent LPE surface. The rules that contain it
//! are numbered in the plan and referenced by number throughout this module;
//! `tests/broker_lpe.rs` has a test per rule that fails if the rule is removed.
//!
//! # Rule 1 is enforced by the type system
//!
//! [`Request`] carries **no data at all**. There is no path, URL, version or
//! channel a caller could supply, because the enum has no field to put one in.
//! That is deliberate: "if the application can say *install from X*, you have
//! shipped a local privilege escalation". Making it unrepresentable is
//! stronger than validating it.
//!
//! # What is not here
//!
//! The Win32 pieces — the named pipe and its DACL, the staging directory ACL,
//! reparse-point hardening, safe DLL loading, Authenticode verification — are
//! declared as traits and implemented by the Windows service that hosts this
//! core. They need `SYSTEM` to exercise honestly and cannot be verified from a
//! unit test. This module is the decision logic they enforce, kept free of
//! `unsafe` so it can be reasoned about and tested on its own.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Everything an unprivileged caller may ask for.
///
/// Rule 1: no parameters. The caller can request an action; it cannot describe
/// one. Adding a field to any variant reopens the escalation this design
/// exists to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Request {
    /// Look for an update now. The broker decides what "an update" means.
    CheckNow,
    /// The user accepted the update the broker last reported.
    UserConsented,
    /// Report current state. Changes nothing.
    Status,
}

/// Why the broker refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Policy says this machine's updates are driven by management tooling.
    ManagedByPolicy,
    /// Consent arrived with no update on offer.
    NothingToInstall,
    /// The staging directory is writable by unprivileged users.
    StagingNotPrivileged,
    /// The artifact's publisher does not match the installed application.
    PublisherMismatch,
    /// Verification failed.
    VerificationFailed,
    /// The download or install failed.
    OperationFailed,
}

/// What the broker tells the caller. Status only, never data it could act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// Request accepted.
    Accepted,
    /// Current state.
    Status(Status),
    /// Refused.
    Denied(DenyReason),
}

/// The broker's view of the world.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Version currently installed, if the broker has installed one.
    pub installed: Option<String>,
    /// Version on offer, if a check found one.
    pub available: Option<String>,
    /// Whether installs are deferred to management tooling (§6.3).
    pub managed: bool,
    /// Whether the last operation failed.
    pub last_error: Option<String>,
}

/// A release the broker resolved for itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Version string.
    pub version: String,
    /// Signed digest of the payload.
    pub sha256: [u8; 32],
    /// Signed payload length.
    pub length: u64,
}

/// Resolves which release is on offer.
///
/// Rule 2: the broker asks this using its **own** configuration. Nothing the
/// caller sent reaches it.
pub trait ReleaseSource {
    /// Latest release for the configured application and channel.
    ///
    /// # Errors
    /// A description of why the release could not be resolved.
    fn available(&self, app_id: &str, channel: &str) -> Result<Option<Release>, String>;
}

/// Downloads a payload into the staging directory.
pub trait PayloadFetcher {
    /// Fetch `release`, returning where it was written.
    ///
    /// # Errors
    /// A description of why the download failed.
    fn fetch(&self, release: &Release, staging: &Path) -> Result<PathBuf, String>;
}

/// Verifies a payload on disk against its signed description.
pub trait PayloadVerifier {
    /// Check the bytes at `path` against `release`.
    ///
    /// # Errors
    /// A description of why verification failed. Must fail closed.
    fn verify(&self, path: &Path, release: &Release) -> Result<(), String>;
}

/// Confirms the staging directory cannot be written by unprivileged users.
///
/// Rule 3. A user-writable staging directory lets the user swap the verified
/// payload between verification and install, which turns the whole design into
/// the escalation it was meant to prevent.
pub trait StagingGuard {
    /// Whether only SYSTEM and Administrators may write here.
    fn is_privileged_only(&self, path: &Path) -> bool;
}

/// Confirms the artifact's platform signature matches the installed app.
///
/// Rule 5. TUF secures the channel; Authenticode secures the file at rest.
pub trait PublisherPin {
    /// Whether `path` is signed by the same publisher as the installed app.
    fn matches_installed(&self, path: &Path, app_id: &str) -> bool;
}

/// Broker configuration. The only source of truth about *what* to install.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Application this broker services.
    pub app_id: String,
    /// Channel to follow.
    pub channel: String,
    /// Directory payloads are staged into.
    pub staging: PathBuf,
    /// Managed mode: check and report, never install (§6.3).
    pub managed: bool,
}

/// Ports the broker needs from its host.
pub struct BrokerPorts<S, F, V, G, P> {
    /// Resolves the available release.
    pub source: S,
    /// Downloads payloads.
    pub fetcher: F,
    /// Verifies payloads.
    pub verifier: V,
    /// Checks staging permissions.
    pub staging_guard: G,
    /// Checks the publisher.
    pub publisher: P,
}

/// Handles requests from the unprivileged side.
pub struct Broker<S, F, V, G, P> {
    config: BrokerConfig,
    ports: BrokerPorts<S, F, V, G, P>,
    installed: Option<String>,
    offered: Option<Release>,
    last_error: Option<String>,
}

impl<S, F, V, G, P> Broker<S, F, V, G, P>
where
    S: ReleaseSource,
    F: PayloadFetcher,
    V: PayloadVerifier,
    G: StagingGuard,
    P: PublisherPin,
{
    /// Build a broker.
    pub const fn new(config: BrokerConfig, ports: BrokerPorts<S, F, V, G, P>) -> Self {
        Self {
            config,
            ports,
            installed: None,
            offered: None,
            last_error: None,
        }
    }

    /// Record the version already installed, so §6.4 rule 5 has something to
    /// compare against.
    pub fn set_installed(&mut self, version: impl Into<String>) {
        self.installed = Some(version.into());
    }

    /// Current status.
    #[must_use]
    pub fn status(&self) -> Status {
        Status {
            installed: self.installed.clone(),
            available: self.offered.as_ref().map(|r| r.version.clone()),
            managed: self.config.managed,
            last_error: self.last_error.clone(),
        }
    }

    /// Handle one request from the unprivileged side.
    ///
    /// Rule 1 in practice: `request` is the *entire* input, and it carries no
    /// data. Everything acted on comes from `self.config`.
    pub fn handle(&mut self, request: Request) -> Response {
        match request {
            Request::Status => Response::Status(self.status()),
            Request::CheckNow => self.check(),
            Request::UserConsented => self.install(),
        }
    }

    fn check(&mut self) -> Response {
        // Rule 2: resolved from configuration, never from the request.
        match self
            .ports
            .source
            .available(&self.config.app_id, &self.config.channel)
        {
            Ok(release) => {
                self.offered = release;
                self.last_error = None;
                Response::Status(self.status())
            }
            Err(e) => {
                self.last_error = Some(e);
                Response::Denied(DenyReason::OperationFailed)
            }
        }
    }

    fn install(&mut self) -> Response {
        // Managed mode (§6.3): checking and reporting still happen, installing
        // does not. Machine-wide software that self-updates bypasses the
        // change control an enterprise runs on.
        if self.config.managed {
            return Response::Denied(DenyReason::ManagedByPolicy);
        }

        let Some(release) = self.offered.clone() else {
            return Response::Denied(DenyReason::NothingToInstall);
        };

        // Rule 3: refuse to stage anywhere an unprivileged user can write.
        if !self
            .ports
            .staging_guard
            .is_privileged_only(&self.config.staging)
        {
            self.last_error = Some(format!(
                "staging directory {} is writable by unprivileged users",
                self.config.staging.display()
            ));
            return Response::Denied(DenyReason::StagingNotPrivileged);
        }

        let payload = match self.ports.fetcher.fetch(&release, &self.config.staging) {
            Ok(path) => path,
            Err(e) => {
                self.last_error = Some(e);
                return Response::Denied(DenyReason::OperationFailed);
            }
        };

        // Verify what was downloaded.
        if let Err(e) = self.ports.verifier.verify(&payload, &release) {
            self.last_error = Some(e);
            return Response::Denied(DenyReason::VerificationFailed);
        }

        // Rule 5: the publisher must match the application already installed.
        if !self
            .ports
            .publisher
            .matches_installed(&payload, &self.config.app_id)
        {
            self.last_error = Some(format!(
                "publisher of {} does not match the installed application",
                payload.display()
            ));
            return Response::Denied(DenyReason::PublisherMismatch);
        }

        // Rule 4: verify again, immediately before use. Checking only at
        // download time leaves a window in which the staged file can be
        // swapped, which is exactly what rule 3 is defending and this is the
        // second line of it.
        if let Err(e) = self.ports.verifier.verify(&payload, &release) {
            self.last_error = Some(e);
            return Response::Denied(DenyReason::VerificationFailed);
        }

        self.installed = Some(release.version.clone());
        self.offered = None;
        self.last_error = None;
        Response::Accepted
    }
}
