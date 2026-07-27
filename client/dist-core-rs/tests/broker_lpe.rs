//! Phase 5 exit criterion (PLAN.md 12): every rule in §6.4 has a test that
//! fails without it.
//!
//! Each test below names the rule it defends. Together they are the
//! local-privilege-escalation suite: the broker runs as SYSTEM and takes
//! requests from unprivileged processes, so a gap here is a full compromise of
//! the machine rather than a failed update.
//!
//! Rules 6 to 9 — named-pipe DACL and caller token, reparse-point hardening,
//! safe DLL loading, minimum privileges — are properties of the Windows
//! service that hosts this core. They need `SYSTEM` to exercise honestly and
//! are noted at the bottom of this file rather than pretended at here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::path::{Path, PathBuf};

use dist_core::broker::{
    Broker, BrokerConfig, BrokerPorts, DenyReason, PayloadFetcher, PayloadVerifier, PublisherPin,
    Release, ReleaseSource, Request, Response, StagingGuard,
};

const APP: &str = "editor";
const CHANNEL: &str = "stable";

fn release(version: &str) -> Release {
    Release {
        version: version.to_owned(),
        sha256: [7; 32],
        length: 42,
    }
}

// ------------------------------------------------------------------- doubles

struct Source {
    offer: Option<Release>,
    seen: Cell<Option<(String, String)>>,
}

impl Source {
    fn offering(version: &str) -> Self {
        Self {
            offer: Some(release(version)),
            seen: Cell::new(None),
        }
    }
    fn empty() -> Self {
        Self {
            offer: None,
            seen: Cell::new(None),
        }
    }
}

impl ReleaseSource for Source {
    fn available(&self, app_id: &str, channel: &str) -> Result<Option<Release>, String> {
        self.seen.set(Some((app_id.to_owned(), channel.to_owned())));
        Ok(self.offer.clone())
    }
}

struct Fetcher {
    staged_into: Cell<Option<PathBuf>>,
}

impl Fetcher {
    fn new() -> Self {
        Self {
            staged_into: Cell::new(None),
        }
    }
}

impl PayloadFetcher for Fetcher {
    fn fetch(&self, release: &Release, staging: &Path) -> Result<PathBuf, String> {
        self.staged_into.set(Some(staging.to_path_buf()));
        Ok(staging.join(format!("{}.bin", release.version)))
    }
}

struct Verifier {
    calls: Cell<u32>,
    fail_on_call: Option<u32>,
}

impl Verifier {
    fn always_ok() -> Self {
        Self {
            calls: Cell::new(0),
            fail_on_call: None,
        }
    }
    /// Passes on the first call and fails on `n`, modelling a payload swapped
    /// after download.
    fn fails_on(n: u32) -> Self {
        Self {
            calls: Cell::new(0),
            fail_on_call: Some(n),
        }
    }
}

impl PayloadVerifier for Verifier {
    fn verify(&self, _path: &Path, _release: &Release) -> Result<(), String> {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if self.fail_on_call == Some(call) {
            return Err(format!("verification failed on call {call}"));
        }
        Ok(())
    }
}

struct Staging(bool);
impl StagingGuard for Staging {
    fn is_privileged_only(&self, _path: &Path) -> bool {
        self.0
    }
}

struct Publisher(bool);
impl PublisherPin for Publisher {
    fn matches_installed(&self, _path: &Path, _app_id: &str) -> bool {
        self.0
    }
}

type Cut = Broker<Source, Fetcher, Verifier, Staging, Publisher>;

struct Harness;

impl Harness {
    fn build(
        source: Source,
        verifier: Verifier,
        staging: Staging,
        publisher: Publisher,
        managed: bool,
    ) -> Cut {
        Broker::new(
            BrokerConfig {
                app_id: APP.to_owned(),
                channel: CHANNEL.to_owned(),
                staging: PathBuf::from("C:/ProgramData/dist/staging"),
                managed,
            },
            BrokerPorts {
                source,
                fetcher: Fetcher::new(),
                verifier,
                staging_guard: staging,
                publisher,
            },
        )
    }

    /// A broker where everything is in order.
    fn healthy() -> Cut {
        Self::build(
            Source::offering("1.4.2"),
            Verifier::always_ok(),
            Staging(true),
            Publisher(true),
            false,
        )
    }
}

// -------------------------------------------------------- rule 1: no parameters

#[test]
fn the_request_type_cannot_carry_a_path() {
    // Rule 1, enforced by construction. `Request` is a fieldless enum, so
    // "install from X" is unrepresentable rather than merely rejected.
    //
    // These are the shapes an attacker would try. All must fail to parse.
    for hostile in [
        r#"{"CheckNow":{"path":"C:\\Users\\me\\evil.exe"}}"#,
        r#"{"UserConsented":{"url":"http://attacker/payload"}}"#,
        r#"{"InstallFrom":"C:\\evil.exe"}"#,
        r#"{"UserConsented":{"version":"9.9.9"}}"#,
        r#"{"CheckNow":{"channel":"attacker"}}"#,
    ] {
        assert!(
            serde_json::from_str::<Request>(hostile).is_err(),
            "broker protocol accepted caller-supplied data: {hostile}"
        );
    }
}

#[test]
fn only_the_three_verbs_are_accepted() {
    for verb in ["\"CheckNow\"", "\"UserConsented\"", "\"Status\""] {
        assert!(
            serde_json::from_str::<Request>(verb).is_ok(),
            "rejected {verb}"
        );
    }
    assert!(serde_json::from_str::<Request>("\"Install\"").is_err());
    assert!(serde_json::from_str::<Request>("\"Elevate\"").is_err());
}

// ----------------------------------------------- rule 2: config, not the caller

#[test]
fn the_broker_resolves_the_application_from_its_own_configuration() {
    // Rule 2. The caller sends `CheckNow` and nothing else; the app id and
    // channel acted on come from the broker's config.
    let mut broker = Harness::healthy();
    broker.handle(Request::CheckNow);

    let status = broker.status();
    assert_eq!(status.available.as_deref(), Some("1.4.2"));
}

#[test]
fn consent_without_a_prior_check_installs_nothing() {
    // The caller cannot name a version, so consent is only meaningful for an
    // update the broker itself found.
    let mut broker = Harness::healthy();
    assert_eq!(
        broker.handle(Request::UserConsented),
        Response::Denied(DenyReason::NothingToInstall)
    );
    assert_eq!(broker.status().installed, None);
}

#[test]
fn nothing_is_offered_when_the_source_has_nothing() {
    let mut broker = Harness::build(
        Source::empty(),
        Verifier::always_ok(),
        Staging(true),
        Publisher(true),
        false,
    );
    broker.handle(Request::CheckNow);
    assert_eq!(broker.status().available, None);
}

// --------------------------------------------------- rule 3: staging must be safe

#[test]
fn a_user_writable_staging_directory_stops_the_install() {
    // Rule 3. Without this the user swaps the verified payload between
    // verification and install, which is the escalation in full.
    let mut broker = Harness::build(
        Source::offering("1.4.2"),
        Verifier::always_ok(),
        Staging(false),
        Publisher(true),
        false,
    );
    broker.handle(Request::CheckNow);

    assert_eq!(
        broker.handle(Request::UserConsented),
        Response::Denied(DenyReason::StagingNotPrivileged)
    );
    assert_eq!(broker.status().installed, None);
}

// ------------------------------------------- rule 4: re-verify before use

#[test]
fn the_payload_is_verified_again_immediately_before_install() {
    // Rule 4. Modelled as a verifier that passes at download and fails later:
    // a file swapped after its first check must not be installed.
    let mut broker = Harness::build(
        Source::offering("1.4.2"),
        Verifier::fails_on(2),
        Staging(true),
        Publisher(true),
        false,
    );
    broker.handle(Request::CheckNow);

    assert_eq!(
        broker.handle(Request::UserConsented),
        Response::Denied(DenyReason::VerificationFailed),
        "a payload that changed after download was installed"
    );
    assert_eq!(broker.status().installed, None);
}

#[test]
fn a_payload_that_fails_its_first_check_never_reaches_install() {
    let mut broker = Harness::build(
        Source::offering("1.4.2"),
        Verifier::fails_on(1),
        Staging(true),
        Publisher(true),
        false,
    );
    broker.handle(Request::CheckNow);
    assert_eq!(
        broker.handle(Request::UserConsented),
        Response::Denied(DenyReason::VerificationFailed)
    );
}

// -------------------------------------------------- rule 5: publisher pinning

#[test]
fn an_artifact_from_a_different_publisher_is_refused() {
    // Rule 5. TUF secures the channel; Authenticode secures the file at rest.
    // A validly-signed binary from someone else is still someone else's.
    let mut broker = Harness::build(
        Source::offering("1.4.2"),
        Verifier::always_ok(),
        Staging(true),
        Publisher(false),
        false,
    );
    broker.handle(Request::CheckNow);

    assert_eq!(
        broker.handle(Request::UserConsented),
        Response::Denied(DenyReason::PublisherMismatch)
    );
    assert_eq!(broker.status().installed, None);
}

// ------------------------------------------------------- managed mode (§6.3)

#[test]
fn managed_mode_reports_but_never_installs() {
    // Enterprises run machine-wide software through change control; a
    // self-updating install bypasses it.
    let mut broker = Harness::build(
        Source::offering("1.4.2"),
        Verifier::always_ok(),
        Staging(true),
        Publisher(true),
        true,
    );

    broker.handle(Request::CheckNow);
    assert_eq!(
        broker.status().available.as_deref(),
        Some("1.4.2"),
        "managed mode must still report what is available"
    );

    assert_eq!(
        broker.handle(Request::UserConsented),
        Response::Denied(DenyReason::ManagedByPolicy)
    );
    assert_eq!(broker.status().installed, None);
}

#[test]
fn managed_mode_is_visible_to_the_caller() {
    let mut broker = Harness::build(
        Source::empty(),
        Verifier::always_ok(),
        Staging(true),
        Publisher(true),
        true,
    );
    let Response::Status(status) = broker.handle(Request::Status) else {
        panic!("Status must answer with a status");
    };
    assert!(status.managed);
}

// ------------------------------------------------------------- the happy path

#[test]
fn a_sound_update_installs() {
    // Without this the refusals above could all be passing for the wrong
    // reason.
    let mut broker = Harness::healthy();
    broker.set_installed("1.4.1");

    broker.handle(Request::CheckNow);
    assert_eq!(broker.handle(Request::UserConsented), Response::Accepted);

    let status = broker.status();
    assert_eq!(status.installed.as_deref(), Some("1.4.2"));
    assert_eq!(
        status.available, None,
        "an installed update is no longer on offer"
    );
    assert_eq!(status.last_error, None);
}

#[test]
fn status_never_changes_anything() {
    let mut broker = Harness::healthy();
    broker.handle(Request::CheckNow);
    let before = broker.status();
    broker.handle(Request::Status);
    assert_eq!(broker.status(), before);
}

// ------------------------------------------------------------------ not tested
//
// Rules 6 to 9 belong to the Windows service that hosts this core and cannot
// be exercised without running as SYSTEM:
//
//   6. named-pipe DACL and caller token verification
//   7. reparse-point hardening (FILE_FLAG_OPEN_REPARSE_POINT, handles not paths)
//   8. safe DLL loading (SetDefaultDllDirectories, fully-qualified paths)
//   9. minimum privileges, no interactive desktop
//
// They are declared in PLAN.md 6.4 and remain unimplemented; see the status
// table in PLAN.md 0.
