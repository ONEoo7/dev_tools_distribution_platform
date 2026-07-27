//! Phase 4 exit criterion (PLAN.md 12): an update survives a forced kill at
//! every stage.
//!
//! The test that matters is `interrupted_update_always_leaves_a_usable_install`.
//! It replays the update sequence truncated after each step and asserts the
//! installation still resolves to a complete, launchable version — the old one
//! or the new one, never a half-written mixture.
//!
//! This is the property A/B slots exist to provide. An updater that can brick
//! an installation is worse than no updater, because the fix ships through the
//! thing that just broke.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use dist_core::install::{
    Health, InstallError, InstallLayout, Installer, MAX_LAUNCH_ATTEMPTS, PerUserLayout,
};

const V1: &str = "1.4.1";
const V2: &str = "1.4.2";

fn installer(root: &Path) -> Installer<PerUserLayout> {
    Installer::new(PerUserLayout::at(root))
}

/// Write a slot's payload so a launched version is identifiable.
fn fill(dir: &Path, version: &str) {
    fs::write(dir.join("app.txt"), version).unwrap();
}

/// Install `version` completely and confirm it.
fn install(installer: &Installer<PerUserLayout>, version: &str) {
    let staging = installer.stage(version).unwrap();
    fill(&staging, version);
    installer.commit_slot(version).unwrap();
    installer.activate(version).unwrap();
    installer.confirm_healthy().unwrap();
}

/// Which version an installation would actually run.
fn active_version(installer: &Installer<PerUserLayout>) -> String {
    let pointer = installer.pointer().expect("pointer unreadable");
    let slot = installer.layout().slot(&pointer.active);
    assert!(slot.is_dir(), "active slot {} is missing", slot.display());
    fs::read_to_string(slot.join("app.txt")).expect("active slot has no payload")
}

// --------------------------------------------------------------- happy path

#[test]
fn first_install_is_active_and_confirmed() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);

    let pointer = installer.pointer().unwrap();
    assert_eq!(pointer.active, V1);
    assert_eq!(pointer.previous, None);
    assert_eq!(pointer.health, Health::Confirmed);
    assert_eq!(active_version(&installer), V1);
}

#[test]
fn update_activates_the_new_version_on_probation() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);

    let staging = installer.stage(V2).unwrap();
    fill(&staging, V2);
    installer.commit_slot(V2).unwrap();
    let pointer = installer.activate(V2).unwrap();

    assert_eq!(pointer.active, V2);
    assert_eq!(pointer.previous.as_deref(), Some(V1));
    assert_eq!(pointer.health, Health::Probation);
    assert_eq!(active_version(&installer), V2);
}

#[test]
fn the_running_version_is_never_touched_during_staging() {
    // The reason a running .exe cannot block an update (PLAN.md 6.1).
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);

    let staging = installer.stage(V2).unwrap();
    fill(&staging, V2);
    installer.commit_slot(V2).unwrap();

    let old = installer.layout().slot(V1).join("app.txt");
    assert_eq!(fs::read_to_string(old).unwrap(), V1);
}

// ------------------------------------------------- the exit criterion

/// Steps of an update, in the order the installer performs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Nothing,
    StagingCreated,
    StagingFilled,
    SlotCommitted,
    Activated,
    Confirmed,
}

const STEPS: [Step; 6] = [
    Step::Nothing,
    Step::StagingCreated,
    Step::StagingFilled,
    Step::SlotCommitted,
    Step::Activated,
    Step::Confirmed,
];

/// Perform an update up to `stop`, as though the process were killed there.
fn update_until(installer: &Installer<PerUserLayout>, version: &str, stop: Step) {
    if stop == Step::Nothing {
        return;
    }
    let staging = installer.stage(version).unwrap();
    if stop == Step::StagingCreated {
        return;
    }
    fill(&staging, version);
    if stop == Step::StagingFilled {
        return;
    }
    installer.commit_slot(version).unwrap();
    if stop == Step::SlotCommitted {
        return;
    }
    installer.activate(version).unwrap();
    if stop == Step::Activated {
        return;
    }
    installer.confirm_healthy().unwrap();
}

#[test]
fn interrupted_update_always_leaves_a_usable_install() {
    for stop in STEPS {
        let tmp = tempdir();
        let installer = installer(&tmp);
        install(&installer, V1);

        update_until(&installer, V2, stop);

        // Whatever was interrupted, the installation still resolves to a
        // complete version and its payload is intact.
        let running = active_version(&installer);
        let expected = match stop {
            Step::Activated | Step::Confirmed => V2,
            _ => V1,
        };
        assert_eq!(
            running, expected,
            "wrong version active after kill at {stop:?}"
        );

        // And a restart from that state still launches.
        let slot = installer.begin_launch().unwrap();
        assert!(slot.is_dir());
    }
}

#[test]
fn interrupted_update_can_be_retried_from_any_point() {
    // Recovery matters as much as survival: a killed update must not leave
    // state that blocks the next attempt.
    for stop in STEPS {
        let tmp = tempdir();
        let installer = installer(&tmp);
        install(&installer, V1);

        update_until(&installer, V2, stop);
        installer.clean_staging().unwrap();

        update_until(&installer, V2, Step::Confirmed);

        assert_eq!(
            active_version(&installer),
            V2,
            "retry failed after kill at {stop:?}"
        );
        assert_eq!(installer.pointer().unwrap().health, Health::Confirmed);
    }
}

#[test]
fn staging_left_by_an_interrupted_update_is_removable() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);

    update_until(&installer, V2, Step::StagingFilled);
    assert!(installer.layout().staging_dir().exists());

    installer.clean_staging().unwrap();
    assert!(!installer.layout().staging_dir().exists());
    assert_eq!(active_version(&installer), V1);
}

#[test]
fn cleaning_staging_when_there_is_none_is_not_an_error() {
    let tmp = tempdir();
    installer(&tmp).clean_staging().unwrap();
}

// ------------------------------------------------------- probation, rollback

#[test]
fn a_version_that_never_confirms_is_rolled_back() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);

    update_until(&installer, V2, Step::Activated);

    // Every launch burns an attempt because the version never confirms.
    for _ in 0..MAX_LAUNCH_ATTEMPTS {
        let slot = installer.begin_launch().unwrap();
        assert_eq!(fs::read_to_string(slot.join("app.txt")).unwrap(), V2);
    }

    let slot = installer.begin_launch().unwrap();
    assert_eq!(
        fs::read_to_string(slot.join("app.txt")).unwrap(),
        V1,
        "a version that never starts must not keep being launched forever"
    );
    assert_eq!(installer.pointer().unwrap().active, V1);
}

#[test]
fn a_confirmed_version_is_never_rolled_back() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);
    install(&installer, V2);

    for _ in 0..(MAX_LAUNCH_ATTEMPTS * 3) {
        installer.begin_launch().unwrap();
    }
    assert_eq!(installer.pointer().unwrap().active, V2);
}

#[test]
fn confirming_clears_probation() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);
    update_until(&installer, V2, Step::Activated);

    installer.begin_launch().unwrap();
    assert!(installer.pointer().unwrap().attempts > 0);

    let pointer = installer.confirm_healthy().unwrap();
    assert_eq!(pointer.health, Health::Confirmed);
    assert_eq!(pointer.attempts, 0);
}

#[test]
fn rollback_target_is_confirmed_so_it_cannot_roll_back_again() {
    // Otherwise a rollback could cascade past the last good version.
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);
    update_until(&installer, V2, Step::Activated);

    let pointer = installer.rollback().unwrap();
    assert_eq!(pointer.active, V1);
    assert_eq!(pointer.health, Health::Confirmed);
    assert_eq!(pointer.previous, None);
}

#[test]
fn rollback_without_a_previous_version_is_refused() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);
    assert!(matches!(
        installer.rollback(),
        Err(InstallError::NoPreviousVersion)
    ));
}

#[test]
fn reactivating_the_current_version_confirms_it() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);
    update_until(&installer, V2, Step::Activated);

    let pointer = installer.activate(V2).unwrap();
    assert_eq!(pointer.health, Health::Confirmed);
    assert_eq!(pointer.previous.as_deref(), Some(V1));
}

// ------------------------------------------------------------ failure modes

#[test]
fn a_damaged_pointer_is_reported_not_guessed() {
    // Guessing by scanning the slots could silently re-activate a version that
    // was rolled back for failing to start.
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);

    fs::write(installer.layout().pointer_path(), b"{ not json").unwrap();
    assert!(matches!(
        installer.pointer(),
        Err(InstallError::CorruptPointer(_))
    ));
}

#[test]
fn an_absent_installation_is_distinguishable_from_a_damaged_one() {
    let tmp = tempdir();
    assert!(matches!(
        installer(&tmp).pointer(),
        Err(InstallError::NotInstalled)
    ));
}

#[test]
fn activating_a_version_that_was_never_committed_is_refused() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);
    assert!(matches!(
        installer.activate("9.9.9"),
        Err(InstallError::MissingSlot(_))
    ));
}

#[test]
fn unsafe_version_strings_never_reach_a_path() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    for version in ["", ".", "..", "../escape", "a/b", "a\\b", "C:evil", "nul\0"] {
        assert!(
            matches!(
                installer.stage(version),
                Err(InstallError::InvalidVersion(_))
            ),
            "accepted {version:?}"
        );
    }
}

// ------------------------------------------------------------------- pruning

#[test]
fn prune_keeps_the_active_and_rollback_versions() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, "1.0.0");
    install(&installer, V1);
    install(&installer, V2);

    let removed = installer.prune().unwrap();
    assert_eq!(removed, vec!["1.0.0"]);
    assert!(installer.layout().slot(V2).is_dir());
    assert!(installer.layout().slot(V1).is_dir());
    assert!(!installer.layout().slot("1.0.0").exists());
}

#[test]
fn prune_leaves_rollback_possible() {
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);
    update_until(&installer, V2, Step::Activated);

    installer.prune().unwrap();
    assert_eq!(installer.rollback().unwrap().active, V1);
}

#[test]
fn pointer_writes_leave_no_temporary_files() {
    // The pointer is written to a sibling temp file and renamed over. A leaked
    // temp file would mean the rename did not happen and the write was not
    // atomic after all.
    let tmp = tempdir();
    let installer = installer(&tmp);
    install(&installer, V1);
    install(&installer, V2);
    installer.begin_launch().unwrap();

    let leftovers: Vec<_> = fs::read_dir(&tmp)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|e| e == "tmp")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary files left behind: {leftovers:?}"
    );
}

// --------------------------------------------------------------------- utils

/// A unique temporary directory. Avoids a dev-dependency for one helper.
fn tempdir() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("dist-install-test-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}
