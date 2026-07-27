//! Deterministic staged-rollout selection.
//!
//! Mirrors `dist_core.naming.in_rollout` in the Python server. Both
//! implementations must agree exactly: the server decides which installs a
//! release reaches by signing a percentage, and the client decides for itself
//! whether it is inside that percentage. If the two disagree, a staged rollout
//! either stalls or overshoots.
//!
//! The client deciding for itself is deliberate (PLAN.md 3.5). There is no
//! per-client server decision, so there is nothing for a network attacker or a
//! compromised edge to manipulate.

use sha2::{Digest, Sha256};

/// Returns whether this install is inside a rollout of `rollout_pct` percent.
///
/// Returns `None` if `rollout_pct` is outside `0..=100`, since an out-of-range
/// percentage means the metadata is malformed rather than that the install is
/// excluded.
#[must_use]
pub fn in_rollout(install_id: &str, app_id: &str, rollout_pct: u32) -> Option<bool> {
    if rollout_pct > 100 {
        return None;
    }
    if rollout_pct == 0 {
        return Some(false);
    }
    if rollout_pct == 100 {
        return Some(true);
    }

    let mut hasher = Sha256::new();
    hasher.update(install_id.as_bytes());
    hasher.update(b":");
    hasher.update(app_id.as_bytes());

    // Destructured rather than indexed: irrefutable on a fixed-size array, so
    // there is no bounds check to elide and no path to a panic.
    let [b0, b1, b2, b3, ..] = <[u8; 32]>::from(hasher.finalize());
    let bucket = u32::from_be_bytes([b0, b1, b2, b3]) % 100;
    Some(bucket < rollout_pct)
}

#[cfg(test)]
mod tests {
    use super::in_rollout;

    /// Cross-language contract with `tests/test_naming.py::test_rollout_vectors_are_stable`.
    ///
    /// If this fails, the Rust and Python implementations have diverged and
    /// staged rollout is broken in a way no single-language test would catch.
    #[test]
    fn matches_python_vectors() {
        let expected = [false, false, true, false, false, false, true, false];
        for (n, want) in expected.iter().enumerate() {
            let install = format!("install-{n}");
            assert_eq!(
                in_rollout(&install, "editor", 50),
                Some(*want),
                "install-{n} disagrees with the Python implementation"
            );
        }
    }

    #[test]
    fn extremes_short_circuit() {
        assert_eq!(in_rollout("any", "editor", 0), Some(false));
        assert_eq!(in_rollout("any", "editor", 100), Some(true));
    }

    #[test]
    fn out_of_range_percentage_is_rejected() {
        assert_eq!(in_rollout("any", "editor", 101), None);
    }

    #[test]
    fn selection_is_monotonic_in_percentage() {
        // Raising the percentage must never remove an install that was already
        // inside the rollout, or an in-flight rollout would claw updates back.
        let mut seen_inside = false;
        for pct in 0..=100 {
            let inside = in_rollout("install-a", "editor", pct).unwrap_or(false);
            if seen_inside {
                assert!(inside, "install dropped out of the rollout at {pct}%");
            }
            seen_inside |= inside;
        }
    }

    #[test]
    fn selection_is_scoped_per_application() {
        let apps = ["alpha", "beta", "gamma", "delta"];
        let editor = in_rollout("install-a", "editor", 50);
        assert!(
            apps.iter()
                .any(|a| in_rollout("install-a", a, 50) != editor),
            "an install unlucky for one app must be selected independently for another"
        );
    }
}
