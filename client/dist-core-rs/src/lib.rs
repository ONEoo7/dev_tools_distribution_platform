//! Shared TUF verifier for the update client.
//!
//! This crate is the single security-critical implementation in the client
//! (PLAN.md decision D2). The five language bindings — napi-rs, `PyO3`, a native
//! crate, P/Invoke and a C header — are thin wrappers over it and contain no
//! verification logic of their own, so a defect in one binding cannot weaken
//! the signature check for any other.
//!
//! # Structure
//!
//! Verification reaches the rest of the client through the [`Verifier`] trait.
//! The `tuf` crate is pre-1.0 (currently `0.3.0-beta9`) and documents its API
//! as unstable, so decision D1 requires it to sit behind that trait: nothing
//! outside [`verifier`] may name a `tuf` or `chrono` type. If the crate stalls
//! or churns, the blast radius is one module rather than the install logic,
//! the bindings and the platform traits.

#![forbid(unsafe_code)]

pub mod broker;
pub mod install;
pub mod rollout;
pub mod verifier;

pub use install::{Health, InstallError, InstallLayout, Installer, PerUserLayout, Pointer};
pub use verifier::{
    ReleaseInfo, Role, TargetInfo, TufVerifier, Verifier, VerifyError, verify_payload,
};

use std::fmt;

/// Identifies one published artifact.
///
/// Rendered form is `<app-id>/<channel>/<platform>-<arch>/<version>/<file>`,
/// matching `dist_core.naming.TargetKey` on the server (PLAN.md 3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPath(String);

impl TargetPath {
    /// Number of segments a well-formed target path has.
    pub const SEGMENTS: usize = 5;

    /// Accepts a target path only if every segment is safe to use on disk.
    ///
    /// A delegated role can name a target such as `app/../../x` that still
    /// satisfies the delegation pattern's segment count (PLAN.md 3.4), so a
    /// path that TUF considers delegated is *not* automatically safe to join
    /// onto a local directory. This is the check that makes it safe.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::SegmentCount`] if the path does not have exactly
    /// [`Self::SEGMENTS`] segments, or [`PathError::UnsafeSegment`] if any
    /// segment is empty, a traversal component, or contains a separator,
    /// drive-letter colon or NUL byte.
    pub fn parse(raw: &str) -> Result<Self, PathError> {
        let segments: Vec<&str> = raw.split('/').collect();
        if segments.len() != Self::SEGMENTS {
            return Err(PathError::SegmentCount(segments.len()));
        }
        for segment in &segments {
            if segment.is_empty() || *segment == "." || *segment == ".." {
                return Err(PathError::UnsafeSegment((*segment).to_owned()));
            }
            if segment.contains('\\') || segment.contains(':') || segment.contains('\0') {
                return Err(PathError::UnsafeSegment((*segment).to_owned()));
            }
        }
        Ok(Self(raw.to_owned()))
    }

    /// The path as it appears in TUF metadata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a target path was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The path did not have exactly [`TargetPath::SEGMENTS`] segments.
    SegmentCount(usize),
    /// A segment was empty, a traversal component, or contained a separator.
    UnsafeSegment(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SegmentCount(n) => {
                write!(
                    f,
                    "expected {} path segments, got {n}",
                    TargetPath::SEGMENTS
                )
            }
            Self::UnsafeSegment(s) => write!(f, "unsafe path segment {s:?}"),
        }
    }
}

impl std::error::Error for PathError {}

#[cfg(test)]
mod tests {
    use super::{PathError, TargetPath};

    #[test]
    fn accepts_a_well_formed_target_path() {
        let raw = "editor/stable/windows-amd64/1.4.2/Editor-1.4.2.zip";
        assert_eq!(
            TargetPath::parse(raw).map(|p| p.as_str().to_owned()),
            Ok(raw.to_owned())
        );
    }

    #[test]
    fn rejects_traversal_that_satisfies_the_segment_count() {
        // Exactly five segments, so TUF's delegation matcher accepts this as
        // belonging to `editor` -- the segment count alone is not a defence.
        assert_eq!(
            TargetPath::parse("editor/../../etc/passwd"),
            Err(PathError::UnsafeSegment("..".to_owned()))
        );
    }

    #[test]
    fn rejects_single_dot_segments() {
        assert_eq!(
            TargetPath::parse("editor/./windows-amd64/1.4.2/x.zip"),
            Err(PathError::UnsafeSegment(".".to_owned()))
        );
    }

    #[test]
    fn rejects_wrong_segment_count() {
        assert_eq!(
            TargetPath::parse("editor/stable"),
            Err(PathError::SegmentCount(2))
        );
    }

    #[test]
    fn rejects_windows_separators_and_drive_letters() {
        assert!(TargetPath::parse("editor/stable/windows-amd64/1.4.2/..\\evil.exe").is_err());
        assert!(TargetPath::parse("editor/stable/windows-amd64/1.4.2/C:evil.exe").is_err());
    }

    #[test]
    fn rejects_empty_segments() {
        assert_eq!(
            TargetPath::parse("editor//windows-amd64/1.4.2/x.zip"),
            Err(PathError::UnsafeSegment(String::new()))
        );
    }
}
