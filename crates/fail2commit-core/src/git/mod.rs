//! T-001 (FR-001, SPEC-001) owns this directory.
//!
//! Frozen API used by the server (T-003) and setup: [`RefUpdate`],
//! [`classify_updates`], [`scan_outgoing`], [`integration`].

use crate::integration::Integration;
use crate::protocol::Finding;
use crate::settings::Limits;
use std::path::Path;

mod classify;
mod detect;
pub(crate) mod gitcmd;
mod integ;
pub mod intent;
pub mod prepush;
mod scan;

pub use integ::{
    default_path_editor, hooks_dir, shim_path, GitIntegration, PathEditor, ProfileEditor,
    PATH_TARGET_ENV,
};

/// One proposed ref update, as Git reports it to pre-push / pre-receive.
/// OIDs are lowercase hex; all-zero means "does not exist".
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefUpdate {
    /// Destination ref, e.g. `refs/heads/main`.
    pub refname: String,
    pub old: String,
    pub new: String,
}

impl RefUpdate {
    pub fn is_zero(oid: &str) -> bool {
        !oid.is_empty() && oid.bytes().all(|b| b == b'0')
    }
}

/// Rewrites (non-fast-forward), deletions and tag replacements among
/// `updates`, checked with Git ancestry in `repo`. A missing old object is
/// a finding, never assumed safe.
pub fn classify_updates(
    git: &Path,
    repo: &Path,
    updates: &[RefUpdate],
) -> crate::Result<Vec<Finding>> {
    classify::classify(git, repo, updates)
}

/// Secret findings in commits that `updates` would publish, excluding
/// history provably reachable from `remote` (a remote name) when given.
/// Bounded by `limits`; an incomplete walk yields an IncompleteScan finding.
pub fn scan_outgoing(
    git: &Path,
    repo: &Path,
    updates: &[RefUpdate],
    remote: Option<&str>,
    limits: &Limits,
) -> crate::Result<Vec<Finding>> {
    scan::scan(git, repo, updates, remote, limits)
}

/// Git hook + shim integration for `fail2commit setup`.
pub fn integration() -> Option<Box<dyn Integration>> {
    Some(Box::new(GitIntegration::new(default_path_editor())))
}
