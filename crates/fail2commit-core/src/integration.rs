//! Setup/uninstall contract (CHORE-001, frozen).
//!
//! `fail2commit setup` calls `install` on each registered integration and
//! records the returned [`OwnedChange`]s in `setup.json`. Uninstall passes
//! back exactly those records so only owned changes are rolled back
//! (third-party hooks, user hooksPath, PATH entries stay intact).

use crate::paths::TrustedPaths;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub struct SetupCtx {
    pub paths: TrustedPaths,
    /// The installed fail2commit executable that shims/hooks call.
    pub exe: PathBuf,
    /// Report what would change without writing.
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OwnedChange {
    /// Integration id that created it.
    pub integration: String,
    /// Integration-defined kind, e.g. `git-config`, `hook-file`, `shim`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Whatever is needed to restore the previous state exactly.
    #[serde(default)]
    pub detail: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IntegrationStatus {
    pub id: String,
    pub installed: bool,
    pub detail: String,
}

pub trait Integration {
    fn id(&self) -> &'static str;
    fn install(&self, ctx: &SetupCtx) -> crate::Result<Vec<OwnedChange>>;
    fn uninstall(&self, ctx: &SetupCtx, owned: &[OwnedChange]) -> crate::Result<()>;
    fn status(&self, ctx: &SetupCtx) -> IntegrationStatus;
}

/// Persisted in `TrustedPaths::setup_file()`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct SetupState {
    pub version: u32,
    pub changes: Vec<OwnedChange>,
}
