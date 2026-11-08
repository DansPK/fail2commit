//! T-006 (FR-006, SPEC-006) owns this directory.
//!
//! Frozen API used by npm (T-004) and pip (T-005): [`Ecosystem`],
//! [`PackageId`], [`AdvisoryReport`], [`check_advisories`], [`ScriptFile`],
//! [`inspect_scripts`].

use crate::paths::TrustedPaths;
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::settings::AdvisorySettings;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "PyPI")]
    PyPI,
}

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct PackageId {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

impl PackageId {
    /// `npm:name@version` / `PyPI:name@version`, used as `Finding::target`.
    pub fn display(&self) -> String {
        let eco = match self.ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
        };
        format!("{eco}:{}@{}", self.name, self.version)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvisoryReport {
    /// Advisory/Malware findings (Approve), plus IncompleteScan/StaleData.
    pub findings: Vec<Finding>,
    /// False when any lookup failed or data was too stale to trust.
    pub complete: bool,
}

/// Batch OSV lookup (vulnerabilities + OpenSSF malware) for exact versions,
/// with the bounded disk cache under `paths.cache_dir`.
pub fn check_advisories(
    paths: &TrustedPaths,
    settings: &AdvisorySettings,
    pkgs: &[PackageId],
) -> AdvisoryReport {
    let _ = (paths, settings);
    AdvisoryReport {
        findings: vec![Finding::new(
            FindingKind::IncompleteScan,
            FindingAction::Approve,
            "scan",
            format!(
                "advisory scanning not implemented; {} package(s) unchecked",
                pkgs.len()
            ),
        )],
        complete: false,
    }
}

/// A local file referenced by a lifecycle script (already extracted by the
/// adapter, bounded in size). Never executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptFile {
    /// Path relative to the package root.
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Inspect lifecycle entries (`(name, command)`) and referenced files for
/// Git force-push evidence. Flagged scripts are `Deny` SuspiciousScript.
pub fn inspect_scripts(
    pkg: &PackageId,
    scripts: &[(String, String)],
    files: &[ScriptFile],
) -> Vec<Finding> {
    let _ = files;
    if scripts.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        FindingKind::IncompleteScan,
        FindingAction::Approve,
        "scan.scripts",
        "script inspection not implemented",
    )
    .target(pkg.display())]
}
