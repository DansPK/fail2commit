//! Trusted user settings (CHORE-001 contract; FR-008 semantics).
//!
//! Read only from [`TrustedPaths::settings_file`]. Never merged with any
//! repository file. A malformed file fails closed (InvalidInput); a missing
//! file means defaults (sandbox on). Commands take one snapshot at start so a
//! later change cannot weaken an in-flight job.

use crate::paths::TrustedPaths;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub sandbox: SandboxSettings,
    pub limits: Limits,
    pub advisories: AdvisorySettings,
    pub approval: ApprovalSettings,
    pub signatures: SignatureSettings,
    /// 0.1.4 (FR-013).
    pub ui: UiSettings,
    /// 0.1.4 (FR-018).
    pub threat_data: ThreatDataSettings,
    /// 0.1.4 (FR-025).
    pub checks: CheckSettings,
    /// 0.1.4 (FR-019).
    pub rules: RuleSettings,
}

/// FR-013.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UiSettings {
    /// Windows: open the progress window during guarded installs.
    pub progress_window: bool,
}

impl Default for UiSettings {
    fn default() -> Self {
        UiSettings {
            progress_window: true,
        }
    }
}

/// FR-018.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ThreatDataSettings {
    /// `status` warns when the offline malware index is older than this.
    pub max_age_days: u64,
    /// Refresh an index older than `max_age_days` before a guarded install.
    pub auto_update: bool,
}

impl Default for ThreatDataSettings {
    fn default() -> Self {
        ThreatDataSettings {
            max_age_days: 7,
            auto_update: false,
        }
    }
}

/// FR-025.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CheckSettings {
    pub enabled: bool,
    /// Versions published more recently than this get a finding.
    pub min_age_hours: u64,
}

impl Default for CheckSettings {
    fn default() -> Self {
        CheckSettings {
            enabled: true,
            min_age_hours: 48,
        }
    }
}

/// FR-019.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RuleSettings {
    /// Match package files against the bundled and user YARA rules.
    pub enabled: bool,
}

impl Default for RuleSettings {
    fn default() -> Self {
        RuleSettings { enabled: true }
    }
}

/// FR-023 / CR-022: what sandboxed scripts may reach.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Nothing (the 0.1.3 behaviour).
    None,
    /// Public internet addresses only.
    #[default]
    Internet,
}

/// FR-027 / FR-029: which sandbox backend runs jobs.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackendChoice {
    /// Hardened mode when installed, else the platform default.
    #[default]
    Auto,
    /// Disposable virtual machine (FR-029).
    Vm,
}

/// CR-018 (P-108): npm registry signatures and Sigstore provenance.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SignatureSettings {
    /// Verify registry signatures for every artifact in an install plan.
    pub verify: bool,
    /// How long fetched registry signing keys are trusted before a refetch.
    pub keys_ttl_secs: u64,
}

impl Default for SignatureSettings {
    fn default() -> Self {
        SignatureSettings {
            verify: true,
            keys_ttl_secs: 24 * 3600,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxSettings {
    /// FR-008: defaults to on.
    pub enabled: bool,
    /// FR-023.
    pub network: NetworkMode,
    /// FR-027 / FR-029.
    pub backend: BackendChoice,
}

/// SPEC-012 bounds. Defaults are provisional until T-012 measurements.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub job_timeout_secs: u64,
    pub job_memory_mb: u64,
    pub job_max_processes: u32,
    pub job_max_output_bytes: u64,
    /// 0.1.4: bytes a sandbox job may write into its stage (MiB).
    pub job_disk_mb: u64,
    /// Max bytes of blob content the Git secret scan reads per push.
    pub scan_max_bytes: u64,
    /// Max commits/packages walked per operation.
    pub graph_max_nodes: u64,
    /// Max bytes of one downloaded/extracted artifact.
    pub artifact_max_bytes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AdvisorySettings {
    pub osv_url: String,
    pub offline: bool,
    pub ttl_secs: u64,
    pub cache_max_bytes: u64,
    pub timeout_secs: u64,
    /// CR-020 (P-110): consult the pinned offline OpenSSF malware list when
    /// OSV cannot answer.
    pub offline_malware: bool,
    /// CR-020 (P-110): largest malware-list archive accepted.
    pub malware_list_max_bytes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalSettings {
    /// Seconds an approval request stays valid.
    pub request_ttl_secs: u64,
}

impl Default for SandboxSettings {
    fn default() -> Self {
        SandboxSettings {
            enabled: true,
            network: NetworkMode::Internet,
            backend: BackendChoice::Auto,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            job_timeout_secs: 900,
            job_memory_mb: 2048,
            job_max_processes: 64,
            job_max_output_bytes: 8 * 1024 * 1024,
            // Room for browser downloads such as puppeteer's Chromium.
            job_disk_mb: 4096,
            scan_max_bytes: 256 * 1024 * 1024,
            graph_max_nodes: 100_000,
            artifact_max_bytes: 512 * 1024 * 1024,
        }
    }
}

impl Default for AdvisorySettings {
    fn default() -> Self {
        AdvisorySettings {
            osv_url: "https://api.osv.dev".to_string(),
            offline: false,
            ttl_secs: 6 * 3600,
            // T-012: ~34 B per clean entry; 16 MiB holds far more than any project needs.
            cache_max_bytes: 16 * 1024 * 1024,
            timeout_secs: 15,
            offline_malware: true,
            malware_list_max_bytes: 256 * 1024 * 1024,
        }
    }
}

impl Default for ApprovalSettings {
    fn default() -> Self {
        ApprovalSettings {
            request_ttl_secs: 300,
        }
    }
}

const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

impl Settings {
    pub fn load(paths: &TrustedPaths) -> crate::Result<Settings> {
        let file = paths.settings_file();
        match crate::fsutil::read_bounded(&file, MAX_SETTINGS_BYTES) {
            Ok(bytes) => {
                let text = String::from_utf8(bytes)
                    .map_err(|_| crate::Error::invalid("settings.toml is not UTF-8"))?;
                toml::from_str(&text)
                    .map_err(|e| crate::Error::invalid(format!("settings.toml is invalid: {e}")))
            }
            Err(_) if !file.exists() => Ok(Settings::default()),
            Err(e) => Err(e),
        }
    }

    pub fn store(&self, paths: &TrustedPaths) -> crate::Result<()> {
        let text = toml::to_string(self)
            .map_err(|e| crate::Error::internal(format!("serialize settings: {e}")))?;
        let file = paths.settings_file();
        crate::fsutil::with_lock(&file, || {
            crate::fsutil::atomic_write(&file, text.as_bytes())
        })
    }

    /// Read-modify-write under the settings lock.
    pub fn update(paths: &TrustedPaths, f: impl FnOnce(&mut Settings)) -> crate::Result<Settings> {
        let file = paths.settings_file();
        crate::fsutil::with_lock(&file, || {
            let mut s = Settings::load(paths)?;
            f(&mut s);
            let text = toml::to_string(&s)
                .map_err(|e| crate::Error::internal(format!("serialize settings: {e}")))?;
            crate::fsutil::atomic_write(&file, text.as_bytes())?;
            Ok(s)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let paths = TrustedPaths::under(d.path());
        assert!(Settings::load(&paths).unwrap().sandbox.enabled);
        Settings::update(&paths, |s| s.sandbox.enabled = false).unwrap();
        assert!(!Settings::load(&paths).unwrap().sandbox.enabled);
    }

    #[test]
    fn malformed_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let paths = TrustedPaths::under(d.path());
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.settings_file(), "[sandbox]\nenabled = \"nope\"\n").unwrap();
        assert_eq!(
            Settings::load(&paths).unwrap_err().code,
            crate::ResultCode::InvalidInput
        );
        std::fs::write(paths.settings_file(), "[sandbox]\nenabeld = false\n").unwrap();
        assert!(Settings::load(&paths).is_err(), "unknown keys rejected");
    }
}
