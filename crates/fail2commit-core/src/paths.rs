//! Trusted per-user locations (CHORE-001, frozen).
//!
//! Trusted policy, credential verifiers, setup state and approvals live only
//! here, never in a repository. `FAIL2COMMIT_HOME` relocates everything under
//! one directory; it exists for disposable test homes. Anyone who can set the
//! user's environment already runs as that user, so it grants nothing.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPaths {
    /// settings.toml
    pub config_dir: PathBuf,
    /// password/recovery verifiers, setup.json, approvals, locks
    pub state_dir: PathBuf,
    /// advisory cache, staging areas
    pub cache_dir: PathBuf,
    /// shims (git/npm/pip) when integrations are installed
    pub bin_dir: PathBuf,
}

impl TrustedPaths {
    pub fn resolve() -> crate::Result<Self> {
        if let Some(home) = std::env::var_os("FAIL2COMMIT_HOME").filter(|v| !v.is_empty()) {
            return Ok(Self::under(Path::new(&home)));
        }
        Self::platform()
    }

    /// All locations below one root (tests, `FAIL2COMMIT_HOME`).
    pub fn under(root: &Path) -> Self {
        TrustedPaths {
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            bin_dir: root.join("bin"),
        }
    }

    #[cfg(windows)]
    fn platform() -> crate::Result<Self> {
        let roaming = env_dir("APPDATA")?;
        let local = env_dir("LOCALAPPDATA")?;
        Ok(TrustedPaths {
            config_dir: roaming.join("fail2commit"),
            state_dir: local.join("fail2commit").join("state"),
            cache_dir: local.join("fail2commit").join("cache"),
            bin_dir: local.join("fail2commit").join("bin"),
        })
    }

    #[cfg(not(windows))]
    fn platform() -> crate::Result<Self> {
        let home = env_dir("HOME")?;
        let xdg = |var: &str, fallback: &str| -> PathBuf {
            std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(fallback))
                .join("fail2commit")
        };
        Ok(TrustedPaths {
            config_dir: xdg("XDG_CONFIG_HOME", ".config"),
            state_dir: xdg("XDG_STATE_HOME", ".local/state"),
            cache_dir: xdg("XDG_CACHE_HOME", ".cache"),
            bin_dir: xdg("XDG_DATA_HOME", ".local/share").join("bin"),
        })
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config_dir.join("settings.toml")
    }

    pub fn setup_file(&self) -> PathBuf {
        self.state_dir.join("setup.json")
    }

    /// Create every directory with private permissions.
    pub fn ensure(&self) -> crate::Result<()> {
        for d in [
            &self.config_dir,
            &self.state_dir,
            &self.cache_dir,
            &self.bin_dir,
        ] {
            crate::fsutil::ensure_private_dir(d)?;
        }
        Ok(())
    }
}

fn env_dir(var: &str) -> crate::Result<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| crate::Error::internal(format!("{var} is not set to an absolute path")))
}
