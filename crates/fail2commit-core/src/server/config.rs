//! Server home directory and policy file (`server.toml`).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Exact refs, or a prefix ending in `*` (e.g. `refs/heads/release/*`).
    pub protected_refs: Vec<String>,
    /// When true, pushes to protected refs must pass the outgoing secret scan.
    pub secret_policy: bool,
    /// Upper bound for an issued approval token's lifetime.
    pub max_token_ttl_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            protected_refs: vec!["refs/heads/main".into()],
            secret_policy: false,
            max_token_ttl_secs: 900,
        }
    }
}

impl ServerConfig {
    pub fn is_protected(&self, refname: &str) -> bool {
        self.protected_refs
            .iter()
            .any(|p| match p.strip_suffix('*') {
                Some(prefix) => refname.starts_with(prefix),
                None => p == refname,
            })
    }

    pub(crate) fn validate(&self) -> crate::Result<()> {
        for p in &self.protected_refs {
            let body = p.strip_suffix('*').unwrap_or(p);
            if !p.starts_with("refs/") || body.contains('*') || p.chars().any(char::is_control) {
                return Err(crate::Error::invalid(format!(
                    "invalid protected ref pattern {p:?}"
                )));
            }
        }
        if self.max_token_ttl_secs == 0 {
            return Err(crate::Error::invalid("max_token_ttl_secs must be > 0"));
        }
        Ok(())
    }
}

/// Trusted server directory: `server.toml` + `approvals.json`.
#[derive(Clone, Debug)]
pub struct ServerHome(PathBuf);

impl ServerHome {
    /// `--state` wins, then `FAIL2COMMIT_SERVER_HOME`. Must be an absolute,
    /// existing directory that other users cannot write to.
    pub fn resolve(state: Option<&Path>) -> crate::Result<Self> {
        let raw = match state {
            Some(p) => p.to_path_buf(),
            None => std::env::var_os("FAIL2COMMIT_SERVER_HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| {
                    crate::Error::invalid(
                        "server state not set: use --state or FAIL2COMMIT_SERVER_HOME",
                    )
                })?,
        };
        if !raw.is_absolute() {
            return Err(crate::Error::invalid(
                "server state must be an absolute path",
            ));
        }
        let dir = raw
            .canonicalize()
            .map_err(|e| crate::Error::invalid(format!("server state is unusable: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&dir)?.permissions().mode() & 0o022 != 0 {
                return Err(crate::Error::invalid(
                    "server state must not be group- or world-writable",
                ));
            }
        }
        Ok(ServerHome(dir))
    }

    pub fn dir(&self) -> &Path {
        &self.0
    }

    pub(crate) fn config_file(&self) -> PathBuf {
        self.0.join("server.toml")
    }

    pub(crate) fn approvals_file(&self) -> PathBuf {
        self.0.join("approvals.json")
    }

    /// A missing or malformed policy file is an error: the caller denies.
    pub fn load_config(&self) -> crate::Result<ServerConfig> {
        let bytes =
            crate::fsutil::read_bounded(&self.config_file(), MAX_CONFIG_BYTES).map_err(|e| {
                crate::Error::invalid(format!("server.toml unavailable: {}", e.message))
            })?;
        let text = String::from_utf8(bytes)
            .map_err(|_| crate::Error::invalid("server.toml is not UTF-8"))?;
        let cfg: ServerConfig = toml::from_str(&text)
            .map_err(|e| crate::Error::invalid(format!("server.toml is invalid: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub(crate) fn store_config(&self, cfg: &ServerConfig) -> crate::Result<()> {
        let text = toml::to_string(cfg)
            .map_err(|e| crate::Error::internal(format!("serialize server.toml: {e}")))?;
        crate::fsutil::atomic_write(&self.config_file(), text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_matching() {
        let c = ServerConfig {
            protected_refs: vec!["refs/heads/main".into(), "refs/heads/release/*".into()],
            ..Default::default()
        };
        assert!(c.is_protected("refs/heads/main"));
        assert!(!c.is_protected("refs/heads/main2"));
        assert!(c.is_protected("refs/heads/release/1.0"));
        assert!(!c.is_protected("refs/heads/feature"));
        let bad = ServerConfig {
            protected_refs: vec!["refs/*/x".into()],
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }
}
