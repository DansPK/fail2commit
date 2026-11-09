//! `server install`: hook + config + push-option advertisement for a bare repo.

use super::config::{ServerConfig, ServerHome};
use std::path::Path;

const MARKER: &str = "# fail2commit-managed pre-receive";

fn shell_quote(p: &Path) -> crate::Result<String> {
    let s = p.to_string_lossy().replace('\\', "/");
    if s.contains(['\'', '\n', '\r']) {
        return Err(crate::Error::invalid(format!("unsupported path {s:?}")));
    }
    Ok(format!("'{s}'"))
}

pub fn install(
    repo: &Path,
    state: &Path,
    exe: &Path,
    protect: &[String],
    git: &Path,
) -> crate::Result<()> {
    let canon = repo
        .canonicalize()
        .map_err(|e| crate::Error::invalid(format!("repository unusable: {e}")))?;
    crate::fsutil::ensure_private_dir(state)?;
    let home = ServerHome::resolve(Some(state))?;
    if home.dir().starts_with(&canon) {
        return Err(crate::Error::invalid(
            "server state must be outside the repository",
        ));
    }
    let bare = crate::winenv::command(git)
        .arg("--git-dir")
        .arg(repo)
        .args(["rev-parse", "--is-bare-repository"])
        .output()?;
    if String::from_utf8_lossy(&bare.stdout).trim() != "true" {
        return Err(crate::Error::invalid("not a bare Git repository"));
    }
    let hook = canon.join("hooks").join("pre-receive");
    if hook.exists() && !std::fs::read_to_string(&hook).is_ok_and(|t| t.contains(MARKER)) {
        return Err(crate::Error::invalid(
            "a different pre-receive hook already exists; not overwriting",
        ));
    }
    if !home.config_file().exists() {
        let mut cfg = ServerConfig::default();
        if !protect.is_empty() {
            cfg.protected_refs = protect.to_vec();
        }
        cfg.validate()?;
        home.store_config(&cfg)?;
    }
    // FAIL2COMMIT_HOME keeps the shared Ctx away from the service user's real home.
    let script = format!(
        "#!/bin/sh\n{MARKER}\nFAIL2COMMIT_HOME={}; export FAIL2COMMIT_HOME\nexec {} server pre-receive --state {}\n",
        shell_quote(&home.dir().join("ctx"))?,
        shell_quote(exe)?,
        shell_quote(home.dir())?
    );
    std::fs::create_dir_all(hook.parent().expect("hook has parent"))?;
    std::fs::write(&hook, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))?;
    }
    let st = crate::winenv::command(git)
        .arg("--git-dir")
        .arg(repo)
        .args(["config", "receive.advertisePushOptions", "true"])
        .status()?;
    if !st.success() {
        return Err(crate::Error::internal("could not enable push options"));
    }
    Ok(())
}
