//! setup / status / uninstall-integrations (CHORE-001, coordinator-owned).
//! Integrations come from each area's frozen `integration()`.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::integration::{Integration, OwnedChange, SetupCtx, SetupState};
use fail2commit_core::Error;

#[derive(clap::Args, Debug)]
pub struct SetupArgs {
    /// Show what would change without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

fn integrations() -> Vec<Box<dyn Integration>> {
    use fail2commit_core::{git, ipc, npm, pip};
    [
        git::integration(),
        npm::integration(),
        pip::integration(),
        ipc::integration(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn setup_ctx(ctx: &Ctx, dry_run: bool) -> fail2commit_core::Result<SetupCtx> {
    let exe = std::env::current_exe()?;
    Ok(SetupCtx {
        paths: ctx.paths.clone(),
        exe,
        dry_run,
    })
}

fn load_state(ctx: &Ctx) -> fail2commit_core::Result<SetupState> {
    let file = ctx.paths.setup_file();
    if !file.exists() {
        return Ok(SetupState {
            version: 1,
            changes: vec![],
        });
    }
    let bytes = fail2commit_core::fsutil::read_bounded(&file, 4 * 1024 * 1024)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::invalid(format!("setup.json is invalid: {e}")))
}

fn store_state(ctx: &Ctx, state: &SetupState) -> fail2commit_core::Result<()> {
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| Error::internal(e.to_string()))?;
    fail2commit_core::fsutil::atomic_write(&ctx.paths.setup_file(), &bytes)
}

pub fn install(ctx: &Ctx, args: SetupArgs) -> CmdResult {
    let sctx = setup_ctx(ctx, args.dry_run)?;
    if !args.dry_run {
        ctx.paths.ensure()?;
    }
    let file = ctx.paths.setup_file();
    let run = || {
        let mut state = load_state(ctx)?;
        let mut installed = Vec::new();
        for i in integrations() {
            // Re-running setup replaces this integration's records only after a successful install.
            let changes: Vec<OwnedChange> = i.install(&sctx)?;
            if !args.dry_run {
                state.changes.retain(|c| c.integration != i.id());
                state.changes.extend(changes);
                state.version = 1;
                store_state(ctx, &state)?;
            }
            installed.push(i.id());
        }
        Ok(installed)
    };
    let installed = if args.dry_run {
        run()?
    } else {
        fail2commit_core::fsutil::with_lock(&file, run)?
    };
    let mut o = Outcome::msg(if installed.is_empty() {
        "no integrations are available in this build".to_string()
    } else {
        format!(
            "{} integration(s): {}",
            if args.dry_run {
                "would install"
            } else {
                "installed"
            },
            installed.join(", ")
        )
    });
    o.data = serde_json::json!({ "integrations": installed, "dry_run": args.dry_run });
    Ok(o)
}

pub fn uninstall(ctx: &Ctx) -> CmdResult {
    let sctx = setup_ctx(ctx, false)?;
    let file = ctx.paths.setup_file();
    let removed = fail2commit_core::fsutil::with_lock(&file, || {
        let mut state = load_state(ctx)?;
        let mut removed = Vec::new();
        for i in integrations() {
            let owned: Vec<OwnedChange> = state
                .changes
                .iter()
                .filter(|c| c.integration == i.id())
                .cloned()
                .collect();
            if owned.is_empty() {
                continue;
            }
            i.uninstall(&sctx, &owned)?;
            state.changes.retain(|c| c.integration != i.id());
            store_state(ctx, &state)?;
            removed.push(i.id());
        }
        Ok(removed)
    })?;
    let mut o = Outcome::msg(format!("removed {} integration(s)", removed.len()));
    o.data = serde_json::json!({ "removed": removed });
    Ok(o)
}

pub fn status(ctx: &Ctx) -> CmdResult {
    let sctx = setup_ctx(ctx, true)?;
    let integrations: Vec<_> = integrations().iter().map(|i| i.status(&sctx)).collect();
    let probe = fail2commit_core::sandbox::platform_backend().probe();
    let mut o = Outcome::msg(format!(
        "sandbox {} ({}: {})",
        if ctx.settings.sandbox.enabled {
            "on"
        } else {
            "off"
        },
        probe.backend,
        if probe.available {
            "available"
        } else {
            "unavailable"
        }
    ));
    o.data = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "integrations": integrations,
        // SPEC-012: report the configured bounds in effect.
        "limits": ctx.settings.limits,
        "advisories": {
            "offline": ctx.settings.advisories.offline,
            "ttl_secs": ctx.settings.advisories.ttl_secs,
            "cache_max_bytes": ctx.settings.advisories.cache_max_bytes,
            "timeout_secs": ctx.settings.advisories.timeout_secs,
        },
        "sandbox": {
            "enabled": ctx.settings.sandbox.enabled,
            "backend": probe.backend,
            "available": probe.available,
            "detail": probe.detail,
        },
        "paths": {
            "config": ctx.paths.config_dir,
            "state": ctx.paths.state_dir,
            "cache": ctx.paths.cache_dir,
            "bin": ctx.paths.bin_dir,
        },
    });
    Ok(o)
}
