//! `fail2commit sandbox on | off | status` (FR-008). The tray and the VS Code
//! extension toggle the same trusted setting through this command.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::sandbox::platform_backend;
use fail2commit_core::settings::Settings;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(clap::Subcommand, Debug, Clone, Copy)]
pub enum Action {
    /// Run required package scripts in the sandbox (default).
    On,
    /// Skip package scripts; a required script needs "Run on host once".
    Off,
    /// Show the setting and the isolation backend probe.
    Status,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let enabled = match args.action {
        Action::Status => ctx.settings.sandbox.enabled,
        Action::On | Action::Off => {
            let on = matches!(args.action, Action::On);
            ctx.paths.ensure()?;
            Settings::update(&ctx.paths, |s| s.sandbox.enabled = on)?
                .sandbox
                .enabled
        }
    };
    let probe = platform_backend().probe();
    let mut text = format!(
        "sandbox: {}\nbackend: {} ({})",
        if enabled { "on" } else { "off" },
        probe.backend,
        if probe.available {
            "available"
        } else {
            "unavailable"
        },
    );
    if !probe.detail.is_empty() {
        text.push_str(&format!("\ndetail: {}", probe.detail));
    }
    for (name, ok) in &probe.controls {
        text.push_str(&format!(
            "\n  {name}: {}",
            if *ok { "ok" } else { "missing" }
        ));
    }
    if !matches!(args.action, Action::Status) && !enabled {
        text.push_str(
            "\nscripts will be skipped by default; a required script needs a separate \
             \"Run on host once\" approval. Dependency scans, integrity and Git checks stay active.",
        );
    }
    if enabled && !probe.available {
        text.push_str("\nsandbox is on but unavailable: installs with scripts will fail closed.");
    }
    Ok(Outcome {
        message: text,
        data: serde_json::json!({
            "sandbox": enabled,
            "backend": probe.backend,
            "available": probe.available,
            "detail": probe.detail,
            "controls": probe.controls.iter()
                .map(|(n, ok)| serde_json::json!({"name": n, "ok": ok}))
                .collect::<Vec<_>>(),
        }),
        ..Default::default()
    })
}
