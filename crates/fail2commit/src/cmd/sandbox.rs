//! `fail2commit sandbox on | off | status` (FR-008). The tray and the VS Code
//! extension toggle the same trusted setting through this command.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::sandbox::select_backend;
use fail2commit_core::settings::Settings;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(clap::Subcommand, Debug)]
pub enum Action {
    /// Run required package scripts in the sandbox (default).
    On,
    /// Skip package scripts; a required script needs "Run on host once".
    Off,
    /// Show the setting and the isolation backend probe.
    Status,
    /// Service entry point (socket activation on Linux; SCM on Windows).
    #[command(hide = true)]
    Serve,
    /// Service-only launcher entry point; never exposed in CLI help.
    #[command(hide = true)]
    Launch {
        jobfile: std::path::PathBuf,
        #[arg(long)]
        watchdog: Option<u64>,
        #[arg(long)]
        prepare_request: Option<u64>,
        #[arg(long)]
        prepare_ack: Option<u64>,
        #[arg(long)]
        launch_id: Option<String>,
        #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
        #[arg(long, hide = true)]
        test_diagnostic: bool,
    },
    /// Fixed internal payload for the authenticated Windows network probe.
    #[command(hide = true)]
    EgressProbe,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let enabled = match &args.action {
        Action::Status => ctx.settings.sandbox.enabled,
        Action::On | Action::Off => {
            let on = matches!(&args.action, Action::On);
            ctx.paths.ensure()?;
            Settings::update(&ctx.paths, |s| s.sandbox.enabled = on)?
                .sandbox
                .enabled
        }
        Action::Serve | Action::Launch { .. } | Action::EgressProbe => {
            return Err(fail2commit_core::Error::rejected(
                "private sandbox entry point was not routed",
            ));
        }
    };
    let probe = select_backend(&ctx.settings).probe();
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
    if !matches!(&args.action, Action::Status) && !enabled {
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

pub fn serve() -> fail2commit_core::Result<()> {
    fail2commit_core::sandbox::hardened::serve()
}

pub fn launch(
    jobfile: &std::path::Path,
    watchdog: Option<u64>,
    prepare_request: Option<u64>,
    prepare_ack: Option<u64>,
    launch_id: Option<&str>,
) -> fail2commit_core::Result<()> {
    fail2commit_core::sandbox::hardened::launch_with_control(
        jobfile,
        watchdog,
        prepare_request,
        prepare_ack,
        launch_id,
    )
}

#[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
pub fn launch_test_diagnostic(
    jobfile: &std::path::Path,
    watchdog: Option<u64>,
    prepare_request: Option<u64>,
    prepare_ack: Option<u64>,
    launch_id: Option<&str>,
) -> fail2commit_core::Result<()> {
    fail2commit_core::sandbox::hardened::launch_with_test_diagnostic_control(
        jobfile,
        watchdog,
        prepare_request,
        prepare_ack,
        launch_id,
    )
}
