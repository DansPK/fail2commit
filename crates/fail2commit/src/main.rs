//! fail2commit CLI (CHORE-001 routing, coordinator-owned).
//!
//! Each subcommand lives in `cmd/<name>.rs`, owned by its task worker, which
//! defines `Args` and `run`. This file only parses, routes and prints.

mod cmd;

use clap::{Parser, Subcommand, ValueEnum};
use fail2commit_core::approver::ApproverChoice;
use fail2commit_core::protocol::{Response, PROTOCOL_VERSION};
use std::ffi::OsString;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "fail2commit",
    version,
    about = "Guard Git pushes and npm/pip installs"
)]
pub struct Cli {
    /// Print one versioned JSON Response on stdout instead of text.
    #[arg(long, global = true)]
    json: bool,
    /// Where approvals are requested.
    #[arg(long, global = true, value_enum, default_value_t = ApproverArg::Auto)]
    approver: ApproverArg,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ApproverArg {
    Auto,
    Terminal,
    Tray,
    Stdio,
    None,
}

impl From<ApproverArg> for ApproverChoice {
    fn from(a: ApproverArg) -> Self {
        match a {
            ApproverArg::Auto => ApproverChoice::Auto,
            ApproverArg::Terminal => ApproverChoice::Terminal,
            ApproverArg::Tray => ApproverChoice::Tray,
            ApproverArg::Stdio => ApproverChoice::Stdio,
            ApproverArg::None => ApproverChoice::None,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Install hooks and shims for this user (T-001/T-004/T-005/T-009).
    Setup(cmd::setup::SetupArgs),
    /// Show integrations, sandbox and settings state.
    Status,
    /// Remove only integrations fail2commit installed.
    UninstallIntegrations,
    /// Guarded git (shim target): `fail2commit git push ...` (T-001).
    Git(cmd::git::Args),
    /// Scan outgoing commits for secrets without pushing (T-001).
    SecretScan(cmd::secrets::Args),
    /// Guarded npm ci / install / i (T-004).
    Npm(cmd::npm::Args),
    /// Guarded pip install for a selected interpreter (T-005).
    Pip(cmd::pip::Args),
    /// Advisory and script checks for exact packages (T-006).
    Scan(cmd::scan::Args),
    /// Offline OpenSSF malware list: update / status (CR-020).
    MalwareList(cmd::malware_list::Args),
    /// Run a command in the sandbox with staged input (T-007).
    Run(cmd::run::Args),
    /// Sandbox on / off / status (T-008).
    Sandbox(cmd::sandbox::Args),
    /// Windows, administrators: guard machine-wide npm and pip (CR-013).
    MachineShims(cmd::machine::Args),
    /// Force-push password set / change / reset / disable (T-002).
    Password(cmd::password::Args),
    /// Self-hosted protected remote: pre-receive and approval issuer (T-003).
    Server(cmd::server::Args),
    /// One JSON Request on stdin, JSON lines out (VS Code, T-010).
    Api,
    /// Private Git hook entry points (T-001).
    #[command(hide = true)]
    Hook(cmd::hook::Args),
}

/// Shim names map to subcommands, so `git push` through the shim is
/// `fail2commit git push`.
fn shim_argv(mut argv: Vec<OsString>) -> Vec<OsString> {
    let stem = argv.first().and_then(|a| {
        std::path::Path::new(a)
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
    });
    let sub = match stem.as_deref() {
        Some("git") => "git",
        Some("npm") => "npm",
        Some("pip") | Some("pip3") => "pip",
        _ => return argv,
    };
    argv[0] = OsString::from("fail2commit");
    argv.insert(1, OsString::from(sub));
    argv
}

fn main() -> ExitCode {
    let argv = shim_argv(std::env::args_os().collect());
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { 2 } else { 0 });
        }
    };
    if matches!(cli.command, Command::Api) {
        return exit(cmd::api::run());
    }
    let json = cli.json;
    let response = execute(cli, None);
    cmd::print_response(&response, json);
    exit(response.exit_status())
}

/// Route one parsed command and convert the outcome to a Response.
pub fn execute(cli: Cli, id: Option<String>) -> Response {
    let ctx = match cmd::Ctx::new(cli.json, cli.approver.into()) {
        Ok(ctx) => ctx,
        Err(e) => return cmd::error_response(e, id),
    };
    let result = match cli.command {
        Command::Setup(a) => cmd::setup::install(&ctx, a),
        Command::Status => cmd::setup::status(&ctx),
        Command::UninstallIntegrations => cmd::setup::uninstall(&ctx),
        Command::Git(a) => cmd::git::run(&ctx, a),
        Command::SecretScan(a) => cmd::secrets::run(&ctx, a),
        Command::Npm(a) => cmd::npm::run(&ctx, a),
        Command::Pip(a) => cmd::pip::run(&ctx, a),
        Command::Scan(a) => cmd::scan::run(&ctx, a),
        Command::MalwareList(a) => cmd::malware_list::run(&ctx, a),
        Command::Run(a) => cmd::run::run(&ctx, a),
        Command::Sandbox(a) => cmd::sandbox::run(&ctx, a),
        Command::MachineShims(a) => cmd::machine::run(&ctx, a),
        Command::Password(a) => cmd::password::run(&ctx, a),
        Command::Server(a) => cmd::server::run(&ctx, a),
        Command::Hook(a) => cmd::hook::run(&ctx, a),
        Command::Api => Err(fail2commit_core::Error::invalid("api cannot be nested")),
    };
    match result {
        Ok(o) => Response {
            version: PROTOCOL_VERSION,
            id,
            code: fail2commit_core::ResultCode::Ok,
            message: o.message,
            findings: o.findings,
            tool_exit: o.tool_exit,
            data: o.data,
        },
        Err(e) => cmd::error_response(e, id),
    }
}

fn exit(status: i32) -> ExitCode {
    ExitCode::from(u8::try_from(status.clamp(0, 255)).unwrap_or(70))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn shims_route_to_subcommands() {
        assert_eq!(
            shim_argv(s(&["/x/bin/git", "push", "-f"])),
            s(&["fail2commit", "git", "push", "-f"])
        );
        // Backslash is a path separator only on Windows.
        #[cfg(windows)]
        assert_eq!(
            shim_argv(s(&["C:\\b\\NPM.exe", "ci"])),
            s(&["fail2commit", "npm", "ci"])
        );
        assert_eq!(
            shim_argv(s(&["/b/NPM", "ci"])),
            s(&["fail2commit", "npm", "ci"])
        );
        assert_eq!(
            shim_argv(s(&["pip3", "install", "x"])),
            s(&["fail2commit", "pip", "install", "x"])
        );
        assert_eq!(
            shim_argv(s(&["fail2commit", "status"])),
            s(&["fail2commit", "status"])
        );
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
