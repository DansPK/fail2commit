//! `fail2commit password set|change|reset|disable|status|verify` (FR-002).
//!
//! Passwords and recovery codes come only from hidden console input. Any
//! extra argument or a secret-looking `FAIL2COMMIT_*` variable is refused
//! without echoing its value.

use super::{CmdResult, Ctx, Outcome};
use console::Zeroizing;
use fail2commit_core::approval::{self, console, password};
use fail2commit_core::approver::new_request;
use fail2commit_core::digest::Digest;
use fail2commit_core::protocol::{ApprovalKind, Decision};
use fail2commit_core::Error;
use std::ffi::OsString;

/// Arguments are captured raw and parsed here, so a mistyped secret is
/// refused without being echoed back by an "unrecognized argument" error.
#[derive(clap::Args, Debug)]
#[command(after_help = USAGE)]
pub struct Args {
    /// set | change | reset | disable | status | verify
    #[arg(
        value_name = "ACTION",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub args: Vec<OsString>,
}

const USAGE: &str = "Actions:
  set      Enable the force-push password; shows a recovery code once
  change   Replace the password (asks for the current one)
  reset    Set a new password with the recovery code; rotates the code
  disable  Turn the password off (asks for the current one)
  status   Show whether the password is enabled (never shows secrets)
  verify   Request a password-protected approval through the selected approver

Passwords and recovery codes are read only from hidden console input.";

enum Action {
    Set,
    Change,
    Reset,
    Disable,
    Status,
    Verify,
}

fn parse(args: &[OsString]) -> fail2commit_core::Result<Action> {
    let action = match args {
        [one] => match one.to_str() {
            Some("set") => Some(Action::Set),
            Some("change") => Some(Action::Change),
            Some("reset") => Some(Action::Reset),
            Some("disable") => Some(Action::Disable),
            Some("status") => Some(Action::Status),
            Some("verify") => Some(Action::Verify),
            _ => None,
        },
        _ => None,
    };
    action.ok_or_else(|| {
        Error::invalid(
            "usage: fail2commit password set|change|reset|disable|status|verify (no other arguments; passwords and recovery codes are read only from hidden console input)",
        )
    })
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let action = parse(&args.args)?;
    password::reject_secret_env()?;
    let paths = &ctx.paths;
    match action {
        Action::Status => {
            let s = password::status(paths)?;
            let mut o = Outcome::msg(if s.enabled {
                "force-push password is enabled"
            } else {
                "force-push password is not set"
            });
            o.data = serde_json::to_value(&s).map_err(|e| Error::internal(e.to_string()))?;
            Ok(o)
        }
        Action::Set => {
            need_console()?;
            if password::enabled(paths)? {
                return Err(Error::invalid(
                    "a password is already set; use `password change` or `password reset`",
                ));
            }
            let new = new_password()?;
            let code = password::set(paths, &new)?;
            show_code(code)?;
            Ok(Outcome::msg(
                "force-push password enabled; the recovery code was shown on the console once",
            ))
        }
        Action::Change => {
            need_console()?;
            let current = console::read_secret("Current force-push password: ")?;
            let new = new_password()?;
            password::change(paths, &current, &new)?;
            Ok(Outcome::msg("force-push password changed"))
        }
        Action::Reset => {
            need_console()?;
            let code = console::read_secret("Recovery code: ")?;
            let new = new_password()?;
            let next = password::reset(paths, &code, &new)?;
            show_code(next)?;
            Ok(Outcome::msg(
                "force-push password reset; the old recovery code no longer works and the new one was shown on the console once",
            ))
        }
        Action::Disable => {
            need_console()?;
            let current = console::read_secret("Current force-push password: ")?;
            password::disable(paths, &current)?;
            Ok(Outcome::msg("force-push password disabled"))
        }
        Action::Verify => verify(ctx),
    }
}

fn need_console() -> fail2commit_core::Result<()> {
    if console::interactive() {
        Ok(())
    } else {
        Err(Error::approval_unavailable(
            "password commands need an interactive console for hidden input",
        ))
    }
}

fn new_password() -> fail2commit_core::Result<Zeroizing<String>> {
    let a = console::read_secret(&format!(
        "New force-push password (at least {} characters): ",
        password::MIN_PASSWORD_CHARS
    ))?;
    let b = console::read_secret("Repeat new password: ")?;
    if fail2commit_core::digest::ct_eq(a.as_bytes(), b.as_bytes()) {
        Ok(a)
    } else {
        Err(Error::invalid("passwords do not match"))
    }
}

fn show_code(code: password::RecoveryCode) -> fail2commit_core::Result<()> {
    console::show_secret(&format!(
        "\nRecovery code (shown once; store it offline):\n\n    {}\n\n",
        code.expose()
    ))
}

/// Exercises the full approval path (channel, binding, password, rate
/// limit, replay) against a self-test operation.
fn verify(ctx: &Ctx) -> CmdResult {
    if !approval::password_required(&ctx.paths)? {
        return Err(Error::invalid("no force-push password is set"));
    }
    let digest = Digest::of(
        "password.verify",
        &[fail2commit_core::approver::session_id()],
    )?;
    let req = new_request(
        ApprovalKind::Operation,
        &digest,
        "fail2commit password verify (self-test; changes nothing)",
        vec![],
        vec![],
        ctx.settings.approval.request_ttl_secs,
        true,
        vec![Decision::ApproveOnce],
    )?;
    match approval::approve(&ctx.approval(), &req)? {
        Decision::ApproveOnce => Ok(Outcome::msg("password verified")),
        _ => Err(Error::rejected("approval canceled")),
    }
}
