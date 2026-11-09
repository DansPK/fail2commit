//! `fail2commit server` (T-003, FR-003): pre-receive hook, maintainer-side
//! approval issuer and hook installer. See docs/server.md.

use super::{CmdResult, Ctx, Outcome};
use clap::Subcommand;
use fail2commit_core::server::{self, ReceiveInput, ServerHome};
use fail2commit_core::toolpath::find_real;
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    cmd: Sub,
}

#[derive(Subcommand, Debug)]
enum Sub {
    /// Git pre-receive hook entry point (reads ref updates on stdin).
    PreReceive {
        /// Server state directory (default: FAIL2COMMIT_SERVER_HOME).
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Maintainer-side: mint a one-time approval token for an exact update set.
    Approve {
        #[arg(long)]
        state: Option<PathBuf>,
        /// Bare repository the push targets.
        #[arg(long)]
        repo: PathBuf,
        /// Authenticated actor the token is bound to.
        #[arg(long)]
        actor: String,
        /// Exact ref update as REF:OLD:NEW (full object ids); repeatable.
        #[arg(long = "update", required = true)]
        updates: Vec<String>,
        /// Token lifetime in seconds.
        #[arg(long, default_value_t = 300)]
        ttl: u64,
    },
    /// Install the pre-receive hook and config into a bare repository.
    Install {
        repo: PathBuf,
        #[arg(long)]
        state: Option<PathBuf>,
        /// Protected ref or `prefix*` pattern; repeatable (default refs/heads/main).
        #[arg(long = "protect")]
        protect: Vec<String>,
    },
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    match args.cmd {
        Sub::PreReceive { state } => {
            let home = ServerHome::resolve(state.as_deref())?;
            let input = ReceiveInput::from_hook_env(std::io::stdin().lock())?;
            let git = find_real("git", None)?;
            server::pre_receive(&home, &git, &ctx.settings.limits, &input)?;
            Ok(Outcome::default())
        }
        Sub::Approve {
            state,
            repo,
            actor,
            updates,
            ttl,
        } => {
            let home = ServerHome::resolve(state.as_deref())?;
            let mut lines = String::new();
            for u in &updates {
                let mut p = u.splitn(3, ':');
                let (Some(r), Some(old), Some(new)) = (p.next(), p.next(), p.next()) else {
                    return Err(fail2commit_core::Error::invalid(
                        "--update needs REF:OLD:NEW",
                    ));
                };
                lines.push_str(&format!("{old} {new} {r}\n"));
            }
            let updates = server::parse_updates(lines.as_bytes())?;
            let id = server::repo_id(&repo)?;
            let issued = server::issue(&home, &id, &actor, &updates, ttl)?;
            let mut out = Outcome::msg(format!(
                "approval issued for {actor}, expires at unix time {}; pass it once with: git push -o f2c-approval=<token>",
                issued.expires_at
            ));
            if ctx.json {
                out.data =
                    serde_json::json!({ "token": issued.token, "expires_at": issued.expires_at });
            } else {
                println!("{}", issued.token); // the only time the token is shown
            }
            Ok(out)
        }
        Sub::Install {
            repo,
            state,
            protect,
        } => {
            let state = state
                .or_else(|| std::env::var_os("FAIL2COMMIT_SERVER_HOME").map(PathBuf::from))
                .ok_or_else(|| {
                    fail2commit_core::Error::invalid("use --state or FAIL2COMMIT_SERVER_HOME")
                })?;
            let exe = std::env::current_exe()?;
            let git = find_real("git", None)?;
            server::install(&repo, &state, &exe, &protect, &git)?;
            Ok(Outcome::msg("pre-receive hook installed"))
        }
    }
}
