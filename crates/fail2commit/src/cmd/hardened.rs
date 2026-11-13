//! `fail2commit hardened install | uninstall | status` (FR-027, SPEC-018).

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::{sandbox::hardened, Error};

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(clap::Subcommand, Debug, Clone, Copy)]
pub enum Action {
    Install,
    Uninstall,
    Status,
}

pub fn run(_ctx: &Ctx, args: Args) -> CmdResult {
    match args.action {
        Action::Install => {
            let data = hardened::install()?;
            let text = if data["installed"] == true {
                "hardened service installed; probe unavailable until all required controls pass"
            } else {
                "hardened install completed"
            };
            Ok(Outcome {
                message: text.into(),
                data,
                ..Default::default()
            })
        }
        Action::Uninstall => {
            let data = hardened::uninstall()?;
            Ok(Outcome {
                message: "hardened service uninstalled".into(),
                data,
                ..Default::default()
            })
        }
        Action::Status => {
            let data = hardened::status();
            if data["installed"] != true {
                return Err(Error::rejected("hardened mode is not installed"));
            }
            if data["probe_available"] != true {
                return Err(Error::isolation_unavailable(
                    "hardened mode is installed but its mandatory probe controls did not pass",
                ));
            }
            Ok(Outcome {
                message: "hardened mode available".into(),
                data,
                ..Default::default()
            })
        }
    }
}
