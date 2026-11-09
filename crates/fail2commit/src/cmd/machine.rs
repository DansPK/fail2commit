//! `fail2commit machine-shims install | uninstall | status` (FR-004, FR-005;
//! CR-013). Windows, administrators only: guards machine-wide npm and pip,
//! which the per-user shims cannot shadow. The installer runs it elevated.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::{machine, Error};

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(clap::Subcommand, Debug, Clone, Copy)]
pub enum Action {
    /// Copy the shims to Program Files and put them first on the machine PATH.
    Install,
    /// Remove the shims and their machine PATH entry.
    Uninstall,
    /// Exit 0 when the shims are installed and on the machine PATH.
    Status,
}

pub fn run(_ctx: &Ctx, args: Args) -> CmdResult {
    match args.action {
        Action::Install => {
            let exe = std::env::current_exe()?;
            let data = machine::install(&exe)?;
            let mut o = Outcome::msg(format!(
                "machine-wide npm and pip shims installed in {}; open a new terminal",
                data["dir"].as_str().unwrap_or_default()
            ));
            o.data = data;
            Ok(o)
        }
        Action::Uninstall => {
            let data = machine::uninstall()?;
            let left = data["left_in_place"].as_array().map_or(0, Vec::len);
            let mut o = Outcome::msg(if left == 0 {
                "machine-wide shims removed".to_string()
            } else {
                format!("machine-wide shims removed from PATH; {left} file(s) in use were left in place")
            });
            o.data = data;
            Ok(o)
        }
        Action::Status => {
            let data = machine::status();
            if data["installed"] != true {
                return Err(Error::rejected("machine-wide shims are not installed"));
            }
            let mut o = Outcome::msg(format!(
                "machine-wide shims installed in {}",
                data["dir"].as_str().unwrap_or_default()
            ));
            o.data = data;
            Ok(o)
        }
    }
}
