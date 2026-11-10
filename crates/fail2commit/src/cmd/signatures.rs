//! `fail2commit signatures forget <registry-url>` (CR-018): drop the
//! trust-on-first-use signing-key record of a registry so the next install
//! records its keys afresh.

use super::{CmdResult, Ctx, Outcome};

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Action {
    /// Forget the recorded signing keys of a registry (re-trust it).
    Forget {
        /// Registry URL, as pinned (e.g. https://npm.example.com/).
        registry: String,
    },
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let Action::Forget { registry } = args.action;
    Ok(Outcome::msg(fail2commit_core::npm::forget_signing_keys(
        &ctx.paths, &registry,
    )?))
}
