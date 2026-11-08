//! T-001 (FR-001) owns this file: define `Args` and `run` freely.

use super::{CmdResult, Ctx};
use std::ffi::OsString;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Placeholder until T-001 defines real arguments.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<OsString>,
}

pub fn run(_ctx: &Ctx, _args: Args) -> CmdResult {
    Err(fail2commit_core::Error::not_implemented("guarded git"))
}
