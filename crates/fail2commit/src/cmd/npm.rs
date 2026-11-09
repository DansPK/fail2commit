//! `fail2commit npm ci | install | i [pkg...]` and the `npm` shim target
//! (T-004, FR-004, SPEC-004). Policy lives in `fail2commit_core::npm`.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::npm::{self, Action, Deps};
use std::ffi::OsString;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// npm command and arguments, e.g. `ci`, `install left-pad -D`.
    /// Commands that could fetch or run packages unguarded are refused.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<OsString>,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let cwd = std::env::current_dir()?;
    match npm::parse(&args.args, &cwd)? {
        Action::Passthrough(a) => Ok(Outcome {
            tool_exit: Some(npm::passthrough(&ctx.paths, &a)?),
            ..Default::default()
        }),
        Action::Guarded(req) => {
            let backend = fail2commit_core::sandbox::platform_backend();
            let approval = ctx.approval();
            let deps = Deps::production(&approval, backend.as_ref());
            let o = npm::execute(&deps, &req)?;
            Ok(Outcome {
                message: o.message,
                findings: o.findings,
                data: o.data,
                ..Default::default()
            })
        }
    }
}
