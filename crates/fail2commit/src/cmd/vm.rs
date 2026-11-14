//! `fail2commit vm prepare | status | remove` (FR-029, SPEC-019 §4.1).
//! Linux-only: the QEMU/KVM micro-VM image lifecycle. `prepare` and `remove`
//! require root and are idempotent; `status` reports the protected preparation.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::sandbox;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(clap::Subcommand, Debug)]
pub enum Action {
    /// Assemble the root-owned QEMU/KVM micro-VM image (run once, as root).
    Prepare,
    /// Show the VM preparation state and hash verification.
    Status,
    /// Remove the prepared VM image and state (as root, idempotent).
    Remove,
}

pub fn run(_ctx: &Ctx, args: Args) -> CmdResult {
    let message = match args.action {
        Action::Prepare => sandbox::vm_prepare()?,
        Action::Status => sandbox::vm_status()?,
        Action::Remove => sandbox::vm_remove()?,
    };
    Ok(Outcome {
        message,
        ..Default::default()
    })
}
