//! `f2c-sandbox-relay` (FR-023, SPEC-013 §4): the in-sandbox half of the Linux egress path.
//!
//! `fail2commit`'s Linux backend stages this program into the job's control directory when
//! `sandbox.network = internet`. It accepts TCP on the sandbox's own loopback and forwards every
//! byte to the parent-side egress proxy over a Unix socket. It holds no policy of its own: the proxy
//! decides every destination, so a package that replaces or kills the relay only loses its own
//! network access.
//!
//! Packaging must ship this binary next to `fail2commit`; without it `internet` fails closed.

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        match fail2commit_core::sandbox::relay_main() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("f2c-sandbox-relay: {e}");
                std::process::ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("f2c-sandbox-relay: only the Linux sandbox backend uses this program");
        std::process::ExitCode::FAILURE
    }
}
