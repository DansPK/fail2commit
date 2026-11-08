//! fail2commit tray (T-009, FR-009, SPEC-009). Native Win32, per user,
//! event driven. On other platforms it only reports that it is Windows-only.

// The renderer is only used by the Windows UI; other targets still compile it.
#[cfg_attr(not(windows), allow(dead_code))]
mod render;
#[cfg(windows)]
mod ui;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    ui::run()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("fail2commit-tray: Windows only");
    std::process::ExitCode::FAILURE
}
