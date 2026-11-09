//! fail2commit tray (T-009, FR-009, SPEC-009). Native Win32, per user,
//! event driven. On other platforms it only reports that it is Windows-only.

// A GUI-subsystem binary: started at sign-in or from the Start menu it must
// not open a console window. Password entry still opens its own console.
#![cfg_attr(windows, windows_subsystem = "windows")]

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
