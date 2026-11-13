# FR-013 install progress verification

Implementation commit tested: `e892b74` (Windows 11 host, 2026-11-13).

## Changes

- Added a best-effort CLI progress sink. Interactive stderr gets one redrawn status line; Windows with an interactive desktop gets a native progress window, regardless of whether the tray is running. The window closes on clean completion and retains findings or an error until closed.
- Connected npm and pip review phases to the existing frozen `Progress` contract, including per-package npm downloads, code scans, npm lifecycle scripts, findings, approvals, and apply progress. Pip reports resolve, pre-install checks, wheel scans, advisories, and apply progress.
- JSON/API calls and redirected or noninteractive stderr receive no terminal output; `ui.progress_window = false` disables the window. Window update messages and retained finding details are bounded, and display text is sanitized.

## Commands and results

| Command | Exit | Result |
|---|---:|---|
| `cargo fmt --all` | 0 | Formatted changed Rust files |
| `cargo fmt --all -- --check` | 0 | Formatting clean |
| `cargo check --tests -p fail2commit -p fail2commit-core` | 0 | Windows host and test targets compile |
| `cargo test -p fail2commit-core progress::tests::steps_are_ordered_as_the_flow_runs` | 0 | 1 passed |
| `cargo build -p fail2commit` | 0 | Windows host build completed |
| `git diff --check` | 0 | No whitespace errors |

## Pending evidence

- No interactive npm/pip install or native-window click-through was run. The task restricts sandbox runtime tests to disposable VMs; Windows GUI behavior and Linux terminal behavior still need their platform evidence there.
- The progress window was compile-checked on the Windows host. Timing to first visible paint, clean auto-close, and result retention until user close remain runtime checks.
