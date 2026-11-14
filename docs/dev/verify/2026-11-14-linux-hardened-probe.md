# FR-027 / SPEC-018 Linux hardened source and glue status

Date: 2026-11-14. Branch: `f2c-014-hardened`; implementation base: `c80f2c51073ff6999190fe220391428373efb4a9`.

## Implemented in source, not runtime verified

- Root service accepts a fixed authenticated `PROBE` request, validates the recorded installer UID and installed sandbox account, and runs fixed launcher/platform/network/bait/watchdog fixtures. Caller requests cannot supply a command, environment, or URI.
- Backend activation remains fail-closed: Internet jobs require service, peer-authentication, platform, and network-effect probe success. `hardened status` now performs that service probe, reports individual controls and details, and the CLI includes the failure detail.
- Linux status now requires the read-only fixture to reside on a kernel-reported read-only mount; its DAC mode alone cannot satisfy the control.
- Hardened installation copies the trusted packaged `f2c-sandbox-relay` beside the installed executable. Debian and Arch packages include that sibling. Unit templates are shipped under `/usr/share/fail2commit/templates`, not systemd's live unit search path; install renders installer-specific values into the active units.
- The Debian guest native library check passed after the mount-flag type correction. See exact commands below.

## Still missing or blocked

- Sol review LP01 remains open: validate the authenticated caller's effective read/traverse access on every caller-supplied ancestor before any root ACL mutation, using kernel-backed peer UID/GID and supplementary groups. Root-owned ancestor owner checks are insufficient.
- Sol review LP02 remains open: retain every journaled temporary target through scope death and exact ACL restoration, then delete it; production recovery/retry needs a failure-injection test.
- Root service/account installation and the full system-scope, ACL effect, bwrap/seccomp/network, bait cancellation, and crash-recovery probes were not run. `sudo -n true` in the authorized Debian guest exited 1 with `sudo: a password is required` as UID 1000; no credentials were guessed and no privileged guest or host state was changed.
- Windows runtime effect-probe review and Linux privileged runtime gates remain pending. This is not a full FR-027 completion report and the backend must stay unavailable when any required effect is absent.

## Verification

Guest: Debian `debian-f2c`, source at `/home/dev/.cache/f2c-linux-launcher-20261114/source`, Rust `1.100.0`, target at `/home/dev/.cache/f2c-linux-launcher-20261114/target`.

| Command | Exit/result |
|---|---|
| `cargo check -p fail2commit-core --lib --locked` (native Debian guest, `CARGO_INCREMENTAL=0`, dev debug info disabled) | 0; four existing dead-code warnings |
| `cargo check -p fail2commit --locked` (native Debian guest, `CARGO_INCREMENTAL=0`, dev debug info disabled) | 0; same four warnings |
| `cargo test -p fail2commit-core --lib sandbox::hardened::service::tests --locked` | 0; 28 passed, 0 failed, 247 filtered |
| `git diff --check` | 0 |

## Integration notes for manager

The child and manager branches diverge from `db4e07497110f46a96ff0eb52857e8728dab669d`; manager FR-013 source through `ce550df` is not integrated here. Shared paths requiring manual preservation during integration are `crates/fail2commit-core/src/pip/mod.rs`, `crates/fail2commit/Cargo.toml`, `crates/fail2commit/src/cmd/mod.rs`, `crates/fail2commit/src/cmd/npm.rs`, and `crates/fail2commit/src/main.rs`. Preserve manager progress UI/seams and this branch's hardened features, command routing, backend selection, package assets, and relay install behavior; do not merge this child branch wholesale over the manager tree.
