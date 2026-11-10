# Verify Report: Windows tray, approval pipe, NSIS (2026-11-08)

> **Requirements covered:** FR-009 (SPEC-009, TC-009)
> **Commit / branch:** `DansPK/f2c-t009-tray`, base `fe411ba`; tested SHA `ef9dfb9` (all commands ran on that tree; only this report was added afterwards).
> **Verified by:** T-009 worker (Claude), Windows 11 Pro 10.0.26200 x64, Rust stable `x86_64-pc-windows-gnu` (cargo 1.99.1); Linux = Docker `rust:1` (Debian, x86_64).

---

## 1. Commands Run

```text
# Windows host (PowerShell), repo root
cargo fmt --all -- --check                                  -> exit 0
cargo clippy --workspace --all-targets -- -D warnings       -> exit 0
cargo test --workspace --no-fail-fast                       -> exit 0 (all targets ok; see section 2)
powershell -NoProfile -File packaging\windows\build.ps1 -Version 0.1.0   -> exit 0
python .claude/hooks/trace_check.py                         -> exit 0 ("[guard:trace_check] OK")

# Linux (Docker rust:1, target on named volume f2c-t009-target)
docker run --rm -v "${PWD}:/src" -v f2c-t009-target:/target -e CARGO_TARGET_DIR=/target -w /src rust:1 sh -c "rustup component add clippy && cargo clippy --workspace --all-targets -- -D warnings"   -> exit 0
docker run ... rust:1 cargo test --workspace --no-fail-fast  -> exit 101, one failure outside this task (section 4)

# Smoke of the release tray (manual, PowerShell)
Start-Process target\release\fail2commit-tray.exe ; list \\.\pipe\ ; start a second copy ; kill the first
   -> pipe \\.\pipe\fail2commit-approval-S-1-5-21-...-1001 present; second copy exit 1; pipe gone after kill
```

NSIS: portable `nsis-3.11.zip` from the official SourceForge release (`https://sourceforge.net/projects/nsis/files/NSIS%203/3.11/nsis-3.11.zip/download`), unpacked under the ignored `target/nsis/`. SHA-256 of the downloaded zip (computed here; SourceForge publishes no checksum next to the file): `c7d27f780ddb6cffb4730138cd1591e841f4b7edb155856901cdf5f214394fa1`.
Built installer: `target/dist/fail2commit-0.1.0-setup.exe`, SHA-256 `5d66115a907842100d5b48fab320da6b4faacdb830a6bebab3238986eb9649fe` (not committed; unsigned; two expected `File /nonfatal` warnings because no NOTICE files exist yet).

## 2. Results

Test counts, Windows: tray unit 2, `ipc_pipe` 8, `ipc_startup` 5, core unit 19, tray `appcontainer` 1. Linux: core unit 18 (including the `ipc::wire` tests), tray unit 2; the Windows-only test files compile to zero tests.

| TC / matrix item | Requirement | Result | Evidence |
|---|---|---|---|
| TC-009 prompt round trip with scripted UI seam (approve once + password, cancel, unoffered decision becomes cancel) | FR-009 | Pass (Windows) | `ipc_pipe`: `round_trip_approve_once_with_password`, `cancel_and_unoffered_decision_both_cancel` |
| TC-009 request bounds and session validation (oversize line, malformed JSON, wrong message type, bad session, expired, long details, wrong version) never reach the UI | FR-009 | Pass (Windows; pure rules also on Linux) | `ipc_pipe`: `oversized_and_malformed_requests_never_reach_the_ui`, `invalid_fields_and_sessions_are_rejected`; `ipc::wire` unit tests |
| TC-009 pipe ACL: same user connects | FR-009 | Pass (Windows) | round-trip tests connect as the current user |
| TC-009 pipe ACL: DACL is exactly deny `S-1-15-2-1`, deny `S-1-15-2-2`, allow current SID | FR-009 | Pass (Windows) | `ipc_pipe::dacl_allows_only_current_user_and_denies_app_packages` reads the DACL from a client handle |
| TC-009 pipe ACL: real AppContainer (LowBox) client is denied | FR-009 | Pass (Windows) | `fail2commit-tray/tests/appcontainer.rs`: temp AppContainer profile, `cmd /c ver` runs inside (exit 0, control), `echo x>PIPE` inside it exits 1, same-user control exits 0, UI never prompted. T-007b can cross-check the sandboxrs path. |
| Pipe first-instance (single tray, anti-squatting) | FR-009 | Pass (Windows) | `second_server_on_the_same_name_is_refused`; smoke: second tray exit 1 |
| Client rejects reply not bound to request | FR-009 | Pass | `reply_for_another_request_is_refused_by_the_client` (uses `validate_response`) |
| TC-009 tray closed: `tray_approver()` is `None`, probe turns `None` after shutdown | FR-009 | Pass (Windows); `None` stub on Linux | `ipc_pipe::tray_closed_means_no_approver`; smoke: pipe gone after the tray is killed |
| TC-009 terminal fallback / reject when no UI | FR-009 | Pending | The fallback is T-002's `Auto` logic in `approval::approve`, still a stub at `fe411ba`. Needs end-to-end rerun after T-002 integrates. |
| TC-009 startup toggle against temp registry key (install, previous value restored, other values kept, dry run, missing tray, foreign record ignored, menu toggle) | FR-009 | Pass (Windows) | `ipc_startup` (5 tests) on `HKCU\Software\fail2commit-test-<random>\Run`, key tree deleted afterwards; the real Run key is never touched |
| TC-009 remote clients rejected (`PIPE_REJECT_REMOTE_CLIENTS`) | FR-009 | Pending | Flag set in code (`ipc/pipe.rs`); no runtime proof: needs a second machine or SMB loopback. `win11` VMware VM can supply it. |
| TC-009 tray dialog and balloon with real user clicks (Cancel default, Approve, Run on host, password box, expiry, tray menu, sandbox toggle, console launch for password) | FR-009 | Pending | The UI is only smoke-tested (starts, owns the pipe, exits). Needs a GUI session with manual clicks or UI automation. |
| TC-009 NSIS installer build | FR-009 | Pass (build only) | Section 1: makensis exit 0, installer produced. |
| TC-009 install / uninstall on clean Windows 11 (components, setup, Run value, uninstall-integrations rollback, only owned files removed, paths with spaces, Git for Windows shell) | FR-009 | Pending | Belongs to the T-011 release check; the `win11` VMware VM is available for it. Not run here: the installer was not executed. |
| Matrix: Approval, closed tray, multi-ref, concurrent attempts | FR-009 | Pending | Needs T-002 approval flow; the pipe serves concurrent clients (up to 8) but no concurrent-request test exists yet. |
| Matrix: sandboxes, approval IPC from a hostile child | FR-007/009 | Pending | AppContainer denial verified above for a plain LowBox token; the sandboxrs-windows child path is T-007b's. |
| Linux: workspace builds, clippy clean, tray prints "Windows only" and exits non-zero | FR-009 | Pass (build/clippy); binary not executed | Linux clippy exit 0; tray `main` is the `cfg(not(windows))` stub. |

## 3. Traceability Check

```text
$ python .claude/hooks/trace_check.py
[guard:trace_check] OK
```

## 4. Issues Found

- Linux `cargo test --workspace` fails in `fail2commit` (bin) `tests::shims_route_to_subcommands`: left `["C:\\b\\NPM.exe", "ci"]`, right `["fail2commit", "npm", "ci"]`. It is in the coordinator-owned `crates/fail2commit/src/main.rs`, which this task did not touch, and it uses a Windows-style path, so it is a Linux-only test bug that predates T-009. Not fixed here (not owned); report to the coordinator.
- `Cargo.lock` gains a `tempfile` entry for `fail2commit-tray` from the new dev-dependency (written by cargo).
- Core had no registry feature in its `windows-sys` entry and `Cargo.toml` is coordinator-owned, so `ipc/startup.rs` declares six `advapi32` functions by hand (`#[link(name = "advapi32")]`). A coordinator may later add `Win32_System_Registry` to core and drop them.
- Known limits (documented, not defects): a connected same-user client that sends nothing holds one of 8 pipe slots until it closes; the pipe handler does not notice a CLI that disconnects while a dialog is open (the request still expires at `expires_at`); the process-id token check has the usual id-reuse window, mitigated by the DACL and anonymous-impersonation open.

## 5. Verdict

- [ ] **Verified:** all linked TCs pass
- [x] **Not verified:** TC-009 stays In progress. Pipe, bounds, ACL (including a real AppContainer), tray-closed and startup tests pass on Windows, and the installer builds. Items marked Pending above (GUI interaction, remote-client rejection, T-002 fallback, clean-machine install/uninstall at T-011) have no passing evidence yet.
