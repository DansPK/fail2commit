# Verify Report: T-002 approval and force-push password (2026-11-09)

> **Requirements covered:** FR-002 (SPEC-002, TC-002 and the approval row of the cross-platform matrix)
> **Commit / branch:** `e4955698b65a8395b8463b977c93bdb8bbfe00b5` on `DansPK/f2c-t002-approval` (base `fe411ba`). The working tree was clean when tested.
> **Verified by:** orca worker (Claude Opus 5.5), task T-002
>
> The file name keeps the slug date assigned in the task brief (2026-11-08). The runs happened on 2026-11-09.

---

## 1. Commands Run

### Windows 11 host

Platform: `x86_64-pc-windows-gnu`, rustc 1.99.1 (58cf8f9c3 2026-10-13), Git Bash.

| Command | Exit |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --workspace` | 0 |
| `python .claude/hooks/trace_check.py` | 0 (`[guard:trace_check] OK`) |
| `python -m unittest discover -s .claude/hooks -p "test_*.py"` | 0 (21 tests OK) |

`cargo test --workspace` results on Windows:

| Test binary | Result |
|---|---|
| `fail2commit` unit tests | 2 passed |
| `approval_cli` | 5 passed |
| `approval_stdio` | 8 passed |
| `approval_tty` | 0 tests. The file is `#![cfg(unix)]`. |
| `fail2commit-core` unit tests | 33 passed (18 in `approval::tests`) |
| `fail2commit-tray` | 0 tests |

### Linux container

Platform: Docker `rust:1` (Debian), rustc 1.99.1. Run from PowerShell:

```text
docker run --rm -v "${PWD}:/src" -v f2c-t002-target:/target -v f2c-t002-cargo:/usr/local/cargo/registry -e CARGO_TARGET_DIR=/target -w /src rust:1 bash -c "..."
```

| Command | Exit |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --workspace --no-fail-fast` | 101 (one failure outside T-002; see §4) |

`cargo test --workspace --no-fail-fast` results on Linux:

| Test binary | Result |
|---|---|
| `fail2commit` unit tests | 1 passed, 1 **FAILED**: `tests::shims_route_to_subcommands` (`main.rs:176`, coordinator-owned, see §4) |
| `approval_cli` | 6 passed |
| `approval_stdio` | 8 passed |
| `approval_tty` | 1 passed, in 24.48 s. It ran through a real pty created by util-linux `script`. |
| `fail2commit-core` unit tests | 33 passed |
| `fail2commit-tray` | 0 tests |

## 2. Results

| TC / matrix item | Requirement | Result | Evidence (test name) |
|---|---|---|---|
| TC-002: wrong password denies | FR-002 | **Pass** (Win + Linux) | `approval_stdio::wrong_password_denies` · `approval::tests::wrong_password_denies_and_right_one_approves` · `approval_tty::terminal_password_lifecycle_and_approval` (Linux pty) |
| TC-002: recovery rotates the code, old code rejected | FR-002 | **Pass** (Win + Linux) | `approval::tests::reset_rotates_recovery_code_and_invalidates_pending` · `approval_tty::terminal_password_lifecycle_and_approval` (CLI `password reset` through the pty; the old code gives `wrong recovery code`) |
| TC-002: changed ref tuples invalidate approval | FR-002 | **Pass** (Win + Linux) | `approval::tests::changed_multi_ref_tuples_and_mismatches_are_rejected` · `approval_stdio::changed_digest_nonce_or_request_id_is_rejected` (multi-ref digest gives `operation changed`) |
| Matrix: rate limit | FR-002 | **Pass** (Win + Linux) | `approval::tests::rate_limit_engages_persists_and_expires`, `backoff_doubles_and_caps` · `approval_stdio::rate_limit_persists_across_processes` (4 child processes; status reports `failed_attempts = 3`) |
| Matrix: expiry | FR-002 | **Pass** (Win + Linux) | `approval::tests::expiry_before_and_during_prompt` · `approval_stdio::late_reply_after_expiry_is_not_an_approval` (TTL 1 s; a late reply gives exit 10) |
| Matrix: cancel (explicit, EOF, empty, garbage, oversized) | FR-002 | **Pass** (Win + Linux) | `approval_stdio::cancel_eof_empty_and_garbage_cancel` · `approval::tests::approves_without_password_and_cancel_is_default` · pty: `""`, `y` and `yes please` all cancel |
| Matrix: closed tray, no tray → terminal fallback | FR-002 | **Pass** (Linux pty) | `approval_tty::…` runs `--approver auto` with no tray, and the terminal prompt is used |
| Matrix: closed tray, no tray and no TTY → unavailable | FR-002 | **Pass** (Win + Linux) | `approval_cli::every_channel_fails_closed_without_console_or_tray` (`auto`, `terminal`, `tray` and `none` all give exit 11 `approval_unavailable`) |
| Matrix: closed tray, real tray | FR-002 | **Pending** | Needs T-009's `ipc::tray_approver()`. It returns `None` in this build. |
| Matrix: non-TTY | FR-002 | **Pass** (Win + Linux) | `approval_cli::every_channel_fails_closed_without_console_or_tray`, `password_management_needs_a_console`. On Windows the child is started with `DETACHED_PROCESS`; on Linux the container has no tty, or the child is started under `setsid`. |
| Matrix: multi-ref changes | FR-002 | **Pass** | Same evidence as the TC-002 ref-tuples row |
| Matrix: replay | FR-002 | **Pass** (Win + Linux) | `approval::tests::replayed_reply_is_rejected_across_processes`, `foreign_session_and_reprompt_are_rejected` |
| Matrix: concurrent attempts | FR-002 | **Pass** (Win + Linux) | `approval::tests::concurrent_replies_and_attempts_serialize`: 8 threads give exactly 1 nonce winner, and exactly 3 `wrong password` before the lockout |
| Matrix: no credential or secret in logs | FR-002 | **Pass** (Win + Linux) | stdout, stderr and the full trusted-home plaintext are scanned in `approval_stdio::*` (`no_secret`), `approval_cli::status_reports_without_secrets`, `secrets_by_argument_are_refused_without_echo`, `secrets_by_environment_are_refused_without_echo` and `approval::tests::state_files_hold_no_plaintext_secrets`. The pty transcript has no password. |
| Stdio channel end to end through `fail2commit api` | FR-002 | **Pass** (Win + Linux) | all 8 tests in `approval_stdio` run against a child process |
| Terminal approver and hidden-input CLI on **Windows** | FR-002 | **Pending** | Needs an interactive Windows console (`CONIN$`). No ConPTY harness is available here. Manual step: in a Windows Terminal, run `fail2commit password set`, then `fail2commit --approver terminal password verify`. |
| Private state permissions (Unix 0700/0600) | FR-002 | **Pass** (Linux) | `approval_cli::state_files_are_private` |

The argon2 cost in the integration tests is the recommended one: m = 19456 KiB, t = 2, p = 1. `status_reports_without_secrets` asserts these values from `--json password status` and from the state file. The core unit tests use a reduced cost through `cfg(test)` to keep runtime low.

## 3. Traceability Check

```text
$ python .claude/hooks/trace_check.py
[guard:trace_check] OK
```

The worker does not update TEST-PLAN, traceability, TODO or DONE statuses. Those belong to the coordinator.

## 4. Issues Found

- **Outside T-002, Linux only:** `crates/fail2commit/src/main.rs` `tests::shims_route_to_subcommands` fails. The assertion `shim_argv(["C:\\b\\NPM.exe","ci"])` expects `["fail2commit","npm","ci"]`, but `Path::file_stem` does not split on `\` on Unix. The file is coordinator-owned, and T-002 does not change it; it is the same at base `fe411ba`. Suggested fix: split the stem on both `/` and `\`, or make the test case `cfg(windows)`. Because cargo stops at the first failing binary, Linux `cargo test --workspace` without `--no-fail-fast` never reaches the approval binaries.
- No WSL runtime run. The approval code has no WSL-specific behaviour. The Linux evidence comes from the Debian container.

## 5. Verdict

- [ ] **Verified:** all linked TCs pass; requirement status set to `Verified`
- [x] **Not verified (pending items):** every TC-002 acceptance check passes on Windows and Linux. Still pending:
  - the real tray channel (T-009);
  - the interactive Windows terminal prompt;
  - the coordinator-owned Linux failure in `main.rs`.
