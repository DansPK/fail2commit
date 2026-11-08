# Verify Report: Sandbox policy (2026-11-09)

> **Requirements covered:** FR-008 (SPEC-008, TC-008)
> **Commit / branch:** base `fe411ba` + T-008 commit on `DansPK/f2c-t008-sandbox-policy` (final SHA in the worker report)
> **Verified by:** T-008 worker (Claude)

---

## 1. Commands Run

Windows 11, Rust stable `x86_64-pc-windows-gnu`:

```text
cargo fmt --all -- --check                              exit 0
cargo clippy --workspace --all-targets -- -D warnings   exit 0
cargo test --workspace                                  exit 0 (all pass)
```

Linux, Docker `rust:1` (Debian), named target volume `f2c-t008-target`:

```text
docker run --rm -v <worktree>:/src -v f2c-t008-target:/target -e CARGO_TARGET_DIR=/target -w /src rust:1 sh -c '
  cargo fmt --all -- --check                              -> exit 0
  cargo clippy --workspace --all-targets -- -D warnings   -> exit 0
  cargo test --workspace --no-fail-fast                   -> 1 failure, not in T-008 code (see section 4)'
```

## 2. Results

| TC ID | Requirement | Result | Evidence |
|-------|-------------|--------|----------|
| TC-008 On fails closed | FR-008 | Pass (Win, Linux) | `on_runs_sandboxed_and_fails_closed_without_backend`, exec unit `table` |
| TC-008 Off skips unless separately approved | FR-008 | Pass (Win, Linux) | `off_skips_unless_separately_approved`, `declined_host_run_is_rejected`, `unreachable_approval_never_runs_on_host` |
| TC-008 Workspace cannot alter policy | FR-008 | Pass (Win, Linux) | `repository_files_cannot_change_policy` (decoy `.fail2commit/settings.toml`, `fail2commit.toml`, `.npmrc`, `pip.conf`) |
| In-flight snapshot | FR-008 | Pass (Win, Linux) | `snapshot_cannot_be_weakened_mid_flight`, `snapshot_holds_while_approval_is_pending` |
| Flagged scripts blocked in both modes | FR-008 | Pass (Win, Linux) | `flagged_scripts_are_blocked_in_both_modes` |
| Explicit run requires isolation | FR-008 | Pass at policy level | `explicit_run_always_requires_isolation_in_both_modes` tests `policy::explicit_run_allowed`. `cmd/run.rs` (T-007) is not wired yet, so the end-to-end `fail2commit run` check is **Pending** on T-007. |
| `sandbox on/off/status` CLI | FR-008 | Pass (Win, Linux) | `sandbox_setting_cli.rs` (4 tests, incl. `--json` and malformed settings failing closed) |
| Real host-approval prompt | FR-008 | **Pending** | Needs T-002 `approval::approve`, still a stub. The tests use the `authorize_scripts_with` seam and a recorder approver. The frozen path is only checked to fail closed with `ApprovalUnavailable`. |
| Real backend end-to-end (script actually runs sandboxed) | FR-008 | **Pending** | Needs T-007a/T-007b backends. Tests use a fake backend. |
| Tray / VS Code toggle | FR-008 | **Pending** | Needs T-009 / T-010. |

Cross-platform matrix (T-008 slice): Windows Pass, Linux (container) Pass for the rows above. The
Linux probe in the container reports whatever `bwrap` finds. The tests never depend on the real
probe result.

## 3. Traceability Check

Not run in this worktree (`python .claude/hooks/trace_check.py` is a coordinator integration step).

## 4. Issues Found

- Linux only: `fail2commit` bin unit test `tests::shims_route_to_subcommands` (`crates/fail2commit/src/main.rs:176`, frozen/coordinator-owned) fails
  because it passes `C:\b\NPM.exe` and Unix `Path::file_stem` does not treat `\` as a separator.
  Not caused by T-008. It passes on Windows. Needs a coordinator fix (for example `cfg(windows)` for that
  assertion). Because of it, plain `cargo test --workspace` exits non-zero on Linux until it is fixed.

## 5. Verdict

- [ ] **Verified:** not claimed. The T-008 logic and tests pass on both platforms, but the items marked Pending depend on T-002, T-007, T-009 and T-010.
- [x] **Not verified end-to-end:** reasons above.
