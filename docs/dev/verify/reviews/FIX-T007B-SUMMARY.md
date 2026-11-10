# Fix summary: T-007b Windows AppContainer review findings S7B-001..013

> **Requirement:** FR-007 (SPEC-007, TC-007)
> **Task brief:** `FIX-t007b.md` (fix pass for `docs/dev/verify/reviews/REVIEW-2026-11-09-t007b.md`)
> **Branch:** `DansPK/f2c-fix-t007b`
> **Fix commit (tested tree; everything except this summary):** `a4ca8fbf17a1456c7d8c3b4e6ab0740dfe7425bc`
> **Final branch tip:** print it with `git log -1 --format=%H`; the tip is the commit that adds this
> summary file
> **Host:** Windows NT `10.0.26200.0`, `rustc 1.99.1 (58cf8f9c3) x86_64-pc-windows-gnu`,
> `cargo 1.99.1`, every build and test run with `-j 2` and empty stdin
> **Author:** T-007b fix pass (a different agent from the reviewer and the original author)

## 1. What changed

| Area | Change |
|---|---|
| Grants (S7B-001, S7B-007) | New `ffi::StagedObject`: every staged path is opened with `FILE_FLAG_OPEN_REPARSE_POINT \| FILE_FLAG_BACKUP_SEMANTICS`, rejected when it is a reparse point, rejected when a file has `nNumberOfLinks != 1`, required to keep a final path (`GetFinalPathNameByHandleW`) under the canonical stage root, and then granted/read back/revoked with `SetSecurityInfo`/`GetSecurityInfo` on that same handle. A NULL DACL is refused, never rewritten. |
| Anchors (S7B-003) | Stage root is `<TrustedPaths::cache_dir>/sandbox-stage` (`%LOCALAPPDATA%\fail2commit\cache\sandbox-stage`). `SHGetKnownFolderPath(FOLDERID_LocalAppData/FOLDERID_Profile)` supplies the anchors used to refuse unsafe roots. `std::env::temp_dir()` is no longer referenced. |
| System facts (S7B-002) | `GetSystemDirectoryW` for System32, `GetSystemWindowsDirectoryW` for the child `SystemRoot`; a disagreeing process `SystemRoot` refuses the operation. The loopback control reads `NetworkIsolationGetAppContainerConfig` from FirewallAPI.dll dynamically: no process launch, no environment input, fail-closed errors. |
| Environment (S7B-008) | `LOCALAPPDATA` is `<work_dir>\localappdata` (Windows derives the container profile from it) unless the caller already points it inside the work dir. Required variables documented. |
| Lifecycle (S7B-004, S7B-006) | `TerminateJobObject` checked; `wait_empty(deadline)` and `collect_drain(deadline)` bound every post-run wait; a surviving tree is an error. Failed revocations are logged, recorded in `<stage root>/pending-revoke.json`, and make `probe()`/`run()` refuse until cleared. |
| Handle canary (S7B-005, S7B-012) | Explicit-handle-list containment is measured on every run: an inheritable canary is opened, the child is created suspended, the parent closes its handle and requires an exclusive open to succeed. |
| Probe cost (S7B-005, S7B-013) | One sandboxed launch, no external process, 30 s TTL keyed on an environment fingerprint, negative verdicts never cached. |
| Dependency (S7B-009) | Dead `sandboxrs-windows` reference removed; every candidate API listed with source citations and rejection reasons in `docs/sandbox-windows.md` §1 for the coordinator's decision. `Cargo.toml` untouched. |
| Tests (S7B-010..012) | Reproductions now assert the fixed behaviour; the matrix tests report and assert their Git, environment and inherited-handle outcomes; the disabled/unavailable case has a positive control. |
| Docs | `docs/sandbox-windows.md` rewritten; dated fix section added to `docs/dev/verify/VERIFY-2026-11-08-sandbox-windows.md`. |

Two change requests are recorded in `docs/dev/verify/VERIFY-2026-11-08-sandbox-windows.md` §7:

1. **Stager contract:** job stages must be direct children of `<cache_dir>/sandbox-stage` (T-004,
   T-005, T-008, `fail2commit run`).
2. **T-009 coupling:** the approval-pipe SDDL reproduced in `windows.rs` must be reconciled with
   `ipc/winsec.rs` when that module lands.
## 2. Per-finding status

| ID | Status | Evidence |
|---|---|---|
| S7B-001 | **Fixed** | `review_t007b_paths::hard_link_inside_staged_tree_is_rejected` (refusal plus an `icacls` DACL comparison of the outside file), `review_t007b_paths::junction_inside_staged_tree_is_rejected`, `review_t007b_paths::a_read_only_root_from_another_stage_is_rejected`, `windows::tests::a_hard_link_in_the_stage_is_rejected_before_any_grant` |
| S7B-002 | **Fixed** | `review_t007b_systemroot::an_environment_selected_system_root_cannot_answer_the_loopback_control` (marker absent, probe unavailable, refusal names `SystemRoot`), `windows::tests::host_probe_verifies_every_mandatory_control` |
| S7B-003 | **Fixed** | `review_t007b_tempdir::temp_dir_anchor_is_not_used` (caller `TMP`/`TEMP` root and the profile fallback both refused, caller DACL unchanged), `windows::tests::a_work_dir_outside_the_stage_root_is_rejected` |
| S7B-004 | **Fixed** | `windows::tests::a_drain_that_misses_its_deadline_is_an_error`, `windows::tests::a_drain_that_reports_in_time_returns_its_bytes`, `sandbox_windows_matrix::process_memory_time_and_output_limits_are_enforced` |
| S7B-005 | **Fixed** | `windows::tests::a_second_probe_reuses_a_short_lived_positive_verdict`, `sandbox_windows_matrix::explicit_handle_list_excludes_an_inheritable_secret_handle`, probe markers `APPROVAL-DENIED` / `DEFAULT-DENIED` with "no client" |
| S7B-006 | **Fixed** | `windows::tests::stale_revoke_state_blocks_the_next_operation_until_it_is_cleared`, `windows::tests::a_recorded_revoke_failure_is_cleared_once_the_object_is_gone` |
| S7B-007 | **Fixed** | `windows::tests::a_null_dacl_is_refused_before_any_write` |
| S7B-008 | **Fixed** | `sandbox_windows_matrix::clean_environment_and_native_workload_succeed` (fixture asserts `PATH` absent, allowlist present, `LOCALAPPDATA` inside the work dir), probe `LAD=` marker check |
| S7B-009 | **Fixed (reported; decision requested)** | `docs/sandbox-windows.md` §1: no API of `sandboxrs-windows 0.1.1` is used; four candidate APIs listed with source citations and rejection reasons; `Cargo.toml` untouched |
| S7B-010 | **Fixed** | `sandbox_windows_matrix::disabled_and_unavailable_policy_never_launches_package_code` (launcher really runs the package code, positive control, call counter) |
| S7B-011 | **Fixed** | `sandbox_windows_matrix::parent_and_grandchild_cannot_reach_network_secret_checkout_or_git` (`git_ls_remote=denied` recorded per generation, after an unsandboxed positive control proves the same bare remote is readable) |
| S7B-012 | **Fixed** | `sandbox_windows_matrix::explicit_handle_list_excludes_an_inheritable_secret_handle` (child must fail `ReadFile` with `ERROR_INVALID_HANDLE`; flag cleared; secret compared) |
| S7B-013 | **Fixed** | `sandbox_windows_matrix::probe_verifies_every_control_in_one_launch_and_then_reuses_it_briefly`; measured cold probe 4.1 s (the timeout it measures), cached probe 0.4-0.5 ms |

No finding is left open. S7B-009 ends with a coordinator decision (keep or drop the pinned
dependency) rather than a code change, as the task brief allows.
## 3. Commands and exit codes

All commands were run from the worktree root with empty stdin. Formatting was applied once before the
checked run.

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `cargo fmt --all` | 0 | formatting applied |
| 2 | `cargo fmt --all -- --check` | 0 | no diff |
| 3 | `cargo clippy --workspace --all-targets -j 2 -- -D warnings` | 0 | clean (core, CLI, tray) |
| 4 | `cargo check -j 2 -p fail2commit-core --all-targets` | 0 | clean |
| 5 | `cargo check -j 2 -p fail2commit --all-targets` | 0 | clean |
| 6 | `cargo test -j 2 -p fail2commit-core` | 0 | 25 passed, 0 failed, 0 ignored (10 of them `sandbox::windows::tests`) |
| 7 | `cargo test -j 2 -p fail2commit --test sandbox_windows_matrix --test review_t007b_paths --test review_t007b_tempdir --test review_t007b_systemroot` | 0 | matrix 6 passed / 1 ignored; paths 3 passed; tempdir 1 passed; systemroot 1 passed |
| 8 | `cargo test -j 2 --workspace` | 0 | 2, 3, 1, 1, 6 (+1 ignored), 25, 0, 0 passed; no failures |
| 9 | `python .claude/hooks/trace_check.py` | 0 | `[guard:trace_check] OK` |
| 10 | `rustc --edition=2021 -C opt-level=0 tests\fixtures\sandbox-windows\attacker.rs -o <temp>` | 0 | fixture compiles standalone |
| 11 | `git add -A; git commit -m "FR-007: fix T-007b AppContainer review findings S7B-001..013"` | 0 | `a4ca8fb`, 9 files changed, 2675 insertions(+), 812 deletions(-) |
| 12 | `git status --short` before staging | 0 | only the nine owned files modified; no scratch files |

Diagnostic runs during the fix, kept for the record because they show the tests were red first:

| Command | Exit | What it showed |
|---|---|---|
| `cargo check -j 2 -p fail2commit-core --all-targets` (first attempt) | 1 | unclosed delimiter while the handle-based grant was written; fixed |
| `cargo test ... windows::tests` (2nd attempt) | 1 | `SystemRoot` comparison compared a canonical `\\?\C:\Windows` with `C:\WINDOWS`; fixed by comparing canonical forms |
| `cargo test ... windows::tests` (3rd attempt) | 1 | `CreateProcessW` returned Win32 error 203 without `LOCALAPPDATA`; the variable is now always provided, scoped inside the work directory |
| `cargo test ... host_probe` (4th-6th attempts) | 1 | the probe child could not open a batch file, and cmd's `if ... else (...) & ...` swallowed the rest of the command line; the probe now uses one unquoted inline command and writes its markers through a file |
| `cargo test ... host_probe` (7th attempt) | 1 | the noise loop and the spin loop were parsed as a single `for` body, so the output budget never filled; both are parenthesized now |
| `cargo test -j 2 -p fail2commit --test sandbox_windows_matrix` (first run) | 1 | Windows rewrites `LOCALAPPDATA` to `<base>\Packages\<package>\AC`; assertions now check the base prefix. Git *does* execute from Program Files, so the Git assertion now measures `git ls-remote` against a disposable bare remote |
| `cargo test -j 2 -p fail2commit --test review_t007b_paths` (first run) | 1 | the "two stages" job was rejected earlier by the "program outside read_only" rule; the job now crosses only the stage boundary |
| the four-target run, once, under load | 1 | transient: with a 2 s probe timeout a loaded host could kill the probe child before its markers landed, so the probe reported unavailable. The probe timeout is now 4 s (the marker phase is the first thing the child does), and repeated runs of the same command are green |
| `PowerShell Add-Type ... NetworkIsolationGetAppContainerConfig` | 0 | the export exists and returns `ERROR_SUCCESS` with 0 exemptions on this host, which is why it is a viable no-launch control |
| `icacls` on `%LOCALAPPDATA%`, `%TEMP%`, the profile and the new stage root | 0 | no `ALL APPLICATION PACKAGES` ACE anywhere in the stage chain, so the backend relies on its granted ACEs and bypass-traverse only |
## 4. Notes for the coordinator

* `sandbox/mod.rs` (T-007a: `export`) was not touched. `run()` still returns `exported: Vec::new()`
  and the export step remains `not_implemented` on this branch.
* `Cargo.toml` and `Cargo.lock` were not modified, so the `sandboxrs-windows` pin is still in the
  manifest even though no API of it is used (S7B-009 decision).
* Frozen shared types (`isolation.rs`, `paths.rs`, `fsutil.rs`, `policy.rs`) were used as-is. Nothing
  outside `crates/fail2commit-core/src/sandbox/windows*`, the Windows test files, the sandbox fixture
  and the two Windows documents changed.
* `docs/dev/verify/VERIFY-2026-11-08-sandbox-windows.md` §7 carries the two change requests (stager
  contract, T-009 SDDL reconciliation) that are outside this worker's file ownership.
* No loopback exemption was added, no ACL outside the fail2commit stage root was changed, and nothing
  was pushed or published. Every test stage lives under
  `%LOCALAPPDATA%\fail2commit\cache\sandbox-stage` and is removed by its `TempDir` guard.
* Behaviour that is measured but not forced: a `TerminateJobObject` failure and a process that
  survives termination cannot be injected on a live Job Object without kernel tricks; both branches
  are checked in code and covered indirectly by the deadline unit tests.