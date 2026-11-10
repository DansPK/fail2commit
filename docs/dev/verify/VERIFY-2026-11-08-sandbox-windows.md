# Verify Report: Windows AppContainer sandbox (2026-11-09)

> **Requirements covered:** FR-007, SPEC-007, TC-007  
> **Commit / branch:** `4950324ae2989267d328f7e9665a547f2151e742` / `DansPK/f2c-t007b-sandbox-windows`  
> **Verified by:** orca:codex dispatched worker T-007b

---

## 1. Platform

- `[System.Environment]::OSVersion.VersionString`: `Microsoft Windows NT 10.0.26200.0`
- Registry `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`: `ProductName=Windows 10 Pro` (the compatibility registry label), `DisplayVersion=25H2`, `CurrentBuild=26200`, `UBR=9711`, `InstallationType=Client`.
- Rust: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, host `x86_64-pc-windows-gnu`, LLVM `23.1.1`; Cargo `1.99.1 (5f94df478 2026-08-27)`.
- Git: `2.56.0.windows.2`.
- GCC available but not staged: WinLibs MinGW-W64 `16.2.0`, root size `961,264,336` bytes across `11,871` files.

## 2. Commands Run

All Rust commands used `CARGO_TARGET_DIR=.target-t007b` and `-j 2` where compilation occurred because the host was overloaded.

```text
git rev-parse HEAD
# 4950324ae2989267d328f7e9665a547f2151e742; exit 0

cargo fmt --all -- --check
# exit 0

cargo clippy --workspace --all-targets -j 2 -- -D warnings
# exit 0

cargo test --workspace -j 2
# exit 0; fail2commit 2 passed; Windows matrix 5 passed / 1 ignored;
# fail2commit-core 17 passed; tray 0 tests; doc tests 0 tests

python .claude/hooks/trace_check.py
# [guard:trace_check] OK; exit 0

%SystemRoot%\System32\CheckNetIsolation.exe LoopbackExempt -s
# "List Loopback Exempted AppContainers" / "OK."; exit 0; no entries

rg -n "tracing|Trace|ETW|Process Monitor" crates/fail2commit-core/src/sandbox/windows.rs crates/fail2commit-core/src/sandbox/windows crates/fail2commit/tests/sandbox_windows_matrix.rs tests/fixtures/sandbox-windows
# no matches; exit 1 (expected: runtime tracing is unused)
```

The dependency review used the resolved registry sources for `sandboxrs-windows-0.1.1` and `rappct-0.13.3`; results and the local patch rationale are in `docs/sandbox-windows.md`.

## 3. Results

| TC / matrix item | Result | Evidence |
|---|---|---|
| TC-007 overall | Pending | All offline Windows enforcement cases passed, but the ignored live external endpoint and full staged GCC build remain pending below. |
| Backend probe and fail-closed control list | Pass | `host_probe_verifies_every_mandatory_control`; all nine controls true before `available=true`. |
| Zero capabilities and no loopback exemption | Pass | Suspended child token read-back validates AppContainer SID, capability count zero, and non-LPAC token; read-only `CheckNetIsolation -s` returned no exemptions. |
| Restrictive staged ACLs | Pass | Runtime ACL read-back; `parent_and_grandchild_cannot_reach_network_secret_checkout_or_git`; read-only native input and writable `work_dir` succeed while fake home and checkout remain unchanged. |
| No inherited credential handle | Pass | `explicit_handle_list_excludes_an_inheritable_secret_handle` marks a synthetic-secret handle inheritable in the parent and verifies that the child cannot read it. |
| Approval IPC, intended DACL | Pass | Runtime probe root child and spawned descendant cannot open a pipe denying `S-1-15-2-1` / `S-1-15-2-2`; server observes no connection. |
| Approval IPC, default DACL | Pass | Same runtime probe against a default-DACL pipe from both generations; server observes no connection. |
| Localhost TCP, parent and grandchild | Pass | Host-bound `127.0.0.1` listener remains unreachable in `parent_and_grandchild_cannot_reach_network_secret_checkout_or_git`. |
| External TCP `1.1.1.1:443` | Pending | `external_tcp_is_denied` is compiled but `#[ignore]`; project rules prohibit live network in default tests. Missing prerequisite: explicit authorization for a live external-network test. |
| Synthetic secret file | Pass | Runtime-concatenated synthetic credential under a separate fake home is unreadable to parent and grandchild and unchanged afterward. |
| Checkout write | Pass | Separate disposable checkout target remains absent after parent and grandchild attempts. |
| `git.exe` | Pass | Both generations attempt host Git. Execution may be denied; if it starts, it runs under the same verified zero-capability token whose direct local TCP attempt fails. |
| Active-process limit / descendants | Pass | `process_memory_time_and_output_limits_are_enforced`; process limit two stops the spawn-many workload; no descendant survives return. |
| Job-wide memory limit | Pass | Same test with 48 MiB job memory limit stops the allocating workload. |
| Timeout kills whole job | Pass | Same test returns `JobStatus::TimedOut` for a spinning workload and waits for `ActiveProcesses == 0`. |
| Combined bounded output | Pass | Same test caps concurrent stdout/stderr at 31 bytes and reports `truncated=true`. Runtime probe independently exercises 127-byte truncation. |
| Clean environment | Pass | `clean_environment_and_native_workload_succeed`; caller allowlist value plus forced Windows essentials exist and inherited `PATH` is absent. |
| Legitimate native workload | Pass | Staged dependency-free native Rust helper reads staged input and writes the expected artifact only in `work_dir`. |
| Full staged MinGW GCC compile | Pending | Installed root is 961,264,336 bytes / 11,871 files; a valid closure needs driver, `cc1`, assembler, linker, CRT objects, libraries, headers, specs, and DLLs. Copying only `gcc.exe` is invalid; a reviewed minimal closure fixture is not available. |
| Sandbox enabled | Pass | All runtime matrix jobs execute through `platform_backend()` only after the real probe passes. |
| Sandbox disabled | Pass | `disabled_and_unavailable_policy_never_launches_package_code` returns `SkipScripts`; launch marker is absent. |
| Sandbox unavailable / missing control | Pass | Policy returns `Deny(IsolationUnavailable)`; `missing_mandatory_limit_fails_before_launch` removes the process limit, returns `IsolationUnavailable`, and proves the launch marker is absent. |
| LPAC | Pass (no claim) | Dependency can model LPAC but does not request it on this path. Runtime token is explicitly checked as non-LPAC; unexpected LPAC fails closed. |
| Runtime tracing unused | Pass | Static search found no tracing/ETW/Process Monitor dependency; decisions use token, ACL, Job Object, pipe, and process results. |
| Linux compile/runtime | Pending | Coordinator explicitly instructed this worker not to use Docker or WSL while WSL is being restarted. T-007a owns Linux; no Linux result is claimed here. |

## 4. Traceability Check

```text
[guard:trace_check] OK
```

## 5. Issues Found

- The recovered pre-existing implementation treated a Job Object handle as waitable and hung even after `ActiveProcesses` reached zero. T-007b now waits through Job accounting/completion-port evidence and never returns before the tree is empty.
- A custom clean Windows environment needs hidden per-drive current-directory entries and, on this host, `LOCALAPPDATA`; omitting them made AppContainer `CreateProcessW` fail with Win32 error 203. Only these required entries and the job allowlist are now present.
- No coordinator-owned TODO row was modified. Remaining evidence gaps are the two explicit Pending items above, not hidden test passes.

## 6. Verdict

- [ ] **Verified:** all linked TCs pass; requirement status set to `Verified`
- [x] **Not verified:** Windows offline controls pass, but live external TCP and a full staged GCC build remain Pending; Linux evidence is outside T-007b and was explicitly deferred.

---

## 7. Fix pass for review findings S7B-001..013 (2026-11-09)

> **Branch:** `DansPK/f2c-fix-t007b` (this worktree); final SHA in
> `docs/dev/verify/reviews/FIX-T007B-SUMMARY.md`
> **Findings addressed:** `docs/dev/verify/reviews/REVIEW-2026-11-09-t007b.md` §2, S7B-001..013
> **Author:** T-007b fix pass (a different agent from the reviewer and the original author)

Every finding was fixed rather than re-documented. Two findings changed the *product* contract and are
recorded as change requests for the coordinator:

1. **CHANGE REQUEST (stager contract, from S7B-003).** A job stage must now be a direct child of
   `<TrustedPaths::cache_dir>/sandbox-stage`. T-004, T-005, T-008 and `fail2commit run` must create
   stages there; a stage anywhere else (including `%TEMP%`) is refused with `IsolationUnavailable`.
   Documented in `docs/sandbox-windows.md` §2 because `sandbox/mod.rs` belongs to T-007a.
2. **CHANGE REQUEST (T-009 coupling, from S7B-005).** The probe measures the approval pipe against the
   tray's DACL shape reproduced locally in `windows.rs`
   (`fail2commit-approval-<SID>-probe-<nonce>`). When `ipc/winsec.rs` lands, both places must carry the
   same SDDL, or it must move to a shared coordinator-owned constant.
| Finding | Status | Fix | Evidence on this host |
|---|---|---|---|
| S7B-001 | Fixed | `StagedObject` opens each staged path with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects reparse points and files with `nNumberOfLinks != 1`, requires `GetFinalPathNameByHandleW` to stay under the stage root, and grants/revokes through that handle with `SetSecurityInfo`/`GetSecurityInfo`. The pre-grant walk also rejects links. | `review_t007b_paths::hard_link_inside_staged_tree_is_rejected` (also compares the outside file's `icacls` DACL before and after), `review_t007b_paths::junction_inside_staged_tree_is_rejected`, `review_t007b_paths::a_read_only_root_from_another_stage_is_rejected`, `windows::tests::a_hard_link_in_the_stage_is_rejected_before_any_grant` |
| S7B-002 | Fixed | System32 comes from `GetSystemDirectoryW`; the child's `SystemRoot` comes from `GetSystemWindowsDirectoryW` and a disagreeing process `SystemRoot` is refused. The loopback control reads `NetworkIsolationGetAppContainerConfig` from FirewallAPI.dll dynamically: no process launch, no environment input, fail-closed errors. | `windows::tests::host_probe_verifies_every_mandatory_control`, `review_t007b_systemroot::an_environment_selected_system_root_cannot_answer_the_loopback_control` |
| S7B-003 | Fixed | Stage root is `<cache_dir>/sandbox-stage`; LOCALAPPDATA and profile anchors come from `SHGetKnownFolderPath`; refusal rules in `docs/sandbox-windows.md` §2; `std::env::temp_dir()` is not referenced anywhere in the backend. | `review_t007b_tempdir::temp_dir_anchor_is_not_used` (caller-selected `TMP`/`TEMP` and the profile fallback are both refused and the caller directory's `icacls` DACL is unchanged), `windows::tests::a_work_dir_outside_the_stage_root_is_rejected` |
| S7B-004 | Fixed | `Job::terminate` returns a checked result; `Job::wait_empty(deadline)` and `collect_drain(deadline, ...)` bound every post-run wait; a surviving tree is an error, never a success. `Spawned::kill` is checked too. | `windows::tests::a_drain_that_misses_its_deadline_is_an_error`, `windows::tests::a_drain_that_reports_in_time_returns_its_bytes`, `process_memory_time_and_output_limits_are_enforced` (timeout path) |
| S7B-005 | Fixed | No permanent probe cache: a positive verdict lives at most 30 s and only for an identical environment fingerprint. Handle containment is now *measured* (inheritable canary plus an exclusive-open check before resume) instead of inferred. Approval IPC is measured against the tray DACL shape and pipe-name pattern. | `windows::tests::a_second_probe_reuses_a_short_lived_positive_verdict`, `sandbox_windows_matrix::explicit_handle_list_excludes_an_inheritable_secret_handle`, `windows::tests::host_probe_verifies_every_mandatory_control` (APPROVAL-DENIED / DEFAULT-DENIED markers plus "no client") |
| S7B-006 | Fixed | `StagingGrants::release` reports every revoke failure: stderr log, `<stage root>/pending-revoke.json` record under a file lock, and `IsolationUnavailable` for the operation. `clear_pending_revokes` runs at the start of `probe()`/`run()` and refuses while a record remains. | `windows::tests::stale_revoke_state_blocks_the_next_operation_until_it_is_cleared`, `windows::tests::a_recorded_revoke_failure_is_cleared_once_the_object_is_gone` |
| S7B-007 | Fixed | A NULL DACL is refused before any write, in `grant`, in `revoke` (nothing to remove) and in `allowed_mask` (cannot read back). | `windows::tests::a_null_dacl_is_refused_before_any_write` (sets a NULL DACL on a disposable staged file and requires the refusal) |
| S7B-008 | Fixed | `SystemRoot`/`SystemDrive` come from the OS; `LOCALAPPDATA` is `<work_dir>\localappdata` unless the caller already points it inside the work dir. Required variables documented. | `sandbox_windows_matrix::clean_environment_and_native_workload_succeed` (fixture requires `PATH` absent, allowlist present and `LOCALAPPDATA` based inside the work dir), probe `LAD=` marker check |
| S7B-009 | Fixed (reported) | Dead reference removed; no API of `sandboxrs-windows 0.1.1` is used. `docs/sandbox-windows.md` §1 lists each candidate API with source citations and the reason it was rejected, for the coordinator's dependency decision. `Cargo.toml` untouched. | Documentation review only; `cargo clippy --workspace --all-targets -D warnings` still passes with the crate unused. |
| S7B-010 | Fixed | The disabled/unavailable case drives the FR-008 decision table through a launcher that *really* executes the package code and counts calls, with a positive control proving the marker appears when the gate allows it. | `sandbox_windows_matrix::disabled_and_unavailable_policy_never_launches_package_code` |
| S7B-011 | Fixed | The helper records the Git outcome (`git_version`, `git_ls_remote`) in a report file; the test asserts Git cannot read a disposable bare remote outside the stage, after proving unsandboxed that the same remote *is* readable. | `sandbox_windows_matrix::parent_and_grandchild_cannot_reach_network_secret_checkout_or_git` |
| S7B-012 | Fixed | The handle canary is a real inheritable handle to a synthetic secret outside the granted roots; the child must fail `ReadFile` with exactly `ERROR_INVALID_HANDLE`, the parent clears the inheritance flag afterwards, and the secret is compared before and after. | `sandbox_windows_matrix::explicit_handle_list_excludes_an_inheritable_secret_handle` |
| S7B-013 | Fixed | `probe()` performs exactly one sandboxed launch, starts no external process, and is covered by a 30 s positive-verdict TTL. Measured: cold probe about 4.1 s (dominated by the timeout it measures), cached probe 0.4-0.5 ms. | `windows::tests::a_second_probe_reuses_a_short_lived_positive_verdict`, `sandbox_windows_matrix::probe_verifies_every_control_in_one_launch_and_then_reuses_it_briefly` |
### Commands and exit codes for this section

```text
cargo fmt --all -- --check
# exit 0
cargo clippy --workspace --all-targets -j 2 -- -D warnings
# exit 0
cargo test -j 2 -p fail2commit-core
# exit 0; 25 passed; 0 failed (sandbox::windows::tests: 10 passed)
cargo test -j 2 -p fail2commit --test sandbox_windows_matrix --test review_t007b_paths --test review_t007b_tempdir --test review_t007b_systemroot
# exit 0; matrix 6 passed / 1 ignored; paths 3 passed; tempdir 1 passed; systemroot 1 passed
python .claude/hooks/trace_check.py
# exit 0
```

Limitations of this fix pass:

* The termination-failure branches (a `TerminateJobObject` error, a process that survives termination)
  cannot be forced on a live Job Object without kernel-level tricks. They are covered by deadline unit
  tests and checked return values rather than by an injected fault.
* The approval-pipe DACL is reproduced locally; reconciling it with `ipc/winsec.rs` is the recorded
  change request above.
* The live external endpoint and the full staged GCC closure remain pending exactly as in §3.
