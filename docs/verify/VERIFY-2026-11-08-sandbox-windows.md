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
