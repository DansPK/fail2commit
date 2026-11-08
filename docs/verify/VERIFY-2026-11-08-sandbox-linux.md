# Verify Report: Linux sandbox, export, `fail2commit run`, Linux harness (2026-11-08)

> **Requirements covered:** FR-007 (SPEC-007, TC-007), Linux half. The Windows AppContainer backend is T-007b.
> **Commit / branch:** `3d2c69347ffde3b7495472703f8ddf73298aa7e7` on `DansPK/f2c-t007a-sandbox-linux` (base `fe411ba`). Evidence was collected 2026-11-09.
> **Verified by:** T-007a worker (Claude Opus 5.5, Orca task `task_edbce5cc5373`)

---

## 1. Commands Run

All commands ran from the worktree root. Windows host: rustc 1.99.1 `x86_64-pc-windows-gnu`.

| # | Platform | Command | Exit |
|---|---|---|---|
| 1 | Windows 11 | `cargo fmt --all -- --check` | 0 |
| 2 | Windows 11 | `cargo clippy --workspace --all-targets -- -D warnings` (`CARGO_BUILD_JOBS=2`) | 0 |
| 3 | Windows 11 | `cargo test --workspace` (`CARGO_BUILD_JOBS=2`) | 0 |
| 4 | Linux container `rust:1` (Debian 13, rustc 1.99.1) | `powershell -File scripts/linux/test.ps1 -Volume f2c-t007a -Stage container -Gcc`, which runs `container.sh`: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast` | 101 (see §4, coordinator-owned `main.rs` test only) |
| 5 | WSL Ubuntu 26.04, kernel 6.18.54.1-microsoft-standard-WSL2, bwrap 0.11.1, systemd 259 user scope, uid 1000 | `powershell -File scripts/linux/test.ps1 -Volume f2c-t007a -Stage container,wsl,privileged -NoCheck -Gcc -Filter '^(sandbox_linux\|run_\|fail2commit_core)'` (WSL stage: `run-bundle.sh` with `F2C_REQUIRE_SANDBOX=1`, `F2C_REQUIRE_NATIVE_BUILD=1`, staged gcc sysroot) | 0 |
| 6 | Privileged container `rust:1` with bubblewrap 0.12.0, no systemd (rlimit-only path), run as uid 1000 through `setpriv` | same invocation as #5, privileged stage (`privileged.sh`); uses real `/usr/bin/gcc` | 0 |
| 7 | WSL Ubuntu | `sandbox_linux_hostile --ignored --exact host_control_reaches_external_endpoint` (live-internet positive control) | 0 |
| 8 | Windows 11 | `python .claude/hooks/trace_check.py` | 0 |

`tracers: none` was printed on both bundle hosts: strace and ltrace are absent, and nothing uses runtime tracing.

## 2. Results

Tests are in `crates/fail2commit/tests/` and the unit tests in `sandbox/{mod,linux}.rs` and `cmd/run.rs`. **WSL** means #5 and **Priv** means #6.

| TC / matrix item | Requirement | Result | Evidence |
|---|---|---|---|
| TC-007 legitimate native build | FR-007 | **Pass** (WSL, Priv) | `sandbox_linux_build::native_c_build_succeeds_and_exports_artifact`: compiles and runs `tests/fixtures/sandbox/native/hello.c` and exports `hello`. WSL uses the staged gcc sysroot bound read-only; Priv uses the system gcc. |
| Hostile: git from parent and child | FR-007 | **Pass** (WSL, Priv) | `hostile_parent_and_child_are_blocked` `git_host_repo` BLOCKED for both parent and child. `host_control_reaches_every_target` LEAKs on the host, proving the probe works. |
| Hostile: network to localhost listener | FR-007 | **Pass** (WSL, Priv) | `tcp_localhost` BLOCKED for parent and child; host control LEAK. |
| Hostile: external endpoint 1.1.1.1:443 | FR-007 | **Pass** (WSL, Priv) | `tcp_external` BLOCKED in the sandbox; the host reaches it (#7). |
| Hostile: planted synthetic secret, host home | FR-007 | **Pass** (WSL, Priv) | `planted_file` and `host_home` BLOCKED; host control LEAK. The token is planted in a temp dir outside every bind, and the real `$HOME` is only listed read-only, never written. |
| Hostile: write the real checkout | FR-007 | **Pass** (WSL, Priv) | `checkout_write` BLOCKED and the checkout stays empty. `run_cli::run_builds_in_staged_copy_and_exports_declared_paths`: the real input is untouched. |
| Hostile: fake credential socket and approval IPC socket | FR-007 | **Pass** (WSL, Priv) | `credential_socket`, `approval_socket` (path sockets) and `abstract_socket` (abstract namespace) BLOCKED; host control LEAK. |
| Hostile output paths (symlink, `..`, absolute, hard link, special, oversize, planted destination link) | FR-007 | **Pass** (Windows, WSL, Priv) | `sandbox::tests::*` (7 per platform), `run_cli::escaping_export_paths_are_rejected_before_anything_runs`, `run_cli::linux::hostile_export_links_are_rejected` (exit 10, nothing copied). |
| Never export on failure or timeout | FR-007 | **Pass** | `run_job_exports_only_after_clean_exit` (Exited(1), TimedOut, Killed) and `run_cli::linux::failed_or_timed_out_jobs_export_nothing` (exit 3 and 124). |
| Fork bomb bounded | FR-007 | **Pass** (WSL: cgroup and rlimit-only; Priv: rlimit-only) | `process_count_is_bounded` (fewer than 16 spawned with a limit of 16) and `fork_bomb_is_contained` (returns within the timeout). |
| Memory hog bounded | FR-007 | **Pass** (WSL: cgroup `memory.max` and RLIMIT_AS; Priv: RLIMIT_AS) | `memory_hog_is_bounded`: never reaches 2 GiB with a 384 MiB limit; status is not Exited(0). |
| Timeout kills the tree; children waited for | FR-007 | **Pass** (WSL, Priv) | `timeout_kills_the_whole_tree` and `background_processes_stop_when_the_job_exits`: no process with the unique marker remains on the host. |
| Bounded output, concurrent drain | FR-007 | **Pass** | `output_is_capped_and_drained` (8 MB written with a 1000-byte cap, no deadlock), `output_budget_is_shared_and_drains`, `run_cli::linux::output_is_sanitized`. |
| Probe: namespaces, clean env, mount policy, limits | FR-007 | **Pass** (WSL, Priv) | `probe_verifies_every_mandatory_control`, `sandbox_sees_only_job_env_and_minimal_mounts`, `jobs_exposing_home_run_or_root_are_refused_before_launch`. |
| Runtime tracing not used | FR-007 | **Pass** | No tracing in the code. Both bundle hosts report `tracers: none`, and every test passed there. |
| Sandbox enabled | FR-007 | **Pass** (WSL, Priv) | `run_cli` runs sandboxed with `enabled = true`. |
| Sandbox disabled | FR-007 | **Pass** (WSL, Priv) | `run_cli`: explicit run is still sandboxed with `enabled = false` (host home not visible). |
| Sandbox unavailable | FR-007 | **Pass** (Windows, Linux) | `missing_bwrap_launches_nothing` (missing bwrap path: IsolationUnavailable, marker file not created), `run_cli::unavailable_sandbox_refuses_to_run` (Windows: exit 14, toggle on and off), `untrusted_executables_are_refused`, `unavailable_backend_launches_nothing`. |
| Windows sandbox behavior | FR-007 | **Pending** | Owned by T-007b. Here, on Windows, only the shared `export()` and the CLI unavailable path were tested. |
| Approval IPC against the real tray pipe | FR-007 | **Pending** | Needs the T-009 tray IPC. A fake unix approval socket (path and abstract) stood in for it. |

## 3. Traceability Check

```text
[guard:trace_check] OK
```

## 4. Issues Found

- `crates/fail2commit/src/main.rs` `tests::shims_route_to_subcommands` fails on Linux (`C:\b\NPM.exe` is not a path separator on Linux). This is coordinator-owned; the coordinator reports it fixed on the integration branch and asked workers to ignore it. It is the only failure in command #4 (`error: 1 target failed`). Everything else in the container passed: fmt, clippy and all T-007a tests. The bwrap tests return early there as skips, because the unprivileged container has no bwrap; that is not evidence, and the evidence comes from #5 and #6.
- Found and fixed during verification: systemd ≥ 254 expands `${VAR}` in the command line of `systemd-run`, which rewrote job arguments. The probe self-test caught it and reported the backend unavailable (fail closed). The fix passes `--expand-environment=no`; a systemd that rejects that flag makes the scope probe fail, and limits fall back to rlimits.

## 5. Verdict

- [x] **Verified for Linux:** every T-007a TC and sandbox-matrix item passes on two real Linux runtimes. Windows backend items remain Pending (T-007b); the approval-IPC item stays Pending until T-009.
- [ ] **Not verified:** —
