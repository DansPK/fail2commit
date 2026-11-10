# Windows sandbox implementation review

This document records the T-007b review, the controls the Windows backend enforces, and the
dependency decision the coordinator has to make. It supersedes the 2026-11-08 text and covers the
2026-11-09 fix pass for review findings S7B-001..013 (`docs/dev/verify/reviews/REVIEW-2026-11-09-t007b.md`).

## 1. Dependency decision (S7B-009)

The manifest pins `sandboxrs-windows = 0.1.1`, whose resolved AppContainer dependency is
`rappct = 0.13.3`. Every public API that matters was read in the registry sources
(`%USERPROFILE%\.cargo\registry\src\*\sandboxrs-windows-0.1.1`) before deciding:

| API | Source | Used? | Why |
|---|---|---|---|
| `SandboxBuilder::preferred_backend(BackendPreference::AppContainer)` | `src/builder.rs:69` | No | It only takes effect through `SandboxBuilder::build()`, which calls `backend::appcontainer::build_state` (`src/backend/appcontainer/mod.rs`). That path runs `rappct::AppContainerProfile::ensure` **and** `compile::apply_grants`, which grants read/execute on `SystemRoot`, `ProgramFiles` and common-program directories and `FILE_ALL_ACCESS` on writable roots (`src/backend/appcontainer/compile.rs`). Broad system-directory ACL mutation and `FILE_ALL_ACCESS` violate SPEC-007's staged-only, least-privilege rule. |
| `Sandbox::probe()` / `Sandbox::available_backends()` | `src/sandbox.rs:95-107` | No | Both call `backend::appcontainer::probe::launch_probe`, which creates a workspace under `std::env::temp_dir()`, copies `current_exe()` into it and launches that executable, then caches the verdict in a process-wide `OnceLock` (`src/backend/appcontainer/mod.rs`). That is a second, environment-anchored, unsandboxed-launch-driven probe and would also break the "one sandboxed launch" probe budget. |
| `AppContainerProfile::ensure` / `delete` / SID access (`rappct`) | `src/backend/appcontainer/mod.rs` | No | `rappct` is not a direct dependency and its types are not re-exported by `sandboxrs-windows`, so profile creation is reachable only through `build_state`, that is, only together with the broad grants above. |
| `BackendKind::as_str()` / `label()` | `src/lib.rs:82-96` | No | Inert strings with no enforcement value. |

Conclusion: **no API of the pinned crate is used**, and the old dead reference
(`let _required_dependency_path = ...`) is gone. `Cargo.toml` is coordinator-owned and was not
edited. Decision requested from the coordinator: either drop the pin from the manifest, or record the
local `windows-sys` implementation below as the accepted SPEC-007 integration. Everything the backend
enforces is implemented and tested in
`crates/fail2commit-core/src/sandbox/windows{,.rs}` and `crates/fail2commit/tests/sandbox_windows_*.rs`.

## 2. Stage contract (S7B-003)

Grants are anchored on a fail2commit-owned directory, never on `std::env::temp_dir()` or any other
environment value:

* Stage root: `<TrustedPaths::cache_dir>/sandbox-stage`, which is
  `%LOCALAPPDATA%\fail2commit\cache\sandbox-stage` for a normal installation. It is created with
  private permissions and canonicalized before use.
* The anchors used for validation come from the operating system:
  `SHGetKnownFolderPath(FOLDERID_LocalAppData)` and `SHGetKnownFolderPath(FOLDERID_Profile)`.
* The stage root is refused when it is not strictly below the OS local app data directory (unless
  `FAIL2COMMIT_HOME` relocates the trusted directory set, which `crate::paths` documents as the
  disposable-home mechanism), when it is the local app data directory or an ancestor of it, when it
  is the user profile or an ancestor of the user profile, or when it is a volume root.
* A job stage is exactly one first-level child of the stage root. `work_dir` must be inside it, every
  `read_only` root must be inside the same one, and nothing may be granted on the stage root itself,
  on an ancestor of the user profile, or on a volume root.
* **Stager contract for T-004, T-005, T-008 and `fail2commit run`:** create the job stage as a direct
  child of `<cache_dir>/sandbox-stage` (documented here because `sandbox/mod.rs` is another worker's
  file). A stage anywhere else is refused with `IsolationUnavailable`, not silently accepted.
## 3. Enforced controls

`probe()` returns `available=true` only after a real sandboxed launch verifies every named control.
`run()` repeats every check that depends on the environment or the job (stage root, grant read-back,
loopback list, token, job limits, handle list), so a cached probe verdict is never the only evidence
for a launch.

| Control | Enforcement and verification |
|---|---|
| Zero network capability | A fresh random profile is created with zero capabilities. The suspended child token is read back and must be an AppContainer token with the expected package SID and `TokenCapabilities.GroupCount == 0`, so none of the three network capabilities is present. |
| No loopback exemption | Read from the operating system's own configuration with `NetworkIsolationGetAppContainerConfig` (FirewallAPI.dll, the same configuration `CheckNetIsolation LoopbackExempt` edits). No process is launched, no environment value is consulted, and a missing export or failing call makes the control false. The fresh random package SID must be absent from the list. |
| Staged-only ACLs | Nothing is granted until a handle-based walk has inspected every staged object (section 4). Only the unique package SID receives read/execute on `read_only` and modify on `work_dir`; every ACE is read back through the same handle, forbidden bits reject the run, and explicit entries are revoked afterwards (section 6). |
| Explicit stdio handle list | `CreateProcessW` uses `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with exactly stdin, stdout and stderr. Containment is **measured** on every run: a canary file is opened inheritable, the child is created suspended, the parent closes its own handle and requires an exclusive open to succeed. A child that inherited the canary keeps the object open and the run fails closed. A second, independent canary lives in the matrix test (`explicit_handle_list_excludes_an_inheritable_secret_handle`), where the child must fail `ReadFile` with exactly `ERROR_INVALID_HANDLE`. |
| Approval IPC denied | The probe creates one pipe with the tray's DACL shape — `D:P(D;;GA;;;S-1-15-2-1)(D;;GA;;;S-1-15-2-2)(A;;GA;;;SY)(A;;GA;;;<user SID>)` — and one pipe with the user's default DACL, named `fail2commit-approval-<SID>-probe-<nonce>` and `fail2commit-probe-default-<nonce>`. The sandboxed child must be denied both and both servers must see no client. The deny ACEs mirror the SDDL documented for `crates/fail2commit-core/src/ipc/winsec.rs` on the wave-1 branch; that module is another worker's file and is not imported here, so **when T-009 lands the constant in `windows.rs` and `ipc/winsec.rs` must be reconciled** (recorded change request). |
| Confined process tree | The root is created suspended and assigned to the Job Object before resume. The Job Object has kill-on-close, active-process, job-wide memory and die-on-unhandled-exception limits plus all UI restrictions; limits are queried back from the kernel before launch. |
| Timeout and cleanup | The timeout is a deadline, `TerminateJobObject`'s result is checked, and every post-run wait (`wait_empty`, both output drains) is bounded. A tree that survives the deadline plus the grace period is an error; a run never reports success while package code lives. |
| Bounded output | stdout and stderr are drained concurrently on two threads into one mutex-protected byte budget; excess bytes are drained and dropped and `truncated` is set. Each drain reports through a channel so the wait can be bounded (section 6). |
| Clean environment | Built from OS facts: `SystemRoot` and `SystemDrive` come from `GetSystemWindowsDirectoryW`; the caller's `SystemRoot` must agree with it or the run is refused. `LOCALAPPDATA` is described in section 5. Windows' hidden per-drive current-directory entries are synthesized with the staged cwd. Nothing else is inherited; `PATH` is absent unless the job supplies it. |

## 4. Handle-based grants and link rejection (S7B-001, S7B-007)

`StagedObject` opens each staged path with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`
and then, on that handle:

1. rejects the object when `GetFileInformationByHandle` reports `FILE_ATTRIBUTE_REPARSE_POINT`;
2. rejects a *file* whose `nNumberOfLinks != 1` — a hard link shares the file object, and therefore
   its DACL, with a directory entry outside the stage. Directory link counts are structural and are
   not used;
3. requires `GetFinalPathNameByHandleW` to still be under the canonical stage root;
4. writes the ACE with `SetSecurityInfo` on the same handle, never by path;
5. reads the ACE back on the same handle and rejects any bit outside the requested mask;
6. refuses a **NULL DACL** explicitly instead of replacing "unrestricted" with a package-only list.

The walk runs twice — once as a pre-grant rejection and once at grant time — so a swap between the
two passes is caught by the grant-time check on the handle that receives the ACE.
## 5. Child environment (S7B-008, S7B-002)

| Variable | Source | Rule |
|---|---|---|
| `SystemRoot` | `GetSystemWindowsDirectoryW` | The process environment's `SystemRoot` must canonicalize to the same directory, otherwise `probe()`/`run()` refuse: an inconsistent parent environment must not decide where system binaries or the child's root come from. |
| `SystemDrive` | derived from that directory | — |
| `LOCALAPPDATA` | computed | Windows requires the variable to exist — `CreateProcessW` fails with Win32 error 203 without it on the verified host — and it *derives the container's own profile folder from it* (`<value>\Packages\<package>\AC`). The child therefore receives `<work_dir>\localappdata`, so its profile folder lands inside its own disposable writable directory. The parent's real `LOCALAPPDATA` is passed only when the caller already points it inside the job's `work_dir`. |
| everything else | job allowlist | Validated (no NUL, no `=` in a key, no duplicate keys case-insensitively) and deduplicated. `PATH` is absent unless the job supplies it. |

## 6. Timeouts, cleanup and revoke state (S7B-004, S7B-006)

* `TerminateJobObject` is checked; a failure to terminate during a timeout is itself an error.
* `Job::wait_empty(deadline)` and `collect_drain(deadline, ...)` bound every post-run wait. A query
  error or an expired deadline is an error, so it can never be mistaken for a stopped tree.
* `StagingGrants::release()` revokes each granted object through the handle path from section 4,
  collects every failure, logs it to stderr, appends it to `<stage root>/pending-revoke.json` under a
  file lock, and returns `IsolationUnavailable`. A failed cleanup therefore fails the operation.
* `clear_pending_revokes()` runs at the start of every `probe()` and `run()`: it retries each recorded
  revocation by parsing the SID from the state file, and **refuses while any record remains**. A record
  whose object is already gone is dropped, so a crash cannot wedge the backend forever.

## 7. Probe cost (S7B-005, S7B-013)

* One sandboxed launch and no unsandboxed process. The same child proves the clean environment
  (`PATH` absent, allowlist value present, `LOCALAPPDATA` scoped), the two approval pipes, the shared
  output budget (`truncated` at 4 KiB) and the timeout (the child is killed at 4 s, which is why the
  probe reports `TimedOut`). The child reports through `probe-result.txt` in its own writable stage so
  the marker checks cannot race the output truncation.
* No permanent cache: a positive verdict is reused for at most 30 s and only for an identical
  environment fingerprint (system directory, Windows directory, stage root, `%SystemRoot%`, probe
  limits). Negative verdicts are never cached, and nothing is cached across processes.
* Measured on the verified host: **cold probe about 4.1 s** (dominated by the timeout it has to
  measure), **cached probe 0.4-0.5 ms**.

## 8. LPAC determination

`rappct 0.13.3` can request LPAC, but the pinned dependency's AppContainer path never selects it and
this backend does not set `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY`. Runtime token
inspection requires `TokenIsLessPrivilegedAppContainer == false`; an unexpected LPAC token fails
closed. No LPAC claim is made.

## 9. Test scope, evidence and pending items

Verified on Windows NT `10.0.26200.0` with `rustc 1.99.1`, `cargo 1.99.1`, `-j 2`:
`cargo test -j 2 -p fail2commit-core` (25 passed), the four Windows test targets
`--test sandbox_windows_matrix --test review_t007b_paths --test review_t007b_tempdir
--test review_t007b_systemroot` (6 passed / 1 ignored, 3 passed, 1 passed, 1 passed), plus
`cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -j 2 -- -D warnings`.
Exact commands, exit codes and the tested SHA are in `docs/dev/verify/reviews/FIX-T007B-SUMMARY.md`.

Qualification: grants are structurally confined to the stage root, and the hard-link regression
compares the DACL of an outside file before and after the refusal with `icacls`, so "no real checkout,
home, or user directory is granted" is now checked for the link case as well as the direct case.

Pending, unchanged: the live external endpoint test stays `#[ignore]` (no authorization for live
network traffic), and the full staged MinGW GCC closure is still unavailable — the installed root is
11 871 files / 961 MB, and copying only `gcc.exe` would not be a legitimate toolchain test.
## Known limitation: user profile required

The AppContainer backend calls `CreateAppContainerProfile`, which needs the user's registry hives (including the `_Classes` hive) to be loaded. In a batch or service logon without a loaded profile (for example a VMware Tools guest operation, a scheduled task without profile loading, or some CI runners) it fails with `HRESULT 0x80070002`; `probe()` then reports the backend unavailable and installs with scripts fail closed. Observed on a clean Windows 11 25H2 VM through VMware Tools (see docs/dev/verify/VERIFY-2026-11-09-release.md section 5). Run guarded installs from an interactive session, or load the profile for the service account. In an interactive sign-in the backend is available with all controls verified on a clean Windows 11 25H2 VM and a clean Windows 10 IoT Enterprise LTSC 2021 VM (section 5b of the same report).

## Node.js child processes inside the AppContainer (CR-014)

Node's `child_process` with piped stdio (`execFileSync`, `spawnSync` with the default `pipe`, `exec`, `spawn`) creates its stdio pipes as `\\?\pipe\uv\...` in the global named-pipe namespace. An AppContainer process may not create pipes there; libuv reads the resulting `ERROR_ACCESS_DENIED` as a name collision and retries forever. An install script that ran another program with piped output therefore hung until `limits.job_timeout_secs` (900 s). Example: `esbuild`'s `node install.js`, which runs `esbuild --version`. Spawning with `stdio: "ignore"` was never affected.

fail2commit now loads a small preload into every sandboxed npm lifecycle script on Windows: `--require` in `NODE_OPTIONS`, file `f2c-node-preload.js` beside the staged `node.exe`. It routes piped child stdio through files in the job's writable temp directory (`F2C_IO_DIR`): synchronous children through Node's `spawn_sync` binding, asynchronous ones through `ChildProcess.prototype.spawn`, with `close` held until the output has been read. Node children inherit `NODE_OPTIONS`, so the preload applies to them as well. It runs only inside the job and grants nothing: the AppContainer, its ACLs, the network denial and the job limits are unchanged. Verified on the development host: `npm install esbuild` from the public registry completes in about 30 s with its postinstall sandboxed, and `e2e_npm_sandbox::install_script_child_processes_with_pipes_finish_in_the_sandbox` covers `execFileSync`, `spawnSync` with input, and async `spawn` with both output streams.

Still unsupported: writing to an asynchronous child's stdin (the child gets `ignore`), `fork()` IPC channels, and non-Node programs that themselves create named pipes. Such a script still fails closed at the job timeout, and the error now says the script "did not finish within limits.job_timeout_secs".

## Known issue: antivirus behaviour detection

Microsoft Defender's machine-learning behaviour monitor can classify the unsigned `fail2commit.exe` as `Behavior:Win32/DefenseEvasion.A!ml` when the sandboxed child behaves like an attack, for example reading a secret file or opening network connections that the sandbox then denies. The executable is then quarantined and its hash blocked. Benign workloads were not flagged. Signed release binaries and a false-positive submission to Microsoft are required before a Windows release; fail2commit does not add antivirus exclusions.

