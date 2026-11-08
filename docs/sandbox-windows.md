# Windows sandbox implementation review

This document records the T-007b review and the controls enforced by the Windows backend. The dependency is exactly `sandboxrs-windows = 0.1.1`; its resolved AppContainer dependency is `rappct = 0.13.3`. The reviewed sources were the registry copies under `%USERPROFILE%\.cargo\registry\src\*\sandboxrs-windows-0.1.1` and `%USERPROFILE%\.cargo\registry\src\*\rappct-0.13.3`.

## Dependency AppContainer path

The reviewed path is `sandboxrs-windows::BackendPreference::AppContainer`, not `WindowsSandboxApi`:

- `backend/appcontainer/mod.rs` creates a unique `rappct::AppContainerProfile`, compiles filesystem grants, launches with `SECURITY_CAPABILITIES`, and deletes the profile from `Drop`.
- `rappct::AppContainerProfile::ensure` calls `CreateAppContainerProfile` with a null capability array and count zero. Profiles are registered by Windows under the per-user AppContainer profile store; `GetAppContainerFolderPath` resolves their data directory below `%LOCALAPPDATA%\Packages`. `DeleteAppContainerProfile` removes the registration.
- `backend/appcontainer/spawn.rs` supplies a zero-entry `SECURITY_CAPABILITIES` list and an explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` for standard I/O. It creates the process suspended, creates and assigns a Job Object, and only then resumes the primary thread.
- `job.rs` sets kill-on-close, an optional active-process limit, and a per-process memory limit. `SandboxChild` terminates the job on timeout/drop.
- `backend/appcontainer/compile.rs` grants the package SID read/execute or read/write ACLs. It also recursively attempts broad read/execute grants on `SystemRoot`, `ProgramFiles`, and common-program directories. Its read/write mask is `FILE_ALL_ACCESS`.
- `rappct` supports the named network capabilities `internetClient`, `internetClientServer`, and `privateNetworkClientServer`, but the dependency's AppContainer path supplies no capabilities. `rappct` can request LPAC through `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`; `sandboxrs-windows` 0.1.1 does not request it.

The public builder cannot be used unchanged for fail2commit: its broad baseline system-directory ACL mutation and `FILE_ALL_ACCESS` writable grant violate SPEC-007's staged-only, least-privilege rule; its job uses a per-process rather than job-wide memory limit and has no UI restrictions or kernel read-back; and its output API does not enforce fail2commit's one combined bounded drain. The fail2commit module therefore pins the dependency and AppContainer selection at compile time, but applies a narrow local patch with `windows-sys` for profile creation, staged ACLs, launch, job limits, and output. Migration to the dependency's VM/API backend is deliberately excluded.

## Enforced controls

`probe()` returns `available=true` only after a real launch verifies every named control. `run()` repeats all setup and token checks for every job; any pre-resume failure returns `IsolationUnavailable`.

| Control | Enforcement and verification |
|---|---|
| Zero network capability | A fresh random profile is created with zero capabilities. The suspended child token is read back and must be an AppContainer token with the expected package SID and `TokenCapabilities.GroupCount == 0`. Therefore none of the three network capabilities is present. |
| No loopback exemption | Before launch, `CheckNetIsolation.exe LoopbackExempt -s` is run read-only with a clean environment. The fresh package SID must not occur in its output. The implementation never invokes `-a` or changes exemptions. |
| Staged-only ACLs | All granted paths must canonicalize beneath one first-level child of the canonical system temp directory; read-only roots and the writable work root cannot overlap; and the complete stage is rejected if any entry is a reparse point. Only the unique package SID receives read/execute on `read_only` and modify on `work_dir`. Every ACE is read back, forbidden bits reject the run, and explicit ACEs are revoked on drop. No real checkout, home, or user directory is granted. |
| No credential-handle inheritance | `CreateProcessW` uses `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` containing exactly stdin, stdout, and stderr. A process-global mutex covers the short interval in which those handles are marked inheritable. A test marks a synthetic-secret handle inheritable in the parent and proves the child cannot read it. |
| Approval IPC denied | The runtime probe creates one pipe with the intended tray DACL (explicit deny for `S-1-15-2-1` and `S-1-15-2-2`, allow only SYSTEM and the current user) and one pipe with the user's default DACL. Both the root child and a spawned descendant must fail to open both pipes; the servers also verify that no client connected. |
| Confined process tree | The root is created suspended and assigned before resume. The Job Object has kill-on-close, active-process, job-wide memory, and die-on-unhandled-exception limits; all UI restrictions are set; breakaway and silent breakaway are absent. Limits and UI restrictions are queried back from the kernel before launch. |
| Timeout and cleanup | Timeout or resource-limit notification terminates the whole job. The backend polls Job Object accounting until `ActiveProcesses == 0` before returning; Job handles themselves are not incorrectly treated as waitable objects. Profile deletion and ACL revocation happen only after the process tree has stopped. |
| Bounded output | stdout and stderr are drained concurrently on two threads into one mutex-protected byte budget. Excess bytes continue to be drained but are dropped, and `truncated=true`. |
| Clean environment | Caller entries are validated and deduplicated case-insensitively. `SystemRoot`, `SystemDrive`, and `LOCALAPPDATA` are forced from the trusted parent, and Windows' required hidden per-drive current-directory entries are synthesized with the staged cwd. Nothing else is inherited; notably `PATH` is absent unless explicitly supplied by the job. `LOCALAPPDATA` is required because AppContainer `CreateProcessW` returns error 203 without it on the verified host; it grants no filesystem access. |

## LPAC determination

`rappct 0.13.3` has an LPAC option, but `sandboxrs-windows 0.1.1` does not select it in its AppContainer backend. fail2commit does not set `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY`. Runtime token inspection requires `TokenIsLessPrivilegedAppContainer == false`; an unexpected LPAC token fails closed. Consequently this implementation makes no LPAC claim.

## Test scope and pending evidence

The Windows matrix compiles a dependency-free Rust helper with the active GNU Rust toolchain, stages only its executable and inputs, and tests localhost TCP, external file access, checkout writes, Git execution under the same zero-network token, inherited handles, clean environment, descendants, process count, job memory, timeout, and combined output bounds. A smaller legitimate native workload reads a staged input and writes an artifact only in `work_dir`.

The full MinGW GCC build remains pending. The installed WinLibs root contains 11,871 files totaling 961,264,336 bytes; a correct GCC invocation needs `gcc.exe`, `cc1.exe`, assembler/linker binaries, target CRT objects, libraries, headers, specs, and runtime DLLs. Copying only `gcc.exe` is not a legitimate toolchain test, while staging the complete installation exceeds the intended minimal fixture. A future dedicated fixture should assemble and hash a reviewed minimal GCC closure.
