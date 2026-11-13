# FR-027 Windows watchdog fix re-review (2026-11-14)

**Pinned implementation:** `ca25e0b77263472096fd849cb30a9dcf67e82ba5`, compared only with launcher snapshot `c776c7c6a2d727a72fcb60c6ddf7fb2b7a47c58b` and HL-01 in `REVIEW-2026-11-14-hardened-launcher.md` (`8d3f576736a95daab49c28511d0623a5ddf0ff7d`). **Verdict:** HL-01 is source-fixed, with one residual exceptional-termination flaw and missing integrated VM proof. Package LAUNCH remains unavailable until LPAC/WFP controls pass (`service.rs:1740-1749`); this is not full FR-027 acceptance. The prior review commits remain reachable on their review branches.

## HL-01 disposition: source-fixed, VM proof pending

The service now polls the already-connected pipe with a one-byte nonblocking `ReadFile` (`service.rs:1566-1602`). A post-request byte becomes `UnexpectedData`; `ERROR_BROKEN_PIPE`/`ERROR_PIPE_NOT_CONNECTED` becomes `Disconnected`, while an empty connected pipe returns `ERROR_NO_DATA`/`Idle`. Either unexpected data or disconnection drops the watchdog writer and starts a two-second fallback timer (`:1514-1535`). This removes the prior `PeekNamedPipe` loop that could mistake unread suffix bytes for a live client. Microsoft documents that [a nonblocking empty pipe returns `ERROR_NO_DATA`](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes); the remaining exact service behavior needs Windows VM evidence.

The two focused pipe tests pass (`service.rs:1874-1920`), but their fixture creates a **blocking** pipe (`:1838-1848`), then tests a closed peer and one suffix byte separately. They do not exercise the production nonblocking mode, idle live client, suffix still buffered *after* client closure, or actual launcher/watchdog termination. These are precise pending integration gates, not failures of the unit tests.

## Residual finding

### HW-R2-01 — Medium, pre-activation: exceptional termination is requested but not confirmed

On `WaitForSingleObject` failure, the service drops the watchdog writer, calls `TerminateProcess`, and returns immediately without checking its result or waiting for process exit (`service.rs:1502-1512`). An unexpected client-pipe read error follows the same pattern (`:1525-1531`). The outer cleanup then calls `UnloadUserProfileW` and assumes no child remains (`:1544-1555`). Trigger: a wait/read error while a launcher is active; if termination fails, the launcher can remain live after service cleanup, and even a successful `TerminateProcess` call is asynchronous. Microsoft's [TerminateProcess contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess) explicitly requires a process wait to establish completed termination. The disconnect fallback also ignores `TerminateProcess` failure and repeats it after two seconds with no bounded exit or error (`service.rs:1533-1535`). **Fix:** check the termination result, wait with a bounded deadline for process exit before unloading the profile, and retain/report a failed containment state if termination cannot be confirmed. Fault-inject wait/read/terminate failures in a Windows VM. No package code runs at this revision, so this is a blocker for activating the transport, not a demonstrated current package escape.

## Related fix paths checked

- The anonymous watchdog write handle now checks `SetHandleInformation` failure before creating the child; the child handle list contains only the read end (`service.rs:1340-1385`). Actual inherited handles and `CreateProcessAsUserW` remain unverified in a full service VM run.
- Outcome bytes are now read from the already validated, bounded open file handle (`service.rs:1643-1675`), removing the second path lookup previously noted as a review risk.
- SYSTEM ownership is explicitly set and read back for the snapshot store and per-job snapshot directories (`service.rs:1006-1062,1124-1212`). This addresses the reported Win10 default Administrators-owner behavior at source level; fresh install, stale-snapshot sweep and ACL read-back need VM checks. The `icacls /setowner` failure path rejects the job.
- The service returns a bounded error detail only to the authenticated installer peer (`service.rs:111-124,857-879`). It does not include password or process output in the reviewed error paths; exact service errors and client behavior remain VM gates.

## Checks performed

| Check | Exit/result | Scope |
|---|---|---|
| Clean-tree confirmation, `git cat-file -t ca25e0b...`, non-destructive `git switch -c DansPK/f2c-014-review-hardened-watchdog-r2 ca25e0b77263472096fd849cb30a9dcf67e82ba5` | `0` | Exact pinned revision; original report branch retained. |
| `git diff c776c7c ca25e0b -- crates/fail2commit-core/src/sandbox/hardened/service.rs` and numbered reads of request, cancellation, snapshot and tests | `0` | Fix delta only. |
| `cargo test -p fail2commit-core sandbox::hardened::service::tests --lib` | `0`; 10 passed, 0 failed, 224 filtered out | Focused Windows-host service suite; no privileged service execution. |

**Pending:** Windows 10 VM suffix-plus-EOF and idle nonblocking-pipe tests, full SYSTEM `CreateEnvironmentBlock`/`CreateProcessAsUserW` run, watchdog/process-tree and forced-error cleanup, inherited handles, snapshot ownership/sweep; Win11 and phase-2 LPAC/WFP remain pending. No privileged host changes, production edits, push, publication, VM shutdown or Win11 use occurred.
