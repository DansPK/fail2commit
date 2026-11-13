# FR-027 exceptional-termination re-review (2026-11-14)

**Pinned implementation:** `a6e6ba34871511739dd5cf2b2089ce0921429372`, compared only with `ca25e0b77263472096fd849cb30a9dcf67e82ba5` and HW-R2-01 in `REVIEW-2026-11-14-hardened-watchdog-r2.md` (`38ed75e2798b22d078e3ed179c5c888221c62a5e`). **Verdict:** HW-R2-01 is source-fixed for the current service process, with a residual restart-state risk and unverified Windows VM behavior. Package execution still refuses until LPAC/WFP controls pass; this does not verify full FR-027. The previous review branch and report remain reachable.

## HW-R2-01 disposition

`service.rs:127-162,1683-1707` now checks `TerminateProcess`, waits up to 5 seconds for the process handle to signal, and distinguishes confirmed exit from timeout/wait failure. The initial `WaitForSingleObject` error, client-pipe read error, and two-second disconnect fallback all use this confirmation path (`:1549-1613`). A confirmed termination reaches the ordinary profile unload; an unconfirmed termination retains the process/token/profile handles and sets a service-wide refusal flag before returning (`:1614-1638`). The service rejects subsequent LAUNCH requests while that flag is set (`:900-910`). Normal process signal exits without forced termination and reaches ordinary cleanup. The four injected-result unit cases cover terminate success without signal, terminate/exit race, wait error and terminate error plus timeout (`:1890-1923`). These changes address the unobserved asynchronous termination reported in HW-R2-01 at source level.

The pipe fixture now uses `PIPE_NOWAIT` (`service.rs:1974-1989`). Targeted Windows-host tests passed for a live idle peer, disconnect without suffix and buffered suffix after client closure (`:2008-2068`). These exercise the prior gap in the unit fixture; they still do not demonstrate a full SYSTEM service launch, watchdog EOF or package-process tree cleanup.

## Residual finding

### HT-R3-01 — Medium, pre-activation: containment poison is process-local and lost on service restart

`LAUNCHER_CONTAINMENT_FAILED` is an in-memory static (`service.rs:519-524`), set only when termination cannot be confirmed (`:1614-1626`) and checked before LAUNCH in the same service process (`:900-910`). Trigger: a termination timeout or wait failure leaves a launcher possibly alive; the service is then restarted before that launcher's exit is established. The new process initializes the flag to false and starts serving after snapshot sweep (`:786-809`), so a later authenticated LAUNCH is no longer blocked even though the earlier containment failure was never resolved. This is conditional on the precise failure the poison is meant to represent; it is not a current package escape because `launch_hidden` still refuses package code. **Fix:** persist a protected containment-failure marker or reconcile retained process/job identity at startup, and refuse new LAUNCH until cleanup is proven. Test a forced unconfirmed termination followed by service restart in a Windows VM. A service shutdown normally closes the watchdog writer, but the unconfirmed branch cannot rely on that mechanism as proof of exit.

## Remaining proof and checks

- Source review found no new normal-path profile unload or token/environment cleanup regression in this delta. `retained_process` is only forgotten on unconfirmed containment; the normal/confirmed paths drop it after a process signal (`service.rs:1538-1638`). The unconfirmed branch intentionally leaks handles and loaded profile for the service lifetime; machine-state cleanup after a crash/restart remains unproven.
- `git status --short --branch` confirmed a clean prior review checkout; `git cat-file -t a6e6ba3...` returned `commit`; `git switch -c DansPK/f2c-014-review-hardened-termination-r3 a6e6ba34871511739dd5cf2b2089ce0921429372` exited `0`. The original review commit remains on its branch.
- `git diff ca25e0b a6e6ba3 -- crates/fail2commit-core/src/sandbox/hardened/service.rs` and numbered reads exited `0`; only the requested fix delta was reviewed.
- `cargo test -p fail2commit-core client_pipe_read_ --lib` exited `0`: 3 passed, 0 failed, 236 filtered out. The worker-reported 15-service-test pass was not rerun here.

**Pending:** installed Windows 10 SYSTEM `CreateEnvironmentBlock`/`CreateProcessAsUserW` path, real client suffix/EOF cancellation, injected wait/read/terminate failures and service restart, process tree and profile/handle cleanup; Win11, Linux launcher, LPAC/WFP and hostile catalogue. No production edit, privileged host operation, push, publication, VM shutdown or Win11 use occurred.
