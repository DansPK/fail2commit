# FR-027 SPEC-018 phase-1 hardened boundary review (2026-11-14)

**Revision reviewed:** `1f49a926272dd05773831f6d7fd4a2a609569795` (including `a81e35d` and `d7baa103`). **Verdict:** phase-1 boundary requires fixes and focused VM re-verification; **full FR-027 is not verified**. This is a source review of the delivered protocol, service, selection, and lifecycle. The launcher and phase-2 LPAC/WFP/proxy/grants/watchdog controls explicitly refuse to run and remain pending implementation, not findings against the delivered boundary. No privileged runtime operation was performed on the host. `CLAUDE.md` was not present in this checkout or its workspace parent chain.

SPEC-018 and CR-023 (`77e2ebf`) require an installer-owned `0600` Linux socket in a root-owned `0755` directory **and** mandatory `SO_PEERCRED` authentication. The socket unit and service match that arrangement (`packaging/linux/fail2commit-hardened.socket:5-8`, `service.rs:275-310`). Windows uses a pipe DACL that denies app-package SIDs and allows the installer SID, then checks the connecting process token SID and AppContainer status (`service.rs:523-585`, `ipc/winsec.rs:165-217`). These are sound source-level boundaries subject to VM tests below. Both LAUNCH handlers reject execution (`service.rs:48-70,603-606`), and the backend probe is always unavailable (`hardened/mod.rs:163-193`), so no hostile-job containment claim follows from this review.

## Findings

### HB-P1-01 — Medium: damaged Linux install marker selects the default backend

`hardened/mod.rs:24-29,84-95` uses `machine_state_path().is_file()` as the entire Linux installed predicate. A marker replaced by a directory or dangling symlink, or a metadata lookup that fails, returns false; `sandbox/mod.rs:47-49` then selects the default Bubblewrap backend under `auto`. This differs from the Windows predicate (`hardened/mod.rs:62-79`) and the explicit installed-but-unhealthy fail-closed contract in SPEC-018 §1/§8. Trigger: `/etc/fail2commit-hardened.json` ceases to be a stat-able regular file while the hardened socket or other installation remnants exist. An unprivileged user cannot normally alter `/etc`, so this is a damaged-install/privileged-misconfiguration path, but a guarded install can silently run through a weaker backend. **Fix:** represent marker absence separately from an invalid or unreadable marker, and consider managed unit/socket/account remnants before allowing the default backend. Add a selection test for each damaged-marker state.

### HB-P1-02 — Medium: Windows uninstall can stop and delete an unowned service

`lifecycle.rs:733-790` reads optional state, but opens, stops and calls `DeleteService` for the fixed service name *before* checking `if let Some(state)` at line 792. Trigger: an elevated `hardened uninstall` when the trusted state file is absent but a service with that name exists (for example, a name collision or an interrupted install). The command can remove a service it has not established ownership of. **Fix:** require validated install state and expected service binary/configuration before modifying SCM; when state is absent, return idempotent success without touching the name. Keep a separate guarded recovery path for a partially installed owned service.

### HB-P1-03 — Medium: Windows install rollback leaves the denied-logon right on a deleted SID

`lifecycle.rs:639-645` removes a newly created account if adding `SeDenyInteractiveLogonRight` fails; the later failure path at `:724-729` deletes the account but never removes the right. `:803-810` removes the right on normal uninstall. Trigger: any post-right failure (copy, ACL, state write, service creation/start). The LSA right can remain assigned to an orphan SID after account deletion. The coordinator's Win10 report independently observed a stale deleted SID in user-right export even after a passed install/RUNNING/uninstall flow; the implementation worker is addressing it concurrently. **Fix:** capture the created account SID, remove only this right before deleting that account on every rollback, and verify exported rights after failure and uninstall. Re-review the implementation worker's patch; this finding describes the pinned revision.

### HB-P1-04 — Medium: Linux uninstall reports success after unchecked cleanup failures

`lifecycle.rs:335-354` ignores exit status for socket/service disable, daemon reload and `userdel`, and ignores errors removing the unit files and owned directories; it then removes the sole state marker and returns `removed: true`. Trigger: a failed `systemctl disable --now`, `userdel`, or filesystem removal. The service/account/units can persist with no marker, making later `auto` select the default backend and leaving durable privileged resources. Install rollback also calls `uninstall()` and discards its error (`:305-307`). **Fix:** check each cleanup result, retain state until ownership cleanup has succeeded, report partial failures, and make retry idempotent with ownership checks. Test an injected cleanup failure in a VM and verify the marker remains until recovery.

### HB-P1-05 — Low: an authorized but malformed or silent peer can stall/terminate the service

Linux serves sockets serially (`service.rs:129-133`) with an unbounded `read_until` wait (`:320-328`); a parse/read error propagates through `?` and exits the service. Windows likewise handles one pipe at a time (`:526-613`), blocks on an incomplete request after changing to `PIPE_WAIT` (`:568-596`), and malformed JSON exits the loop (`:596-597`). Trigger: a same-installer-user process opens the authenticated socket/pipe and withholds a newline or sends invalid JSON. This is an availability issue within the trusted installer's OS identity, not a cross-user or sandbox escape. **Fix:** set a short per-request read deadline, close the offending connection, and continue serving; send a bounded error response where feasible. Exercise silent and malformed peers in VM integration tests.

## Boundary assessment and pending checks

- Protocol: `protocol.rs:144-222` bounds job/outcome files, rejects non-UTF-8 job fields, validates base64 streams and refuses backend export claims. `service.rs:11,324-329,593-607` bounds and parses one JSON request. These are source-level observations; the launcher currently does not consume `job.json`.
- Path trust: Linux LAUNCH requires absolute canonical directory and matching peer uid (`service.rs:80-97`). Windows LAUNCH is rejected before any path is used (`:603-606`); its future owner/canonical-path check remains phase-2 work. No service-side file read or privileged job launch occurs at this revision.
- Identity: Linux `SO_PEERCRED` fails closed on error/size mismatch (`service.rs:291-310`), requires the recorded installer uid and excludes root/sandbox uid (`:75-77`). Windows peer PID/token lookup errors close the connection (`:576-585`), and the client probe checks the server is SYSTEM (`:234-245`). The Linux socket ownership correction is present. VM tests of another user, sandbox uid/AppContainer, and path replacement remain pending.
- Runtime/lifecycle: No phase-2 watchdog, grants, account logon, WFP, loopback exemption, or LPAC job is present, so SPEC-018 TC-027-2 through TC-027-17 are **not** verified here. Windows profile deletion and full post-uninstall residue checks remain release-gate work. A reported Win10 happy-path install/RUNNING/uninstall pass is external worker evidence, not a check reproduced here.

## Checks performed

| Check | Exit/result | Meaning |
|---|---|---|
| `git rev-parse HEAD` | `0`, `1f49a926272dd05773831f6d7fd4a2a609569795` | Pinned review revision. |
| `git show --stat --oneline` for `1f49a926`, `a81e35d`, `d7baa103`, `77e2ebf` | `0` each | Identified delivered files and manager correction. |
| Source inspection of `hardened/{protocol,mod,service,lifecycle}.rs`, `sandbox/mod.rs`, `ipc/winsec.rs`, CLI routing and Linux units | `0` reads | Findings above; no production edits. |
| `cargo test -p fail2commit-core hardened:: --lib` | `0`; 9 passed, 0 failed, 209 filtered out | Targeted Windows-host unit suite only; no privileged runtime boundary was exercised. |

**Skipped/pending:** Windows 10/11 and Linux root VM integration tests, hostile catalogue, service crash/restart, concurrent LAUNCH, unauthorized peer, malformed request, damaged-state selection and rollback fault injection. No host install/uninstall, account/right, SCM, systemd, ACL, or VM changes were made for this review.
