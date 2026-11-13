# FR-027 Windows launcher transport review (2026-11-14)

**Pinned implementation:** `c776c7c6a2d727a72fcb60c6ddf7fb2b7a47c58b`; delta reviewed from `b263a6d45ddb31aae8bb75c909861dc4c3806b4d`, including R2 fixes `58c6df8e26ec287bf9deeed89b2128a0fc83cefd` and manager CR-024 `e215f2e`. **Verdict:** R2 lifecycle findings are source-fixed, but the new Windows transport has a cancellation flaw that needs correction and VM evidence before enabling execution. This is a focused source review, not full FR-027 verification. The previous reports remain in Git; this file is the only review edit.

`launch_hidden` still returns `IsolationUnavailable` before package execution because LPAC and per-job WFP are unverified (`service.rs:1632-1647`), and `HardenedBackend::probe` remains unavailable (`hardened/mod.rs:176-219`). The Linux launcher remains refused. The findings below therefore describe defects in newly delivered *pre-activation* code, with no claim that they are exploitable by a package at this pinned revision.

## R2 disposition

- **R2-01, replacement Windows account deletion — source-fixed.** Uninstall requires a recorded sandbox SID (`lifecycle.rs:1298-1303`), resolves the current account, compares SIDs and refuses a mismatch before `NetUserDel` (`:1411-1426`). The unit test for SID matching passed. A privileged account-replacement/SCM lifecycle test remains pending. The service may already have been stopped and deleted before the account mismatch is discovered; the protected state remains for recovery, but the uninstall is not atomic.
- **R2-02, Linux post-`useradd` rollback — source-fixed.** The installer selects an unused configured system UID and persists it before `useradd --uid` (`lifecycle.rs:491-535`); cleanup checks the actual UID against state (`:662-674`). The allocation and injected-failure unit tests passed on the Windows host. Native Linux build and privileged rollback fault injection remain pending.

## New findings in the Windows transport

### HL-01 — Medium (pre-activation): buffered client bytes can defeat disconnect cancellation

`service.rs:640-699` reads a request until it sees a newline. While the launcher runs, `run_snapshot_as_sandbox` tests client liveness only with `PeekNamedPipe` (`:1464-1488`); it drops the watchdog write end only when peek fails and does not consume pending bytes. Trigger once package execution is enabled: an authenticated installer-identity client sends a valid `LAUNCH` line, waits for dispatch, then writes extra bytes and disconnects. Those unread bytes can keep `PeekNamedPipe` reporting available data, so the service does not reach EOF or close the launcher watchdog. Microsoft's [pipe peek protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6b6c8b8b-c5ac-4fa5-9182-619459fce7c7) describes a closing state in which the peer has closed but data remains readable. This violates SPEC-018's client-death containment rule for direct protocol clients. **Fix:** track disconnect with a read operation that consumes buffered input and reaches EOF, or otherwise enforce an exact one-message framing with a reliable disconnect signal; test disconnect both with and without a post-request suffix in a Windows VM. A normal CLI request writes only one line, but the service accepts any peer with the installer SID.

## Other boundary observations and pending gates

- The service authenticates the Windows pipe peer before parsing LAUNCH (`service.rs:819-850`), opens the user job directory without following the final reparse point and checks owner SID (`:910-938`), then copies a bounded, peer-owned, single-link `job.json` into a SYSTEM-owned snapshot (`:954-1003`). The source handle is held during the bounded read. These checks address the principal request/job owner path at source level; ancestor/path replacement and foreign-owner cases still need VM tests.
- The service validates `output/outcome.json` through a handle opened with `FILE_SHARE_READ` and no delete sharing (`service.rs:1552-1566`), then decodes a bounded outcome. It reopens by path for the byte read; using the checked handle would be clearer, but the held handle's sharing mode prevents a straightforward replace/delete race. No outcome swap vulnerability is claimed from source review.
- The SYSTEM service stores a random account password in protected state, validates the secret ACL and format, zeroizes the temporary buffers, grants batch logon while preserving deny-interactive, and uses `LogonUserW` + `LoadUserProfileW` + `CreateEnvironmentBlock` + `CreateProcessAsUserW` with an explicit inherited watchdog handle list (`lifecycle.rs:1160-1192`, `service.rs:1251-1507`). No password enters command arguments or child environment in the reviewed path. `SetHandleInformation` at `service.rs:1318` does not check its return value; the explicit handle list still limits the child, but the VM check should inspect inherited handles. The manager's probe showed logon/profile/AppContainer creation and cleanup, not this exact environment/process-launch path.
- Account grant journaling writes the root record before each recursive grant and retains failures for retry (`windows.rs:1468-1499,1505-1572,1667-1807`). The client wraps the service transaction with grant release (`:621-646`). Cancellation, process-tree kill on service death, ACL residue after client death, journal tampering and retry cleanup need privileged VM evidence; source checks alone cannot establish them.
- The launcher watchdog thread kills its process on pipe EOF/error (`service.rs:1584-1647`). No AppContainer tree is started at this revision. LPAC, WFP, egress, hostile catalogue and full SPEC-018 acceptance remain pending phase-2 work.

## Checks performed

| Check | Exit/result | Scope |
|---|---|---|
| Clean-tree confirmation and `git switch -c DansPK/f2c-014-review-hardened-launcher c776c7c6a2d727a72fcb60c6ddf7fb2b7a47c58` | `0` | Non-destructive checkout; prior report commits remain reachable on their branches. |
| `git diff --stat b263a6d c776c7c`, targeted diff/source reads of lifecycle, service, winsec, Windows grants and CR-024 | `0` | Only new code and R2 fixes reviewed. |
| `cargo test -p fail2commit-core hardened:: --lib` | `0`; 20 passed, 0 failed, 211 filtered out | Focused Windows-host unit suite; no privileged runtime operation. |

**Skipped/pending:** actual `CreateEnvironmentBlock`/`CreateProcessAsUserW`, Windows 10/11 service LAUNCH and cleanup, account substitution, foreign peer/path/reparse, suffix-plus-EOF watchdog, inherited-handle audit, grant journal and crash retry; Linux native build and rollback; phase-2 LPAC/WFP/hostile catalogue. No privileged host changes, VM shutdown, push or publication were performed.
