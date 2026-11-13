# FR-027 phase-1 boundary re-review (2026-11-14)

**Implementation pinned:** `b263a6d45ddb31aae8bb75c909861dc4c3806b4d`. **Baseline:** `REVIEW-2026-11-14-hardened-boundary.md` at `43ad109b7e20cfe018fea14236f25e7a2c6e58d8`. **Verdict:** four original findings have source-level fixes, one is partial, and two related lifecycle edge cases need correction. Privileged Windows/Linux lifecycle results are pending. The launcher and phase-2 controls deliberately remain unavailable; full FR-027 is not accepted.

The review checkout is `DansPK/f2c-014-review-hardened-r2`, created at the pinned implementation commit after confirming a clean tree. The original review commit remains reachable from `DansPK/f2c-014-review-hardened`; this addendum makes no production changes.

## Disposition of the five original findings

| Finding | Disposition at `b263a6d` | Evidence and remaining gate |
|---|---|---|
| HB-P1-01, Linux damaged marker fallback | **Source fixed.** | `hardened/mod.rs:84-132` treats any existing marker, metadata error, managed unit/socket path, account entry, or install remnant as installed. `auto` consequently retains the unavailable hardened backend. The new damaged-marker unit test passes on the Windows host; Linux native build and damaged-state VM behavior remain pending. |
| HB-P1-02, Windows unowned service deletion | **Service-name case source fixed; related account deletion remains unsafe.** | `lifecycle.rs:1123-1165` returns before SCM work without validated state and verifies the SCM binary command, account, service type, and start mode before stop/delete. The focused config test passes. See R2-01 for the account identity gap. Privileged SCM lifecycle remains pending. |
| HB-P1-03, persistent denied-logon right | **Source fixed; VM proof pending.** | The created account SID is persisted before the right is added (`lifecycle.rs:1007-1026`); rollback invokes uninstall or removes the right before `NetUserDel` (`:1065-1113`), and uninstall removes the right using the recorded SID (`:1235-1245`). The reported Win10 fixture orphan SID was removed separately; current install, failure-injection, export-of-rights and uninstall checks remain pending. See R2-01 for deletion of a replacement account. |
| HB-P1-04, unchecked Linux cleanup | **Partial.** | `lifecycle.rs:462-542` checks `systemctl`, unit path/content, account uid, `userdel`, directory removal and daemon reload; `cleanup_then_remove_state` (`:155-165`) retains the marker on failure. The injected-cleanup unit test passes. R2-02 identifies an install/rollback state window that is not retryable. Linux native build and privileged install/uninstall remain pending. |
| HB-P1-05, malformed/silent peer stalls service | **Source fixed; transport VM proof pending.** | Linux uses an absolute two-second request deadline and continues after malformed or failed requests (`service.rs:142-158,338-411`). Windows peeks/reads with a two-second deadline and continues after malformed requests (`:561-654,743-783`). The decoder test passes on Windows; the Linux silent-peer test is Linux-only and was not run here. Windows named-pipe and Linux socket integration checks remain pending. |

## Residual findings

### R2-01 — Medium: Windows uninstall can delete a replacement sandbox account

The protected state records `sandbox_sid`, but `lifecycle.rs:1235-1245` removes the right from that SID and then calls `NetUserDel` on the fixed name `f2c-sandbox` without checking that the current account resolves to the same SID. Trigger: after installation, the original account is removed and another account receives the same name. An elevated uninstall deletes the replacement account, while the saved SID remains the identity whose right was removed. The legacy-state fallback at `:1237` resolves the current name and has no original SID to compare. **Fix:** resolve the current account SID immediately before deletion, compare with the recorded SID, and refuse name-based deletion on mismatch; for legacy records without a recorded SID, require a guarded migration or recovery path that proves account ownership. Verify replacement-account refusal in a Windows VM. This is related to HB-P1-02's unsafe-deletion concern; the service-name case itself is fixed.

### R2-02 — Medium: Linux account creation can precede the UID needed for retryable rollback

`lifecycle.rs:363` writes the initial marker with `sandbox_uid: None`. `useradd` then creates the account at `:376-385`; only after a successful `id` and second state write at `:386-391` does the marker carry its UID. Trigger: `id` or the second state write fails (or the process exits) after `useradd` succeeds. Install rollback calls `uninstall` (`:417-424`), but uninstall finds the account and requires `state.sandbox_uid == Some(uid)` (`:512-529`), so it refuses cleanup. Retrying `hardened uninstall` repeats the mismatch; a manual privileged repair is required. The retained marker does keep `auto` fail closed, so this is a retryability/lifecycle defect, not a default-backend bypass. **Fix:** obtain and persist the allocated UID as part of account creation before any fallible step that relies on it, or make a narrowly scoped rollback path able to prove and remove the just-created account when the marker lacks its UID. Fault-inject failure after `useradd` in a Linux VM and verify a retry completes without touching a replacement identity.

## Checks and limits

| Check | Exit/result | Scope |
|---|---|---|
| `git status --short --branch`, `git rev-parse HEAD`, `git cat-file -t b263a6d...` before checkout | `0`; clean at `43ad109...`, pinned object is a commit | Confirmed non-destructive branch switch was safe and the original report stays reachable. |
| `git switch -c DansPK/f2c-014-review-hardened-r2 b263a6d45ddb31aae8bb75c909861dc4c3806b4d` | `0` | Reviewed exact implementation revision. |
| `git diff 1f49a92 b263a6d --` for `hardened/{mod,service,lifecycle}.rs`; numbered source reads | `0` | Inspected only the five fix paths and related lifecycle edges. |
| `cargo test -p fail2commit-core hardened:: --lib` | `0`; 14 passed, 0 failed, 209 filtered out | Targeted Windows-host unit suite; it does not exercise privileged SCM, LSA, socket, or Linux paths. |

**Pending:** implementation fixes for R2-01/R2-02; Windows 10/11 privileged install/RUNNING/uninstall and rights export, failure rollback and account replacement tests; Linux native build and privileged lifecycle, damaged marker, UID rollback and silent-peer tests. No privileged host changes, VM operations, push or publication were performed.
