# FR-029 Linux VM lifecycle fix review, round 3

Date: 2026-11-15. Review branch: `DansPK/f2c-014-vm-linux-review-r3`.

Immutable source pin: `74715a458f80c4b0c16cfdd2c608a8a7d934de50`.
Compared with `1d43e94c5ce9a74a41f1550abf459d8462c8cd26` and prior review `f5b104e5b19a45b1cf42a5fc08575a2c565bbf5b` (`docs/dev/verify/REVIEW-2026-11-15-vm-linux-fixes-r2.md`).
Windows refusal integration target: `27378f2eff3db4616554cdc469c3335665385a3b`.

## Verdict

**Changes requested before Linux source acceptance.** R2-04's init failure path is fixed. R2-01 and R2-02 remove the earlier blocking `wait()` and add bounded caller-owned query draining, but their shared group scanner treats an unreadable or incomplete `/proc` scan as proof that the group is dead. R2-03 fixes parent descriptor inheritance, but fixed QEMU child slots can overwrite source descriptors under ordinary fd pressure. These are production-path findings, not missing VM test evidence. Root preparation, KVM boot, QEMU `/proc/self/fd/N` 9p acceptance, VM exit/export, and real cleanup remain separate runtime gates.

## R2 disposition at this pin

| Prior finding | Source disposition | Evidence and limit |
|---|---|---|
| R2-01 unbounded cleanup/early guard release | **Partly fixed; R3-01 remains blocking.** | `vm/prepare.rs:645-694` uses polled `try_wait` and deadline checks instead of unbounded `wait`. `vm/linux.rs:578-646` routes every post-spawn exit through `contain_group`; unconfirmed containment passes pins, control/result tempdirs and child to a process-lifetime registry (`vm/linux.rs:216-236,549-574`). An actual `run_job` fixture creates an unreaped group zombie and checks quarantine, refusal and recovery (`vm/linux.rs:1613-1730`). However `group_members` can return an empty vector on scan failure or truncation, and both containment and recovery interpret empty as confirmed death. Crash/restart record durability and cleanup ownership also have R3-03 limits. |
| R2-02 whole-query deadline/reader | **Substantially fixed; R3-01 and R3-04 limits.** | `vm/prepare.rs:708-857` computes one deadline before spawn, reserves cleanup time, sets stdout nonblocking, drains in the caller, and passes the same deadline to containment and final drain. There is no detached reader or join. The near-deadline fixture asserts completion under 1.5 s for a 1 s budget (`vm/prepare.rs:1957-1975`), so its tolerance is wider than the declared deadline. A `/proc` scan can still incorrectly confirm cleanup or overrun the deadline; see findings below. |
| R2-03 parent fd inheritance | **Parent leak fixed; child-slot collision R3-02.** | `pin_shares` keeps `FD_CLOEXEC` on parent `O_PATH` fds (`vm/linux.rs:1049-1092`), and a QEMU-only `pre_exec` hook uses `dup2`/`fcntl` on a captured preallocated slice (`vm/linux.rs:1095-1127`). The child swap fixture and unrelated child fixture check the intended path (`vm/linux.rs:1775-1819`). They use one source fd and do not test sources overlapping fixed slots 64 onward. |
| R2-04 shutdown-return fallthrough | **Source fix accepted; boot pending.** | Generated init now calls `f2c_fail`, which invokes poweroff then `exit 1`, on every required mount, module, validation and capability failure (`vm/prepare.rs:1160-1235`). Executable fixture makes poweroff return failure and asserts the launcher is never reached across those branches (`vm/prepare.rs:1755-1871`). Real PID 1 shutdown and boot remain pending. |

## New findings

### R3-01 — High: incomplete process scan can falsely confirm group death

**Trigger:** `/proc` cannot be enumerated, an entry's `stat` cannot be read or parsed while it is still live, or the first 65,536 entries omit a group member. `group_members` silently returns an empty vector on `read_dir` failure and skips all individual errors, then caps the scan using `.take(65_536)` (`vm/prepare.rs:617-635`). `contain_group` interprets empty as `Confirmed` (`vm/prepare.rs:675-687`). `run_job` then releases QEMU pins and control/result guards (`vm/linux.rs:578-646`); `recover_or_refuse` likewise drops retained guards and removes a durable record (`vm/linux.rs:340-408`). This defeats the claimed fail-closed cleanup and quarantine semantics. **Fix:** distinguish a complete, reliable scan from an empty group; treat scan errors, malformed entries and a hit scan cap as unconfirmed, with tests injected through the production containment/recovery paths. A direct owned-leader check should remain in the evidence until reaped.

### R3-02 — High: fixed child fd slots can clobber later pinned share sources

**Trigger:** the host has enough open descriptors that pinned source fds overlap slots `64..` (for example sources 60–66 for seven shares). `pin_shares` assigns slots `64 + index` (`vm/linux.rs:1032-1036,1049-1092`). `add_slot_inheritance` then runs forward `dup2(src, slot)` (`vm/linux.rs:1105-1123`): the first `60 -> 64` overwrites source fd 64 before its later share is copied, so QEMU's `/proc/self/fd/68` can point at the wrong share. The pre-exec syscalls themselves are async-signal-safe, and the parent keeps close-on-exec, but the copy ordering is not collision-safe. **Fix:** duplicate every source to disjoint temporary child descriptors before installing target slots, or allocate target slots proven disjoint from all sources, then clear close-on-exec only on the final allowlist. Add an actual child-spawn test with occupied descriptors that force overlap and verify every mapped inode.

### R3-03 — Medium: durable quarantine does not establish crash-safe recovery

**Trigger:** host process crashes or loses power after `persist_quarantine` renames its temp file but before directory metadata is durable. The code syncs the file and renames it but never syncs `stage_root` (`vm/linux.rs:282-303`); after restart the record can be absent while an independently surviving QEMU still holds its inherited pins. The next `recover_or_refuse` returns `Ok(())` when the file is absent (`vm/linux.rs:356-360`). Also, `persist_quarantine` discards the oldest record after eight entries (`vm/linux.rs:271-280`); concurrent unconfirmed runs can exceed that limit and lose a live identity across restart. **Fix:** durably sync the containing directory after rename, fail closed on persistence uncertainty across process restart, and refuse or preserve all unconfirmed identities rather than evicting them. The current fixture tests in-process recovery only; it does not restart after an unconfirmed run.

### R3-04 — Medium: one deadline is passed through query phases, but a full `/proc` scan has no internal time check

**Trigger:** a dense or slow `/proc` while a capability query reaches cleanup near its deadline. `contain_group` calls `group_members`, which may read up to 65,536 `stat` files without checking the deadline (`vm/prepare.rs:617-635,675-692`); a single scan can extend past the absolute deadline before the loop notices. Query errors after a genuinely unconfirmed group return and drop the `Child` without a retained query containment owner (`vm/prepare.rs:735-739,786-810,830-835`). **Fix:** make enumeration deadline-aware and treat incomplete scans as unconfirmed; define bounded ownership/recovery for query processes that remain live. Test a scan that exhausts its budget, not only a short-lived shell helper.

## Evidence and gates

- Reviewed only the delta at `74715a458f80c4b0c16cfdd2c608a8a7d934de50` and production call sites for the four R2 findings. `git diff --check 1d43e94c5ce9a74a41f1550abf459d8462c8cd26 74715a458f80c4b0c16cfdd2c608a8a7d934de50` passed. No production files changed in this review, and no broad cold build or host/VM operation was run.
- At this immutable pin the tracked worker verification report still documents the earlier `1d43e94c5ce9a74a41f1550abf459d8462c8cd26` test result, not a final run for this delta. New tests are visible in source, but passing results for the pin remain pending worker evidence; I did not infer them from test names. The source tests also do not cover failed `/proc` scans, fd-slot overlap, cross-process restart, or a slow scan consuming the deadline.
- Root `vm prepare/remove`, real KVM boot and CPUID/capability success, actual QEMU 9p acceptance of `/proc/self/fd/N`, clean VM exit/outcome/export authority, and timeout/tree cleanup remain unverified. Even after the source findings are fixed, these runtime gates must remain pending until run on a suitable host.
- Integration must retain Windows VM probe/run/guest refusal from `27378f2eff3db4616554cdc469c3335665385a3b`; this Linux review does not accept or modify Windows behavior.
