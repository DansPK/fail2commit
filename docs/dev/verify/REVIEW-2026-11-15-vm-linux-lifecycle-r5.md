# FR-029 Linux VM lifecycle review, round 5

Date: 2026-11-15. Review branch: `DansPK/f2c-014-vm-linux-review-r5`.

Immutable source pin: `443e0b453706dfa51696e0a8f8909db78cf5a4b0`.
Worker evidence snapshot: `f0541db44b1245bab71ab17cef5029a500f53021` (`docs/dev/verify/2026-11-15-fr029-r4-lifecycle-fixes.md`).
Compared with source `c5d028bfdd2732fdd228741354b976c993713c71` and review `05c9dc41aac394464b7b31df2e7f572bfe520193` (`docs/dev/verify/REVIEW-2026-11-15-vm-linux-lifecycle-r4.md`).
Windows refusal integration target: `27378f2eff3db4616554cdc469c3335665385a3b`.

## Verdict

**Linux source accepted for manager integration within this focused R4 scope.** The patch closes R4-01 and R4-02 in the production paths; I found no remaining concrete source defect in their delta. This is source acceptance, not root preparation, QEMU/KVM boot, fd-root 9p, outcome/export, or runtime lifecycle acceptance. Preserve the manager's Windows VM refusal in the actual merge.

## R4 dispositions

| Finding | Disposition | Production path and test limit |
|---|---|---|
| R4-01: root prepare/remove bypass query quarantine | **Closed in source at `443e0b453706dfa51696e0a8f8909db78cf5a4b0`.** | `prepare_inner` calls `recover_or_refuse(lib_dir)` before kernel validation, directory creation, QEMU query and image/state writes (`vm/prepare.rs:135-157`). `remove_inner` calls the same gate before any recursive deletion (`vm/prepare.rs:360-379`). `verify_qemu_support` now passes its caller's `lib_dir` to every capability query (`vm/prepare.rs:533-557`), matching the durable record location. Shared `recover_or_refuse` checks in-process retained guards first even if the directory/state is absent, then checks the durable record; live or uncertain identities refuse, and only proven-dead records clear (`vm/prepare.rs:1716-1799`). The entry-helper fixture exercises live in-process, durable-only with missing state, and dead recovery (`vm/prepare.rs:2592-2691`). It simulates restart by clearing the registry; it does not start a fresh OS process, and root-owned successful removal is pending. |
| R4-02: reap grace extended query deadline | **Closed for containment/scan/drain source path at `443e0b453706dfa51696e0a8f8909db78cf5a4b0`.** | `run_bounded_with_grace` reserves `max(grace/4, 250 ms)` capped at `grace` before the one absolute deadline (`vm/prepare.rs:884-910`). `contain_group` now polls the leader only to that supplied deadline, does one final nonblocking `try_wait`, and returns `Unconfirmed` without a fresh grace (`vm/prepare.rs:717-749`). The same deadline reaches the nonblocking stdout drain and deadline-aware `/proc` scan (`vm/prepare.rs:639-676,957-1043`). Unconfirmed branches retain the query owner and durable identity (`vm/prepare.rs:830-868,910-1039`). The expired-deadline test checks there is no 250 ms extension (`vm/prepare.rs:2565-2590`). The worker tightened elapsed assertions, though they allow post-deadline persistence overhead; see limit below. |

## Source and evidence limits

- The returned error can occur after the query's absolute process-control deadline when `query_containment_retained` writes and fsyncs a durable quarantine record (`vm/prepare.rs:830-868,1675-1699`). This is required to preserve an unconfirmed live owner; the source now makes no new *cleanup grace* after expiry. The worker's 400 ms fixture permits up to 650 ms wall time for that persistence, and its 1 s near-bound fixture permits up to 1.25 s. A strict API-wide wall-clock SLA including durable storage is not established by these tests; it would require a separate policy and evidence. This is a documented timing limit, not a newly observed fail-open path.
- The worker reports an exact-source Debian targeted run of **13 passed, 0 failed**, covering query helpers, expired-deadline containment and prepare/remove entry gates; `cargo check -p fail2commit-core --all-targets` exited 0; fmt and diff checks were clean. Changed VM files were clippy clean; `-D warnings` still failed in untouched `hardened/*` and `sandbox/linux.rs` baseline code. I read the pinned report and assertions rather than repeat a broad cold build. `git diff --check c5d028bfdd2732fdd228741354b976c993713c71 443e0b453706dfa51696e0a8f8909db78cf5a4b0` passed here.
- The prior pin `c5d028bfdd2732fdd228741354b976c993713c71` reported VM unit **47 pass**, protocol **9 pass**, workspace check 0, and Linux integration **3 exercised plus 4 self-skipped**. The R4 worker did not rerun the full prior suite, so those remain prior-pin evidence, not fresh results for this pin.
- Root `vm prepare/remove` twice, real QEMU/KVM boot and prepared capability success, QEMU 9p acceptance of `/proc/self/fd/N`, comma-path parsing, mounted control/result isolation, clean VM exit and authorized outcome/export, and timeout/tree cleanup are still pending runtime gates. The unprivileged dev VM lacked root, `/dev/kvm` and QEMU; no self-skipped boot test counts as runtime acceptance.
- The worker reports a conflict-free trial merge with Windows refusal `27378f2eff3db4616554cdc469c3335665385a3b`. The manager must verify that refusal remains active after the actual merge; this Linux source review did not modify or runtime-check Windows code.
