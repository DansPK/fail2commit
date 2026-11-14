# FR-029 Linux VM lifecycle — R4 review fixes (verify report)

Date: 2026-11-15. Branch: `DansPK/f2c-014-vm-linux-qwen`.
Review source: `05c9dc41aac394464b7b31df2e7f572bfe520193`
(`docs/dev/verify/REVIEW-2026-11-15-vm-linux-lifecycle-r4.md`), immutable source
pin `c5d028bfdd2732fdd228741354b976c993713c71`.
**Fix SHA `443e0b453706dfa51696e0a8f8909db78cf5a4b0`** (one file:
`crates/fail2commit-core/src/sandbox/vm/prepare.rs`, +176/−25).
Linux scope only; Windows behavior untouched (refusal commit
`27378f2eff3db4616554cdc469c3335665385a3b` trial `git merge-tree` against the fix
SHA: exit 0, tree `f167296609f7ef89e69c2cfc24fb383aa0dec0b6`, 0 conflicts).
Manager integration ownership unchanged: only private Linux entry helpers and
`pub(super)` internals were edited; no public API, protocol or SPEC change.

## R4-01 (High) — prepare/remove entry gates consult the query quarantine

Fix at `443e0b4`:

- `prepare_inner` runs `recover_or_refuse(lib_dir)` as its first action
  (`prepare.rs:137-140`), before kernel/qemu validation, directory creation and
  any capability-query spawn. `remove_inner` runs the same gate before any
  deletion (`prepare.rs:365-368`). Both therefore consult the in-process
  registry AND the durable record under the lib dir, including the
  missing-state/partial-install path (no state file, missing or empty lib dir:
  the registry is still checked; a missing record file recovers to Ok).
- `verify_qemu_support(qemu, quarantine)` now persists unconfirmed query
  records into the lib dir being prepared (`prepare.rs:541-557`, caller
  `prepare.rs:157`) instead of a hardcoded constant, so the entry helpers own
  one consistent quarantine location.
- Live/unknown records refuse (in-process: "still contained"; durable: "still
  live"); only a complete proven-dead identity scan recovers. A live durable
  identity can no longer be erased by `vm remove`, and no new query starts
  while one is unresolved.

Test: `prepare_and_remove_entries_gate_on_query_quarantine`
(`prepare.rs:2592-2694`) exercises the actual entry helpers, not manual
recovery: a live external group (leader reaped, background member survives in
the group) is retained via `retain_containment`, then

1. in-process live guard: `prepare_inner` and `remove_inner` both refuse; no
   state file, no initramfs, durable record and retained guard intact;
2. fresh-process case (registry cleared, durable record only, no state file):
   both entries refuse with the durable "still live" message; the record
   survives the removal attempt;
3. proven-dead recovery through the entry itself: after the survivor is killed
   and `group_proven_gone` holds, `remove_inner` clears the durable record
   before the pre-existing root-ownership check refuses the deletion itself
   (unit tests run non-root; full root removal stays a runtime gate).

`state_protection_and_idempotent_remove` now takes `VM_TEST_LOCK` because
`remove_inner` consults the process-global registry (missing-dir idempotent
remove still passes through the new gate).

## R4-02 (Medium) — one absolute query deadline, no post-deadline grace

Fix at `443e0b4`:

- The reap window is reserved BEFORE the deadline:
  `reserve = (grace / 4).max(REAP_FLOOR).min(grace)` (`prepare.rs:902-905`);
  the cap keeps tiny graces representable (containment then starts immediately
  with the whole budget as its hard bound). `REAP_FLOOR` (250 ms) is now a
  reserved minimum, documented as never extending the deadline
  (`prepare.rs:77-81`).
- `contain_group` reaps against the caller's `deadline` itself — the
  `deadline.max(now + REAP_FLOOR)` extension is gone (`prepare.rs:735-762`).
  At the hard deadline it performs one final non-blocking `try_wait` (no
  sleep, no fresh grace) so a leader that died in the final slice is not
  retained as an unreaped zombie, then returns `Unconfirmed` and the caller
  retains. `/proc` enumeration and the final drain already share that same
  `deadline` (unchanged).
- `run_bounded_with_grace` doc updated to state the single hard bound
  (`prepare.rs:884-892`). VM-run cleanup callers always pass a fresh
  `now + CLEANUP_GRACE`, so their semantics are unchanged.

Tests:

- New `contain_group_expired_deadline_grants_no_fresh_grace`
  (`prepare.rs:2565-2590`): production `contain_group` with an already-expired
  deadline and a live leader returns `Unconfirmed` in well under `REAP_FLOOR`
  (no fresh 250 ms grace); the fixture reaps its killed leader afterwards.
- Tightened the two bounds the review flagged: the 1 s near-bound test now
  asserts `< 1 s + REAP_FLOOR` (was 1500 ms) and the 400 ms budget-exhaustion
  test `< 400 ms + REAP_FLOOR` (was 1200 ms; margin covers only the
  post-deadline durable persist).

## Evidence (Debian dev VM `debian-f2c`, uid 1000, kernel 6.12.86+deb13-amd64, cargo/rustc 1.100.0)

Exact-source run: `git archive` at `443e0b453706dfa51696e0a8f8909db78cf5a4b0`,
extracted to fresh guest dir `/home/dev/vmfix-443e0b4`, shared warm target
`/home/dev/.cache/f2c-vmfix-target`, `CARGO_BUILD_JOBS=2`, debug info off.
Bounded scope per task: only the affected tests ran; the rest reuse the
`c5d028b` results (no public API changed).

| Command | Result |
|---|---|
| `cargo test -p fail2commit-core --lib -- bounded_query contain_group_expired_deadline_grants_no_fresh_grace prepare_and_remove_entries_gate_on_query_quarantine state_protection_and_idempotent_remove durable_quarantine_refuses_after_restart_then_recovers quarantine_capacity_never_evicts_and_retains_refusal unconfirmed_containment_retains_guards_and_recovers contain_group_confirms_descendant_death` | exit 0 — **13 passed, 0 failed, 322 filtered out** (26.41 s) |
| `cargo check -p fail2commit-core --all-targets` | exit 0 (only the pre-existing `hardened/mod.rs` dead-code warning) |
| `cargo clippy -p fail2commit-core --all-targets -- -D warnings` | exit 101 — **0 hits in `sandbox/vm/`**; all 26 error lines are the pre-existing baseline in untouched `hardened/*` and `sandbox/linux.rs` |
| host `cargo fmt --all --check`, `git diff --check HEAD~1 HEAD` | clean (exit 0) |
| host `git merge-tree --write-tree HEAD 27378f2e…` | exit 0, no conflicts |

The 13 cover both new tests, all six `bounded_query_*` fixtures (shared
`run_bounded_with_grace`), the locked idempotent-remove test, and the
registry/recovery/containment fixtures adjacent to the changed helpers.
Logs: `/home/dev/vmfix-443e0b4/r4-{test,check,clippy}.log`.

## Still pending (runtime gates — unchanged, not source acceptance)

Root `vm prepare`/`remove` twice (including full root-owned removal after
recovery), real KVM boot and prepared capability success, QEMU 9p acceptance
of `/proc/self/fd/N` share roots, comma-path parser behavior, mounted
control/result isolation, clean VM exit/outcome/export authority and real
timeout/tree cleanup. The dev VM has no root, `/dev/kvm` or
`qemu-system-x86_64`; none of these ran. The remaining 322 lib tests,
protocol 9 and integration 7 were not re-run (bounded task scope; prior
`c5d028b` results stand). Source acceptance of R4-01/R4-02 must not be
labeled runtime or feature acceptance.
