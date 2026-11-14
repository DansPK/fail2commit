# FR-029 Linux VM lifecycle — R2 + R3 review fixes (verify report)

Date: 2026-11-15. Branch: `DansPK/f2c-014-vm-linux-qwen`.
Base: `42687e6`; R1 pin `1d43e94` (report `2a8658d`); R2 review `f5b104e5`;
R2 fixes pin `74715a4`; R3 review `6a2cd2b`; **final fix SHA `c5d028bfdd2732fdd228741354b976c993713c71`**.
Linux scope only; Windows behavior untouched (refusal commit `27378f2` merges with
0 conflict markers via trial `git merge-tree`; SPEC-019 untouched).

## R2 findings (review `f5b104e5`)

| Finding | Fix summary | Milestone SHA | Verifying tests |
|---|---|---|---|
| R2-01 blocking cleanup / early guard release | Bounded polled reap + shared `stop_process_group` → later `contain_group`; unconfirmed cleanup hands pins/control/result/child to a process-global retained containment owner with a durable quarantine record; entry-guard refuses/recovers before spawning | `1a3f84b`→`2cb275f` | `boot_deadline_is_checked_before_any_spawn`, `stop_process_group_confirms_descendant_death`, `overflow_timeout_never_spawns_qemu`, `unconfirmed_containment_retains_guards_and_recovers` (production `run_job` injection) |
| R2-02 fresh graces per phase, detached reader | One absolute whole-query deadline; reserve for cleanup; caller-owned O_NONBLOCK drain; containment shares the same deadline | `0995d7b`→`74715a4` | `bounded_query_drains_pipe_pressure_concurrently`, `bounded_query_stops_descendant_held_pipe`, `bounded_query_times_out_and_kills_the_group`, `bounded_query_rejects_oversized_output`, `bounded_query_leader_near_deadline_completes_inside_bound` |
| R2-03 parent CLOEXEC cleared for all spawns | Parent pins keep FD_CLOEXEC; only the QEMU spawn installs a `pre_exec` slot allowlist (dup2+fcntl only, no post-fork allocation) | `6760a3d` | `fd_backed_pin_resists_pathname_swap`, `slot_child_sees_pinned_inode_after_swap` (+unrelated-child non-inheritance) |
| R2-04 init continues when poweroff returns | `f2c_fail() { $BB poweroff -f; exit 1; }` on every module/mount/validation/capability branch; capability fd consumed (closed) by the launcher | `938fb69` | `init_exec_fails_even_when_poweroff_returns_failure` (every branch, failing poweroff, launcher never reached) + fixture matrix |

## R3 findings (review `6a2cd2b`)

| Finding | Fix summary | Milestone SHA | Verifying tests |
|---|---|---|---|
| R3-01 incomplete scan read as group death | `group_members_checked` → `Complete/Uncertain`: read_dir/stat errors (non-ENOENT), unparsable present entries, entry cap, and mid-walk deadline are all Uncertain; Confirmed requires a Complete-empty scan cross-checked by the kernel `kill(-pgid,0)` probe (ESRCH confirms; Present re-scans; Unknown stays uncertain); exact pgrp+starttime revalidation immediately before every signal; `Unconfirmed{live,uncertain}` surfaced through quarantine reasons and recovery | `84d3bdc` | `member_scan_distinguishes_complete_from_uncertain`, updated production containment test |
| R3-02 fixed slots can clobber later sources | `assign_slots` places child slots strictly above the highest source fd (proven disjoint); only final slots clear CLOEXEC | `12b048f` | `slot_allocation_avoids_source_overlap_under_fd_pressure` (fd-pressure fixture, real exec'd child verifies every mapped inode after a swap) |
| R3-03 quarantine not crash-safe; evicted identities | Directory fsync after rename/clear; cap now fails closed (never evicts); recovery prunes only proven-dead records, durably rewrites live survivors and refuses before launching anything; persistence failure still retains guards + refusal | `4ebf6eb` | `quarantine_capacity_never_evicts_and_retains_refusal`, `durable_quarantine_refuses_after_restart_then_recovers` (cross-process restart fixture) |
| R3-04 scan without internal deadline; query drops Child | Enumeration is deadline-bounded; unconfirmed query paths retain the owned process + durable record like VM runs (registry/durable quarantine moved to prepare.rs and shared); bounded reap floor so a killed leader is never kept as an unreaped zombie; capability queries record under the prepared lib dir | `c5d028b` | `bounded_query_budget_exhaustion_retains_and_recovers` (production injection: uncontained member exhausts the 400 ms budget → retain + durable record → recovery clears) |

## Evidence (Debian dev VM `debian-f2c`, uid 1000, kernel 6.12.86+deb13, cargo 1.100.0)

Each milestone was `git archive`d at its exact SHA, extracted to a fresh guest
directory, and tested there (never copied binaries; shared warm target dir,
`CARGO_BUILD_JOBS=2`, debug info off). Final source `c5d028b`:

| Command | Result |
|---|---|
| `cargo test -p fail2commit-core --lib vm` | exit 0 — **47 passed, 0 failed** (~26 s; production containment fixtures dominate) |
| `cargo test -p fail2commit-core --lib protocol` | exit 0 — **9 passed** (frozen wire contract intact) |
| `cargo test -p fail2commit --test sandbox_vm_linux` | exit 0 — **7 passed, 0 failed**; 4 self-skips recorded as pending evidence (`prepare_and_remove_idempotent` needs root; `exports_after_clean_exit_and_vm_is_gone`, `timeout_kills_the_vm`, `comma_stage_path_boots` need `F2C_VM_GATE=1` + root + KVM + prepared image), never counted as passes |
| `cargo clippy -p fail2commit-core -p fail2commit --all-targets -- -D warnings` | **0 hits in any changed file**; remaining 19 lib + 18 lib-test errors are the identical pre-existing baseline in untouched `hardened/*` and `sandbox/linux.rs` (verified against base `42687e6`) |
| `cargo check --workspace --all-targets` | exit 0 |
| host `cargo fmt --all --check`, `git diff --check` | clean |

Per-milestone VM runs: R2-04 39 → R2-03 40 → R2-01 41 → R3-01 43 → R3-02 44 →
R3-03 46 → R3-04 47 passed (all 0 failed). The R2 tip additionally passed
protocol 9 / integration 7 / check 0 at `74715a4`; the host Windows-target
`cargo check` of the touched crates passed at `1d43e94`-era code and the R2/R3
Linux-only files do not compile on Windows, so the shared entry points are
unchanged since.

## Still pending (runtime gates — unchanged claims, not source acceptance)

Root `vm prepare`/`remove` twice; real KVM boot with CPUID + root-owned
capability success; QEMU 9p acceptance of `/proc/self/fd/N` share roots;
comma-path boot against the real QEMU parser; mounted control/result
isolation; VM exit/outcome/export authority; timeout process-tree cleanup on
real QEMU. None ran on the dev VM (no `/dev/kvm`, no `qemu-system-x86_64`, no
root); skipped tests are recorded as skipped.

## Notes for integration

- Windows refusal `27378f2`/`9fe6` merges cleanly (0 conflict markers in trial
  merge-tree against this tip); this branch still contains no Windows changes.
- Test-side ETXTBSY retries only: exec'ing a just-written fixture script can
  transiently fail when a parallel test forks while the writer still holds
  the fd; production keeps the single bounded spawn failure. Registry-touching
  tests serialize on `prepare::VM_TEST_LOCK`.
- If durable persistence fails while retaining, refusal is guaranteed
  in-process (registry); across a restart it depends on the durable record,
  which is why cap/persist errors keep guards and the message tells the
  operator which file/group to resolve.