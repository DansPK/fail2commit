# FR-029 / SPEC-019 — Linux VM backend LV-01…LV-07 review fixes (verify report)

Date: 2026-11-15. Branch: `DansPK/f2c-014-vm-linux-qwen`.
Base source SHA: `42687e6fd2bf9d21655d6ef97e3b1e921f8a8d1f`.
Final fix SHA: `1d43e94c5ce9a74a41f1550abf459d8462c8cd26`.
Review addressed: `94e0fd7b:docs/dev/verify/REVIEW-2026-11-14-vm-linux.md` (LV-01…LV-07).
Worker: Claude (qwen), dispatched Orca worker. Linux scope only.

## Status

**All seven source findings fixed and unit/fixture-verified on the Debian dev VM.
Boot/KVM/root runtime gates remain PENDING evidence** — the dev VM has no
`/dev/kvm`, no `qemu-system-x86_64` and no root auth, so no VM was booted and no
root image was prepared. Skipped boot/root tests are recorded as skipped, never
as passes. No host/global/root change, push, publish, subworker or VM shutdown
occurred.

## Fixes per finding (milestone SHA → tests)

| Finding | Fix | Milestone SHA | Verifying tests |
|---|---|---|---|
| **LV-01** input mounts | init creates **every** configured input mount point, parses the required count `f2c_inputs` from the cmdline, mounts exactly the supplied slots and **fails closed** (poweroff before dispatch) on a required mount error; unused slots stay distinct empty dirs. Host encodes the count in the QEMU append. | `568af01` | executable init fixture runs the generated script under `/bin/sh` with logging fake tools + real mount-point creation: `init_exec_creates_every_mountpoint_and_mounts_required_inputs`, `init_exec_fails_closed_on_required_mount_errors`, `init_exec_rejects_missing_or_invalid_input_count`, `init_exec_rejects_bad_boot_identity` |
| **LV-02** KVM context | replaced the Xen `/sys/hypervisor/type` check with the **KVM hypervisor CPUID signature** (leaf `0x40000000`). Dispatch bound to a **root-only prepared-guest capability** baked into the initramfs: init opens it and hands the launcher the fd; the launcher verifies the fd refers to that exact root-owned inode. Cmdline job id stays correlation, not auth. Outside-guest syntactically valid tree refused. | `876d961` | `kvm_signature_detection_matches_only_kvm`, `capability_refuses_outside_the_prepared_guest`, `dispatch_outside_the_prepared_guest_is_refused`; init fixture exercises the fd hand-off |
| **LV-03** pre-spawn deadline | checked absolute `boot_deadline` computed **before any spawn**; every post-spawn path (timeout, wait error, failed exit, clean exit) runs shared `stop_process_group` (kill group, reap leader, re-probe until gone) **before** mapped state is released. | `1a3f84b` | `boot_deadline_is_checked_before_any_spawn`, `stop_process_group_confirms_descendant_death`, `overflow_timeout_never_spawns_qemu` (spawn sentinel) |
| **LV-04** QEMU escaping | `-fsdev` path values double literal commas per QEMU syntax; non-UTF-8 share paths refused (no lossy conversion). fd-backed paths (LV-05) also remove the raw user path from the option string. | `7421873` | `fsdev_paths_escape_commas_and_option_looking_segments` (parses rendered fsdev with QEMU's documented option grammar), `non_utf8_share_paths_are_rejected_not_lossily_converted`; boot gate `comma_stage_path_boots` added |
| **LV-05** stable mappings | each share anchor pinned with an **explicitly inherited** (`FD_CLOEXEC`-cleared) `O_PATH` fd; QEMU maps `/proc/self/fd/N`, which always resolves to the pinned inode regardless of later rename/replace. Job anchors re-checked against the re-walked identity; pins held until the group is confirmed dead. No comment-only pin claim. | `0cf4634` | `fd_backed_pin_resists_pathname_swap` (swap between validation and share-open), `pinned_share_renders_fd_backed_path_and_identity_change_is_refused` |
| **LV-06** bounded queries | `run_bounded` spawns its own process group, **cap-drains stdout concurrently** (full pipe no longer blocks the child), bounds leader wait **and** reader completion with deadlines, stops the whole group so a descendant-held pipe cannot hang the reader, and **surfaces** kill/wait cleanup uncertainty. | `0995d7b` | `bounded_query_drains_pipe_pressure_concurrently`, `bounded_query_stops_descendant_held_pipe`, `bounded_query_times_out_and_kills_the_group`, `bounded_query_rejects_oversized_output` |
| **LV-07** tool paths / modules | init renders the **actual selected** busybox/setpriv/kmod paths (`/bin` on non-merged hosts); `modules.dep`/`modules.builtin` names normalized across `.ko`/`.ko.xz`/`.ko.zst` so the required module dependency closure resolves. | `edcf72a` | `init_renders_the_selected_tool_paths`, `init_mounts_non_merged_system_shares`, `module_closure_normalizes_compressed_names_and_orders_dependencies`, `builtin_modules_need_no_files_and_missing_modules_fail_closed` |

Boot-gate addition: `1e9173b` (comma-stage-path). Clippy cleanup of the fix files:
`1d43e94` (final). Intermediate compile-fix commits (`d158de0`→`edcf72a`,
`bf9d47e`→`568af01`, `812daf8`→`1a3f84b`, `a7d24d9`→`0cf4634`) are folded into the
milestone SHAs above.

## Evidence (Debian dev VM `debian-f2c`, uid 1000, kernel 6.12.86+deb13-amd64)

Toolchain: `RUSTUP_HOME/CARGO_HOME=/home/dev/.cache/fr013-progress-r2-4383611/{rustup,cargo}`
(cargo/rustc 1.100.0), `CARGO_BUILD_JOBS=2`, `CARGO_PROFILE_*_DEBUG=0`, shared
`CARGO_TARGET_DIR=/home/dev/.cache/f2c-vmfix-target`. Each milestone was archived
with `git archive` at its exact SHA, extracted to a fresh dir and tested there
(never from copied binaries). Final source `1d43e94`:

| Command | Result |
|---|---|
| `cargo test -p fail2commit-core --lib vm` | exit 0 — **38 passed, 0 failed** |
| `cargo test -p fail2commit-core --lib protocol` | exit 0 — **9 passed, 0 failed** (frozen contract intact) |
| `cargo test -p fail2commit --test sandbox_vm_linux` | exit 0 — **7 test fns, 0 failed**; 3 ran, **4 self-skipped (pending evidence)**: `prepare_and_remove_idempotent` (needs root), `exports_after_clean_exit_and_vm_is_gone`, `timeout_kills_the_vm`, `comma_stage_path_boots` (`F2C_VM_GATE=1` not set) |
| `cargo check --workspace --all-targets` | exit 0 |
| `cargo clippy -p fail2commit-core -p fail2commit --all-targets -- -D warnings` | **0 hits in any changed file**; 19 lib + 18 lib-test errors remain, all pre-existing in untouched `hardened/` and `sandbox/linux.rs` (verified identical on base `42687e6`) |
| `cargo fmt --all --check` (host) | exit 0 |
| host `cargo check -p fail2commit-core -p fail2commit --all-targets` (Windows target) | exit 0 — shared/cross-platform code compiles; only pre-existing dead-code warnings in untouched Windows files |

Per-milestone VM runs: LV-07 20 → LV-01 24 → LV-04 26 → LV-03 29 → LV-05 31 →
LV-02 34 → LV-06 38 passed (all 0 failed), each on its exact archived SHA.

## Pending runtime gates (need root + `/dev/kvm` + prepared image + QEMU)

- LV-01: boot a one-input job and a missing-input-device case (init fixture covers
  the fail-closed semantics; real 9p mount behaviour is a boot gate).
- LV-02: real KVM CPUID detection and the root-owned capability success path
  inside an actual KVM guest; outside-guest refusal with a planted control tree.
- LV-04: `comma_stage_path_boots` against QEMU's real option parser.
- LV-05: QEMU acceptance of `/proc/self/fd/N` 9p roots and a live swap under boot.
- LV-03/06: real QEMU process-tree timeout/kill and query behaviour.
- TC-029-10 root `prepare`/`remove` twice; TC-029-2/3/4/5/6/7/8/9/12 catalogue,
  export, killed-VM and hash-mismatch gates.

## Integration notes for the manager

- **Windows untouched.** Only `vm/linux.rs`, `vm/prepare.rs`, `vm_guest.rs` and
  `tests/sandbox_vm_linux.rs` changed. `vm_guest.rs` edits are confined to
  Linux-only regions (`verify_linux_vm_context`, new Linux helpers/tests); the
  `launch` signature and Windows blocks are unchanged. A trial `git merge-tree`
  with the Windows-refusal commit `9fe6d5f8` shows **0 conflict markers**, so the
  manager's `27378f2`/`9fe6` Windows refusal merges cleanly. SPEC-019 was left
  untouched to avoid conflicting with `27378f2`.
- **Pre-existing clippy baseline.** `-D warnings` fails on 19/18 errors in
  `hardened/*` and `sandbox/linux.rs` on the base commit already; these are
  frozen/other-owner files and were not modified. The fix files are clippy-clean.
- **LV-05 residual risk (boot gate).** fd-backed mapping relies on QEMU's 9p local
  backend opening `/proc/self/fd/N` as the share root. The fd-inheritance and
  swap-resistance are OS-level tested; QEMU-specific acceptance is not verifiable
  without QEMU/KVM and is deferred to the boot gate. If QEMU rejects the fd path
  the job fails closed (no silent mis-mapping).