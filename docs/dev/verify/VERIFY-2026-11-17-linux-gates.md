# VERIFY 2026-11-17 — Linux runtime gates (FR-027 hardened, FR-029 VM non-KVM)

- Branch: `DansPK/f2c-014-linux-gates`; base `origin/DansPK/f2c-0.1.4` @ 23f7291 (merged; earlier base b0deb7b).
- **Round 1 tested SHA: `13eaafd7293a818fece5f7f66922ecbd32498e34`; round 2 (B1) tested SHA: `07dd7ea362b3aba5097bc5d62c645cde65429ce2`**
- Guest: VMware `debian-f2c`, Debian 13, kernel 6.12.86, systemd 257.13, QEMU 10.0.13, rustc/cargo 1.100.0, user `dev`, passwordless sudo.
- Host (Windows) ran only fmt / check / clippy / build; no tests or binaries. Evidence logs: `/home/dev/.cache/linux-gates-b0deb7b/final-*.log` in the guest.
- Cargo env in guest: separate `CARGO_HOME`/`RUSTUP_HOME`, `CARGO_TARGET_DIR=/home/dev/.cache/linux-gates-b0deb7b/target`, `-j 2`.

## Bugs found and fixed (each with a regression test or fixture)

| # | Commit | Defect | Evidence / test |
|---|--------|--------|-----------------|
| 1 | f583f85 | `vm prepare` rejected QEMU 10 quoted `-device help` names | unit tests (earlier worker) |
| 2 | e1dd11a | system UID range not derived from stock Debian 13 `login.defs` (commented `#SYS_UID_MIN`) | `lifecycle.rs` unit test |
| 3 | 2e21653 | TC-029-11 guest-path and TC-029-12 stale-prepare unit gates missing | new unit tests |
| 4 | b445e09 | `systemd-run --scope --wait --pipe` is rejected by systemd 257 ("--pty/--pipe is not compatible in timer or --scope mode"); every hardened probe/job failed closed | `linux_scope_flags_are_valid_for_systemd_257` |
| 5 | 9331a6e | `sandbox_hostile_linux` 8 failures in the full workspace run: **not parallelism** — cargo 1.100 puts test binaries in `target/debug/build/<pkg>/<hash>/out`, so `relay::locate()` no longer finds `f2c-sandbox-relay` (deterministic `no f2c-sandbox-relay next to the executable`). Test now points `F2C_SANDBOX_RELAY` at `CARGO_BIN_EXE_f2c-sandbox-relay` | 21/21 pass with no env, default threads |
| 6 | 47fa153 | hardened unit `RestrictAddressFamilies` lacked `AF_NETLINK`; bubblewrap needs rtnetlink for loopback in its netns. Probe job `max_processes`/`TasksMax` 8 starved launcher threads + bwrap (EAGAIN) → 32 | `linux_unit_allows_netlink_for_bubblewrap_loopback`; manual probe in an emulated unit |
| 7 | fbac0f6 | `User=root` + `NoNewPrivileges=yes` makes systemd drop CAP_SETUID/SETGID (service CapEff `…ff7f`), so `setpriv --reuid f2c-sandbox` failed `setresuid: Operation not permitted`. `User=`/`Group=` removed (system units default to root); bisected with the real unit | `linux_unit_keeps_cap_setuid_for_the_launcher` |
| 8 | 13eaafd | watchdog probe sent `READY` before the payload launched; the service closes the pipe on READY, so bwrap was SIGKILLed pre-launch ("sandbox setup failed before launch: no diagnostic"). `READY` now fires from the launch-marker thread | exercised by the manual probe (`watchdog_cancelled:true`) |

The `wd` strace work of the previous worker was the hardened **watchdog probe** (`sandbox hardened-probe --watchdog 0`) failing with exit 70; defects 4, 6, 7 and 8 above are its causes (the probe hides its error and the service drops stderr, so they were only visible by bisecting a transient unit and `strace -f -p` on the service).

## Commands and results at 13eaafd

| Gate | Command | Exit | Result |
|------|---------|------|--------|
| Windows host | `cargo fmt --all -- --check`; `cargo clippy -j 2 --workspace --all-targets --locked -- -D warnings` | 0 / 0 | clean (on fbac0f6; 13eaafd is Linux-only code, checked in the VM) |
| Linux clippy/fmt | same two commands in the VM | 0 / 0 | clean |
| Workspace | `cargo test --workspace --locked` | 0 | 65 targets, **785 passed, 0 failed, 5 ignored** (includes `sandbox_hostile_linux` 21/21 in the parallel suite) |
| Hostile, default mode | `F2C_REQUIRE_SANDBOX=1 cargo test -p fail2commit --test sandbox_hostile_linux -- --test-threads=1` | 0 | 21/21 pass |
| VM unit | `cargo test -p fail2commit-core --lib vm` | 0 | 51/51 pass |
| TC-027-1 non-root install | `fail2commit hardened install` as dev | 10 | rejected (pass) |
| TC-027-1 root install | `sudo fail2commit hardened install` | 0 | installed; socket active; unit has AF_NETLINK, no `User=` |
| TC-027-9 uninstall twice | `sudo fail2commit hardened uninstall` ×2 | 0 / 0 | idempotent; no residue under `/etc`, `/usr/lib`, `/var/lib`, `/run`, `/etc/systemd/system`; account `f2c-sandbox` removed; socket inactive; host network still up |
| TC-029-10 non-root | `vm prepare` / `vm remove` as dev | 10 / 10 | `rejected` (pass) |
| TC-029-10 root | `sudo vm prepare` ×2, `sudo vm remove` ×2 | 0 ×4 | idempotent; state removed (pass) |
| TC-029-12 stale hash | tamper `kernel_sha256`, `vm status` | 0 | `hashes: MISMATCH (prepared kernel hash mismatch…)`; restored → `hashes: ok` (pass; unit gate also added) |
| TC-029-1 | `ls /dev/kvm`; no `vmx`/`svm` in cpuinfo | 2 / 1 | no KVM; probe reason recorded (pass for fallback-reason evidence; full fallback run needs a KVM-less probe path — status shows reason only) |
| TC-029-11 | unit gate `2e21653` | 0 | pass (51 vm unit tests) |

## Per-TC summary

| TC | Result |
|----|--------|
| TC-027-1 install (non-root rejected, root install, unit/socket/account) | PASS |
| TC-027-1 `hardened status` available after install | FAIL in round 1; **resolved in round 2** |
| TC-027-3/4 hardened job run | BLOCKED in round 1; PASS in round 2 |
| TC-027-7 crash/recovery | PARTIAL: stop/start fails closed (`isolation_unavailable`, exit 14) and service restarts, but recovery to *available* is blocked by B1 |
| TC-027-9 uninstall twice, no residue | PASS |
| Hostile catalogue, hardened mode (`F2C_SANDBOX_BACKEND=hardened`) | BLOCKED in round 1; PASS in round 2 |
| Hostile catalogue, default mode | PASS 21/21 |
| TC-029-1 reason without /dev/kvm | PASS (reason evidence) |
| TC-029-10, -11, -12 | PASS |
| TC-029-3..9 | BLOCKED: no /dev/kvm: VMware nested VT-x unsupported on Hyper-V host |

## B1 resolved — round 2 (tested SHA `07dd7ea362b3aba5097bc5d62c645cde65429ce2`)

Coordinator decision: implement B1 under the reviewer's conditions. Guest `debian-f2c`, snapshot `b1-pre-root-20261117` taken before root tests and **reverted afterwards**; evidence logs saved on the host in `f2c-scratch/b1-evidence.tgz` (`b1-*.log`, script `lg-b1-neg.sh`).

### Reviewer conditions

| # | Condition | Result |
|---|-----------|--------|
| a | probe stages in root-owned 0711 `/run/fail2commit-hardened/probe-stages`; one shared const `PROBE_STAGES_DIR` used by `probe_stage_dir`, `cleanup_roots_from_targets`, `legacy_cleanup_roots_from_records`, `validate_cleanup_root`, `recover`/sweep; parent mode exactly 0o711 for probe-stages and 0o700 for jobs (`managed_parent_mode`); uid 0, not-symlink and dev/ino identity checks kept; journal dir stays 0700 | done (`linux_acl.rs`); unit tests `probe_stages_are_the_only_traversable_managed_parent`, `stage_sweep_removes_probe_dirs_and_rejects_strangers` |
| b | legacy `<journal>/probe-stages` tolerated and removed on service start; uninstall removes the new dir | done (`remove_legacy_probe_stages`); VM: legacy dir removed, status exit 0, also after reboot; uninstall leaves no `/run/fail2commit-hardened` |
| c | per-stage dirs stay tempfile 0700, chowned to the peer | unchanged; VM shows `700 dev:root probe-XXXX` |
| d | VM evidence | below |
| e | x32 (`nr & 0x40000000`) → KILL after the arch check | done: `JSET 0x40000000` + `RET_KILL` (`seccomp.rs`); test `x32_syscall_numbers_are_killed_before_the_deny_list` |
| nit | watchdog treats any byte as closed | done: `spawn_watchdog_monitor`; test `watchdog_monitor_treats_any_byte_as_closed` |

### Additional defects found while making (d) pass (each with a regression test)

The stage move alone was not enough; these latent defects only appeared once the hardened service really ran on Debian 13:

| Defect | Fix |
|--------|-----|
| `setfacl --modify --no-mask <spec>`: `--modify` consumed `--no-mask` as its spec ("Invalid argument near character 1"), so no ACL grant ever worked | `setfacl_grant_args` puts `--no-mask` first |
| ACL traversal grants were attempted on `/`, `/run`, `/var` (read-only under `ProtectSystem=strict`) | `needs_traverse_grant` skips world-traversable ancestors |
| grants went to the **peer uid** instead of the sandbox account (`u:1000`), so `f2c-sandbox` could not read its job | grant to `sandbox_uid` |
| snapshot dir check required group bits 0, but the ACL mask shows in group bits (0710) | `private_acl_dir_mode`: uid/gid 0 and no "other" bits |
| `bindable()` refuses everything under `/run`, including the service's own probe stages | narrow carve-out strictly below `PROBE_STAGES_DIR` (`denied_inside`; test keeps `jobs`, `sock` and the root itself denied) |
| UDP probe expected `send_to 127.0.0.1:53` to fail; `lo` is up in the job netns, so it succeeds harmlessly | loopback removed from `LINUX_PROBE_UDP_DESTINATIONS` (error now names the destination) |
| `/etc/fail2commit-hardened.json` was 0600, so `hardened status`/`run` as the installer got EACCES (hidden behind a generic message) | 0644, root-writable only (`LINUX_STATE_MODE`, `trusted_state_file`) |
| client job dir was created 0755 by tempfile 3.27 and rejected by the service | `private_job_dir` sets 0700 |
| `ProtectHome=read-only` overrides `ReadWritePaths=/home` (verified in a transient unit), so every ACL grant under `/home` failed with EROFS | directive removed; test `linux_unit_leaves_home_writable_for_stage_acl_grants` |

### (d) VM evidence

| Check | Command / observation | Exit | Result |
|-------|-----------------------|------|--------|
| TC-027-1 install + status | `sudo hardened install`; `hardened status` as dev | 0 / 0 | `hardened mode available`; PROBE detail: account, system-scope limits, ACL stage, Bubblewrap, watchdog, shared public-only egress, direct-route refusal and bait-trip probes passed |
| TC-027-3/4 runtime effects | service PROBE jobs (account, ACL stage, read-only/writable stage, direct-route refusal, bait trip) + hostile catalogue through the installed service | 0 | PASS. `fail2commit run` is Internet-mode and is rejected by design on hardened Linux (`Linux Internet execution is reserved for the authenticated fixed egress probe`, exit 14) |
| Hostile catalogue, hardened (`F2C_HARDENED_E2E=1`, backend asserted `hardened-bubblewrap`, `TMPDIR` under `$HOME` because the unit has `PrivateTmp`) | `cargo test -p fail2commit --test sandbox_hostile_linux -- --test-threads=1` | 0 | 21 ok: 13 real rows pass through the service; 8 Internet/bait-proxy rows report "N/A in hardened mode" (Internet is reserved to service probes). Earlier "hardened hostile" runs ignored `F2C_SANDBOX_BACKEND` (it is read nowhere), so only this round is real hardened evidence |
| TC-027-7 crash/recovery | stop socket+service; `status`; start socket; `status` | 14 → 0 | fails closed while stopped, recovers when restarted |
| Negative: second local user `f2cneg` | `ls probe-stages`; while a probe runs, `ls`/`cd`/`cat` in the live stage | 2 / 2 / 1 / 1 | all `Permission denied`; stage is `700 dev:root` |
| getfacl after a grant | `stat`, `getfacl -p probe-stages` after probes | | stays `711 root:root`, `user::rwx group::--x other::--x`, no named entries |
| Legacy dir | `mkdir <journal>/probe-stages/probe-legacy`; restart service | 0 | removed; status available |
| Unknown object in probe-stages | `mkdir probe-stages/not-a-probe`; restart | 14 | service fails closed; after removal and `reset-failed` → available (exit 0) |
| Reboot | legacy dir present, soft reset, then `hardened status` | 0 | socket active after boot, service starts on demand, recovery succeeds, legacy removed, probe-stages recreated 0711 |
| TC-027-9 uninstall twice | `sudo hardened uninstall` ×2 | 0 / 0 | no residue incl. `/run/fail2commit-hardened`; account removed |
| Workspace | `cargo test --workspace --locked` (service uninstalled) | 0 | 65 targets, **797 passed, 0 failed, 5 ignored** |
| Hostile default | `--test-threads=1` | 0 | 21/21 |
| VM unit | `cargo test -p fail2commit-core --lib vm` | 0 | 51/51 |
| TC-029-10/-12/-1 | `vm prepare` ×2, stale hash, `vm remove` ×2, `/dev/kvm` absent | 10,10,0,0,0,0,0,0 | PASS |
| Linux clippy / fmt | in VM at 07dd7ea | 0 / 0 | clean |
| Windows clippy / fmt | host, `-j 2` | 0 / 0 | clean |

Two core unit tests (`an_installed_hardened_backend_never_reports_available_before_controls_pass`, `v1_journals_reconstruct_only_fixed_temporary_root_paths`) fail for a non-root user while the hardened service is installed (they assume it is absent); they pass in the clean workspace run above.

### Per-TC summary (final)

| TC | Result |
|----|--------|
| TC-027-1 install and available status | PASS |
| TC-027-3/4 hardened runtime effects | PASS (PROBE + hostile catalogue; Internet rows N/A by design) |
| TC-027-7 crash/recovery, reboot recovery | PASS |
| TC-027-9 uninstall twice | PASS |
| Hostile catalogue default / hardened | PASS 21/21 / PASS 13 + 8 N/A |
| TC-029-1, 10, 11, 12 | PASS |
| TC-029-3..9 | BLOCKED: no /dev/kvm: VMware nested VT-x unsupported on Hyper-V host |

### Notes
- Only guest-side diagnostics (hidden launcher/probe errors) were added temporarily; they are not committed.
- Probe and launcher errors are still reported generically to clients (exit 70 / "rejected the job or failed its mandatory controls"); finding the causes above needed `strace`. A follow-up could surface a bounded reason in the PROBE detail.
