# VERIFY 2026-11-17 — Linux runtime gates (FR-027 hardened, FR-029 VM non-KVM)

- Branch: `DansPK/f2c-014-linux-gates`; base `origin/DansPK/f2c-0.1.4` @ 23f7291 (merged; earlier base b0deb7b).
- **Tested SHA (VM, all runs below): `13eaafd7293a818fece5f7f66922ecbd32498e34`**
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
| TC-027-1 `hardened status` available after install | **FAIL / OPEN BLOCKER B1** |
| TC-027-3/4 hardened job run | **BLOCKED by B1** |
| TC-027-7 crash/recovery | PARTIAL: stop/start fails closed (`isolation_unavailable`, exit 14) and service restarts, but recovery to *available* is blocked by B1 |
| TC-027-9 uninstall twice, no residue | PASS |
| Hostile catalogue, hardened mode (`F2C_SANDBOX_BACKEND=hardened`) | **BLOCKED by B1** |
| Hostile catalogue, default mode | PASS 21/21 |
| TC-029-1 reason without /dev/kvm | PASS (reason evidence) |
| TC-029-10, -11, -12 | PASS |
| TC-029-3..9 | BLOCKED: no /dev/kvm: VMware nested VT-x unsupported on Hyper-V host |

## Open blocker B1 — probe stage is untraversable (design decision needed)

After fixes 4–8 the watchdog probe passes (`watchdog_cancelled:true`) but the next probe stage fails:

`authenticated caller cannot traverse requested path ancestor /var/lib/fail2commit-hardened-acl/probe-stages/probe-XXXXXX`

Cause: `linux_acl::probe_stage_dir` places the per-probe stage under the ACL journal directory, which `verify_journal_dir` requires to be root-owned with no group/other bits (0700). `verify_peer_traversal` then runs `test -x` as the installer uid, and the `f2c-sandbox` account also needs to traverse the path; neither can through a 0700 root directory. The Linux probe-stage path was only unit-tested against temp dirs, never against the real private journal.

Proposed fix (not applied, because it changes the security layout): put probe stages in a root-owned 0711 directory outside the private journal (e.g. `/run/fail2commit-hardened/probe-stages`, parent is 0755) and update the five `probe-stages` references in `linux_acl.rs` (recover/cleanup at ~305, 358, 421, 514, 623) plus `probe_stage_dir`; alternatively make the journal dir 0711 (leaks journal file names only). Needs a coordinator/reviewer call.

## Environment notes
- No snapshot revert was used: the pre-root snapshot `linux-gates-pre-root-20261117` exists but would also discard the guest build cache; instead hardened and VM state were uninstalled/removed and verified clean (see TC-027-9, TC-029-10).
- `/opt/f2c-linux-gates` (staged root-owned binaries) remains in the guest.
- A debug build with `DBGPROBE` instrumentation was used only in the guest and is not committed.
