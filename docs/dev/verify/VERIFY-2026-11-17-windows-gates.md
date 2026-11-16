# Windows gates — 2026-11-17

## Environment and source

- Branch: `DansPK/f2c-014-win-gates`.
- Tested source SHA: `316c4949f31712f9ac4a1492282e1032e1c87040` (after coordinator merge `cdf9e4352efcd04b6242ab22f9eab9a643616b03`).
- Runtime: VMware `win11`, Windows 11, active interactive `win11` console session; guest checkout `C:\Users\win11\f2c-014-wingates\repo`.
- Snapshot `f2c-014-wingates-pre` was taken before installs and restored on both Win11 and Win10 after the run. Win10 was not powered on or tested; its snapshot was restored as cleanup. No runtime commands were run on the Windows host.
- `CreateAppContainerProfile` previously returned `HRESULT 0x80070002` when the guest had no signed-in console user. After the coordinator enabled autologon, the active interactive session allowed profile creation and the targeted sandbox integration test passed; no source change was needed for that error.

## Host build-only gates

All commands below ran on the Windows host, capped at two Cargo jobs. No host test binary was executed.

| Command | Exit | Result |
|---|---:|---|
| `cargo fmt --all -- --check` | 0 | Clean |
| `cargo clippy --workspace --all-targets --locked -j 2 -- -D warnings` | 0 | Clean on final source |
| `cargo test --workspace --locked --no-run -j 2` | 0 | All test targets compiled; build-only |
| `git diff --check` | 0 | Clean |

## Win11 workspace tests

The full Windows workspace run was executed in the guest at the tested SHA:

```text
cargo test --workspace --locked --no-fail-fast -j 2
exit 101
```

Per-target results (Windows-inapplicable Linux-only targets correctly contain zero tests):

| Target | Passed | Failed | Ignored | Result |
|---|---:|---:|---:|---|
| `f2c-sandbox-relay` unit | 0 | 0 | 0 | PASS |
| `fail2commit` unit | 12 | 0 | 0 | PASS |
| `approval_cli` | 5 | 0 | 0 | PASS |
| `approval_stdio` | 8 | 0 | 0 | PASS |
| `approval_tty` | 0 | 0 | 0 | PASS |
| `checks_preinstall` | 10 | 0 | 0 | PASS |
| `e2e_npm_approval` | 4 | 0 | 0 | PASS |
| `e2e_npm_sandbox` | 6 | 0 | 0 | PASS |
| `e2e_push` | 5 | 0 | 0 | PASS |
| `e2e_setup` | 1 | 0 | 0 | PASS |
| `git_push` | 13 | 0 | 0 | PASS |
| `git_setup` | 6 | 0 | 0 | PASS |
| `ipc_pipe` | 8 | 0 | 0 | PASS |
| `ipc_startup` | 5 | 0 | 0 | PASS |
| `malware_list` | 7 | 0 | 0 | PASS |
| `npm_cli` | 3 | 0 | 0 | PASS |
| `npm_flow` | 21 | 0 | 0 | PASS |
| `npm_scripts` | 7 | 0 | 0 | PASS |
| `npm_signatures` | 13 | 0 | 0 | PASS |
| `pip_cli` | 6 | 0 | 0 | PASS |
| `pip_install` | 16 | 0 | 0 | PASS |
| `pip_recover` | 7 | 0 | 0 | PASS |
| `pip_reject` | 4 | 0 | 0 | PASS |
| `rereview2_git` | 4 | 0 | 0 | PASS |
| `rereview2_npm` | 19 | 0 | 0 | PASS |
| `rereview2_pip` | 7 | 0 | 1 | PASS |
| `rereview3_npm` | 21 | 0 | 0 | PASS |
| `rereview_npmscan` | 24 | 0 | 0 | PASS |
| `rereview_pip_boot` | 14 | 0 | 0 | PASS |
| `rereview_pip_journal` | 11 | 0 | 0 | PASS |
| `rereview_pip_shim` | 6 | 0 | 0 | PASS |
| `rereview_relay` | 4 | 0 | 0 | PASS |
| `rereview_wave1` | 8 | 0 | 0 | PASS |
| `resource_bounds` | 5 | 0 | 0 | PASS |
| `resource_process` | 0 | 0 | 0 | PASS |
| `review_coordinator_fixes_pip` | 3 | 0 | 0 | PASS |
| `review_e2e_relay` | 7 | 0 | 0 | PASS |
| `review_t007b_paths` | 3 | 0 | 0 | PASS |
| `review_t007b_systemroot` | 1 | 0 | 0 | PASS |
| `review_t007b_tempdir` | 1 | 0 | 0 | PASS |
| `review_wave1` | 10 | 0 | 0 | PASS |
| `review_wave2_pth` | 3 | 0 | 0 | PASS |
| `review_wave2_scan` | 3 | 0 | 0 | PASS |
| `rules_yara` | 9 | 0 | 0 | PASS |
| `run_cli` | 3 | 0 | 0 | PASS |
| `sandbox_hostile_linux` | 0 | 0 | 0 | PASS (not applicable) |
| `sandbox_hostile_windows` | 19 | 2 | 1 | FAIL |
| `sandbox_linux_build` | 0 | 0 | 0 | PASS (not applicable) |
| `sandbox_linux_hostile` | 0 | 0 | 0 | PASS (not applicable) |
| `sandbox_linux_policy` | 0 | 0 | 0 | PASS (not applicable) |
| `sandbox_setting_cli` | 4 | 0 | 0 | PASS |
| `sandbox_setting_policy` | 9 | 0 | 0 | PASS |
| `sandbox_vm_linux` | 0 | 0 | 0 | PASS (not applicable) |
| `sandbox_windows_matrix` | 6 | 0 | 1 | PASS |
| `scan_advisories` | 15 | 0 | 1 | PASS |
| `scan_cli` | 12 | 0 | 0 | PASS |
| `scan_hardening` | 7 | 0 | 0 | PASS |
| `scan_output` | 3 | 0 | 0 | PASS |
| `scan_scripts` | 3 | 0 | 0 | PASS |
| `server_protected` | 9 | 0 | 0 | PASS |
| `threat_update` | 8 | 0 | 0 | PASS |
| tray unit | 3 | 0 | 0 | PASS |
| `appcontainer` | 1 | 0 | 0 | PASS |
| fail2commit-core doc tests | 0 | 0 | 0 | PASS |

The two remaining default-mode sandbox failures are `hb030_internet_mode_reaches_the_public_registry` (the HTTPS request succeeded but no `net_allowed` event was reported) and `hb036_hb037_listen_multicast_and_broadcast_are_refused` (the test failed on its first UDP assertion: Internet-mode multicast `224.0.0.251:5353` succeeded). At the original test order, Internet mode ran first, so None-mode multicast/broadcast and Internet-mode broadcast were not reached. A guest user-context `Test-NetConnection registry.npmjs.org -Port 443` and HTTPS request both succeeded, so general guest connectivity is present. HB-030 matches SPEC-014 section 1's known 25 ms TCP-table reporting limit: a short-lived successful connection can close between ticks and be absent from `net_allowed`; this is a reporting limitation, not evidence of a network security bypass. By contrast, TC-023-6 explicitly requires multicast/broadcast datagram sends to fail; the observed Internet-mode multicast send is a SPEC-014 deviation, not a documented limit. The cleanup regression test `hb070_a_killed_owner_leaves_nothing_behind` now passes.

### Regression fix

`process_creation_time` treated a terminated process as live while another process still held its process handle. The Windows profile sweeper therefore retained the dead owner's profile. The fix in `crates/fail2commit-core/src/sandbox/windows/watch.rs` adds `SYNCHRONIZE`, checks `WaitForSingleObject(handle, 0) == WAIT_TIMEOUT`, and adds `terminated_child_is_not_considered_live_while_parent_holds_its_handle`. The targeted guest test passed (exit 0; 1 passed, 21 filtered out).

## FR-013 — Windows progress window

| Check | Result | Evidence |
|---|---|---|
| Native window during successful npm and pip installs; visible phases and completion; screenshots | BLOCKED | Current-source npm attempts stopped at `approval_unavailable` (exit 11); no successful install produced a phase window. No progress screenshots are claimed. |
| `ui.progress_window = false` hides window | NOT RUN | Requires a successful visible guarded install to compare. |
| Terminal progress line behavior | NOT RUN | No successful terminal-mode install completed. |
| JSON/API silence | PARTIAL PASS | JSON-mode npm attempt returned one JSON response without a progress window; it exited 11 at approval. The successful-install JSON/API case remains unverified. |
| `npm_install` / `pip_install` current-source integrations | PASS (suite) | Guest workspace run: `npm_flow` 21/21 and `pip_install` 16/16 passed. The suite tests are not evidence of the requested native GUI appearance. |

An initial npm attempt using `eslint@9.17.0` stopped because the package lifecycle path escaped its package root. A subsequent clean `lodash@4.17.21` attempt still required approval and exited 11 while unattended. A local loopback OSV stub was attempted; it did not produce a completed guarded install. Therefore no screenshots were saved under `docs/dev/verify/assets/` and no visual pass is claimed.

The prior `0x80070002` profile-creation failure was due to the absence of an interactive signed-in guest session. After autologon established the active `win11` console session, the exact-source AppContainer profile probe succeeded; the targeted cleanup test passed as above.

## FR-027 — Windows hardened backend

Commands ran elevated (`ADMIN=True`) in the Win11 guest using an isolated `FAIL2COMMIT_HOME`.

| SPEC-018 case | Result | Evidence |
|---|---|---|
| TC-027-1 install/status | FAIL / UNAVAILABLE | `hardened install` exit 0 created service/account/state; readiness was false. `hardened status` exited 14 with `isolation_unavailable`; it named the absent hardened service pipe, unresolved Windows launcher/watchdog and platform controls, and the unaccepted FirewallAPI writer requirement. |
| TC-027-2, 4–8, 10–12 | UNAVAILABLE | Windows hardened backend is not available; no hardened jobs or service-kill scenarios were run. Probe fails closed. Linux-only TC-027-3 and TC-027-17 were not run in Windows. |
| TC-027-9 uninstall twice | PASS after follow-up fix | Initial pre-fix uninstall exited 70 (`The directory is not empty`, OS error 145), and the retry returned 0 without removing the leftover machine-data directory. Follow-up testing after the fix: first uninstall exit 0; second uninstall exit 0; final status exit 10. No service/account, `Program Files\fail2commit-hardened`, or `ProgramData\fail2commit-hardened` residue remained. |
| TC-027-13 backend selection | PASS (unit) | Full workspace suite passed selection tests; Windows status confirms unavailable backend is refused. |
| TC-027-14 probe fails closed | PASS (runtime refusal) | Installed status exited 14 with `isolation_unavailable`; no launch was allowed. |
| TC-027-15 malformed outcome | PASS (suite coverage) | Workspace suite passed; no separate hardened Windows service fixture was available. |
| TC-027-16 concurrent launch | UNAVAILABLE | No hardened service launch can be accepted while readiness is false. |

The first uninstall's directory-not-empty failure was from `C:\ProgramData\fail2commit-hardened`: the old path removed `install.json` and then tried to remove its parent while `sandbox.secret` and the service-created empty `jobs` directory still existed. The idempotent retry saw no install marker and did not clean that residue. Follow-up code removes stale snapshot jobs after stopping the service and removes the plain secret/state files before the state directory; the first uninstall now succeeds, and a second invocation remains idempotent. The external administrative FirewallAPI whole-list writer race is unaccepted; mutex/readback is not atomic CAS. A concurrent external `NetworkIsolationSetAppContainerConfig` writer can be overwritten without the readback detecting the lost entry. Normal Internet jobs remain gated.

## FR-029 — Windows VM backend

| SPEC-019 case | Result | Evidence |
|---|---|---|
| TC-029-1 no virtualization fallback | PASS | With `[sandbox] backend = "vm"`, JSON `sandbox status` exited 0 and reported `backend=appcontainer`, `available=true`, `vm_fallback_to_platform=ok`, with firmware virtualization disabled. `run --input <scratch> -- cmd.exe /c echo fallback-ran` exited 0 under the AppContainer fallback and returned the expected output. |
| Windows VM guest dispatch refusal | PASS | `sandbox launch <job.json> --vm-guest` exited 70 with the Windows guest-dispatch-unavailable error. `vm status` is absent as expected because the VM lifecycle subcommand is Linux-only. |
| TC-029-2 Windows VM hostile catalogue | BLOCKED | Host Hyper-V prevents VMware from exposing nested VT-x/virtualization to the guest. The required Windows Sandbox backend cannot be exercised; no result is fabricated. |
| TC-029-3 through TC-029-12 | NOT WINDOWS RUNTIME GATES | Linux KVM / VM lifecycle rows are not applicable to this Windows guest run; Windows job/lifecycle rows remain unavailable with the disabled Windows VM backend. |

## Remaining gates

- FR-013 native successful npm/pip phase-window screenshots, hidden-window toggle, terminal line, and successful JSON silence remain unverified.
- Default Windows sandbox catalogue still fails HB-030 and HB-036/HB-037 as detailed above.
- FR-027 readiness remains unavailable; first uninstall failed before successful retry; Windows hardened runtime effects and the external FirewallAPI writer condition remain open.
- TC-029-2 remains blocked by unavailable nested virtualization.
- Win10 cross-check was not run due VM resource constraints.
- Snapshot `f2c-014-wingates-pre` was restored on both Win11 and Win10.

## Follow-up - HB-030/HB-036/HB-037 and TC-027-9

### 0.1.3 baseline versus `a3932ee`

The exact requested target does not exist at release tag `v0.1.3` (`6e28cff5ebb10f6cb5f4c830c92a8731564fd6b1`): `cargo test -p fail2commit --test sandbox_hostile_windows --locked -j 2 -- hb030` and the corresponding `hb036` invocation both exited 101 with `no test target named sandbox_hostile_windows`. The available 0.1.3 Windows matrix has no HB-030 or HB-036 test. Its ignored equivalent `cargo test -p fail2commit --test sandbox_windows_matrix --locked -j 2 -- external_tcp_is_denied --ignored --nocapture` passed (1 passed, exit 0).

For a direct UDP baseline, a temporary guest-only diagnostic was added to the 0.1.3 matrix helper and then discarded with the VM snapshot. Its no-capability AppContainer returned `UDP_SEND_RESULT=Ok(14)` for both `224.0.0.251:5353` and `255.255.255.255:9` (diagnostic test exit 0). At `a3932ee`, the original Internet-first test failed on multicast, before it reached None mode or either broadcast case. This is an existing Windows AppContainer policy gap, not a regression introduced after 0.1.3.

After reordering/splitting `hb036_hb037_listen_multicast_and_broadcast_are_refused` in `2ce4fda`, guest command `cargo test -p fail2commit --test sandbox_hostile_windows --locked -j 2 -- hb036 --nocapture` exited 101 after recording every case: None multicast `Some("ok")`, None broadcast `Some("ok")`, Internet multicast `Some("ok")`, Internet broadcast `Some("ok")`; the TCP listener was killed in both modes. Guest `pktmon` captured outbound Ethernet frames for `224.0.0.251:5353` and `255.255.255.255:9` on the VM NIC while the None-first matrix was running, confirming this is not just `send_to` reporting local queue acceptance. The active Windows Firewall profile was Public, enabled, with default outbound action Allow. AppContainer token verification still shows zero capabilities in None mode, but that is insufficient to block these UDP egress packets; the default backend has no per-job packet filter, so adding equivalent enforcement requires privileged per-job networking state and is not a small safe default-mode change. TC-023-6 explicitly requires these sends to fail, so the spec deviation remains open for the owner.

At `a3932ee`, `cargo test -p fail2commit --test sandbox_hostile_windows --locked -j 2 -- hb030 --nocapture` exited 101 only because there was no `net_allowed` event; the HTTPS helper returned `ok`. This matches the documented 25 ms TCP-table tick-reporting limit (see above), not a new network reachability regression.

### TC-027-9 retest and code

At source `ddc6731f911cac67dfc1179935d280a881099863`, guest elevated commands produced:

```text
hardened status before install: exit 10 (rejected, not installed)
hardened install:               exit 0
hardened status after install:  exit 14 (isolation_unavailable; readiness false)
hardened uninstall #1:          exit 0
hardened uninstall #2:          exit 0
hardened status after removal:  exit 10 (rejected, not installed)
```

The first uninstall now removes the SYSTEM-owned stale `jobs` snapshot store before deleting the service, removes the sandbox account secret and install marker as regular non-reparse files, then removes the empty state directory. The revised owner-liveness regression test also passed in the guest at this source SHA (`cargo test -p fail2commit-core --locked -j 2 terminated_child_is_not_considered_live_while_parent_holds_its_handle -- --nocapture`: exit 0, 1 passed, 298 filtered out). `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked -j 2 -- -D warnings` passed on the host (build/static checks only). Follow-up runtime work used snapshot `f2c-014-wingates-autologon`, which was restored after all runs; Win10 remained off.
