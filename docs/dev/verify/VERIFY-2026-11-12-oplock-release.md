# Verification: bait-oplock release on the Windows host (FR-024, SPEC-014)

Tested commit: `6c864bd` before the fix, working tree after it (not yet committed at the time of this record).
Host: Windows 11 Pro 26200, `C:` is NTFS, user `nutyo`, repository at
`C:\Users\nutyo\orca\workspaces\fail2commit\f2-commit-coordinator`.
Branch: `DansPK/f2c-0.1.4` (local only; nothing pushed).

This record documents a product defect found while re-running the 0.1.4 test suite on the
Windows host. The three Windows sandbox failures reported at hand-over were **not**
environment-gated: the probe failed on a code path that could never succeed on any host.

## 1. What failed before the fix

```
cargo test -p fail2commit --test sandbox_hostile_windows controls_read_back_for_desktop_com_and_dll_rows -- --nocapture
```

exit code 1:

```
thread 'controls_read_back_for_desktop_com_and_dll_rows' panicked at
crates\fail2commit\tests\sandbox_hostile_windows.rs:595:5:
bait oplock self test failed (break delivered: true, reader finished: true, idle oplock released: false)
test result: FAILED. 0 passed; 1 failed; 21 filtered out
```

`reader finished: true` and `break delivered: true` show that granting an oplock, delivering a
break and releasing the blocked reader all worked. Only the *unbroken* request, closed by its
holder, reported that it never completed, and the probe therefore reported the whole
AppContainer backend as unavailable (`Error::IsolationUnavailable`).

## 2. Isolating the cause

The release path polled `OVERLAPPED::Internal` for `STATUS_PENDING` after closing the holder.
A standalone reproduction (`PowerShell` + `Add-Type` + P/Invoke of `CreateFileW`,
`CreateIoCompletionPort`, `DeviceIoControl(FSCTL_REQUEST_OPLOCK)`) was run in three
directories (`%TEMP%`, `%LOCALAPPDATA%\fail2commit\cache`, the repository root), each with
and without a completion port:

| Directory | Handle bound to an IOCP | Result after `CloseHandle` |
|---|---|---|
| `%TEMP%\f2c-oplock-probe` | yes | `OVERLAPPED` still `STATUS_PENDING` after 5002 ms; the completion packet *was* queued (`GetQueuedCompletionStatus` returned the request's `OVERLAPPED`; `Internal` then read `0x216`) |
| `%TEMP%\f2c-oplock-probe` | no | completed at once (`Internal` = `0x216`) after 0 ms |
| `%LOCALAPPDATA%\fail2commit\cache` | yes | still `STATUS_PENDING` after 5014 ms; packet queued, `Internal` `0x216` after dequeue |
| `%LOCALAPPDATA%\fail2commit\cache` | no | completed at once after 0 ms |
| repository root | yes | still `STATUS_PENDING` after 5000 ms; packet queued, `Internal` `0x216` after dequeue |
| repository root | no | completed at once after 0 ms |

Result: identical on every directory, so the file system and the ACL layout were not the
cause. For a handle bound to a completion port the I/O manager queues the completion packet
and leaves `OVERLAPPED::Internal` at `STATUS_PENDING` until the packet is dequeued; polling
`Internal` alone can never see the release. The earlier Win11 problem (bait jobs hanging in
`CancelIoEx` + `GetOverlappedResult`) is the same class of mistake: those APIs are not valid
for completion-port handles.

## 3. Fix

`crates/fail2commit-core/src/sandbox/windows/watch.rs`:

* `Oplock` records `completed` when its break packet is dequeued (`mark_completed`).
* `Oplock::release(&Job)` closes the holder and then waits, at most 5 s, for the request's
  packet on the job port (`key == BAIT_KEY`, `value == overlapped_addr()`). An already
  completed request returns at once. A request that does not complete has its buffers leaked,
  never freed.
* `Drop` only closes a confirmed request; a request that may still be pending keeps its
  buffers.

`crates/fail2commit-core/src/sandbox/windows.rs`:

* `Monitor::on_event` and `Monitor::settle_before_resume` mark the oplock completed when they
  dequeue its break.
* `Monitor::release_bait` and `Monitor::finish` take the job and release each oplock through
  the port; `wait_for_tree` passes it.
* `Monitor::new` releases the oplocks it already holds when a later request fails.
* New regression test `the_oplock_self_test_releases_a_broken_and_an_idle_oplock`.

Documentation: `docs/dev/specs/SPEC-014-sandbox-windows-0.1.4.md` section 2.4 and section 5
now state that completion is read from the port packet, and `docs/dev/LESSONS_LEARNED.md`
records the pattern.

## 4. Evidence after the fix

| Command | Result |
|---|---|
| `cargo test -p fail2commit-core the_oplock_self_test_releases_a_broken_and_an_idle_oplock -- --nocapture` | ok, 1 passed, 0.04 s |
| `cargo test -p fail2commit-core host_probe_verifies_every_mandatory_control -- --nocapture` | ok, 1 passed, 4.11 s (`probe().available == true`) |
| `cargo test -p fail2commit --test sandbox_hostile_windows controls_read_back_for_desktop_com_and_dll_rows -- --nocapture` | ok, 1 passed, 4.11 s |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0, no warnings |
| `cargo test --workspace --locked` | see section 5 |

The unit test finished in 0.04 s where the broken code needed more than 5 s to fail, which is
the direct measurement of the fix: the release is now observed instead of timed out.

## 5. Test expectations corrected for the merged 0.1.4 behaviour

With the probe fixed, three end-to-end npm tests that had been skipping past a dead sandbox
actually ran, and two of their expectations were written for the 0.1.3 backend:

* `native_build_runs_in_the_real_sandbox_and_its_artifact_is_installed` and
  `install_script_child_processes_with_pipes_finish_in_the_sandbox` failed on
  `stage_leftovers()` returning `["profile-records"]`. That directory is the backend's own
  state at the stage root (`PROFILE_RECORDS`, SPEC-014 section 6), not a left-over job stage.
  `e2e_support/npm_world.rs::stage_leftovers` now ignores `profile-records` and
  `pending-revoke.json` (the S7B-006 revoke record) and still fails on anything else.
* `hostile_script_cannot_reach_network_home_or_checkout` failed with
  `lifecycle script was stopped by a sandbox resource limit`. The run's activity report showed
  why: `NetRefused 127.0.0.1:55988`. SPEC-014 section 1 stops a job at its first connection to
  a non-public destination, so on Windows the hostile script is killed at
  `net.connect(127.0.0.1)` and never writes `build/report.json`; bubblewrap leaves the network
  unshared, so on Linux the script finishes and reports the refusal itself. The test now
  asserts, on Windows, that the install is stopped, that the script produced no report, that
  the home canary and the checkout are unchanged, that nothing was written outside the stage
  and that the loopback listener saw no connection. The Linux assertions are unchanged.

Recorded follow-up: `npm/apply.rs` reports a job stopped by the network policy as "stopped by
a sandbox resource limit". That wording is misleading (P-205 plain-language goal); the
activity report already names `net_refused`.

## 6. Full suite

`cargo test --workspace --locked` stops at the first failing test binary, so the runs below are
listed in the order the gate executes them. Every entry is a separate command.

| Command | Result |
|---|---|
| `cargo test -p fail2commit-core --locked` (lib unit tests) | 208 passed, 0 failed, 1 ignored |
| `cargo test -p fail2commit --locked` up to `e2e_setup` (`f2c_sandbox_relay`, `fail2commit` unit tests, `approval_cli`, `approval_stdio`, `approval_tty`, `checks_preinstall`, `e2e_npm_approval`, `e2e_npm_sandbox`, `e2e_push`) | 46 passed, 0 failed |
| `cargo test -p fail2commit --test e2e_setup` | 1 passed, 0 failed (1008 s) |

## 7. Runtime on this host

`target\debug\fail2commit.exe` is 491 MB (514,696,958 bytes) in a debug build, and the npm and
pip shim integrations hash it in full to prove ownership. A second `fail2commit setup` on an
already-installed shim hashes it about sixteen times (npm `ours()`: two hashes of the shim plus
one of the exe, a second npm pass, pip `is_ours`/`marked`/`place`/`write_marker` per shim, and
one `sha(&ctx.exe)` per recorded change), which is what makes `e2e_setup` take 17 minutes here
rather than seconds and holds ~540 MB resident. It is slow, not stuck: the trace in this record
followed it through every integration. A release binary is an order of magnitude smaller.

Follow-up (not done here, because both files are owned by other workstreams and the checks are
security-relevant): hash `ctx.exe` once per install and each shim once, and stream the hash
instead of `std::fs::read` of the whole executable. That would cut the work by roughly a factor
of four and the resident set to a buffer.

## 8. Windows sandbox gate after the fix

With the probe available again the sandbox suites actually run. Three test expectations assumed
the 0.1.3 backend, where a refused connection left the job alive; SPEC-014 section 1 stops the
job at its first non-public destination, so the helper never answers. Those three were aligned
with the spec (they now accept the stop and still assert that nothing was reached):

* `sandbox_hostile_windows::hb021_every_bait_file_trips` reused one stage for six runs; the
  second run was refused because the bait home already held `.npmrc` (SPEC-014 2.1). Each run
  now gets its own stage.
* `sandbox_hostile_windows::hb032_hb035_loopback_and_local_names_are_refused` and
  `hb033_lan_and_gateway_are_refused` demanded a `denied` answer from the helper; both now use
  the same "stopped at the attempt, or denied by the helper" check as
  `hb033_hb034_non_local_private_ranges_are_stopped`.
* `sandbox_windows_matrix::parent_and_grandchild_cannot_reach_network_secret_checkout_or_git`
  expected `Exited(0)`: the loopback attempt now ends the job before the helper writes its
  report, so an empty report with a `Killed` status is accepted and the host-side checks
  (checkout not writable, launch marker absent, secret unchanged) still apply.

Current results on the Windows 11 26200 host:

| Binary | Result |
|---|---|
| `sandbox_hostile_windows` | 18 passed, **3 failed**, 1 ignored |
| `sandbox_windows_matrix` | 6 passed, 0 failed, 1 ignored |
| `sandbox_setting_cli`, `sandbox_setting_policy` | 5 passed each, 0 failed |
| `sandbox_hostile_linux`, `sandbox_linux_build`, `sandbox_linux_hostile`, `sandbox_linux_policy` | 0 tests on Windows |

The three remaining failures are open questions for the owner; none is a crash or a leak:

1. `hb030_internet_mode_reaches_the_public_registry` - the host reaches
   `registry.npmjs.org:443` (`Test-NetConnection` returns true) but the run recorded no
   `net_allowed` entry. The job's connection is likely opened and closed between two 25 ms
   ticks, which SPEC-014 section 1 records as a known limit. Either the test accepts a missed
   observation or the tick interval changes.
2. `hb036_hb037_listen_multicast_and_broadcast_are_refused` - "udp 224.0.0.251:5353 sent in
   Internet". SPEC-014 section 1 states that UDP rows carry no remote address, so a UDP send
   cannot be reported; the test expects it to be refused. This needs either an accepted known
   limit in the test or a WFP/firewall rule (out of scope for 0.1.4).
3. `hb070_a_killed_owner_leaves_nothing_behind` - after the owning process is killed, the next
   run did not remove the orphaned AppContainer profile ("stale profile kept"). The sweep in
   `clear_stale_profiles` needs investigation: it may refuse when the profile is still in use
   or when the record cannot be replayed.

## 9. Not re-run in this session

The following binaries were not executed after the change (the session exhausted its time on
the sandbox suites above): `git_push`, `git_setup`, `ipc_pipe`, `ipc_startup`, `malware_list`,
`npm_cli`, `npm_flow`, `npm_scripts`, `npm_signatures`, `pip_cli`, `pip_install`,
`pip_recover`, `pip_reject`, the `rereview*` and `review_*` suites, `resource_bounds`,
`resource_process`, `rules_yara`, `run_cli`, `scan_*`, `server_protected`, `threat_update` and
`fail2commit-tray`. Their last recorded state is the 0.1.3 gate; run `cargo test --workspace
--locked` on the finalized tree before release.

## 10. Outstanding

* Run `cargo test --workspace` on the Windows 10 VM and the Linux/Debian/Arch VMs; this record
  covers the Windows 11 26200 host only.
* Re-run the bait hostile cases (`hb009`, `hb020`) on the Win11 VM, since the same release
  path is what made them overrun their deadline there.
* Nothing was pushed; `origin/DansPK/f2c-0.1.4` is 14 commits behind the local branch.