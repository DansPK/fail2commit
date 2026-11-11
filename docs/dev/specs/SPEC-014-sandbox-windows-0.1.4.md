# SPEC-014 — Windows sandbox for 0.1.4

FR-020 · FR-023 · FR-024 · FR-026 · CR-022 · Owner paths: `crates/fail2commit-core/src/sandbox/windows.rs`, `crates/fail2commit-core/src/sandbox/windows/`, `crates/fail2commit/tests/sandbox_windows_*.rs`, `crates/fail2commit/tests/sandbox_hostile_windows.rs`, `tests/fixtures/hostile/windows/`, `docs/sandbox-windows.md`.

Extends SPEC-007 (the T-007b AppContainer backend). Everything SPEC-007 and `docs/sandbox-windows.md` sections 2–7 enforce is unchanged: fail2commit-owned stage root, handle-based grants with link rejection, a fresh random profile per job, explicit stdio handle list, approval IPC denied, Job Object limits, bounded output, clean environment, checked cleanup. This spec adds the 0.1.4 fields of the frozen contract (`JobSpec::network`, `JobSpec::bait`, `JobLimits::disk_bytes`, `JobOutcome::report`) and records the default-mode ("tier 1") choices agreed with the owner. No administrator right, firewall rule, service, driver, account or system-wide setting is used.

## 1. Network (FR-023)

| `JobSpec::network` | Capabilities given to the fresh profile | What Windows enforces |
|---|---|---|
| `None` | none (as 0.1.3) | no network at all |
| `Internet` | exactly `internetClient` (`S-1-15-3-1`) | outbound to addresses Windows classes as internet; loopback, the host's own subnets and inbound connections refused |

Why `internetClient` only: `internetClientServer` would allow inbound connections and `privateNetworkClientServer` would allow the LAN. AppContainer network isolation (WFP, built into Windows since 8) refuses loopback unless the package SID is loopback-exempt, which the existing control proves it is not. It also refuses every subnet of the host's interfaces (the LAN, the gateway) and every inbound connection. The child token is read back on every run and must hold exactly the expected capability SIDs, so `None` still means zero capabilities.

**Detection layer, no administrator rights.** While the job runs, the backend reads the TCP tables (`GetExtendedTcpTable`, `TCP_TABLE_OWNER_PID_ALL`, IPv4 and IPv6) on each poll tick and keeps rows owned by job processes (PIDs from `JobObjectBasicProcessIdList`).

* A connecting (`SYN_SENT`) or established row to a public address (`netpolicy::is_public`) is a `net_allowed` entry, once per destination.
* A row to a non-public address is a `net_refused` entry, and the job is terminated (`Killed`). This covers the ranges that AppContainer isolation treats as internet in default mode: private ranges that are not a local subnet, CGNAT, metadata `169.254.169.254` when it is not on-link, and IPv6 unique-local.
* A `LISTEN` row (any address) is a `net_refused` "listen" entry, and the job is terminated.

TCP-table and disk checks run at most every 25 ms, however many job messages arrive. Limits of the detection layer, recorded as known limits (section 7): a connection that opens and closes between two ticks (25 ms) is not seen; a connection that Windows refused leaves no row, so refused attempts are not listed (`net_refused` comes only from the kill path above); UDP rows carry no remote address, so UDP is not reported. Bait values sent over the network are not seen (no traffic inspection without hardened mode, FRD open question FR-024).

## 2. Bait credentials (FR-024)

When `job.bait` is true:

1. **Home.** The bait home is the job's `USERPROFILE` when it is set and is a subfolder of `work_dir`. When `USERPROFILE` is not set, the home is `<work_dir>\.f2c-home`, which is created, and `USERPROFILE` is added to the job environment. A `USERPROFILE` outside `work_dir`, or equal to `work_dir` itself (bait would sit beside the job's own project files, such as a project `.env`), refuses the job. So does a bait path that already exists: a file the job brought is never overwritten. `HOME` is added with the same value only when the job does not set it. Windows tools find home through `USERPROFILE` (Node `os.homedir()`, Python `expanduser`). It is not `HOME`, because the npm call site sets `HOME` to its temp folder. The coordinator sets `npm_config_userconfig` and `PIP_CONFIG_FILE` at the call sites so that a nested npm or pip does not read the bait.
2. **Files and values.** `BaitSet::generate()` (frozen) is written into the home before grants, so the files sit inside the job's writable stage and never outside it. `BaitSet::env` is added to the environment; a key the job already sets is a duplicate and refuses the job.
3. **Detection without administrator rights: oplocks.** After the grants and before the root is resumed, the parent opens each bait file overlapped and requests an exclusive read/write/handle oplock (`FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ|WRITE|HANDLE`, Windows 7+). The file handle is bound to the job's completion port with its own key. Any other open of the file for data or delete access breaks the oplock: reading, writing, copying, deleting or memory-mapping it. Windows holds that open until the holder acknowledges the break, and the backend never acknowledges it. It terminates the job, records a `bait` entry naming the file relative to home, and returns `Killed`. The opener therefore never receives the bait bytes. Opens for attributes only (`stat`, `existsSync`) and directory listings do not break oplocks and are not bait touches.
4. **False positives.** A break that arrives before the root is resumed is not the job's (for example an antivirus scan of the new file). The oplock is requested again once; a second early break refuses the job (`IsolationUnavailable`). After resume, a break is the job's. The parent does not open bait files again until the oplock handles are closed after the job.
5. **Fail closed.** An oplock that cannot be granted (for example a file system without oplocks) refuses the job before launch. The probe checks oplock delivery in-process (section 5).

## 3. Disk limit (FR-020, HB-053)

Windows has no per-user disk quota without administrator rights (FRD open question FR-020), so stage writes are measured and the job is killed on overrun, using two signals:

* Job I/O accounting (`JobObjectBasicAndIoAccountingInformation.WriteTransferCount`), read every tick. It also counts pipe writes and rewrites, so it never kills by itself. Each 64 MiB of new writes triggers an immediate size scan.
* A size scan of `work_dir` on a background thread, every 2 s or four times the last scan's duration, whichever is longer (a large `node_modules` tree keeps the scan a small share of the CPU). It sums file sizes, follows no links, and is capped at 1,000,000 entries; reaching the cap counts as over the limit. The baseline is scanned before launch, and the limit applies to growth above that baseline (`JobLimits::disk_bytes`). The scan also catches writes the counter misses, such as memory-mapped files and `SetEndOfFile`.

When growth exceeds `disk_bytes`, the job is terminated, a `limit` "disk" entry is recorded and the status is `Killed`. `disk_bytes = None` disables the scan. Known limit: between two scans a job can go past the limit by whatever it writes before the next scan (2 s or more on a large tree), or 64 MiB of counted writes.

## 4. Process hardening

* **Mitigation policies** on the root process (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`, all available on Windows 10 1607+, so 1809 and 21H2 are covered). Each is read back with `GetProcessMitigationPolicy` on the suspended root; a mismatch refuses the job.
  * extension points disabled (no AppInit DLLs, legacy hooks or IMEs loaded into the root);
  * no image loads from remote (UNC) paths;
  * non-system fonts blocked.

  Not used, because each breaks the toolchain: no low-label image loads (esbuild and native addons run binaries the job itself wrote, which carry the Low label), Win32k lockdown (cmd, MSVC and Python load user32), dynamic-code prohibition (V8 JIT), child-process restriction (every build), strict handle checks (an exception on a stale handle kills legitimate tools). Prefer-System32 is left out because Python loads the `vcruntime140.dll` beside `python.exe`. Windows does not pass creation mitigation policies on to children; children rely on the AppContainer boundary.
* **LPAC.** LPAC removes the `ALL APPLICATION PACKAGES` group. On the development host (Windows 11 26200), `icacls "C:\Program Files"` grants read only to `ALL APPLICATION PACKAGES` and not to `ALL RESTRICTED APPLICATION PACKAGES`, whereas `System32` grants both. Windows 10 is expected to use the same default ACL; this is to be confirmed with the same `icacls` on the Windows 10 VM. No LPAC launch experiment with node or python was run (the host may not run tests, owner rule 2026-11-11); one can be added on the VMs if hardened mode wants LPAC. A node-gyp or Python extension build needs MSVC, which installs under `Program Files (x86)` and is not staged. LPAC is therefore **not** the default: it would break native builds. HB-066 is a default-mode known limit, and hardened mode adds the boundary (section 8). The token check keeps refusing an unexpected LPAC token.
* **Desktop.** All Job Object UI restrictions (clipboard read and write, handles, global atoms, desktop, display settings, system parameters, exit Windows) are already set and read back from the kernel on every run (SPEC-007). The AppContainer runs at Low integrity, so User Interface Privilege Isolation refuses input to and hooks on the user's medium-integrity windows.

## 5. Probe

New mandatory controls, added to `mandatory_controls()`:

| Control | How it is verified |
|---|---|
| `internet-capability-only` | A fresh profile is created with `internetClient`. The capability SID array passed to `CreateProcessW` is checked to equal the requested set, and the child token is read back for it on every `Internet` run. The probe launch itself keeps zero capabilities. |
| `mitigation-policies` | Read back from the probe's suspended root, as on every run. |
| `bait-oplock-detection` | In-process: a file in the probe stage gets the oplock, a second thread opens it for read, and the break must arrive on a completion port within 2 s. The holder then closes and the reader completes. No process is launched. |
| `disk-accounting` | `JobObjectBasicAndIoAccountingInformation` and `JobObjectBasicProcessIdList` can be read for the probe job. |
| `stale-profile-cleanup` | Leftover profiles of dead fail2commit processes are deleted (section 6) before the launch. |

The probe stays one sandboxed launch with no unsandboxed process.

## 6. Cleanup after a crash (HB-070, HB-071)

`KILL_ON_JOB_CLOSE` already ends the job when fail2commit dies. A profile created by a process that crashed stays in `HKCU\Software\Classes\Local Settings\...\AppContainer\Mappings`. Each profile now gets a record `<stage root>\profiles\<name>.json` naming the owner's PID and process creation time, written before the profile is created and removed after it is deleted. Every `probe()` and `run()` deletes the profile of each record whose owner is gone (no process with that PID and creation time) and removes the record. A live owner's profile is never touched. ACEs left inside a crashed stage name a deleted package SID and are confined to the stage (SPEC-007); the stage itself is the caller's to delete, as before.

## 7. Activity report (FR-026)

`JobOutcome::report` is filled by the backend; entries are untrusted and bounded (`ActivityReport::push`, 200 entries), each detail cut to 512 characters, and redaction is left to the display layer (frozen contract).

| Kind | Windows default mode source |
|---|---|
| `process` | `JOB_OBJECT_MSG_NEW_PROCESS` on the job port, then `QueryFullProcessImageNameW`; an image that exits before it can be read is listed as `pid <n>` |
| `net_allowed` / `net_refused` | TCP table rows (section 1) |
| `bait` | oplock break (section 2) |
| `limit` | process limit, memory limit, timeout, disk, output truncated |
| `file_denied` | **not observable** without administrator rights (object-access auditing needs a SACL and the audit privilege); listed in `docs/sandbox-windows.md` |
| `blocked` | **not observable** (mitigation and Job Object refusals return an error to the caller only) |

## 8. Hardened mode (FR-027) — what it must add on Windows (later task)

* Jobs run as a dedicated local account with no access to the user's profile, through a minimal service that accepts only the installing user's processes and only starts the launcher; the AppContainer runs inside that account.
* WFP filters for that account's AppContainer at the ALE connect, listen and receive layers, refusing everything `netpolicy::is_public` refuses (non-local private ranges, CGNAT, metadata, IPv6 ULA and link-local), with filters scoped to the service's dynamic session so they disappear when it stops. This closes the section 1 known limit and gives `net_refused` events for refused attempts (WFP net events).
* DNS and HTTP egress through a service-owned resolver/proxy so bait values in host names and plain HTTP (HB-022, HB-023) are seen.
* LPAC with the toolchain (including MSVC) staged or granted to the account, closing HB-066.
* Object-access auditing on the account's file accesses for `file_denied` entries.

## 9. Error cases

| Case | Result |
|---|---|
| `network = Internet` and the token does not hold exactly `internetClient` | `IsolationUnavailable`, nothing runs |
| mitigation read-back mismatch | `IsolationUnavailable`, root killed before resume |
| bait home outside `work_dir`, bait key duplicated in env, oplock refused, second early break | `IsolationUnavailable` before resume |
| bait touched during the job | `Killed`, `bait` entry, no export (`run_job` exports only after `Exited(0)`) |
| connection to a non-public address or a listen row | `Killed`, `net_refused` entry |
| disk growth over `disk_bytes` or scan cap reached | `Killed`, `limit` "disk" |
| stale profile cannot be deleted | `IsolationUnavailable` (`stale-profile-cleanup` false) |

## 10. Test cases

All in `crates/fail2commit/tests/sandbox_hostile_windows.rs` unless named otherwise. The helper `tests/fixtures/hostile/windows/probe.rs` is compiled with `rustc` into the stage, as `sandbox_windows_matrix` already does. It only performs ordinary operations (open a file, connect a socket, write bytes, spawn a child) and reports what the OS answered. It carries out no attack technique (no injection, hooking, screen capture or input synthesis; coordinator decision). Rows whose hostile attempt would need such code are verified from the control's kernel read-back and are reported as "control verified".

| TC | Given / When / Then | Test function |
|---|---|---|
| TC-020-1 | Given planted fake secrets in a temporary fake home and a fake checkout outside the stage (HB-001–005), When the job opens each, Then every open is access denied and the files are unchanged | `hb001_005_secrets_and_checkout_outside_the_stage_are_denied` |
| TC-020-2 | Given the job, When it writes to the fake home, fake checkout, host temp and the Startup folder (HB-006, HB-041), Then each write is denied and nothing is created | `hb006_hb041_writes_outside_the_stage_are_denied` |
| TC-020-3 | Given a junction and a hard link the job creates in its stage that point outside (HB-007), When it reads through them, Then access is denied | `hb007_links_created_in_the_stage_do_not_escape` |
| TC-020-4 | Given read-only inputs (HB-008, HB-065), When the job replaces a reviewed file or plants a file beside the staged program, Then the write is denied | `hb008_hb065_read_only_inputs_cannot_be_replaced` |
| TC-020-5 | Given `GITHUB_TOKEN`, `AWS_*` and `NPM_TOKEN` set on the parent (HB-009), Then the job sees none of the parent's values | `hb009_parent_environment_secrets_are_not_inherited` |
| TC-020-6 | Given a planted HKCU test value (HB-010, HB-041), When the job reads it and writes a sibling key, Then both are denied; the test key is deleted afterwards | `hb010_hb041_registry_is_denied` |
| TC-020-7 | Given a detached child and a breakaway request (HB-040, HB-042), Then breakaway fails, the detached child is gone when `run` returns, and both processes are listed | `hb040_hb042_detached_children_end_with_the_job` |
| TC-020-8 | Given a process of the user outside the job (HB-043, HB-044), When the job opens it for terminate or for memory write access, Then both opens are denied (access check only) | `hb043_hb044_processes_outside_the_job_cannot_be_opened` |
| TC-020-9 | Given the job, Then the Job Object UI restrictions, breakaway disallowed, the AppContainer token and the mitigation policies read back as required (HB-042, HB-045, HB-063, HB-064, HB-065: control verified) | `controls_read_back_for_desktop_com_and_dll_rows` (and `sandbox_windows_matrix::probe_verifies_every_control_in_one_launch_and_then_reuses_it_briefly`) |
| TC-020-10 | Given a disk limit of 8 MiB (HB-053), When the job writes 64 MiB, Then it is `Killed` with a `limit` "disk" entry | `hb053_disk_limit_kills_the_job` |
| TC-020-11 | Given process, memory, time and output limits (HB-050–052, HB-054), Then each is enforced and listed as a `limit` entry | `hb050_052_054_limits_are_reported` |
| TC-020-12 | Given a fail2commit process killed mid-job (HB-070), Then the job's processes are gone, and the next probe deletes the dead owner's profile and leaves no record | `hb070_a_killed_owner_leaves_nothing_behind` |
| TC-023-1 | Given `Internet` (HB-030), When the job fetches `https://registry.npmjs.org/` over TCP 443, Then it connects and a `net_allowed` entry names the address | `hb030_internet_mode_reaches_the_public_registry` |
| TC-023-2 | Given `None` (HB-031), Then the same connection fails | `hb031_none_mode_refuses_the_internet` |
| TC-023-3 | Given a host listener on 127.0.0.1 and ::1 and the name `localhost` (HB-032, HB-035, HB-038 relay), Then each connection fails in both modes | `hb032_hb035_loopback_and_local_names_are_refused` |
| TC-023-4 | Given the host's own LAN address and gateway (HB-033), Then each connection fails | `hb033_lan_and_gateway_are_refused` |
| TC-023-5 | Given a non-local private, CGNAT or metadata address (HB-033, HB-034), When the job connects, Then the job is `Killed` with a `net_refused` entry, or the connection fails | `hb033_hb034_non_local_private_ranges_are_stopped` |
| TC-023-6 | Given a TCP listen and a UDP multicast and broadcast send (HB-036, HB-037), Then the listen kills the job with a `net_refused` "listen" entry and the sends fail | `hb036_hb037_listen_multicast_and_broadcast_are_refused` |
| TC-024-1 | Given `bait = true` (HB-020), When the job reads `%USERPROFILE%\.npmrc`, Then the job is `Killed` before the read returns data, and the report has a `bait` entry for `.npmrc` | `hb020_reading_the_bait_npmrc_stops_the_job` |
| TC-024-2 | Given `bait = true` (HB-021), When the job reads each other bait file, Then each run is `Killed` with a `bait` entry naming the file | `hb021_every_bait_file_trips` |
| TC-024-3 | Given `bait = true` and a clean workload that stats home, lists it and builds a native file (HB-024), Then it exits 0 with no `bait` entry; the bait env values are present in the child | `hb024_clean_work_touches_no_bait` |
| TC-024-4 | Given a bait home outside the work dir, equal to the work dir, already holding a bait path, or a duplicated bait key, Then the job is refused before launch and nothing is written outside the stage or over the job's files | `windows::tests::bait_setup_fails_closed` (unit) |
| TC-026-1 | Given the catalogue rows above, Then each report lists the kinds the Windows default mode can observe (`process`, `net_allowed`, `net_refused`, `bait`, `limit`), bounded to 200 entries | asserted inside the tests above; bound: `windows::tests::report_details_are_bounded` (unit) |

HB-022 and HB-023 (bait values on the network) are hardened-mode rows on Windows and are not run here. HB-039 and HB-060–062 are Linux only. HB-071 (power cycle) needs the coordinator's VM; its cleanup path is the same as TC-020-12.
