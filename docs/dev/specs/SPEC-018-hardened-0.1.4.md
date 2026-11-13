# SPEC-018 — Hardened sandbox mode for 0.1.4 (FR-027)

Status: ready for implementation (architect pass, 2026-11-13). Task T-013.
Follows SPEC-007 (backend contract), SPEC-013 (Linux sandbox), SPEC-014 (Windows
sandbox, §8 sketched this mode), CR-022 (network policy). Requirements: FR-027
(Must); closes catalogue rows HB-022/HB-023 on Windows and HB-066, and the
hardened half of HB-070.

Frozen APIs stay frozen: `isolation::{JobSpec, JobOutcome, SandboxBackend}`,
`sandbox::{run_job, platform_backend}`, `bait`, `netpolicy`, `report`. Hardened
mode is a new backend behind the same contract; `run_job` still probes, runs and
exports, and backends still never export.

## 1. Selection and fail-closed rules

`settings.sandbox.backend` (`BackendChoice`, already defined, currently unread):

| Value | Behaviour |
|---|---|
| `auto` (default) | hardened backend when hardened mode is installed, else the platform default |
| `vm` | FR-029, SPEC-019: VM backend; without the feature or hardware virtualization it falls back to the platform default (FR-029), other failures are `IsolationUnavailable` |

- New `sandbox::select_backend(&Settings) -> Box<dyn SandboxBackend>`;
  `platform_backend()` keeps its signature and returns the default backend.
  Call sites switch to `select_backend`: `cmd/npm.rs`, `cmd/run.rs`,
  `cmd/sandbox.rs`, `cmd/setup.rs`, `pip/mod.rs`.
- `auto` + installed + unhealthy (service stopped, account missing, probe
  control failed) = `IsolationUnavailable`. **Never a silent fallback** to the
  default backend (FRD: jobs fail closed when the service is gone).
- `sandbox status` and `setup status` report hardened state: installed, service
  running, probe result. `hardened status` exits 0 only when installed and the
  probe passes.
- Installing hardened mode needs administrator (Windows) / root (Linux); running
  jobs through it does not.

## 2. Common shape

```text
user CLI (Hardened backend)                 service (SYSTEM / root)          launcher (account f2c-sandbox)
  stage job dir in user cache                 minimal: authenticate peer,      same fail2commit binary,
  grant account access to inputs              start launcher only              hidden `sandbox launch <jobfile>`
  LAUNCH {job_dir} over local IPC  -------->  validate job_dir owner  ------->  run the platform backend
  hold pipe open for the job                  hold watchdog pipe open          (AppContainer / bwrap) unchanged
  read outcome.json after EOF   <-----------  close pipe when launcher exits   write outcome.json, exit
  revoke grants, delete job dir
```

- The service never parses `job.json` and never starts anything but the
  launcher (FRD "minimal service"). Two requests: `LAUNCH {job_dir}` and
  `STATUS` (probe facts).
- The launcher is the installed `fail2commit` binary with a hidden
  `sandbox launch` subcommand. It runs the existing platform backend code; bait,
  limits, monitoring and the activity report work exactly as in default mode.
- Job dir: a per-job subdirectory of the user's own stage root (as today), so
  staging, content verification and export are unchanged. `job.json` = serde
  `JobSpec`; `outcome.json` = serde `JobOutcome` with base64 stdout/stderr.
- Liveness chain: user↔service pipe and service↔launcher watchdog pipe are held
  open for the whole job. Either breaks → the launcher kills its job tree and
  exits (§3.4, §4.3). A dead service therefore always ends the job.
- Install state is machine-level and root/SYSTEM-owned; it records the
  installing user (SID / uid) and version. Only that user may launch.
- CLI: `fail2commit hardened install | uninstall | status`, administrator/root
  only, following the `machine-shims` pattern (`cmd/machine.rs`,
  `core::machine`). Uninstall is idempotent and removes everything install
  created (§3.8, §4.6).

## 3. Windows

### 3.1 Install (administrator)

1. Create local account `f2c-sandbox`: `NetUserAdd`, random 64-character
   password, no group memberships, password never expires, no interactive
   logon right. The password is never stored; the service logs on with it via
   `CreateProcessWithLogonW` (kept in service-only memory, read from a
   SYSTEM-only secret file created at install).
2. Copy the running exe to `%ProgramFiles%\fail2commit-hardened\fail2commit.exe`
   (the service must not depend on a per-user install).
3. Create service `fail2commit-hardened`: LocalSystem, auto-start, binary
   `"…\fail2commit.exe" sandbox serve` (hidden subcommand).
4. Write `%ProgramData%\fail2commit-hardened\install.json`: installer SID,
   version, account name. ACL: SYSTEM + Administrators only.

Without elevation: `rejected`, nothing created.

### 3.2 Service: peer authentication

- Pipe `\\.\pipe\fail2commit-hardened-<installer-SID>` created with
  `ipc::winsec::PipeSecurity::new(installer_sid)` — the approval pipe's DACL:
  deny both app-package SIDs, allow only the installer. This already refuses
  every AppContainer (acceptance 4) and every other user.
- Defence in depth: `GetNamedPipeClientProcessId` → `winsec::process_facts`:
  peer user SID must equal the installer SID and `app_container` must be false;
  otherwise close.
- `LAUNCH {job_dir}`: canonicalize; must be an existing directory owned by the
  installer SID (`GetSecurityInfo`). The service does not read `job.json`.
- The service holds one job at a time per installer (the user-side
  `sandbox-job` lock already serializes; the service refuses a second
  concurrent LAUNCH with `busy`).

### 3.3 Launch

`CreateProcessWithLogonW(f2c-sandbox, LOGON_WITH_PROFILE)` runs
`fail2commit.exe sandbox launch <jobfile> --watchdog <handle>` with an inherited
pipe handle (write end stays with the service). `LOGON_WITH_PROFILE` loads the
account profile — the probe must verify AppContainer profile creation succeeds
under this logon type before any real job (LESSONS_LEARNED: batch logon broke
`CreateAppContainerProfile` in VM guest ops; fail closed with a named control,
not a hang).

### 3.4 Launcher

1. Parse `job.json`; run `windows::AppContainer` with the hardened launch
   variant: **LPAC on**, **no `internetClient` capability** (all egress goes
   through the proxy, §3.6), everything else (mitigations, job object, bait,
   monitor, disk limit, read-backs) unchanged.
2. After profile creation, send the profile SID over the watchdog pipe; wait
   for the service's `FILTERS_READY` (WFP filters + loopback exemption applied,
   §3.5) **before resuming the root process**. Timeout or refusal → abort the
   suspended job, `IsolationUnavailable`.
3. Watchdog thread: blocking read on the pipe; EOF or error →
   `TerminateJobObject` → exit. This is the fail-closed path when the service
   dies (acceptance 2).
4. Merge `net_refused` events forwarded by the service (§3.5) into the
   activity report; write `outcome.json`; exit. The service sees the exit and
   closes the user pipe.

### 3.5 WFP and loopback (service, per job)

- The service opens one **dynamic** WFP session (`FWPM_SESSION_FLAG_DYNAMIC`)
  at startup. Filters added in it disappear when the service stops or crashes
  — no persistent firewall state, host network never affected (acceptance 2).
- On receiving the profile SID, add per-job filters conditioned on
  `FWPM_CONDITION_ALE_PACKAGE_ID` = profile SID:
  - `ALE_AUTH_CONNECT_V4/V6`: block everything, except a higher-weight permit
    for remote loopback (127.0.0.1, ::1) at the proxy port only;
  - `ALE_RESOURCE_ASSIGNMENT_V4/V6` (listen): block all;
  - `ALE_AUTH_RECV_ACCEPT_V4/V6` (inbound): block all.
- Add the profile's loopback exemption (`NetIsolationLoopbackExemptAdd`) so the
  job can reach the proxy; remove it at job end; sweep stale exemptions at
  service start (a crashed job's exemption is harmless — its profile is gone —
  but must not accumulate).
- Subscribe to classify-drop net events in the session; forward drops for the
  job's package SID to the launcher as `net_refused` entries. This gives
  reliable refusal observation in hardened mode (the default mode's 25 ms tick
  gaps, hb030/hb036, do not apply here).
- Filter read-back is a probe control; the self-test must exercise **both**
  paths (a refused non-public connect and the permitted proxy connect) before
  the backend reports available (oplock lesson: probe the path that can hide a
  bug).

### 3.6 Egress proxy (HB-022, HB-023)

- The launcher starts the shared egress proxy (§5) **as the sandbox account,
  outside the AppContainer**, listening on 127.0.0.1 port 0; the port goes to
  the service (for the WFP permit) and into the job's proxy environment
  variables (same set as SPEC-013 §4.2).
- The proxy enforces `netpolicy::is_public` and trips `Bait` on bait values in
  CONNECT host names and plain HTTP requests — the Linux policy, unchanged.
- The job itself has no direct egress (WFP blocks it, no `internetClient`);
  DNS is resolved by the proxy. Direct DNS or connects from the job are
  refused and reported, exactly as a Linux job's direct connects fail.
- HB-030 in hardened mode: the fetch succeeds through the proxy CONNECT; the
  `net_allowed` entry comes from the proxy's observation.

### 3.7 Grants and cleanup

- Before LAUNCH, the user side grants the **account SID** (not a profile SID)
  `FILE_GENERIC_READ|EXECUTE` on each `read_only` tree and `FILE_MODIFY` on
  `work_dir` — the `StagingGrants` pattern with a different trustee. No
  ancestor grants: traverse checking is bypassed by `SeChangeNotifyPrivilege`,
  and the account can read nothing it has no ACE for.
- After the outcome is read: revoke the ACEs and delete the job dir. A crashed
  run's leftovers are swept by the next run's stage cleanup (the
  `clear_stale_profiles` analogue, extended to hardened job dirs).
- The account's own stage root (profiles, records) lives in its profile; the
  backend code resolves it through `TrustedPaths` as today, now per-account.

### 3.8 Uninstall

Stop and delete the service (dynamic WFP filters die with it), sweep loopback
exemptions, delete the account and its profile directory, delete
`%ProgramFiles%\fail2commit-hardened` and `%ProgramData%\fail2commit-hardened`.
Idempotent; third-party firewall rules are never touched.

## 4. Linux

### 4.1 Install (root)

1. System user `f2c-sandbox`: `useradd --system --no-create-home --shell
   /usr/sbin/nologin`.
2. Units: `fail2commit-hardened.socket` (`ListenStream=/run/fail2commit-hardened/sock`,
   mode 0600, installer uid via `SocketUser`) + `fail2commit-hardened.service` (socket-activated, root,
   `ExecStart=<exe> sandbox serve`). The exe path is the packaged binary
   (packaging records it; a per-user cargo install is not a supported hardened
   host).
3. State `/etc/fail2commit-hardened.json`: installer uid, version, exe path.
   Stage root `/var/lib/fail2commit-hardened/` (account-writable) is created but
   job stages stay in the user's cache (§2); the directory holds only service
   state.

The runtime directory is root-owned mode 0755 and never writable by the
installer or sandbox account. Unit files, executable and installation state
remain root-owned and not user-writable. The installer uid must be neither
root nor the sandbox account. Socket ownership permits the intended client
to connect; it does not replace service peer authentication (CR-023).

### 4.2 Service: peer authentication

`SO_PEERCRED` on the accepted socket: uid must equal the installer uid recorded
at install; otherwise close (acceptance 4). `LAUNCH {job_dir}`: `stat` uid must
equal the peer uid; must be a directory. One job at a time per installer.

### 4.3 Launch and launcher

- Spawn: `systemd-run --scope -p TasksMax=N -p MemoryMax=M -- setpriv
  --reuid=f2c-sandbox --regid=f2c-sandbox --init-groups <exe> sandbox launch
  <jobfile> --watchdog <fd>`. A **system** scope needs no logind session
  (LESSONS: the `--user` scope fails for guest-ops/nologin users). Without
  `systemd-run`, spawn via `setpriv` directly and rely on the wrapper rlimits;
  the probe records which path is active.
- The launcher runs `Bubblewrap` with its own `systemd-run --user` wrapper
  disabled (it is already scoped). Proxy, relay, seccomp, bait, control
  directory: SPEC-013 unchanged. Watchdog: fd EOF → kill the bwrap tree
  (`--die-with-parent` already covers launcher death) → exit.
- Network: **no host firewall changes** (FR-020 host-safety; SPEC-013 §4.1).
  The egress proxy is the boundary, exactly as in default mode.

### 4.4 Grants

POSIX ACLs via the trusted system binaries `setfacl`/`getfacl` (`toolpath`):
`u:f2c-sandbox:r-x` on `read_only` trees, `u:f2c-sandbox:rwX` on `work_dir`,
`u:f2c-sandbox:--x` on each ancestor directory (Linux has no traverse bypass).
Removed with `setfacl -x` after the job; ancestors restored exactly. Missing
`setfacl` → `IsolationUnavailable`. Crash leftovers swept by the next run.

### 4.5 Uninstall

Stop and disable socket + service, remove unit files, `daemon-reload`,
`userdel f2c-sandbox`, remove `/etc/fail2commit-hardened.json`,
`/var/lib/fail2commit-hardened`, `/run/fail2commit-hardened`. Idempotent.

## 5. Shared egress policy (one implementation, two transports)

Extract the policy core of `sandbox/linux/proxy.rs` (destination decision via
`netpolicy::is_public`, bait inspection of CONNECT host names and plain HTTP,
`Watch`/trip semantics) into `sandbox/egress.rs`, platform-neutral. Linux keeps
its Unix-socket transport; the Windows hardened proxy uses a TCP loopback
listener. No policy fork: both transports call the same decision and bait code.
`linux/proxy.rs` behaviour and tests must pass unchanged after the extraction.

## 6. Data and contract changes

- `JobSpec`, `JobLimits`, `JobOutcome`, `JobStatus` gain
  `Serialize`/`Deserialize` (`ActivityReport`, `NetworkMode` already have them).
  A non-UTF-8 `OsString` fails serialization → `IsolationUnavailable` before
  launch (paths and env in the guarded flows are UTF-8 in practice).
- `ProbeReport.backend`: `hardened-appcontainer` / `hardened-bubblewrap`.
- No new settings; `BackendChoice` is finally read. No changes to the frozen
  coordinator contracts beyond the serde derives.

## 7. Probe controls (all mandatory; any failure = unavailable, nothing runs)

| Windows | Linux |
|---|---|
| service running, pipe peer auth passes | socket present, peer auth passes |
| account exists, logon creates a profile and an AppContainer profile (§3.3) | system user exists; `setfacl` present |
| WFP session + per-job filter read-back | bwrap probe as the account (scope or rlimit path recorded) |
| self-test: non-public connect refused, proxy loopback connect permitted, direct public connect refused | proxy self-test: refused destination and permitted public fetch (SPEC-013 controls) |
| LPAC token read-back; exemption present for the test profile | relay found (SPEC-013 §4.2) |

The probe caches per user like the default probe; the self-test uses a
throwaway profile and job dir and cleans both.

## 8. Edge cases

| Case | Result |
|---|---|
| service stopped/crashed mid-job | watchdog EOF kills the job tree; dynamic WFP filters gone; host network unaffected; user side returns `IsolationUnavailable` |
| user CLI killed mid-job | service sees pipe EOF, kills the launcher; grants and job dir swept by the next run |
| launcher crashes | service closes the user pipe; missing/invalid `outcome.json` → `IsolationUnavailable`, no export |
| `outcome.json` malformed or over the output cap | rejected, no export |
| request from another user | refused (DACL / `SO_PEERCRED`) |
| request from inside a sandbox (AppContainer / sandboxed process) | refused (app-package deny ACE + peer token check; uid check on Linux) |
| `job_dir` relative, missing, not a directory, or not owned by the peer | refused before launch |
| `auto`, hardened not installed | default backend |
| `auto`, installed but unhealthy | `IsolationUnavailable`, no fallback |
| `backend = vm` | SPEC-019: VM backend, or the platform default when virtualization is absent |
| second concurrent job | waits on the existing per-user `sandbox-job` lock; service refuses a second LAUNCH `busy` |
| install without admin/root | `rejected`, nothing created |
| uninstall twice | ok |
| non-UTF-8 path/env in the job | `IsolationUnavailable` before launch |
| service restart between jobs | stale exemptions (W) and stale job dirs swept at start |

## 9. Acceptance criteria → test cases

| FR-027 criterion | TCs |
|---|---|
| catalogue holds in hardened mode; an escaped script cannot read the user profile | TC-027-2, TC-027-3, TC-027-4, TC-027-5, TC-027-6 |
| service killed mid-job: job ends, no rule remains, host network works | TC-027-7, TC-027-8 |
| `hardened uninstall` leaves nothing | TC-027-9 |
| requests from another user or inside a sandbox refused | TC-027-10, TC-027-11, TC-027-12 |

## 10. Files expected to change

- `crates/fail2commit-core/src/isolation.rs` — serde derives (§6).
- `crates/fail2commit-core/src/sandbox/mod.rs` — `select_backend`.
- `crates/fail2commit-core/src/sandbox/hardened.rs` + `hardened/` (new) —
  user-side backend (grants, transport, probe), `protocol.rs` (job/outcome
  JSON), `service.rs` (peer auth, launch, watchdog), `launcher.rs`,
  `wfp.rs` (Windows), `proxy.rs` (Windows TCP transport).
- `crates/fail2commit-core/src/sandbox/egress.rs` (new) — extracted policy (§5);
  `sandbox/linux/proxy.rs` — use it, behaviour unchanged.
- `crates/fail2commit-core/src/sandbox/windows.rs`, `windows/ffi.rs` — LPAC
  launch variant, profile-SID reporting, hardened probe controls.
- `crates/fail2commit-core/src/sandbox/linux.rs` — no-`--user`-scope launch,
  hardened probe.
- `crates/fail2commit-core/src/hardened.rs` (new) or `machine.rs` extension —
  install/uninstall/status (account, service, units, state).
- `crates/fail2commit/src/main.rs`, `cmd/hardened.rs` (new), `cmd/mod.rs`,
  `cmd/sandbox.rs`, `cmd/npm.rs`, `cmd/run.rs`, `cmd/setup.rs`,
  `crates/fail2commit-core/src/pip/mod.rs` — command + `select_backend` call
  sites; hidden `sandbox serve` / `sandbox launch`.
- `crates/fail2commit/tests/sandbox_hardened_windows.rs`,
  `sandbox_hardened_linux.rs` (new), `tests/fixtures/hostile/` escape fixture;
  existing hostile suites gain a test-only `F2C_SANDBOX_BACKEND=hardened`
  override.
- `packaging/` — ship the units (Linux); document the optional hardened install
  (Windows installer does not enable it by default).
- Docs: `docs/sandbox-policy.md`, `docs/windows.md`, `docs/sandbox-linux.md`,
  `docs/install.md`, catalogue known-limits table if a limit is accepted.

## 11. Test cases

New suites run elevated/root in the VM gate (host-build/VM-test split); unit
tests run anywhere. The escape fixture is compiled only under the cargo feature
`hardened-escape-test`, which release builds never enable.

| TC | Given / When / Then | Type / path |
|---|---|---|
| TC-027-1 | Given an elevated shell, When `hardened install` runs, Then account, service and state exist, `hardened status` exits 0 and the probe is available; without elevation it is `rejected` and nothing was created | integration, `sandbox_hardened_windows::install_requires_admin_and_reports_state` / `sandbox_hardened_linux::install_requires_root_and_reports_state` |
| TC-027-2 | Given hardened mode on Windows, When the hostile catalogue runs through it (`F2C_SANDBOX_BACKEND=hardened`), Then every default-mode containment result holds (HB-001…071 as applicable) | e2e, `sandbox_hostile_windows` hardened run |
| TC-027-3 | Same on Linux | e2e, `sandbox_hostile_linux` hardened run |
| TC-027-4 | Given the escape-test build, When the fixture runs as the sandbox account **outside** the AppContainer/bwrap, Then it cannot read any file in the user's profile, and can read only the granted job stage | e2e, `sandbox_hardened_windows::escaped_process_cannot_read_the_user_profile` / Linux twin |
| TC-027-5 | Given hardened Windows and bait, When the job puts a bait value in a host name (HB-022) or a plain HTTP body (HB-023), Then the proxy trips `Bait`, the job is killed and nothing is exported | e2e, `sandbox_hardened_windows::bait_in_hostname_and_plain_http_stop_the_job` |
| TC-027-6 | Given hardened Windows (HB-066), When the job reads a user-data file under Program Files readable only by ALL APPLICATION PACKAGES, Then it is denied (`file_denied`); a staged native build still succeeds under LPAC | e2e, `sandbox_hardened_windows::lpac_denies_program_files_and_builds_staged_toolchain` |
| TC-027-7 | Given a running hardened job, When the service is killed, Then the job tree dies, no WFP filter or exemption remains (W), the host network works, and the user side reports `IsolationUnavailable`; the next job after service restart works | integration, `sandbox_hardened_*::killed_service_ends_the_job_and_leaves_no_rules` |
| TC-027-8 | Given a running hardened job, When the user CLI is killed, Then the launcher dies, grants are swept by the next run and no profile/exemption/job dir leaks | integration, `sandbox_hardened_*::killed_client_leaves_nothing_behind` |
| TC-027-9 | Given installed hardened mode, When `hardened uninstall` runs (twice), Then no account, service, unit, filter, exemption, state file or installed file remains and the host network works | integration, `sandbox_hardened_*::uninstall_removes_everything` |
| TC-027-10 | Given a second local user, When it requests LAUNCH, Then the request is refused and nothing starts | integration, `sandbox_hardened_*::another_user_is_refused` |
| TC-027-11 | Given a request from inside a sandbox (AppContainer token / sandboxed uid), Then it is refused | integration, `sandbox_hardened_windows::request_from_inside_the_sandbox_is_refused` (+ Linux peer-cred unit test) |
| TC-027-12 | Given `job_dir` relative, missing, a file, or owned by another user, Then LAUNCH is refused before anything starts | unit + integration, `hardened::protocol::tests` / `sandbox_hardened_*::foreign_job_dir_is_refused` |
| TC-027-13 | Given `auto` without install / `auto` with a stopped service, Then the backend is default / `IsolationUnavailable` respectively (`vm` selection: SPEC-019 TC-029-1) | unit, `sandbox::tests::backend_selection_fails_closed` |
| TC-027-14 | Given the probe, When a control fails (filter missing, self-test refused path open), Then `available = false` and `run_job` launches nothing; the self-test exercises both the refused and the permitted path | unit + integration, `hardened::probe::tests` / `sandbox_hardened_*::probe_fails_closed` |
| TC-027-15 | Given a malformed or oversized `outcome.json`, or non-UTF-8 job fields, Then the job fails closed and nothing is exported | unit, `hardened::protocol::tests::bad_outcome_and_non_utf8_fail_closed` |
| TC-027-16 | Given two concurrent guarded installs, Then the second waits on the `sandbox-job` lock and both succeed in turn | integration, existing lock test + `sandbox_hardened_*::second_launch_is_busy` |
| TC-027-17 | Given the egress extraction (§5), When the Linux proxy suite runs, Then it passes unchanged | regression, `sandbox_hostile_linux` network/bait rows |

## 12. Known limits and risks (probe-first items)

- **WFP scoping**: `ALE_PACKAGE_ID` filters plus the loopback exemption must be
  verified by the probe self-test on Windows 10 and 11 before any job runs. If
  the mechanism cannot be made to hold on a supported edition, the row goes
  back to the owner as a known limit (catalogue rule) — not a silent weaken.
- **Logon type**: `CreateProcessWithLogonW` + `LOGON_WITH_PROFILE` must create
  AppContainer profiles reliably (LESSONS: batch logon did not). Probe control.
- **Object-access auditing** (SPEC-014 §8 sketch): not required for catalogue
  evidence — fixtures report their own denials as in default mode — and is
  deferred. Recorded deviation from the sketch; the owner may reject it at
  review.
- Direct DNS from the job is refused, not inspected (same containment as
  Linux, where the job has no route at all).
- Implementation order: (1) boundary, lifecycle, uninstall (criteria 1–4,
  TC-027-1/4/7…14); (2) proxy egress + LPAC catalogue rows (TC-027-5/6). Both
  are required before the 0.1.4 release gate; (1) lands first so the service
  contract is reviewed before the network machinery is built on it.
