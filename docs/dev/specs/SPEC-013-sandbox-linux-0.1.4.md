# SPEC-013 — Linux sandbox for 0.1.4 (FR-020, FR-023, FR-024, FR-026, CR-022)

FR-020 · FR-023 · FR-024 · FR-026 · CR-022 · TC-020, TC-023, TC-024, TC-026 · Owner paths:
`crates/fail2commit-core/src/sandbox/{linux.rs,linux/,mod.rs}`, `docs/sandbox-linux.md`,
`crates/fail2commit/tests/sandbox_hostile_linux.rs`, `tests/fixtures/hostile/linux/`.

Status: design fixed before code. Every choice below is justified against the frozen contracts
(`isolation.rs`, `settings.rs`, `protocol.rs`, `sandbox/bait.rs`, `sandbox/netpolicy.rs`) and against
`docs/dev/sandbox-hostile-catalogue.md`. Defensive scope only: this is the containment and detection
layer of a developer security tool, not an offensive capability.

## 1. What 0.1.4 adds on Linux

| Requirement | Behaviour required | Linux mechanism chosen |
|---|---|---|
| FR-020 | Contain every catalogue row, report what happened | bwrap mount/PID/IPC/UTS/cgroup namespaces (0.1.3) **plus** a seccomp deny-list, a disk meter and the bait/egress watchers below |
| FR-023 / CR-022 | `sandbox.network = internet` reaches public addresses only; `none` keeps 0.1.3 | per-job egress proxy on a Unix socket + an in-sandbox TCP relay; `netpolicy::is_public` decides every destination |
| FR-024 | Bait credentials in the job's home; a touch stops the job | `BaitSet` written into a private per-job home, watched with inotify; bait values also watched on the egress path |
| FR-026 | `JobOutcome::report` carries observed activity | one `ActivityReport` shared by the proxy, the inotify watcher and the limit meter; `report_findings` turns it into findings |

## 2. Job shape (0.1.3 core unchanged)

```text
[systemd-run --user --scope -p TasksMax= -p MemoryMax= --]
bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --clearenv --setenv K V ...
      <system mounts> --proc /proc --dev /dev --tmpfs /tmp
      --ro-bind <read_only>... --bind <work_dir> <work_dir>
      --bind <job_ctl_dir> /f2c            (new: relay, seccomp filter, egress socket, bait home)
      --chdir <cwd> --json-status-fd 3
  -- bash -c WRAPPER f2c-sandbox <nproc|-> <as_kib|-> <fsize_kb|-> \
        <relay|-> <relay_sock> <relay_port> <relay_ready> <setpriv|-> <filter|-> <program> <args...>
```

Everything from 0.1.3 (trusted bwrap/bash paths, `bindable()`, program must live in a system
directory or a read-only input, wrapper writes the launch marker `L` to fd 4 only after the limits
are set, `--die-with-parent`, PID-namespace init killed on timeout) stays as it is. `--unshare-all`
stays in **both** network modes; see §4 for why that is what makes `internet` safe.
The wrapper receives, in order: process limit, address-space limit, file-size limit, relay program,
relay socket, relay port, relay ready file, `setpriv`, seccomp filter file, program, arguments. It
sets the rlimits, starts the relay when one is given, waits (bounded) for the relay's ready file and
exports the proxy variables, then either `exec setpriv --seccomp-filter <file> --no-new-privs --
<program>` or `exec <program>`; the launch marker is written to fd 4 immediately before each `exec`.

## 3. Per-job control directory (`<tmp>/f2c-job-*`, bound at `/f2c`)

Created per job (`tempfile::TempDir`) and removed when the job ends, so nothing survives a job:

| Path | Written by | Read by | Why not inside `work_dir` |
|---|---|---|---|
| `/f2c/relay` | backend (copy) | wrapper | The package tree is content-verified after scripts (`npm::tree::verify_after_scripts` rejects a new file outside the package dirs) and `work_dir` is the export source; a tool binary there would be a finding. |
| `/f2c/seccomp.bpf` | backend | `setpriv` in the wrapper | Same reason; also keeps the filter out of export reach. |
| `/f2c/egress.sock` | proxy (parent) | relay | Unix sockets cannot be placed in `work_dir` without exposing them to the package. |
| `/f2c/ready` | relay | wrapper | Handshake between relay and wrapper (it carries the TCP port). |
| `/f2c/home` | backend (`BaitSet::write_into`) | job (`HOME`) | FR-024 asks for the bait in the job's home. `bait::write_into` documents "inside the job's own writable stage"; a private directory **is** that stage for the job (`HOME` points at it and nothing else can reach it), and it is what keeps bait out of the exported and content-verified project tree. Documented deviation, justified by the two contracts it protects. |

`/f2c` is bound read-write (`--bind`) because the relay must create `/f2c/ready`. A package that
deletes or replaces anything below `/f2c` only breaks its own job: the proxy's listening socket is
already open on the parent side, the seccomp filter is already loaded, and the relay was started
before the package program ran.

## 4. FR-023 network: egress proxy + in-sandbox relay

### 4.1 Why a proxy and not a firewall or a namespace peer

- `netpolicy.rs` (frozen) says it is "shared by ... the Linux egress proxy", so the egress proxy is
  the intended Linux mechanism.
- Unprivileged user namespaces give no way to put a filtering gateway *inside* a fresh netns:
  creating a veth/tap peer needs CAP_NET_ADMIN in the parent netns, iptables/nftables need root, and
  a TUN-based user-mode NAT needs a full TCP/IP stack. All of those are out of scope for a
  user-writable tool that must never touch host firewall state (FR-020 host-safety criterion).
- A destination filter built on `LD_PRELOAD` is bypassable (static binaries, direct syscalls) and
  cannot be called evidence.

### 4.2 Shape

```text
sandbox (own netns, only lo up)              parent process (host netns)
  package program --TCP 127.0.0.1:P--> relay --Unix /f2c/egress.sock--> proxy --TCP--> public host
```

- The sandbox keeps `--unshare-all`, so it has **no route to anything**: not the host's loopback, not
  the LAN, not the metadata service, not the Docker socket, not a host abstract socket. A direct
  `connect()` from a package therefore fails in **both** network modes (HB-031...HB-034, HB-037,
  HB-038).
- In `internet` mode the backend additionally copies the relay into `/f2c/relay`, the wrapper starts
  it before the program and exports `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (upper and lower case),
  `NO_PROXY=` and the `npm_config_*_proxy` equivalents pointing at `http://127.0.0.1:<port>`. The
  port is chosen by the relay (bind port 0) and handed to the wrapper through `/f2c/ready`, so two
  jobs can never collide.
- A relay is unavoidable: a TCP listener reachable from inside the netns must live in that netns, and
  anything in that netns has no internet. The relay is a dumb byte pump; **all policy is in the
  parent-side proxy**, so a package that kills, replaces or talks nonsense to the relay gains
  nothing.
- The relay is `crates/fail2commit/src/bin/f2c-sandbox-relay.rs` (new file, ~10 lines) over
  `fail2commit_core::sandbox::linux::relay`. It is located by, in order: `F2C_SANDBOX_RELAY`,
  `CARGO_BIN_EXE_f2c-sandbox-relay` (compile time, used by the tests), then a sibling of the running
  executable. **If no relay is found, `Internet` returns `IsolationUnavailable`** (fail closed);
  packaging must ship the relay next to `fail2commit` (recorded as a follow-up for the coordinator).
- `none` mode starts no relay, exports no proxy variable and creates no socket: the 0.1.3 behaviour
  is preserved exactly.
### 4.3 Proxy policy (`sandbox/linux/proxy.rs`)

Per connection, from a bounded request head (8 KiB) and, for plain HTTP, up to 8 KiB of body:

1. Parse `CONNECT host:port` or the absolute URI of a `GET`/`POST`/... request. Anything else gets
   `400` plus `ActivityKind::NetRefused` (`net_refused`).
2. Bait: `BaitSet::find_value` over the raw head and the body prefix. A hit is
   `ActivityKind::Bait` (the detail names the destination, never the value), the response is `403`
   and the job is stopped (FR-024).
3. Resolve the authority **on the host** (`ToSocketAddrs`), then require **every** resolved address
   to satisfy `netpolicy::is_public`; anything else (loopback, private, CGNAT, link-local, metadata,
   multicast, documentation, NAT64 or mapped IPv4 forms) gets `403` and `NetRefused`
   (HB-032...HB-035). Refusing when *any* address is non-public keeps a DNS answer from smuggling a
   local address past the check.
4. Otherwise connect (10 s), reply `200` for `CONNECT`, pump both directions and record
   `ActivityKind::NetAllowed` with `host:port` (HB-030).
5. UDP, multicast and broadcast never reach the proxy: the sandbox has no interface, so those
   attempts fail in the kernel (HB-037). The platform reports the failing exit status and the report
   says so; the catalogue row is recorded as "refused, not proxied".
6. Concurrency is capped (64 connections, 60 s idle) so a package cannot exhaust the parent.

### 4.4 What `internet` does *not* mean on Linux

FR-023 is "public internet only", not "the same packet path as the host". A program that ignores
proxy variables cannot reach the network at all; it fails closed instead of failing open. This is
stricter than CR-022 requires and is the only rootless design that is both enforceable and
reportable.

## 5. FR-024 bait

- `JobSpec::bait` -> the backend generates a `BaitSet`, writes it into `/f2c/home` and rewrites the
  job's `HOME` to that path (bait **is** the job's home, so `~/.ssh/id_ed25519` is the bait file).
  `BaitSet::env` values are added to the job environment (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`). The
  values are fake and per job; they appear in bwrap's argv because `--setenv` carries them, which is
  a documented, bounded disclosure of worthless data.
- `sandbox/linux/baitwatch.rs` puts an inotify watch (`IN_OPEN|IN_ACCESS|IN_MODIFY|IN_ATTRIB`) on
  each bait file and turns events into `ActivityKind::Bait` plus a job kill. inotify works across
  mount and PID namespaces because the watch is on the inode, so the parent sees the open of the
  file it planted. Recursive watching is unnecessary: the bait set is a fixed list of files.
- Never logged: the bait value. The `detail` is the bait file's relative path
  (`home/.ssh/id_ed25519`), which is safe by construction. `report_findings` turns every bait entry
  into `FindingKind::BaitTouched` / `FindingAction::Deny`.
- `job.bait == false` (probe and Windows-only call sites) changes nothing: no home, no watches.

## 6. FR-020 catalogue rows that need more than bwrap

- **seccomp deny-list** (`sandbox/linux/seccomp.rs`): the backend compiles a classic-BPF program and
  writes it to `/f2c/seccomp.bpf`; the wrapper applies it with the trusted
  `/usr/bin/setpriv --seccomp-filter <file> --no-new-privs -- program`. Denied with `EPERM`:
  `mount`, `umount2`, `swapon`, `swapoff`, `reboot`, `sethostname`, `setdomainname`, `iopl`,
  `ioperm`, `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`,
  `unshare`, `setns`, `pivot_root`, `chroot`, `ptrace`, `process_vm_readv`, `process_vm_writev`,
  `personality`, `bpf`, `userfaultfd`, `perf_event_open`, `keyctl`, `add_key`, `request_key`,
  `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `open_by_handle_at`, `name_to_handle_at`,
  `quotactl`, `acct`, `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `syslog`,
  `vhangup`, `seccomp`, `listen`, and `socket()` for every address family except `AF_UNIX`,
  `AF_INET` and `AF_INET6` (so `AF_PACKET`, `AF_NETLINK`, `AF_VSOCK`, `AF_XDP`, `AF_ALG`, ... are
  refused). The program also validates the audited architecture (`x86_64`, `aarch64`) so a foreign
  ABI cannot reach the deny-list by number. Both argument checks sit behind a `nr` gate
  (`jeq <gate> jf=<block length>`): without it every syscall would be judged by its first argument,
  and a pointer there is almost never one of the allowed values. seccomp's verifier accepts
  `JEQ/JGE/JGT/JSET` but not `JNE`, so the inverted test is a `JEQ 0` that skips the denial. A unit
  test loads the program with `setpriv` and proves `unshare(CLONE_NEWUSER)` is refused, so a broken
  filter fails `cargo test` instead of a job.
  - Why `setpriv` and not an in-sandbox helper: the filter must be installed *after* bwrap's setup
    (bwrap itself needs `mount`/`unshare`) and *before* the package program, i.e. inside the sandbox.
    `setpriv` is the util-linux tool for exactly this, is present on Ubuntu 24.04 and Arch, and gets
    the same trusted-path probe as `bwrap`, `bash` and `systemd-run`. When it is missing the backend
    reports `IsolationUnavailable`: a mandatory control is missing, so nothing runs.
  - `EPERM` rather than `SIGSYS` is deliberate: the package script sees a normal failure, the install
    reports it, and no core dump of a user process is produced.
- **disk limit** (HB-053, `JobLimits::disk_bytes`): `RLIMIT_FSIZE` (through `ulimit -f`, KiB) bounds a
  single file, and a meter samples the bytes below `work_dir` and `/f2c/home` every 100 ms and kills
  the job on overrun (`ActivityKind::Limit`, detail `disk`). A `SIGXFSZ` death is also reported as
  `disk`. Measuring is the only rootless option (no per-directory quota without privileges); the
  FRD records the same limitation for Windows.
- Everything else in the catalogue already holds through bwrap (mount policy, PID namespace, cgroup
  scope, `--die-with-parent`) and is proven by the tests in section 9.
## 7. FR-026 report and `report_findings`

`sandbox/mod.rs` gains:

```rust
pub fn report_findings(report: &ActivityReport) -> Vec<Finding>
```

- `ActivityKind::Bait` -> `FindingKind::BaitTouched`, `FindingAction::Deny`, `source = "sandbox.bait"`.
  A touched bait can never be approved away (FR-024).
- Every other entry -> `FindingKind::RiskSignal`, `FindingAction::Info`, `source = "sandbox.activity"`,
  `evidence = "<kind>: <detail>"` (the detail is already bounded and free of secret values).
- Deduplicated by `(kind, detail)` and bounded by `MAX_ACTIVITY`: the report is untrusted input.

Wiring at the call sites:

- `fail2commit run` (`cmd/run.rs`): `network` from `settings.sandbox.network`, `bait = true`,
  `Outcome.findings = report_findings(&outcome.report)`, and the report is added to `--json` data.
- npm (`npm/apply.rs`, the `JobSpec` site): `network` from `settings.sandbox.network`, `bait = true`,
  and `report_findings` is applied to the job's report: a bait entry denies the install with the
  `BaitTouched` findings attached, and a failed job carries the activity entries in its evidence.
  Surfacing *Info* activity for a successful install needs `run_scripts` to return the report and
  `npm/mod.rs` to merge it into `NpmOutcome.findings`; both files are outside this task's list, so it
  is reported as a follow-up rather than edited.
- pip: the pip command runs no package code in a sandbox job (`authorize_scripts(... has_scripts:
  false ...)`; every interpreter it starts skips `site`), so there is no `JobSpec` call site to wire.
  Recorded in the report instead of inventing one.

## 8. Error cases

| Case | Result |
|---|---|
| `setpriv` missing or untrusted | `probe()` -> `available = false`, `IsolationUnavailable`, nothing launched |
| `Internet` requested but no relay binary | `IsolationUnavailable` before staging (fail closed) |
| relay does not write `/f2c/ready` within 5 s | wrapper exits `125` before the launch marker -> `IsolationUnavailable` |
| proxy cannot resolve, or any address is non-public | `403` + `NetRefused`; the job continues (a package may retry another registry) |
| bait opened, or bait value on the egress path | job killed, `Bait` entry, `BaitTouched` `Deny` |
| disk overrun or `SIGXFSZ` | job killed, `Limit` entry |
| inotify setup fails while `job.bait` is set | `IsolationUnavailable`; never a silently unwatched job |
| proxy socket creation fails | `IsolationUnavailable` (no partial network) |
| report longer than `MAX_ACTIVITY` | truncated flag set, first 200 entries kept |
| any job path below `/f2c`, `/proc`, `/sys`, `/dev`, `/etc` | unchanged `bindable()` rejection before launch |
## 9. Test cases

`crates/fail2commit/tests/sandbox_hostile_linux.rs` (Linux only; when bwrap is unavailable the tests
print `SKIP (pending evidence)` unless `F2C_REQUIRE_SANDBOX=1`, as in the 0.1.3 harness). Fixtures
live in `tests/fixtures/hostile/linux/`.

| ID | Given / When / Then | Test function |
|---|---|---|
| TC-020-1 | Given a job with the host home and a planted synthetic secret, When the payload reads it, writes the checkout and `/tmp`, Then every attempt fails, nothing outside the stage changed and the job reports it (HB-001...008) | `files_outside_the_stage_are_denied` |
| TC-020-2 | Given `GITHUB_TOKEN`/`AWS_*`/`NPM_TOKEN` in the parent environment, When the payload dumps its environment, Then none of those keys or values is visible (HB-009) | `host_environment_secrets_are_absent` |
| TC-020-3 | Given a hostile payload, When it opens `AF_PACKET`/`AF_NETLINK` sockets, Then both fail with `EPERM` (HB-039) | `raw_and_netlink_sockets_are_blocked` |
| TC-020-4 | Given a job that forks a detached child and exits, When the job returns, Then the child is gone before the report is produced (HB-040) | `detached_child_stops_with_the_job` |
| TC-020-5 | Given a job that writes cron entries, systemd units and Startup paths, When it runs, Then every write fails (HB-041) | `persistence_paths_are_unwritable` |
| TC-020-6 | Given another process of the same user, When the payload tries to signal or trace it, Then both fail (HB-042...HB-044) | `process_control_outside_the_job_is_blocked` |
| TC-020-7 | Given `disk_bytes`/`max_output_bytes`/`timeout` limits, When the payload exceeds them, Then the job is killed, the report carries `Limit` entries and the stage stays below the limit (HB-050...HB-054) | `resource_limits_are_reported` |
| TC-020-8 | Given a payload that calls `mount`, `unshare`, `pivot_root`, `chroot`, `bpf`, `userfaultfd`, `perf_event_open`, `keyctl`, `io_uring_setup`, `kexec_load`, `init_module`, `personality` and `ptrace`, Then each fails with `EPERM` (HB-060...HB-062) | `kernel_surfaces_are_blocked` |
| TC-020-9 | Given a running job, When the host side is killed, Then no sandbox process survives and the next job starts cleanly (HB-070) | `killed_host_side_leaves_no_processes` |
| TC-023-1 | Given `sandbox.network = internet`, When the payload fetches a public host through the proxy, Then it succeeds and the report has `NetAllowed` (HB-030) | `internet_mode_reaches_a_public_host` |
| TC-023-2 | Given `sandbox.network = none`, When the payload tries the same GET, Then it fails and no proxy socket exists (HB-031) | `network_none_refuses_every_destination` |
| TC-023-3 | Given a host listener on 127.0.0.1, a LAN address, 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254.169.254, fd00:ec2::254, fe80::/10, fc00::/7 and a name that answers 127.0.0.1, When the payload requests each through the proxy, Then each is refused with `NetRefused` (HB-032...HB-035) | `private_and_loopback_destinations_are_refused` |
| TC-023-4 | Given an internet job, When the payload binds and listens on a TCP port, Then `listen` fails with `EPERM` (HB-036) | `listening_sockets_are_blocked` |
| TC-023-5 | Given an internet job, When the payload sends UDP to a public address, multicast and broadcast, Then every send fails (HB-037) | `udp_multicast_and_broadcast_are_refused` |
| TC-023-6 | Given an internet job and host sockets (approval socket, Docker socket, D-Bus path), When the payload connects, Then each attempt fails (HB-038) | `local_sockets_are_unreachable` |
| TC-024-1 | Given `JobSpec::bait` and a payload that opens the bait `~/.npmrc`, When the job runs, Then the job is killed, the report has a `Bait` entry and `report_findings` yields `BaitTouched`/`Deny` (HB-020) | `bait_file_open_stops_the_job` |
| TC-024-2 | Given the bait `~/.ssh/id_ed25519`, `~/.git-credentials`, `~/.aws/credentials` and `~/.env`, When the payload reads each, Then every read is detected (HB-021) | `every_bait_file_is_detected` |
| TC-024-3 | Given a bait value inside a proxied host name, When the payload requests it, Then the job stops with a `Bait` entry (HB-022) | `bait_value_in_a_host_name_is_detected` |
| TC-024-4 | Given a bait value in an unencrypted HTTP request body, When the payload POSTs it to a public address, Then the job stops with a `Bait` entry (HB-023) | `bait_value_in_plain_http_is_detected` |
| TC-024-5 | Given a clean native build, When it runs with bait enabled, Then the report has no `Bait` entry (HB-024) | `clean_build_touches_no_bait` |
| TC-026-1 | Given an `ActivityReport` with bait and non-bait entries, When `report_findings` runs, Then bait becomes `BaitTouched`/`Deny` and the rest `RiskSignal`/`Info`, deduplicated | `report_findings_maps_bait_to_deny` (unit test in `sandbox/mod.rs`) |
| TC-026-2 | Given a job that is refused a destination and one that is allowed, When the job ends, Then the report shows `NetRefused` and `NetAllowed` with bounded details | `private_and_loopback_destinations_are_refused`, `internet_mode_reaches_a_public_host` |
| TC-026-3 | Given `fail2commit run`, When it executes a job, Then `--json` carries `network` and the `activity` list, and the findings are the report's findings | `run_cli.rs` (existing CLI coverage; the report shape is asserted by `report_findings_is_bounded_by_the_report`) |

## 10. Known limits (for the coordinator's catalogue table)

1. Rows a Docker container cannot host (cgroup delegation, VM power-cycle: HB-051 through cgroups,
   HB-071) stay "pending (needs VM)".
2. seccomp denials surface as `EPERM` plus a failing exit status; the parent cannot see *which*
   syscall was refused, so no `blocked` activity entry is produced for HB-039/HB-060...HB-062 (the
   row's behaviour fails and the install reports it, which the catalogue's "exit code, finding or
   activity entry" allows).
3. Mount-based file denials are invisible to the parent (no fanotify permission events without
   root), so no `file_denied` entry is produced for HB-001...HB-008; bait reads are (HB-020/021).
4. UDP to public addresses is not proxied, so HB-037 records "refused" rather than "allowed where the
   platform allows it".
5. `Internet` needs the relay binary next to the CLI; packaging must ship it.