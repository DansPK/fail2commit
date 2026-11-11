# Linux sandbox (Bubblewrap) and Linux test harness

> FR-007 · FR-020 · FR-023 · FR-024 · FR-026 · SPEC-007 · SPEC-013 · CR-022 · TC-007 · Tasks T-007a, W-A.
> Code: `crates/fail2commit-core/src/sandbox/{linux.rs,linux/,mod.rs}`,
> `crates/fail2commit/src/{cmd/run.rs,bin/f2c-sandbox-relay.rs}`.
> Evidence: `docs/dev/verify/VERIFY-2026-11-08-sandbox-linux.md`, and the 0.1.4 catalogue run.

## 0. What 0.1.4 adds (SPEC-013)

| Requirement | What a job gets |
|---|---|
| FR-023 / CR-022 | `sandbox.network = internet` is an **egress proxy** (host side) reached through a **relay** inside the sandbox; `none` keeps the 0.1.3 "no network at all" behaviour. |
| FR-024 | A per-job **fake home** with bait credentials, watched with inotify; a touch stops the job. |
| FR-026 | `JobOutcome::report` — `net_allowed`, `net_refused`, `bait`, `limit`, `process` entries, turned into findings by `sandbox::report::findings`. |
| FR-020 | a **seccomp deny-list** (applied by `setpriv`), a **disk meter**, and the existing mount/PID/cgroup isolation. |

The sandbox keeps `--unshare-all` in **both** network modes. It therefore has no route to anything
— not the host's loopback, not the LAN, not the metadata service, not the Docker socket. `internet`
adds exactly one path out:

```text
sandbox (own netns, only lo)              parent process (host netns)
  package program --TCP 127.0.0.1:P--> relay --Unix /f2c/egress.sock--> proxy --TCP--> public host
```

- The relay (`f2c-sandbox-relay`) is a byte pump with no policy. The proxy decides every
  destination with `sandbox::netpolicy::is_public` (public unicast only; IPv4-mapped and NAT64
  forms are judged by the IPv4 address they carry) and refuses loopback, private, CGNAT,
  link-local, metadata, multicast, documentation and unique-local addresses. Every resolved address
  must be public, so a DNS answer cannot smuggle a local address past the check.
- The wrapper exports `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (upper and lower case), an empty
  `NO_PROXY` and the `npm_config_*_proxy` equivalents. A program that ignores them reaches nothing:
  `internet` is stricter than "same packets as the host", never wider.
- Bait values in a request head, a host name or a plain-HTTP body stop the job. The value is never
  logged — only the destination.
- `internet` needs `f2c-sandbox-relay` next to the `fail2commit` binary. Without it the backend
  fails closed (`IsolationUnavailable`); packaging ships it.

## 1. How a job runs

```text
[systemd-run --user --scope --quiet --collect -p TasksMax=N -p MemoryMax=M -p MemorySwapMax=0 --]
bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --clearenv --setenv K V ...
      <system mounts> --proc /proc --dev /dev --tmpfs /tmp
      --ro-bind <read_only>... --bind <work_dir> <work_dir> --bind <job_ctl> /f2c
      --chdir <cwd> --json-status-fd 3
  -- bash -c WRAPPER f2c-sandbox <nproc|-> <as_kib|-> <fsize_kib|-> <relay|-> <sock> - <ready>
        <setpriv> <filter> <program> <args...>
```

- **Trusted binaries.** bwrap comes only from `/usr/bin/bwrap` or `/usr/local/bin/bwrap`, and `setpriv` only from `/usr/bin/setpriv` or `/bin/setpriv`. Each must be a root-owned executable that group and others cannot write, in a root-owned directory with the same restriction. bash and systemd-run pass the same check. PATH and the repository are never consulted. A missing `setpriv` makes the backend unavailable, because the seccomp deny-list is mandatory.
- **Namespaces.** `--unshare-all` creates new user, mount, network, PID, IPC, UTS and cgroup namespaces. There is no `--share-net`, so the sandbox has only its own loopback. Abstract unix sockets are bound to the network namespace, so the sandbox cannot reach host ones either.
- **Environment.** The bwrap process starts with an empty environment. With a scope it gets only `XDG_RUNTIME_DIR`, which systemd-run needs. `--clearenv` then removes everything else, and only `job.env` is set. Values in `job.env` appear in bwrap's argv, so callers pass tool settings there and never secrets.
- **Mounts.**
  - Read-only: `/usr`, plus `/bin`, `/sbin` and `/lib*` (recreated as symlinks on merged-/usr systems).
  - From `/etc`, only `ld.so.cache`, `ld.so.conf(.d)`, `passwd`, `group`, `nsswitch.conf`, `localtime`, `alternatives`, `ssl/certs`, `pki/tls/certs` and `ca-certificates`.
  - A fresh `/proc` for the PID namespace, a minimal `/dev` and a fresh tmpfs `/tmp`.
  - `job.read_only` is bound read-only and `job.work_dir` read-write, each at its own canonical path.
  - `/f2c`: the job's control directory (relay, seccomp filter, egress socket, bait home). It is a fresh temporary directory per job, removed when the job ends, and it is **not** inside the project tree, so package verification and exports never see it.
  - Not mounted: the host home, `/run` (D-Bus, ssh-agent, the Docker socket, `XDG_RUNTIME_DIR`), `/var`, `/mnt`, `/media`, `/srv`, `/root`, `/sys` and the rest of `/etc`.
  - `bindable()` refuses any job path that is `/`, the host home or an ancestor of it, an ancestor of `/home`, `/root`, `/tmp`, `/var/tmp`, `/run`, `/etc`, `/mnt`, `/media` or `/srv`, or anything inside `/run`, `/var/run`, `/proc`, `/sys`, `/dev` or `/etc`. It refuses before launching anything.
- **Program.** The program must be absolute, and its canonical path must be inside a system directory or a `read_only` input. It cannot be inside the writable work dir.
- **seccomp (FR-020).** The wrapper applies `/f2c/seccomp.bpf` through `setpriv --seccomp-filter … --no-new-privs`. The program validates the audited architecture, then returns `EPERM` for `mount`, `umount2`, `swapon`, `swapoff`, `reboot`, `sethostname`, `setdomainname`, `iopl`, `ioperm`, `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `unshare`, `setns`, `pivot_root`, `chroot`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `personality`, `bpf`, `userfaultfd`, `perf_event_open`, `keyctl`, `add_key`, `request_key`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `open_by_handle_at`, `name_to_handle_at`, `quotactl`, `acct`, `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `syslog`, `vhangup`, `seccomp`, `listen`, `clone` with any `CLONE_NEW*` flag, and `socket()` for every family except `AF_UNIX`, `AF_INET` and `AF_INET6` (so `AF_PACKET`, `AF_NETLINK` and `AF_VSOCK` are refused). The filter is applied after bwrap's setup and before the package program; a missing or untrusted `setpriv` is a hard failure.
- **Bait (FR-024).** When `JobSpec::bait` is set, a `BaitSet` is generated per job, written into `/f2c/home` and watched with inotify (`IN_OPEN|IN_ACCESS|IN_MODIFY|IN_ATTRIB`). `HOME` points at that directory and the bait variables are added to the environment, so `~/.ssh/id_ed25519` **is** the bait file. An event is a `bait` activity entry and stops the job; only the file's path is recorded, never a value.
- **Limits.**
  - Processes: the wrapper sets RLIMIT_NPROC (`ulimit -S -H -u`) inside the new user namespace. Set on the outer bwrap, the kernel would count every host process of the user and refuse to create the namespace. This was measured: with `prlimit --nproc=3 bwrap ...` and 7 host processes, bwrap failed with `Creating new namespace failed: Resource temporarily unavailable`.
  - Memory: without a scope, RLIMIT_AS. With a scope, cgroup `pids.max` and `memory.max` (with swap 0) also apply, and RLIMIT_AS is skipped, because it breaks runtimes that reserve large virtual ranges.
  - Real root bypasses RLIMIT_NPROC, so as root `process_limit` is reported unverified unless a scope applies.
  - Disk: `ulimit -f` (RLIMIT_FSIZE, KiB) bounds a single file, and a meter samples the stage and the fake home every 100 ms and kills a job that writes past `limits.disk_bytes`, recording `limit: disk`. A `SIGXFSZ` death is reported the same way. Measuring is the only rootless option: there is no per-directory quota without privileges.
- **Fail closed on setup.** The wrapper writes `L` to fd 4 only after the limits are set, the relay is ready and immediately before `exec`. It then closes fd 4. bwrap already closes its own status fd 3 in the sandbox. If the marker is missing (bwrap, systemd-run, ulimit, setpriv or the relay failed), `run` returns `IsolationUnavailable`, and nothing from the job was executed.
- **Activity report (FR-026).** `JobOutcome::report` carries `net_allowed` and `net_refused` (the destination, never a payload), `bait` (the bait file or the destination), `limit` (`timeout`, `output`, `disk`) and one `process` entry for the program that was launched. `sandbox::report::findings` turns every `bait` entry into a `BaitTouched` `Deny` and other relevant activity into an informational `SandboxActivity` finding; process-only entries are omitted.
- **Timeout and cleanup.**
  - `--json-status-fd` reports the host pid of the sandbox's PID-namespace init. On timeout that pid gets SIGKILL, the kernel kills every process in the namespace, and bwrap exits after its init is reaped. `run` reaps bwrap.
  - When the main program exits, bwrap's init exits and the namespace is torn down too, so background processes never outlive a job.
  - `--die-with-parent` covers fail2commit itself dying.
- **Output.** Two threads drain stdout and stderr at the same time against one shared byte budget (`max_output_bytes`). Bytes over the budget are read and dropped, and `truncated` is set, so the writer never blocks.
- **Probe.**
  - `probe()` runs a real sandbox through the same code path. From inside, it compares every namespace id with the host's. It also checks:
    - `ulimit -u` and `ulimit -v`;
    - that `/run`, `/var/run` and the host home are absent and the root directory has only the expected entries;
    - that `/proc/self/environ` has only the job's keys, while a canary in the bwrap process's own environment is missing.
  - cgroup delegation is accepted only when a test scope really reports the requested `pids.max` and `memory.max`.
  - `available` requires every mandatory control: trusted bwrap, wrapper shell, user/net/pid/ipc/uts/mount namespaces, clean env, mount policy and memory limit. `process_limit` and `cgroup_v2_limits` are reported but optional, because the spec says "where supported".
  - Runtime tracing (strace, eBPF) is never used.

## 2. Export (`sandbox::run_job`, shared with Windows)

`run_job` probes, runs, and calls `export()` only after `Exited(0)`. On failure, timeout, kill or cancel, nothing is exported.

- `export()` checks each `job.exports` entry. It must be a plain relative path (only normal components: no `..`, `.`, root or prefix), and every component below the work dir must be a real directory.
- The whole tree is validated before anything is written. These are rejected:
  - symlinks;
  - Windows reparse points (`FILE_ATTRIBUTE_REPARSE_POINT`);
  - hard-linked files (`nlink` > 1; on Windows, `nNumberOfLinks` through `GetFileInformationByHandle`);
  - special files (sockets, FIFOs, devices);
  - totals over 512 MiB (`EXPORT_MAX_BYTES`, the default `artifact_max_bytes`) or 100,000 entries.
- The destination may be an untrusted checkout. Existing destination directories must be plain directories, and files are created with `create_new`, so a planted link or file is never followed or overwritten. On any error, everything this export created is removed. File modes keep only `0o755` bits.

## 3. `fail2commit run`

```text
fail2commit run --input <dir> [--export <relpath>]... [--to <dir>] -- <program> [args...]
```

1. Validates `--export` (plain relative, and needs `--to`), then probes. `policy::explicit_run_allowed` applies whatever the sandbox toggle is set to. Unavailable gives `isolation_unavailable` (exit 14) before anything is staged.
2. Copies `--input` into `<cache>/staging/run-*/work`. It never follows links (symlinks are recreated as links; on Windows, links and junctions are refused) and never copies `.git` (remote URLs, credentials, hooks). Special files are refused. The copy is bounded by `artifact_max_bytes` and `graph_max_nodes`.
3. Resolves the program as an absolute path or a bare name on PATH (skipping fail2commit shims). A program in a system directory runs in place. Anything else is copied alone into a read-only `toolchain` directory. Input scripts run through an interpreter, for example `-- /bin/sh build.sh`.
4. Environment: `PATH`, `HOME`=work, `TMPDIR=/tmp` and `LANG=C.UTF-8` (Windows: `SystemRoot`, `PATH`, `USERPROFILE`, `TEMP` and `TMP`). Limits come from the settings snapshot.
5. Prints sanitized output: lossy UTF-8, control and bidi-override characters replaced with `?`, at most 64 KiB per stream. Exit codes: the program's status, 124 for timeout, 137 for killed. `--json` puts status, output, `truncated`, `network`, `activity` and `exported` in `data`. The staging directory is removed afterwards.
6. `sandbox.network` and `sandbox.bait` apply as for package scripts: `internet` routes through the egress proxy, `none` grants no network, and bait is always planted (`bait: true`). Activity entries become findings: a bait touch is a `BaitTouched` `Deny`, everything else an `Info` `RiskSignal`.

Limitations:
- A program outside system directories is staged alone, so tools that need sibling files (such as rustup proxies) must be given as system tools or run through an interpreter.
- Files physically inside `--input`, hard links included, count as input.
- `internet` is proxy-only: a program that ignores `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` reaches nothing (see §4.4 of SPEC-013). UDP is not proxied.
- seccomp denials reach the parent as a failing exit status (`EPERM`), not as a `blocked` activity entry; mount-based file denials are invisible to the parent, so no `file_denied` entry is produced. Bait reads, network decisions and every limit are reported.
- `internet` needs `f2c-sandbox-relay` next to the `fail2commit` binary.
- The disk limit is measured and enforced by killing the job; there is no per-directory quota without privileges.

## 4. Linux test harness

Entry point: `scripts/linux/test.ps1` (Windows host, Docker running).

| Stage | What runs | Where |
|---|---|---|
| `container` | `cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace`, then `container.sh` bundles every test binary (from `cargo test --no-run --message-format=json`) and the `fail2commit` CLI into `target/linux-bundle/bundle`. `-Gcc` adds a relocatable gcc sysroot (`stage-gcc.sh`). | `rust:1` image, named volumes `<Volume>-target`, `f2c-rustup` (keeps rustfmt and clippy), `f2c-cargo-registry`, `CARGO_BUILD_JOBS=2`. |
| `wsl` | `run-bundle.sh` copies the bundle to a private temp dir and runs each test binary with `F2C_REQUIRE_SANDBOX=1` (a missing sandbox fails instead of skipping), `F2C_BIN=<bundle>/bin/fail2commit` and, with `-Gcc`, `F2C_TEST_GCC_ROOT` and `F2C_REQUIRE_NATIVE_BUILD=1`. | WSL `Ubuntu`: real bwrap, unprivileged user namespaces, systemd user scope. No cargo or gcc needed. |
| `privileged` | `privileged.sh` installs bubblewrap and runs the bundle as uid 1000 (`setpriv`). Real root would bypass RLIMIT_NPROC. Uses the image's real `/usr/bin/gcc`. There is no systemd, so this stage covers the rlimit-only path. | `docker run --privileged rust:1`. Reliable here (bwrap 0.12). Use it only for this repository's own tests. |

```powershell
# Worker or coordinator, full Linux gate plus the real-sandbox tests:
powershell -File scripts/linux/test.ps1 -Volume f2c-<task> -Stage container,wsl,privileged -Gcc
# Only the sandbox and run tests, on an already-built bundle:
powershell -File scripts/linux/test.ps1 -Volume f2c-<task> -Stage wsl,privileged -Filter '^(sandbox_linux|run_|fail2commit_core)'
```

Notes:
- Test binaries embed compile-time container paths. Tests that need the CLI use `F2C_BIN`, and fixtures are `include_str!`-embedded. Tests in other areas that read `CARGO_MANIFEST_DIR` at run time may need the same treatment before they can run in WSL.
- On hosts without bwrap (the unprivileged container, Windows) the Linux sandbox tests print `SKIP (pending evidence)`. A skip is never evidence.
- The scripts must have LF line endings (`scripts/linux/.gitattributes`).
- If a WSL call fails with `Wsl/Service/CreateInstance/CreateVm/ERROR_TIMEOUT`, run `wsl -d Ubuntu -- echo ok` once to start the VM, then retry.
