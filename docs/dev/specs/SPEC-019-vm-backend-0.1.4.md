# SPEC-019 — Virtual-machine sandbox backend for 0.1.4 (FR-029)

Status: ready for implementation (architect pass, 2026-11-13). Task T-015.
Priority Could — lands after T-013 (SPEC-018) and T-014 (FR-013). Follows
SPEC-007 (backend contract), SPEC-013/014 (inner backends), SPEC-018 (launcher
subcommand, serde job transport, backend selection).

FR-029: an optional backend runs jobs inside a disposable VM — Windows Sandbox
where the Windows edition has it, a small Linux VM otherwise — with the same
grants, network rules, bait and report as the other backends. Without hardware
virtualization the other backends are used.

Interpretation recorded for review: "a small Linux VM otherwise" is read as
Linux hosts with KVM. Windows editions without Windows Sandbox (Home) report
unavailable and fall back; a QEMU-on-Windows stack is out of scope for a Could.

## 1. Selection

`sandbox.backend = "vm"` → `VmBackend` (SPEC-018 §1 `select_backend`):

- probe proves the feature or hardware virtualization is absent →
  **fall back to the platform default backend**, as FR-029 states; `status`
  records the fallback and its reason.
- probe unavailable for any other reason, or a VM failure at run time →
  `IsolationUnavailable`, fail closed, no silent retry on another backend.
- `auto` never selects the VM backend (it stays default-or-hardened).

## 2. Common shape

The VM is an outer boundary; **inside it runs the unchanged platform backend**
(AppContainer on Windows, Bubblewrap on Linux), so grants, `netpolicy`, bait,
limits and the activity report are the same code and the same evidence as
default mode. The host side is a thin `SandboxBackend`:

```text
host: stage job dir (as today) → write guest job.json (guest paths) → start VM
guest: launcher = fail2commit sandbox launch (SPEC-018 §3.4, flag --vm-guest)
       → platform backend runs the job → outcome.json into the shared job dir
       → --vm-guest powers the VM off
host: wait outcome.json + VM process exit → revoke nothing (VM is disposable)
      → run_job exports from the host work_dir after Exited(0), unchanged
```

- Job dir: the user's per-job stage dir, shared into the VM. `job.json` carries
  **guest** paths; the host keeps its own `JobSpec` for export. Host paths never
  appear in the guest spec.
- `outcome.json`: SPEC-018 §6 transport, reused as-is (serde `JobOutcome`,
  base64 stdio). Missing/invalid outcome → `IsolationUnavailable`, no export.
- One VM at a time per user: the existing `sandbox-job` lock serializes
  (Windows Sandbox is single-instance per session anyway).
- Timeout: the host kills the VM process at `limits.timeout` + a boot grace;
  `JobStatus::TimedOut`, no export.

## 3. Windows: Windows Sandbox (WSB)
**Current implementation status (2026-11-14): Windows VM selection is unavailable.** The active
preflight checks firmware virtualization only: proven absence may use the documented
platform fallback; otherwise it returns `IsolationUnavailable` because WSB instance
lifecycle correlation and trusted guest-context verification are not implemented.
It returns before feature queries, install-path checks, mappings, or VM launch, so
unknown feature state and permission errors never trigger fallback. The design below
is a target only and does not describe an available Windows backend; activation
requires bounded feature probing plus lifecycle/context proof and VM validation.


### 3.1 Planned launch (inactive)

- Generate a `.wsb` configuration:
  - `MappedFolder` per `read_only` tree → `C:\f2c\in\<n>`, `ReadOnly=true`;
  - `MappedFolder` work_dir → `C:\f2c\work`, read-write (this **is** the host
    stage dir, so exports need no copy-back);
  - `MappedFolder` the fail2commit install dir → `C:\f2c\bin`, read-only;
  - `Networking`: `Enable` for `internet`, `Disable` for `none` (the inner
    AppContainer enforces the policy either way; `Disable` is defence in depth);
  - `MemoryInMB` from `limits.memory_bytes` + guest headroom;
  - `LogonCommand`: `C:\f2c\bin\fail2commit.exe sandbox launch C:\f2c\work\job.json --vm-guest`.
- Start `WindowsSandbox.exe <config.wsb>`; wait for `outcome.json`, then for the
  Windows Sandbox process to exit (`--vm-guest` runs `shutdown /s /t 0` after
  writing the outcome). Kill the process tree on timeout or outcome failure.
- The inner backend runs exactly as on the host: fresh AppContainer profile,
  bait in the guest job home, monitor, report. Its stage root lives in the
  disposable guest — nothing to clean on the host.

### 3.2 Current probe gate (unavailable)

No external feature query is active. With firmware virtualization present, probe
returns unavailable for the unimplemented WSB instance lifecycle and guest-context
gates, before inspecting feature state or touching job mappings. Unknown support and
permission errors are not evidence of feature absence and therefore do not fall back.
Only proven firmware virtualization absence takes the documented fallback. Enabling
the design in 3.1 requires a bounded, trusted feature probe and proven lifecycle and
guest-context binding, followed by VM-backed validation.
### 3.3 Limits of the mechanism (recorded)

- WSB needs an interactive desktop session (LESSONS: batch/guest-ops logon
  cannot drive it); the VM gate runs with auto-logon.
- WSB inside a VMware guest needs nested virtualization exposed to the guest
  (`vhv.enable = "TRUE"`); the gate VMs must be configured for it.
- No hidden/windowless mode: the sandbox window is visible while a job runs.
  Acceptable for a Could backend; recorded, not worked around.

## 4. Linux: QEMU/KVM micro-VM

### 4.1 Prepare (root, once): `fail2commit vm prepare | status | remove`

- Kernel: the host's running distro kernel (`/boot/vmlinuz-$(uname -r)`), so
  guest and host userland match. No kernel is bundled (no GPL source-offer
  burden).
- Initramfs: assembled from trusted host binaries and their library closure
  (`ldd`): `fail2commit`, `f2c-sandbox-relay`, `bash`, `bwrap`, `setpriv`,
  busybox (or coreutils equivalents), plus an init script. Stored under
  `/var/lib/fail2commit-vm/`, root-owned; kernel path + hashes recorded in
  `/etc/fail2commit-vm.json`. `vm remove` deletes both, idempotent.
- The job's toolchain and system userland are **not** copied: the host's `/usr`
  (and `/lib`, `/lib64`, `/bin` where not merged-usr) is shared read-only over
  9p and bound by the inner bwrap at the same paths, so staged native builds
  link against the same libraries as on the host.

### 4.2 Launch

```text
qemu-system-x86_64 -M microvm -kernel <recorded> -initrd <prepared>
  -append "console=ttyS0 quiet" -m <memory+headroom> -smp 2 -no-reboot -nographic
  -virtfs local,path=<jobdir>,mount_tag=f2cjob,security_model=passthrough
  -virtfs local,path=/usr,mount_tag=f2cusr,security_model=none,readonly=on  (+ /lib* as needed)
  -netdev user,id=n,restrict=<on for none | off for internet>
  -device virtio-net-pci,netdev=n
```

- Guest init: mount the 9p shares, run `fail2commit sandbox launch
  /f2c/job/job.json --vm-guest`, then `poweroff -f`. `-no-reboot` makes qemu
  exit when the guest powers off.
- Inner Bubblewrap: SPEC-013 unchanged (proxy + relay enforce `internet`;
  `none` has no route). Slirp `restrict=on` is defence in depth for `none`.
  No host firewall state is touched.
- Host waits for `outcome.json` + qemu exit; kills qemu on timeout. The VM is
  a process: gone means no qemu process and no VM disk (there is none —
  initramfs + shares only).

### 4.3 Probe (cached)

`qemu-system-x86_64` present; `/dev/kvm` accessible; prepared initramfs +
recorded kernel exist and hash-match; 9p support available (`9pnet_virtio`,
`9p`, `virtio` modules/built-in). Any missing → unavailable, reason named →
§1 fallback. `vm prepare` missing is reported as "run fail2commit vm prepare".

## 5. Edge cases

| Case | Result |
|---|---|
| feature / KVM absent | probe unavailable → platform default backend (FRD), reason in `status` |
| VM process killed mid-job | `IsolationUnavailable`, no export; next job starts a fresh VM |
| guest hangs before outcome | host timeout kills the VM, `TimedOut`, no export |
| outcome.json missing/invalid/oversized | `IsolationUnavailable`, no export |
| guest powers off without outcome | `IsolationUnavailable`, no export |
| second concurrent job | waits on the `sandbox-job` lock |
| WSB already running (another session) | launch fails → `IsolationUnavailable`, named reason |
| `vm prepare` without root | `rejected`, nothing created |
| kernel updated after prepare | hash mismatch → probe unavailable, "run vm prepare again" |
| host paths in guest job.json | rejected by the guest launcher before launch (validation) |

## 6. Acceptance criteria → test cases

| FR-029 criterion | TCs |
|---|---|
| with the feature, `backend = vm` passes the catalogue suite | TC-029-2, TC-029-3, TC-029-5, TC-029-6 |
| the VM is gone after the job | TC-029-4, TC-029-7, TC-029-8 |
| without hardware virtualization the other backends are used | TC-029-1 |

## 7. Files expected to change

- `crates/fail2commit-core/src/sandbox/vm.rs` + `vm/` (new): host backend,
  `wsb.rs` (Windows), `qemu.rs` (Linux), `prepare.rs` (initramfs assembly).
- `crates/fail2commit-core/src/sandbox/mod.rs`: `vm` arm of `select_backend`
  (with SPEC-018).
- `crates/fail2commit/src/cmd/vm.rs` (new): `vm prepare | status | remove`;
  `main.rs`, `cmd/mod.rs` routing. Guest launcher reuses SPEC-018's
  `sandbox launch --vm-guest` (poweroff after outcome).
- `crates/fail2commit/tests/sandbox_vm_windows.rs`, `sandbox_vm_linux.rs`
  (new); existing hostile suites accept `F2C_SANDBOX_BACKEND=vm`.
- `packaging/`: nothing bundled for the VM (host kernel + host binaries);
  document `qemu-system-x86_64` and KVM as optional runtime dependencies.
- Docs: `docs/sandbox-policy.md`, `docs/windows.md`, `docs/sandbox-linux.md`;
  SPEC-018 §1/§8 `vm` rows point here.

## 8. Test cases

VM-gated (Windows: WSB feature + nested virtualization + interactive session;
Linux: `/dev/kvm`), in the VM gate, not on the host. Unit tests run anywhere.

| TC | Given / When / Then | Type / path |
|---|---|---|
| TC-029-1 | Given no WSB feature / no KVM, When `backend = vm`, Then the probe names the reason and the platform default backend runs the job; `status` records the fallback | unit + integration, `vm::tests::selection_falls_back_without_virtualization` |
| TC-029-2 | Given Windows with WSB and `backend = vm`, When the hostile catalogue runs (`F2C_SANDBOX_BACKEND=vm`), Then every default-mode containment result holds | e2e, `sandbox_hostile_windows` vm run |
| TC-029-3 | Given Linux with KVM and a prepared initramfs, When the catalogue runs, Then every default-mode result holds | e2e, `sandbox_hostile_linux` vm run |
| TC-029-4 | Given a completed vm job, Then no WindowsSandbox/qemu process remains and no VM state file is left; the host stage dir holds only the job's own files | integration, `sandbox_vm_*::vm_is_gone_after_the_job` |
| TC-029-5 | Given `internet` and `none` modes in the VM, Then public fetches succeed through the inner backend's policy and loopback/private/listen attempts are refused, with the same report kinds as default mode | e2e, catalogue network rows under vm |
| TC-029-6 | Given bait enabled in the VM, When the job touches a bait file, Then the job is killed, the report carries the `Bait` entry and findings deny, and nothing is exported | e2e, catalogue bait rows under vm |
| TC-029-7 | Given a job that exceeds its timeout, Then the host kills the VM, status is `TimedOut` and nothing is exported | integration, `sandbox_vm_*::timeout_kills_the_vm` |
| TC-029-8 | Given the VM process killed mid-job, Then the host reports `IsolationUnavailable`, exports nothing and the next job starts a fresh VM | integration, `sandbox_vm_*::killed_vm_fails_closed` |
| TC-029-9 | Given a clean vm job with exports, Then `run_job` exports only after `Exited(0)` from the host work_dir, with the usual link/size validation | integration, `sandbox_vm_*::exports_after_clean_exit` |
| TC-029-10 | Given root, When `vm prepare` runs twice and `vm remove` runs twice, Then the initramfs + state are created idempotently and removed completely; without root, `rejected` | integration, `sandbox_vm_linux::prepare_and_remove` |
| TC-029-11 | Given a guest job.json containing host paths, Then the guest launcher rejects it before running anything | unit, `vm::tests::guest_paths_are_validated` |
| TC-029-12 | Given a kernel update after prepare, Then the probe reports the hash mismatch and names `vm prepare` | unit, `vm::tests::stale_prepare_fails_closed` |

## 9. Known limits (for the catalogue table and the owner)

- Windows editions without WSB can fall back only after a trusted probe proves
  the feature is absent; current Windows preflight deliberately performs no
  feature query and reports the lifecycle/context implementation gap instead.
- The WSB window is visible during jobs; no hidden automation API exists.
- Linux guests need `qemu-system-x86_64` installed (documented optional
  dependency) and a prepared initramfs (one root command).
- VM boot adds seconds per job; the Could priority accepts this. P-202-style
  overhead numbers are recorded in the verify report, not optimized here.
- Nested-virtualization gate configuration is a tester prerequisite, not a
  product feature.
