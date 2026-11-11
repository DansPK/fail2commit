# Hostile script catalogue (FR-020)

Coordinator-owned. Each row is one behaviour that a lifecycle script in the catalogue test package (`tests/fixtures/hostile/`) tries. A platform passes a row when the behaviour fails or the job is killed, **nothing outside the job's stage changes**, and the install reports it (exit code, finding or activity entry). "Observed" says which activity kind (FR-026) the report must show where the platform can see it; `-` means only the failure is required.

Platforms: **W** = Windows 11 and Windows 10 (default mode and hardened mode, FR-027), **L** = Ubuntu 24.04 and Arch (default and hardened). A row that a platform cannot meet blocks the release until the owner accepts it as a known limit, recorded in the "Known limits" table below with the reason.

Test rules:

- Synthetic secrets only. Every "secret" the tests plant on the host is a marked fake created by the test, never a real file of the user running the test.
- Each test snapshots the planted host files, the user profile's top level, the checkout and (Windows) `HKCU\...\Run`, scheduled tasks and services before and after, and fails on any difference.
- Each row is its own script so one escape cannot hide another; the suite also runs all rows in one job.
- Rows run in CI on every pull request on `windows-latest` and `ubuntu-latest` where the runner allows (bubblewrap needs unprivileged user namespaces; a row the runner cannot host is run on the VMs and marked so in the verify report), and on all four platforms before a release.

## Secrets and files

| ID | Behaviour | Platforms | Observed |
|---|---|---|---|
| HB-001 | Read `~/.ssh/id_ed25519` (planted fake) of the real home | W L | file_denied |
| HB-002 | Read the real `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.config/gh/hosts.yml` (planted fakes) | W L | file_denied |
| HB-003 | Read the fail2commit state, settings, approvals and password verifier | W L | file_denied |
| HB-004 | Read a browser profile file (`Login Data`, `cookies.sqlite`, planted fakes) and a wallet folder | W L | file_denied |
| HB-005 | Read the checkout outside the package's granted inputs (`.env`, `.git/config`) | W L | file_denied |
| HB-006 | Write outside the stage: home, checkout, `%TEMP%` / `/tmp` of the host, Startup folder | W L | file_denied |
| HB-007 | Escape through links: symlink, hard link, junction and mount point created in the stage pointing outside | W L | file_denied |
| HB-008 | Replace a reviewed package file or a toolchain file in the read-only inputs | W L | file_denied |
| HB-009 | Read host environment secrets (`GITHUB_TOKEN`, `AWS_*`, `NPM_TOKEN` set by the test on the parent) | W L | - (env is cleared; only bait values exist) |
| HB-010 | Read the Windows registry for credentials (`HKCU\Software\...` planted value) and the Credential Manager | W | file_denied or blocked |

## Bait (FR-024)

| ID | Behaviour | Platforms | Observed |
|---|---|---|---|
| HB-020 | Open the bait `~/.npmrc` inside the job | W L | bait, install denied `bait_touched` |
| HB-021 | Open the bait SSH key, `.git-credentials`, AWS `credentials`, `.env` | W L | bait |
| HB-022 | Put a bait environment value into a host name it resolves or connects to | L (W hardened) | bait |
| HB-023 | Send a bait value in an unencrypted HTTP request to a public address | L (W hardened) | bait |
| HB-024 | A clean native build (node-gyp addon, esbuild, sharp) touches no bait | W L | no bait entry (false-positive check) |

## Network (FR-023)

| ID | Behaviour | Platforms | Observed |
|---|---|---|---|
| HB-030 | HTTPS GET to `registry.npmjs.org` succeeds when `sandbox.network = internet` | W L | net_allowed |
| HB-031 | Same with `sandbox.network = none` fails | W L | net_refused |
| HB-032 | Connect to 127.0.0.1 and ::1 (a listener the test runs on the host) | W L | net_refused |
| HB-033 | Connect to the host's LAN address, its gateway, 10/8, 172.16/12, 192.168/16, 100.64/10 | W L | net_refused |
| HB-034 | Connect to 169.254.169.254 and fd00:ec2::254 (metadata), fe80::/10, fc00::/7 | W L | net_refused |
| HB-035 | Resolve a name that answers 127.0.0.1 or a private address (test DNS name or hosts entry), then connect | W L | net_refused |
| HB-036 | Listen on a TCP or UDP port | W L | net_refused |
| HB-037 | UDP to a public address other than DNS; multicast and broadcast | W L | net_refused for multicast/broadcast; UDP to public allowed only if the platform's internet mode allows it, recorded |
| HB-038 | Connect to the fail2commit approval pipe / relay port, a Unix socket in the host's runtime dir, the Docker socket, D-Bus | W L | net_refused or file_denied |
| HB-039 | Raw sockets, `AF_PACKET`, `AF_NETLINK` route changes | L | blocked |

## Process and persistence

| ID | Behaviour | Platforms | Observed |
|---|---|---|---|
| HB-040 | Start a detached child (`setsid`, double fork, `start /b`, `DETACHED_PROCESS`) that is still alive after the install | W L | process; child gone when the job ends |
| HB-041 | Create a scheduled task / cron entry / systemd user unit / Run key / Startup shortcut | W L | file_denied or blocked |
| HB-042 | Breakaway from the job (`CREATE_BREAKAWAY_FROM_JOB`) or the cgroup | W L | blocked |
| HB-043 | Debug or inject into another process of the user (`ptrace`, `OpenProcess` + `WriteProcessMemory`) | W L | blocked |
| HB-044 | Signal or kill a process outside the job | W L | blocked |
| HB-045 | Start a COM / WMI process creation (`Win32_Process.Create`) or a shell broker | W | blocked |

## Resources

| ID | Behaviour | Platforms | Observed |
|---|---|---|---|
| HB-050 | Fork bomb | W L | limit |
| HB-051 | Allocate past the memory limit | W L | limit |
| HB-052 | Run past the job timeout | W L | limit |
| HB-053 | Write past the stage disk limit | W L | limit |
| HB-054 | Print past the output limit | W L | limit (output truncated) |

## Kernel and desktop surface

| ID | Behaviour | Platforms | Observed |
|---|---|---|---|
| HB-060 | `bpf`, `userfaultfd`, `perf_event_open`, `keyctl`/`add_key`, `io_uring_setup`, `kexec_load`, `init_module` | L | blocked |
| HB-061 | `mount`, `unshare`/`clone` with new namespaces, `pivot_root`, `chroot` inside the job | L | blocked |
| HB-062 | `personality`, `ptrace(PTRACE_TRACEME)` tricks, `/proc/self/mem` writes to other processes | L | blocked |
| HB-063 | Read or write the clipboard | W | blocked |
| HB-064 | Send input to or read another window (`SendInput`, `SetWindowsHookEx`, `PrintWindow` / screenshot) | W | blocked |
| HB-065 | Load a DLL from the stage into the toolchain process (DLL planting next to `node.exe` / `python.exe`) | W | blocked |
| HB-066 | Read files only "ALL APPLICATION PACKAGES" can read (for example under `C:\Program Files`) where they hold user data | W | file_denied under LPAC |

## Host safety (FR-020 last criterion)

| ID | Behaviour | Platforms | Observed |
|---|---|---|---|
| HB-070 | Kill fail2commit (and the hardened service) mid-job: the job dies, no firewall rule, account session, ACL grant or mount stays, the host network works | W L | - |
| HB-071 | Power-cycle the VM mid-job: the host boots normally and the next run cleans up leftovers | W L | - |

## Known limits

| ID | Platform | Reason | Owner accepted |
|---|---|---|---|
| (none yet) | | | |
