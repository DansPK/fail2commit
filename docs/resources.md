# Resource use (NFR-012, SPEC-012, TC-012)

fail2commit runs on demand. Linux has no daemon and no idle sandbox. The only
resident process is the Windows tray. This page records measured numbers, the
configured limits, proposed defaults and known gaps. Raw data and exact
commands: `docs/verify/VERIFY-2026-11-09-resources.md`.

Re-run: `scripts/bench/run.ps1` (Windows), `scripts/bench/run.sh` +
`scripts/bench/privileged.sh` (Linux). Results land in `target/bench/`.

## Hosts and fixtures

| | Windows | Linux |
|---|---|---|
| OS | Windows 11 Pro 10.0.26200 | WSL2 Ubuntu (kernel 6.18.54.1-microsoft-standard-WSL2), glibc 2.43; sandbox build in `rust:1` (Debian 13, glibc 2.41) `--privileged` |
| CPU / RAM | i7-8700 (12 threads), 47.9 GB | WSL: 4 vCPUs, 15.6 GB |
| Tools | rustc 1.99.1, git 2.56.0.windows.2, Python 3.12.10 | rust:1 image (cargo -j 2), git 2.53.0, bwrap 0.12 (container) |
| Build | `cargo build --release -j 2`, base commit 3d924c1 | same, in `rust:1` |

Fixtures (all generated, disposable, deterministic seed): secret-scan repos of
9.7 MB and 82.6 MB (10 commits of 64 KiB low-entropy text files, no remote);
advisory lookups of 50, 200 and 500 `npm:pkg-N@1.0.0` against a loopback OSV
stub that returns clean results. Sandbox build: `tests/fixtures/sandbox/native/hello.c`,
`gcc -O2`. Nothing touches the network except 127.0.0.1.

## Measured

Cold = first launch with a fresh home (OS file cache is not flushed, no admin
needed). Warm = median of N repeats (N = 20; scans 6). p95 over the same runs.

| Measure | Windows | Linux (WSL) |
|---|---|---|
| `fail2commit` release size | 13,726,979 B (13.1 MiB) | 9,871,736 B (9.4 MiB) |
| `fail2commit-tray` release size | 12,334,836 B (11.8 MiB) | n/a (Windows only) |
| `--version` cold / warm median / p95 | 11.8 / 10.9 / 37.0 ms | 1.5 / 1.4 / 1.7 ms |
| `status` cold / warm median / p95 | 47.9 / 54.0 / 94.8 ms | 79.0 / 78.1 / 92.5 ms |
| Tray idle RAM at 5 s | working set 18.2 MiB, private 1.7 MiB | n/a |
| Tray idle RAM at 60 s | working set 23.6 MiB, private 2.4 MiB; 7 threads, 214 handles | n/a |
| `secret-scan` 9.7 MB, 10 commits: cold / warm median / p95 | 519 / 641 / 1122 ms | 67 / 66 / 69 ms |
| `secret-scan` 82.6 MB, 10 commits: cold / warm median / p95 | 1257 / 1398 / 2160 ms | 440 / 426 / 441 ms |
| `scan` 50 pkgs, empty cache / warm median | 236 / 17.0 ms | 6.9 / 2.1 ms |
| `scan` 200 pkgs, empty cache / warm median | 885 / 41.8 ms | 42 / 3.2 ms |
| `scan` 500 pkgs, empty cache / warm median | 2606 / 43.7 ms | 213 / 5.8 ms |
| Stub requests, cold / warm (500 pkgs) | 8 / 0 | 8 / 0 |
| Advisory cache after 50 / 200 / 500 lookups | 1,700 / 6,800 / 17,000 B (50 / 200 / 500 files, 34 B each) | same |
| Native build peak memory (sandbox) | Not measured yet (the AppContainer backend has landed; re-run the Windows bench) | 22,960 to 23,164 KB largest process (5 runs), gcc 0.04 s, 0.10 s wall incl. staging and export |

Notes on method and limits of the evidence:

- Windows `--version` p95 (37 ms) comes from a few slow runs among 20; quote the median. Windows `secret-scan` warm is not faster than cold: the cost is dominated by the repeated `git` process spawns, not by anything cached (cause not isolated).
- The advisory cache entries here are clean results (`[]`, 34 B). Real
  vulnerability records are larger (the per-entry cap is 1 MiB) and are not
  measured, so the byte figures are a floor.
- The native build fixture is tiny. 23 MB is the floor for a gcc run, not a
  size for a real native module build. No evidence here supports lowering
  `job_memory_mb`.
- Sandbox peak memory is the largest single process (cc1/as/ld) measured by
  `getrusage` inside the sandbox. Measuring from outside bwrap undercounts
  (14 MB vs 23 MB), so the harness measures inside.
- The container leg has no systemd, so only rlimits apply there. The WSL leg
  uses cgroup v2 limits. Memory numbers were taken in the container leg.

### Pending

- Windows sandbox native-build memory: not measured yet. The AppContainer
  backend has landed, but the Windows leg still needs a native fixture that the
  AppContainer job can build: add one to `bench.py` `native_build` (the current
  fixture needs `/usr/bin/gcc` and python3), then re-run
  `scripts/bench/run.ps1 -SkipBuild`.
- Peak memory of a realistic (not hello-world) native build on either OS.
- `run` input staging cost (`artifact_max_bytes`, `graph_max_nodes` copy
  budget) and `job_timeout_secs` have no measurement.

## Configured limits

Read from the trusted `settings.toml` only. A malformed value fails closed
(`invalid_input`, exit 2). Current defaults in `crates/fail2commit-core/src/settings.rs`:

| Setting | Default | Bounds |
|---|---|---|
| `limits.job_timeout_secs` | 900 | wall time of one sandboxed job |
| `limits.job_memory_mb` | 2048 | job memory (cgroup v2 where available, else rlimit) |
| `limits.job_max_processes` | 64 | processes in a job |
| `limits.job_max_output_bytes` | 8 MiB | captured job output (reported as truncated) |
| `limits.scan_max_bytes` | 256 MiB | blob bytes read per Git secret scan |
| `limits.graph_max_nodes` | 100,000 | commits, packages or staged entries per operation |
| `limits.artifact_max_bytes` | 512 MiB | one downloaded or staged artifact; also the `run --input` copy budget |
| `advisories.cache_max_bytes` | 16 MiB (was 64 MiB; applied from the proposal below) | advisory cache (oldest entries evicted first) |
| `advisories.ttl_secs` / `timeout_secs` | 6 h / 15 s | cache expiry; OSV request timeout |

Incomplete versus clean is observable through `--json`: an exhausted scan
budget returns `code: "incomplete_scan"`, exit 12, with a finding that states
the configured value ("blob content read budget of N bytes reached"). A clean
scan returns `code: "ok"`, exit 0. An advisory scan that cannot reach OSV and
has no cache entry is also `incomplete_scan`. `resource_bounds.rs` asserts
all three.

## Proposed defaults (coordinator to apply; `settings.rs` is not edited here)

| Setting | Current | Proposed | Reason |
|---|---|---|---|
| `advisories.cache_max_bytes` | 64 MiB | **16 MiB** | Measured entries are about 34 B (clean) and capped at 1 MiB each; 500 lookups used 17 KB. 16 MiB still holds thousands of real vulnerability records and is a smaller footprint to cap. Low risk: eviction only costs a refetch. |
| `limits.scan_max_bytes` | 256 MiB | keep | An 82.6 MB scan takes 0.44 s (Linux) and 1.4 s (Windows) warm; 256 MiB extrapolates to about 1.4 s and 4.5 s. Cheap enough that a lower cap would only cause false `incomplete_scan` results. |
| `limits.job_memory_mb` | 2048 | keep | A trivial gcc run uses 23 MB, which says nothing about real native builds. Lowering without data would fail legitimate builds. Revisit with a real build measurement. |
| `limits.job_timeout_secs` | 900 | keep | Trivial build takes 0.04 s; no evidence for a change. |
| `limits.job_max_processes` | 64 | keep | Not stressed by the fixture (a gcc run needs fewer than 10). |
| `limits.job_max_output_bytes` | 8 MiB | keep | Output is also bounded for display (64 KiB); no measurement suggests a change. |
| `limits.graph_max_nodes`, `limits.artifact_max_bytes` | 100,000 / 512 MiB | keep | Unmeasured. |
| `advisories.timeout_secs` | 15 | keep | Loopback only; real-network latency is out of scope for offline fixtures. |

Only one default changes. The rest stay because the evidence cannot justify a
different number, which is itself recorded as a gap below.

## Known gaps and findings

1. **Fixed (2026-11-09): one active sandbox build per user.** Measured
   first: two simultaneous `fail2commit run -- sleep 2` jobs finished in 2.3 s,
   so they overlapped. `sandbox::run_job` now holds a per-user lock
   (`<state>/sandbox-job.lock`) across probe, run and export, so later jobs
   wait. `resource_process.rs` `second_concurrent_build_is_queued_or_refused`
   asserts it (no longer ignored).
2. **Fixed (2026-11-09): configured limits are reported.** `fail2commit status`
   `data.limits` and `data.advisories` give the exact values in effect;
   `resource_bounds.rs` `status_reports_configured_limits` asserts it.
3. **`run` cannot bind a toolchain sysroot**, so a native build on a host with
   no root-owned gcc (WSL Ubuntu here) cannot run through the CLI. The harness
   measures the native build in the privileged `rust:1` container instead.
4. **Windows tray idle memory** was measured on one machine, one run. A
   regression threshold (for example 40 MiB working set) is not asserted in CI
   because the tray needs an interactive desktop.
5. The harness does not flush the OS file cache, so "cold" means first launch
   with a fresh home, not a cold disk.
