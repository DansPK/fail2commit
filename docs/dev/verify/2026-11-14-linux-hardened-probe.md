# FR-027 / SPEC-018 Linux hardened probe implementation

Date: 2026-11-14  
Branch: child worktree `f2c-014-hardened`  
Base: `4bf0004e1712781637e4a2c6556989d897b8a6f7`

## Implemented

- The authenticated root service handles only a fixed `PROBE` request. It verifies the kernel
  peer UID against the recorded installer, verifies the installed sandbox account and trusted
  service executable/tools, and runs the installed launcher with fixed platform, network-effect,
  bait-trip and watchdog fixtures. The caller supplies no command, path, environment or URI.
- A passing platform probe requires the real system-scope launcher, account identity, immutable
  fixed job snapshot, Bubblewrap, read-only fixture, writable stage, resource controls, watchdog
  cancellation and confirmed scope cleanup. A passing network probe additionally requires public
  HTTP proxy access, direct IPv4/IPv6 TCP, DNS/UDP and listen refusal, private/metadata/loopback
  proxy refusal, and a bait-triggered killed outcome with no exports.
- Normal Internet launches remain rejected unless the complete service-owned network probe has
  passed. The platform and network results are reported separately; a service/unit file alone
  cannot set either result.
- Caller stage trees and every descendant must be owned by the authenticated peer. Root-owned
  inaccessible descendants are rejected before any ACL mutation. ACL journals use staged,
  synced, no-replace publication, retryable cleanup, exact-object recovery, and durable probe-scope
  markers. Marker removal requires successful kill and exact inactive-state readback; failures
  retain the refusal marker for service recovery.

## Verification evidence

Host build: `cargo check -p fail2commit --locked` — exit 0 (Windows host; Linux-only code is not
compiled by this check). `git diff --check` — exit 0.

Native guest: Debian VM `debian-f2c`, user `dev` UID 1000, Rust `1.100.0`; source staged at
`/home/dev/.cache/f2c-linux-launcher-20261114/source`. To limit guest disk usage, tests used
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_TEST_DEBUG=0`, and
`CARGO_PROFILE_DEV_DEBUG=0` with target directory
`/home/dev/.cache/f2c-linux-launcher-20261114/target`.

| Command | Result |
| --- | --- |
| `cargo check -p fail2commit --locked` | exit 0 |
| `cargo test -p fail2commit-core --lib sandbox::hardened::linux_acl::tests --locked` | exit 0; 8 passed, 1 ignored (root-only ownership fixture) |
| `cargo test -p fail2commit-core --lib sandbox::hardened::service::tests --locked` | exit 0; 27 passed |
| `cargo test -p fail2commit-core --lib sandbox::linux::proxy::tests --locked` | exit 0; 4 passed |
| `cargo test -p fail2commit-core --lib sandbox::egress::tests --locked` | exit 0; 2 passed |

The ACL tests include partial-write/file-sync/publication/parent-sync fault injection, cleanup
retry, preservation of a pre-existing colliding journal, peer-owner policy, and path-substitution
rejection. Service tests require real effect events and a killed bait outcome, and inject failed
watchdog kill/inactive-readback paths.

## Pending runtime gates

No root-installed service or sandbox job was run. On the authorized Debian guest,
`sudo -n true` returned exit 1 (`sudo: a password is required`) as `dev` UID 1000; credentials were
not guessed and no guest or host privileged state was changed. The root-only root-owned-descendant
ACL test remains ignored, and actual root service/account installation, scope/cgroup effect probes,
Bubblewrap+seccomp filesystem/network effects, bait cancellation, cleanup-after-crash, and Internet
activation remain unverified. Until those exact installed-service probes pass, the backend must
continue to report unavailable and must reject Internet jobs.

Remaining beyond this Linux code milestone: complete Windows runtime probe/review gates and finish
the broader FR-027 release review; this report does not claim FR-027 is complete.
