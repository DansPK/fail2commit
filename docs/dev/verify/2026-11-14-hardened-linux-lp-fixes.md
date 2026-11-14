# FR-027 Linux LP-01 through LP-03 source fixes

Date: 2026-11-14. Parent: `39334cccbab2d62cd2e6d8848ddffc911d6c403c`.

## Finding dispositions

- **LP-01, source fixed.** The ACL path reads `SO_PEERCRED` and bounded `SO_PEERGROUPS` from the authenticated Unix socket. Before it collects any ACL mutation request, a trusted non-login shell executes constant `test -x`/`test -r` predicates after dropping to the exact kernel-reported supplementary groups, GID and UID; paths remain positional arguments. It checks the caller's original and canonical read-only/work roots and cwd ancestors. The fixed service probe stage is passed only by the internal fixed `PROBE` path as a separate trusted root, and the service snapshot remains a distinct `extra` grant. A root-only test creates peer-owned stage leaves behind a root-only parent and asserts rejection, no journal, and unchanged ACLs; it is ignored until root tests are available. The non-root effective-access regression passed.
- **LP-02, source fixed with retry coverage.** Each service snapshot and fixed probe-stage TempDir shares a retention latch with `GrantGuard`; any deferred recovery or active-guard drop sets the latch, keeping both paths. New v2 journals record exact disposable-root and parent device/inode/owner identities, while v1 journals reconstruct only roots at the two fixed temporary parents for recovery after upgrade. Recovery first confirms scope death, restores available recorded ACLs, removes only identity-matching roots beneath the fixed `/run/.../jobs` or journal `probe-stages` parents, then removes the journal. Missing targets are skipped only beneath an exact recorded disposable root, covering partial cleanup and cleared `/run`; unrelated missing/replaced objects still fail closed. Regressions exercise guard-drop retention, injected restoration failure, retained journal/tree, successful retry through the production recovery-order and root-cleanup helpers, and constrained legacy-root reconstruction.
- **LP-03, source fixed and predicate independently checked.** The in-sandbox child uses `statvfs` on the actual read-only fixture and requires `ST_RDONLY` before it can emit the platform pass marker. The focused writable-filesystem predicate test passed; actual bwrap mount verification remains part of the privileged runtime probe.

## Verification evidence

Native guest: Debian `debian-f2c`; staged source `/home/dev/.cache/f2c-linux-launcher-20261114/source`; target `/home/dev/.cache/f2c-linux-launcher-20261114/target`; Rust `1.100.0`; `CARGO_INCREMENTAL=0`, dev/test debug info disabled.

| Command | Result |
|---|---|
| `cargo check -p fail2commit-core --lib --locked` | exit 0; four existing dead-code warnings |
| `cargo test -p fail2commit-core --lib sandbox::hardened::linux_acl::tests --locked` | exit 0; 11 passed, 1 root-only test ignored |
| `cargo test -p fail2commit-core --lib sandbox::hardened::service::tests --locked` | exit 0; 28 passed |
| `rustfmt --check --edition 2021 crates/fail2commit-core/src/sandbox/hardened/linux_acl.rs crates/fail2commit-core/src/sandbox/hardened/service.rs` | exit 0 |
| `git diff --check` | exit 0 |

## Runtime limits

No installed root service, actual system scope, ACL mutation/recovery, or bwrap/network effect probe was run. `sudo -n true` in the authorized guest previously exited 1 with `sudo: a password is required` as user `dev` UID 1000; no credentials were guessed and no privileged guest or host state was changed. The root-only LP-01 fixture and all privileged Linux runtime gates remain pending; Windows runtime review and other FR-027 release gates also remain open. Keep Linux hardened execution unavailable until the installed service's complete mandatory probe passes.
