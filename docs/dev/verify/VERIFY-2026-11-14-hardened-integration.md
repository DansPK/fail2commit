# Hardened source integration verification

Reviewed source `155e823240ddfad0cd29c0f0db92f9658a5644f4` merged into `DansPK/f2c-0.1.4` after Sol source acceptance (`6c4503a`). Formatting was normalized at `a8a31ab`; platform/diagnostic helper cfgs were scoped at `479ee6a`.

- `cargo check --workspace --all-targets --locked`: exit 0 (1m 29s), with four dead-code warnings before helper cfg cleanup.
- `cargo fmt --all -- --check`: exit 0 after formatting/helper cfg changes.
- `git diff --check`: exit 0.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: exit 1; 19 lint failures in integrated hardened source. Assigned narrow cleanup to Luna, dispatch `ctx_841d36f054c2`; this gate is pending, not passed.

Installed root Linux and Windows runtime effects, crash/recovery/cleanup, Windows GUI/current package behavior, and the unaccepted external FirewallAPI writer limitation remain open. Windows hardened readiness remains unavailable. No release readiness or full FR-027 verification is claimed. T-015 VM implementation started in child `f2c-014-vm` using Luna, dispatch `ctx_cc8aba1a63fa`.

## Clippy gate resolved

Luna cleanup `f596e97913f48d340f8232533346ae6eb9262ba7` was reviewed as mechanical and integrated at `0eedc112bd7b813390547a210bed0eb10068a214`. Worker evidence: `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo fmt --all -- --check`, and `git diff --check` each exit 0; existing handover rejection test 1 passed. Manager diff of crates, manifests, packaging and scripts between tested worker snapshot and integrated tree is empty. Only manager documentation differs, so the same source check evidence applies without a duplicate build. Privileged runtime/platform gates remain pending.
