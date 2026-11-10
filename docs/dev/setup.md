# Development setup

## Prerequisites

You always need:
- Git
- Rust stable, with `rustfmt` and `clippy`

Some tests also need:

| Area | Needs |
|---|---|
| npm and pip guards | Node.js with npm, and Python with pip |
| Linux sandbox | `bubblewrap`, plus a systemd user session for the cgroup v2 limits |
| Windows installer | NSIS 3.11 (`packaging/windows/build.ps1` looks for a portable copy in `target/nsis`) |
| Linux packages | Docker (the `.deb` and Arch package build in containers) |
| VS Code extension | Node.js 20 or later |
| Release notices | Python 3 (`scripts/release/notices.py`) |

## Clone, build and test

```sh
git clone https://github.com/DansPK/fail2commit.git
cd fail2commit
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

- Sandbox and end-to-end tests skip themselves when their platform prerequisite is missing. A skipped test counts as pending evidence, not a pass.
- On Linux under WSL or Docker, see [sandbox-linux.md](../sandbox-linux.md) and [e2e.md](e2e.md).

## Project records

| Record | Where |
|---|---|
| Requirements (FR/NFR IDs) | [requirements/](requirements/) |
| Specs | [specs/](specs/) |
| Test plan | [tests/TEST-PLAN.md](tests/TEST-PLAN.md) |
| Requirement → spec → test → verify matrix | [traceability.md](traceability.md) |
| Behaviour changes | [change-requests.md](change-requests.md) |
| Test evidence and security reviews | [verify/](verify/README.md) |
| What was delivered, and lessons learned | [DONE.md](DONE.md), [LESSONS_LEARNED.md](LESSONS_LEARNED.md) |

## Release builds

See [release.md](release.md). The `release-candidate` GitHub workflow builds every package and checks each one in a clean container.
