# Development setup

## Prerequisites

You always need:
- Git and Python 3
- Rust stable, with `rustfmt` and `clippy`

Some tests also need:

| Area | Needs |
|---|---|
| npm and pip guards | Node.js with npm, and Python with pip |
| Linux sandbox | `bubblewrap`, plus a systemd user session for the cgroup v2 limits |
| Windows installer | NSIS 3.11 (`scripts/release/` and `packaging/windows/build.ps1` use a portable copy) |
| Linux packages | Docker (the `.deb` and Arch package build in containers) |
| VS Code extension | Node.js 20 or later |

## Clone and enable the repository hooks

```sh
git clone https://github.com/DansPK/fail2commit.git
cd fail2commit
git config core.hooksPath .githooks
```

`.githooks` holds this repository's own development checks: commit-msg (the requirement ID), pre-commit and pre-push. They are separate from the hooks that fail2commit installs for users.

## Build and test

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Scaffold and traceability checks:

```sh
python -m unittest discover -s .claude/hooks -p "test_*.py"
python -m unittest discover -s .codex/hooks -p "test_*.py"
python .claude/hooks/trace_check.py
```

- Sandbox and end-to-end tests skip themselves when their platform prerequisite is missing. A skipped test counts as pending evidence, not a pass.
- On Linux under WSL or Docker, see [docs/sandbox-linux.md](docs/sandbox-linux.md) and [docs/e2e.md](docs/e2e.md).

## Release builds

See [docs/release.md](docs/release.md). The `release-candidate` GitHub workflow builds every package and checks each one in a clean container.
