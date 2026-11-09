# Setup

Extract the ZIP and open the fail2commit folder. It contains no inherited Git history, remotes, or workspace credentials. Initialize a new local repository before creating Orca worktrees.

```sh
git init -b main
git add .
git commit -m "CHORE-001: import fail2commit implementation scaffold"
git config core.hooksPath .githooks
```

Use Git and Python 3 for scaffold checks. Install stable Rust and Cargo for implementation. Product testing also needs Node/npm, Python/pip, VS Code, NSIS on Windows, and Bubblewrap and cargo-deb on Linux. Keep product hooks and test hooks separate. Review project agent hooks before trusting them in the coding client.

```sh
python -m unittest discover -s .claude/hooks -p "test_*.py"
python -m unittest discover -s .codex/hooks -p "test_*.py"
python .claude/hooks/trace_check.py
```

Planned Rust checks once Cargo is available: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`. Generate and commit Cargo.lock on the integration branch before enforcing locked builds.
