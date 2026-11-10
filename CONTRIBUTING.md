# Contributing

Thanks for helping. Bug reports, test results on platforms we have not covered, and pull requests are all welcome.

## Before you start

- For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening an issue.
- For a new feature or a change in behaviour, open an issue first. Behaviour is defined by approved requirements ([docs/requirements](docs/requirements/FRD.md)) and specs ([docs/specs](docs/specs/)). A change to either needs the maintainer's sign-off.
- The task board and the roadmap are in [TODO.md](TODO.md).

## Development setup

See [SETUP.md](SETUP.md) to build, test, and enable the repository's own commit hooks.

## Pull requests

- **Cite an ID in every commit message**, for example `FR-004: ...`, `BUG-012: ...` or `CHORE-001: ...`. The commit-msg hook checks this.
- **Add or update tests** for the behaviour you change. Security tests must use disposable repositories, synthetic secrets and local fixtures, never real credentials or live registries.
- **Run the checks** before you push:

  ```sh
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
  python .claude/hooks/trace_check.py
  ```

- **Platform behaviour needs evidence from the real platform.** For a change to sandbox, PATH or installer behaviour, say in the PR which OS you tested on. Windows and Linux are both release gates (see [docs/tests/TEST-PLAN.md](docs/tests/TEST-PLAN.md)).
- **Keep PRs focused**, one change per PR, and fill in the PR template.

## AI coding agents

[AGENTS.md](AGENTS.md) holds the rules for coding agents, which also apply to people. The hooks under `.claude/` and `.codex/` are development guards for this repository. They are not part of the product.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
