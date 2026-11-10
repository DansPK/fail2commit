# Contributing

Thanks for helping. Bug reports, test results on platforms we have not covered, and pull requests are all welcome.

## Before you start

- For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening an issue.
- For a new feature or a change in behaviour, open an issue first. Behaviour is defined by the approved [requirements](docs/dev/requirements/FRD.md) and [specs](docs/dev/specs/). A change to either needs the maintainer's sign-off and an entry in [change-requests.md](docs/dev/change-requests.md).
- The roadmap and task board are in [TODO.md](TODO.md).

## Development setup

See [docs/dev/setup.md](docs/dev/setup.md) for the prerequisites, how to build and how to run the tests.

## Pull requests

- **Start each commit message with an ID:** the requirement, bug or chore it serves. For example `FR-004: ...`, `BUG-012: ...` or `CHORE-001: ...`.
- **Add or update tests** for the behaviour you change. Security tests must use disposable repositories, synthetic secrets and local fixtures. Never use real credentials or live registries.
- **Run the checks** before you push:

  ```sh
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
  ```

- **Test platform behaviour on the real platform.** For a change to sandbox, PATH or installer behaviour, say in the PR which OS you tested on. Windows and Linux are both release gates (see [TEST-PLAN.md](docs/dev/tests/TEST-PLAN.md)). Record the evidence in a report under [docs/dev/verify/](docs/dev/verify/README.md).
- **Keep each PR to one change**, and fill in the PR template.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
