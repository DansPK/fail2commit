# fail2commit

fail2commit is a free, open-source Rust guard for Git pushes and npm or pip installs on Windows, Linux, and VS Code. It checks outbound commits for secrets, asks before force pushes, and reviews dependencies before package code can run. Allowed build scripts automatically use the configured sandbox when needed.

This archive is the implementation scaffold. Product features are specified and awaiting implementation and platform verification.

## Start here

- [AGENTS.md](AGENTS.md) contains the implementation and worktree rules.
- [Architecture](docs/ARCHITECTURE.md) describes the stack and trust boundaries.
- [Requirements](docs/requirements/FRD.md), [specs](docs/specs/), and [tests](docs/tests/TEST-PLAN.md) define the release.
- [ORCA-PROMPT.md](ORCA-PROMPT.md) is ready to paste into the coordinator.
- [SETUP.md](SETUP.md) covers fresh repository setup.

The existing template is retained under its MIT license. New fail2commit code uses Apache-2.0.
"# fail2commit" 
