# fail2commit documentation

## Using fail2commit

| Document | What it covers |
|---|---|
| [install.md](install.md) | Installing, verifying the download, and removing, for each platform |
| [git-integration.md](git-integration.md) | The Git push guard: what it scans, what it asks about, and what bypasses it |
| [approval.md](approval.md) | Approval prompts, the force-push password and recovery codes |
| [npm.md](npm.md) | The npm guard (`npm ci`, `npm install`) |
| [pip.md](pip.md) | The pip guard, virtualenvs and `python -m pip` |
| [scan.md](scan.md) | Package checks: OSV advisories, known malware and script scanning |
| [sandbox-policy.md](sandbox-policy.md) | `sandbox on` / `off` and what each setting allows |
| [windows.md](windows.md) | Windows PATH order, machine-wide shims and the tray app |
| [vscode.md](vscode.md) | The VS Code extension |
| [server.md](server.md) | The self-hosted server hook that enforces protected refs for every client |

## How it works

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components and trust boundaries |
| [sandbox-linux.md](sandbox-linux.md) | The bubblewrap and cgroup v2 sandbox |
| [sandbox-windows.md](sandbox-windows.md) | The AppContainer sandbox |
| [resources.md](resources.md) | CPU, memory and disk budgets, and how they are measured |
| [e2e.md](e2e.md) | The end-to-end test harness |
| [release.md](release.md) | Building and checking release packages |

## Project records

These are the development records. You don't need them to use fail2commit.

| Path | What it holds |
|---|---|
| [requirements/](requirements/) | Business, product and functional requirements (FR/NFR IDs) |
| [specs/](specs/) | One technical spec per requirement |
| [tests/TEST-PLAN.md](tests/TEST-PLAN.md) | Test cases and the release gates for each platform |
| [traceability.md](traceability.md) | Requirement → spec → test → verify matrix |
| [change-requests.md](change-requests.md) | Behaviour changes made during implementation |
| [verify/](verify/README.md) | Test evidence and security reviews |
| [WORKFLOW.md](WORKFLOW.md), [WRITING_STANDARD.md](WRITING_STANDARD.md), [agents/](agents/) | How the work is done, and the rules for coding agents |
