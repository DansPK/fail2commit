# Agent instructions

Implement fail2commit from the approved baseline in docs/requirements and docs/specs. Read docs/ARCHITECTURE.md, TODO.md, the assigned SPEC and its tests before editing. Requirements already represent the user's authorized implementation scope. Routine engineering decisions do not need another approval. Log material behavior changes as change requests and continue independent work.

## Worktree ownership

The Orca coordinator owns shared interfaces, manifests, integration, TODO.md, DONE.md and the release decision. Freeze shared types and route stubs before parallel work. Claim tasks on the integration branch, then dispatch each worker from a base containing its claim into a distinct Git worktree and branch. Workers own only the files in their assignment, commit locally citing FR/NFR or CHORE IDs, and return their branch, SHA, changed paths, test evidence and blockers. Workers do not update the shared board or merge themselves. The coordinator integrates completed branches, resolves shared-file conflicts and reruns tests.

If child worktrees are unavailable, the coordinator can implement sequentially in one worktree. Preserve user edits. Do not reconfigure real global hooks, alter production repositories, use real secrets in fixtures, or push/publish artifacts during implementation. Template development guards under .githooks, .claude and .codex are separate from fail2commit product hooks. Keep guard copies synchronized.

## Security and verification

- Keep security policy in Rust. Treat workspace files, arguments, package metadata, script output and sandbox exports as untrusted.
- A cancelled operation cannot apply changes. A failed isolation setup cannot launch package code. A changed plan invalidates approval.
- Keep passwords, recovery codes, Git credentials and secret values out of arguments, environments and logs.
- Use offline fixtures and disposable Git remotes. Probe and test both real target platforms before marking platform behavior verified.
- Use docs/tests/TEST-PLAN.md and write reports in docs/verify/. Record exact commands, exit codes and the tested SHA. A skipped or simulated test is pending evidence. Report blockers with the exact missing prerequisite.
- Verify scaffold traceability with `python .claude/hooks/trace_check.py`. See SETUP.md for other checks and docs/WORKFLOW.md for status rules.
