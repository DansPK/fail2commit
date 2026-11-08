# fail2commit task board
Coordinator owns this file and marks claims on the integration branch before dispatch. Workers use the claim in their task brief and do not edit this board. The coordinator may copy the claim into the worker baseline so edit guards see it.

Integration branch: `DansPK/f2-commit-coordinator`. Contracts frozen at CHORE-001 (`fe411ba`); workers build against the frozen area APIs, so "Depends on" is the integration order, not a dispatch gate. Candidate merges land on `DansPK/f2c-int-wave1` and reach the integration branch only after the full gate and an independent security review.

**Concurrency limit:** the host lagged with ~10 parallel worktrees, and some agents crashed. Run at most 3 workers at once with cargo `-j 2`. Paused tasks keep their uncommitted work in their worktree and resume in the order below as slots free.

| ID | Task | Req IDs | Owner | Status | Depends on |
|---|---|---|---|---|---|
| CHORE-001 | Finalize workspace contracts, CLI routing and CI entry points | - | coordinator | done | - |
| T-001 | Guard Git pushes | FR-001, SPEC-001 | orca:claude-sonnet | review (candidate wave 1) | CHORE-001 |
| T-002 | Approve exact operations | FR-002, SPEC-002 | orca:claude-opus | review (candidate wave 1) | CHORE-001 |
| T-003 | Enforce protected remote updates | FR-003, SPEC-003 | orca:claude-sonnet | review (candidate wave 1) | T-001, T-002 |
| T-004 | Guard npm installs | FR-004, SPEC-004 | orca:claude-sonnet | in-progress | T-006, T-007 |
| T-005 | Guard pip installs | FR-005, SPEC-005 | orca:claude-sonnet | done on branch (cf42f28); awaiting wave-2 review | T-006, T-007 |
| T-006 | Scan packages and scripts | FR-006, SPEC-006 | orca:cline-deepseek | in-progress (resumed on Cline DeepSeek) | CHORE-001 |
| T-007 | Isolate build scripts: T-007a Linux Bubblewrap, export, `run`, Linux test harness | FR-007, SPEC-007 | orca:claude-opus | in-progress | CHORE-001 |
| T-007 | Isolate build scripts: T-007b Windows sandboxrs-windows AppContainer | FR-007, SPEC-007 | orca:codex | pending (paused for host load; Opus 5.5 safeguard flagged it; partial FFI work in f2c-t007b-sandbox-windows; resume 2nd on Codex, Cline DeepSeek if refused) | CHORE-001 |
| T-008 | Manage sandbox policy | FR-008, SPEC-008 | orca:claude-sonnet | review (candidate wave 1) | T-007 |
| T-009 | Ship Windows desktop integration | FR-009, SPEC-009 | orca:claude-sonnet | review (candidate wave 1) | T-002, T-008 |
| T-010 | Integrate VS Code | FR-010, SPEC-010 | orca:claude-sonnet | review (candidate wave 1) | T-002, T-004, T-005, T-008 |
| T-011 | Ship reproducible releases: prep (Linux .deb, source tarball, notices, hashes, release CI); final artifact run by coordinator after integration | FR-011, SPEC-011 | orca:codex | pending (paused for host load; resume 3rd) | T-003â€“T-010 |
| T-012 | Keep resource use bounded | NFR-012, SPEC-012 | - | ready | T-004, T-005, T-007, T-009 |
