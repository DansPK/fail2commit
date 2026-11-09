# fail2commit task board
Coordinator owns this file and marks claims on the integration branch before dispatch. Workers use the claim in their task brief and do not edit this board. The coordinator may copy the claim into the worker baseline so edit guards see it.

Integration branch: `DansPK/f2-commit-coordinator`. Release candidate built from `4559bab` (`DansPK/f2c-release-a026090`); evidence in `docs/verify/VERIFY-2026-11-09-release.md`. Change requests CR-001 to CR-012 are in `docs/change-requests.md`.

**Concurrency limit:** run 3 workers in parallel by default, 4 only when CPU and RAM have headroom, with cargo `-j 2`; WSL/Docker is capped at 4 CPUs and 16 GB. If Codex runs out of usage, its task moves to Cline DeepSeek or Claude.

"Done" means implemented, independently security-reviewed until closed, merged, and passing the gate on both platforms. Requirement status stays `Approved` (not `Verified`) until the pending platform gates in the release report have evidence.

| ID | Task | Req IDs | Owner | Status | Depends on |
|---|---|---|---|---|---|
| CHORE-001 | Finalize workspace contracts, CLI routing and CI entry points | - | coordinator | done | - |
| T-001 | Guard Git pushes | FR-001, SPEC-001 | orca:claude-sonnet | done; GitHub-hosted CI run pending | CHORE-001 |
| T-002 | Approve exact operations | FR-002, SPEC-002 | orca:claude-opus | done; Windows interactive terminal prompt pending | CHORE-001 |
| T-003 | Enforce protected remote updates | FR-003, SPEC-003 | orca:claude-sonnet | done; GitHub rulesets pending | T-001, T-002 |
| T-004 | Guard npm installs | FR-004, SPEC-004 | orca:claude-sonnet | done | T-006, T-007 |
| T-005 | Guard pip installs | FR-005, SPEC-005 | orca:claude-sonnet | done | T-006, T-007 |
| T-006 | Scan packages and scripts | FR-006, SPEC-006 | orca:cline-deepseek | done; live OSV smoke pending | CHORE-001 |
| T-007 | Isolate build scripts: T-007a Linux Bubblewrap, export, `run`, Linux test harness | FR-007, SPEC-007 | orca:claude-opus | done | CHORE-001 |
| T-007 | Isolate build scripts: T-007b Windows AppContainer | FR-007, SPEC-007 | orca:codex, cline-deepseek | done; clean-VM interactive run passed on Windows 10 and 11; Defender false positive needs code signing; LPAC and staged MinGW build pending | CHORE-001 |
| T-008 | Manage sandbox policy | FR-008, SPEC-008 | orca:claude-sonnet | done | T-007 |
| T-009 | Ship Windows desktop integration | FR-009, SPEC-009 | orca:claude-sonnet | done; tray GUI click-through pending | T-002, T-008 |
| T-010 | Integrate VS Code | FR-010, SPEC-010 | orca:claude-sonnet | done; GUI and Remote-WSL session pending | T-002, T-004, T-005, T-008 |
| T-011 | Ship reproducible releases | FR-011, SPEC-011 | orca:codex + coordinator | done; GitHub release workflow run pending | T-003–T-010 |
| T-012 | Keep resource use bounded | NFR-012, SPEC-012 | orca:claude-sonnet | done | T-004, T-005, T-007, T-009 |
