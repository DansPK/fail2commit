# fail2commit task board
Coordinator owns this file and marks claims on the integration branch before dispatch. Workers use the claim in their task brief and do not edit this board. The coordinator may copy the claim into the worker baseline so edit guards see it.
| ID | Task | Req IDs | Owner | Status | Depends on |
|---|---|---|---|---|---|
| T-001 | Guard Git pushes | FR-001, SPEC-001 | - | ready | CHORE-001 |
| CHORE-001 | Finalize workspace contracts, CLI routing and CI entry points | - | - | ready | - |
| T-002 | Approve exact operations | FR-002, SPEC-002 | - | ready | CHORE-001 |
| T-003 | Enforce protected remote updates | FR-003, SPEC-003 | - | ready | T-001, T-002 |
| T-004 | Guard npm installs | FR-004, SPEC-004 | - | ready | T-006, T-007 |
| T-005 | Guard pip installs | FR-005, SPEC-005 | - | ready | T-006, T-007 |
| T-006 | Scan packages and scripts | FR-006, SPEC-006 | - | ready | CHORE-001 |
| T-007 | Isolate build scripts | FR-007, SPEC-007 | - | ready | CHORE-001 |
| T-008 | Manage sandbox policy | FR-008, SPEC-008 | - | ready | T-007 |
| T-009 | Ship Windows desktop integration | FR-009, SPEC-009 | - | ready | T-002, T-008 |
| T-010 | Integrate VS Code | FR-010, SPEC-010 | - | ready | T-002, T-004, T-005, T-008 |
| T-011 | Ship reproducible releases | FR-011, SPEC-011 | - | ready | T-003–T-010 |
| T-012 | Keep resource use bounded | NFR-012, SPEC-012 | - | ready | T-004, T-005, T-007, T-009 |
