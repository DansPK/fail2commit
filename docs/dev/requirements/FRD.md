# Functional and non-functional requirements

All listed items are in the MVP. Approved is an implementation baseline. Verified requires runtime evidence.

### FR-001 — Guard Git pushes

- **Links** PRD-001
- **Behavior** Detect force intent, actual ref rewrites and outgoing secrets.
- **Acceptance** Normal push passes. Forced refspecs, mirror rewrites and a deleted outgoing .env pause.
- **Priority** Must
- **Status:** Approved

### FR-002 — Approve exact operations

- **Links** PRD-001
- **Behavior** Support terminal, tray and extension decisions plus optional force-push password and recovery.
- **Acceptance** Wrong password denies; recovery rotates the code; changed ref tuples invalidate approval.
- **Priority** Must
- **Status:** Approved

### FR-003 — Enforce protected remote updates

- **Links** PRD-001
- **Behavior** Require trusted, one-time approval for protected self-hosted rewrites.
- **Acceptance** Direct bypass and token replay fail; approved rewrite succeeds.
- **Priority** Must
- **Status:** Approved

### FR-004 — Guard npm installs

- **Links** PRD-002
- **Behavior** Review the exact project install plan and artifacts before any package-controlled execution.
- **Acceptance** Clean installs work, malicious transitive findings pause, and cancel preserves project state.
- **Priority** Must
- **Status:** Approved

### FR-005 — Guard pip installs

- **Links** PRD-002
- **Behavior** Resolve for the selected interpreter and install only verified registry wheels.
- **Acceptance** Clean wheel install works; source and direct-reference inputs stop; no second resolution occurs.
- **Priority** Must
- **Status:** Approved

### FR-006 — Scan packages and scripts

- **Links** PRD-002
- **Behavior** Check exact versions for vulnerabilities and malware, and inspect lifecycle scripts for force-push evidence.
- **Acceptance** A known advisory prompts once; a suspicious script stays blocked; stale data is reported.
- **Priority** Must
- **Status:** Approved

### FR-007 — Isolate build scripts

- **Links** PRD-003
- **Behavior** Run allowed scripts automatically in a supported backend when enabled. Provide an explicit isolated run command.
- **Acceptance** Native build succeeds and hostile child processes cannot access secrets, network, checkout or approval channel.
- **Priority** Must
- **Status:** Approved

### FR-008 — Manage sandbox policy

- **Links** PRD-003
- **Behavior** Expose the local sandbox toggle with separate host execution consent.
- **Acceptance** On fails closed; Off skips scripts unless separately approved; workspace cannot alter policy.
- **Priority** Must
- **Status:** Approved

### FR-009 — Ship Windows desktop integration

- **Links** PRD-003
- **Behavior** Deliver a per-user NSIS setup, native tray and approval IPC.
- **Acceptance** Install, prompt, startup toggle, terminal fallback and uninstall work on Windows.
- **Priority** Must
- **Status:** Approved

### FR-010 — Integrate VS Code

- **Links** PRD-003
- **Behavior** Route guarded commands, findings, approvals and sandbox setting to the local workspace CLI.
- **Acceptance** Commands and setting work on Windows and Linux; WSL selects Linux CLI.
- **Priority** Must
- **Status:** Approved

### FR-011 — Ship reproducible releases

- **Links** PRD-003
- **Behavior** Deliver Windows setup, Debian package, Linux source and VSIX with platform verification.
- **Acceptance** Artifacts install cleanly and can be removed without deleting third-party integrations.
- **Priority** Must
- **Status:** Approved

### NFR-012 — Keep resource use bounded

- **Links** PRD-003
- **Behavior** Measure startup, idle tray memory, peak scan/build memory and disk cache. No idle sandbox or Linux daemon.
- **Acceptance** Record cold/warm results and configured memory/time/output/cache limits on both platforms.
- **Priority** Must
- **Status:** Approved
