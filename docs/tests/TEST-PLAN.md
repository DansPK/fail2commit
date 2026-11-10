# MVP test plan
Results for each case are in the verify reports under `docs/verify/`; start with `VERIFY-2026-11-09-release.md`. Use disposable repositories, synthetic credentials and package fixtures, and local test endpoints. Record exact commands, platform, version and results in a verification report.
| ID | Requirement | Expected evidence |
|---|---|---|
| TC-001 | FR-001 | Normal push passes. Forced refspecs, mirror rewrites and a deleted outgoing .env pause. |
| TC-002 | FR-002 | Wrong password denies; recovery rotates the code; changed ref tuples invalidate approval. |
| TC-003 | FR-003 | Direct bypass and token replay fail; approved rewrite succeeds. |
| TC-004 | FR-004 | Clean installs work, malicious transitive findings pause, and cancel preserves project state. |
| TC-005 | FR-005 | Clean wheel install works; source and direct-reference inputs stop; no second resolution occurs. |
| TC-006 | FR-006 | A known advisory prompts once; a suspicious script stays blocked; stale data is reported. |
| TC-007 | FR-007 | Native build succeeds and hostile child processes cannot access secrets, network, checkout or approval channel. |
| TC-008 | FR-008 | On fails closed; Off skips scripts unless separately approved; workspace cannot alter policy. |
| TC-009 | FR-009 | Install, prompt, startup toggle, terminal fallback and uninstall work on Windows. |
| TC-010 | FR-010 | Commands and setting work on Windows and Linux; WSL selects Linux CLI. |
| TC-011 | FR-011 | Artifacts install cleanly and can be removed without deleting third-party integrations. |
| TC-012 | NFR-012 | Record cold/warm results and configured memory/time/output/cache limits on both platforms. |
 
## Cross-platform acceptance matrix

- Git: fast-forward, both lease styles, force alias/short flag, forced wildcard/config refspec, mirror, multiple refs, tag replacement, deletion, shallow/missing objects, alternate hash format if supported, first branch and add/delete secret history. Prove existing hook failure aborts the push.
- Approval: wrong password and rate limit, reset and old recovery rejection, expiry, cancel, closed tray, non-TTY, multi-ref changes, replay and concurrent attempts. No credential or secret value in logs.
- npm/pip: clean and vulnerable/malicious transitive fixtures, mismatched bytes, stale/offline cache, source or URL bypass attempts, changed plans, canceled installs and interrupted recovery. Verify an unsupported input cannot invoke an unguarded manager path.
- Sandboxes: legitimate native build on both OSes. Hostile fixtures invoke Git and direct networking from both parent and child; test localhost and external test endpoint, secret files, fake credential sockets or handles, checkout writes, approval IPC, hostile output paths and resource/time limits. Test with runtime tracing unavailable. Test sandbox enabled, disabled, and unavailable.
- Distribution: clean install/uninstall, paths with spaces, Git for Windows shell and PowerShell, Debian/Ubuntu, source build, native VS Code on both OSes, workspace-side CLI in WSL, server receive over a disposable protected repository. Record any unsupported combinations explicitly.
