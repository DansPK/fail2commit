# SPEC-001 — Git protection

FR-001 · TC-001 · Owner paths: CLI git adapter, Git scan logic, Git integration fixtures.

Use a shim to catch explicit force intent and a pre-push hook to check each proposed old/new ref tuple. Handle --force, -f, lease forms, leading + refspecs, configured push refspecs, mirror mode and multiple refs. Let Git resolve refspecs rather than replicating its parser. Check branch ancestry using Git and treat tag replacement and deletions as separate findings. No assumption that a missing old object is safe. Scan outgoing commits, including initial branches and add/delete history, excluding only known remote-reachable history where it can be proved. Batch blob access, deduplicate, handle filename bytes, enforce bounded traversal and report incomplete scans. Check .env and .env.* with template exceptions and independent content detectors. Redact values. Chain existing hooks without losing stdin or exit status. Setup/uninstall must preserve configuration and old hooks, including effective hooksPath, worktrees and paths with spaces.

Prompt once for the approved plan where possible. Bind final confirmation to proposed tuples observed by the hook. An explicit force intent with no actual rewrite still needs local confirmation. Distinguish paths that bypass local integration and cover them with SPEC-003 where deployed.
