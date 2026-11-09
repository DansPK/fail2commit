# SPEC-008 — Sandbox policy setting

FR-008 · TC-008 · Owner paths: trusted setting and execution policy.

Sandboxing defaults to on. CLI, tray and extension read and write the same trusted user setting. Check every guarded install for package-controlled execution regardless of setting. On runs allowed required scripts automatically in the sandbox. Off skips scripts by default. A required allowed script needs a separate Run on host once prompt showing that the code gains the current user's access. Treat a sandbox startup failure as a denial, with no automatic host fallback. Flagged force-push scripts remain blocked. Settings changes cannot weaken an in-flight job or come from a repository. Explicit fail2commit run always requires isolation. Dependency scans, integrity and Git checks stay active in both modes.
