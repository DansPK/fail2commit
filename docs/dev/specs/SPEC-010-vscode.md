# SPEC-010 — VS Code integration

FR-010 · TC-010 · Owner paths: extensions/vscode.

Use TypeScript, the VS Code Extension API and @vscode/vsce. Expose guarded push, npm and pip commands, status, findings, approval and sandbox on/off. Resolve an explicitly configured trusted CLI or known installation outside the workspace. Use the versioned JSON protocol without shell interpolation. Honor Workspace Trust and run where the workspace lives, including WSL. Never print secret values or transfer passwords through command lines. Standard SCM push coverage depends on whether Git invokes the installed hook; exercise and document that path separately.
