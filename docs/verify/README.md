# Verification records

Each report records the exact commands, exit codes and the tested commit. A skipped or simulated test is recorded as pending, not passed.

**Start with [VERIFY-2026-11-09-release.md](VERIFY-2026-11-09-release.md).** It is the 0.1.0 release candidate report. It covers:
- the GitHub build,
- the clean-VM runs on Windows 10 and 11, Debian and Arch,
- the attack simulation,
- the gates that are still open.

## Verification by area

| Area | Report |
|---|---|
| Git push guard | [VERIFY-2026-11-08-git.md](VERIFY-2026-11-08-git.md) |
| Approvals and password | [VERIFY-2026-11-08-approval.md](VERIFY-2026-11-08-approval.md) |
| Protected remote (server hook) | [VERIFY-2026-11-08-server.md](VERIFY-2026-11-08-server.md) |
| npm guard | [VERIFY-2026-11-08-npm.md](VERIFY-2026-11-08-npm.md) |
| pip guard | [VERIFY-2026-11-08-pip.md](VERIFY-2026-11-08-pip.md) |
| Package and script scanning | [VERIFY-2026-11-08-scan.md](VERIFY-2026-11-08-scan.md) |
| Linux sandbox | [VERIFY-2026-11-08-sandbox-linux.md](VERIFY-2026-11-08-sandbox-linux.md) |
| Windows sandbox | [VERIFY-2026-11-08-sandbox-windows.md](VERIFY-2026-11-08-sandbox-windows.md) |
| Sandbox policy | [VERIFY-2026-11-08-sandbox-policy.md](VERIFY-2026-11-08-sandbox-policy.md) |
| Windows tray and installer | [VERIFY-2026-11-08-windows-tray.md](VERIFY-2026-11-08-windows-tray.md) |
| VS Code | [VERIFY-2026-11-08-vscode.md](VERIFY-2026-11-08-vscode.md) |
| Resource use | [VERIFY-2026-11-09-resources.md](VERIFY-2026-11-09-resources.md) |
| End-to-end wiring | [VERIFY-2026-11-09-e2e.md](VERIFY-2026-11-09-e2e.md) |
| Integration wave 1 | [VERIFY-2026-11-09-integration-wave1.md](VERIFY-2026-11-09-integration-wave1.md) |
| Release preparation | [VERIFY-2026-11-08-release-prep.md](VERIFY-2026-11-08-release-prep.md) |

New reports start from [VERIFY-template.md](VERIFY-template.md).

## Security reviews

[reviews/](reviews/) holds the internal adversarial reviews and re-reviews. Most findings have a reproduction test under `crates/fail2commit/tests/`, and the verify reports above record each fix. Findings recorded as closed have their fixes merged. Known limits that are still open are listed in the release report and the README.
