# Sandbox policy (FR-008, SPEC-008)

One trusted user setting, `sandbox.enabled` (default **on**), decides how package-controlled
code (npm lifecycle scripts, pip build steps) runs. The npm and pip adapters, the tray and the
VS Code extension all use it the same way.

## Where it lives

- Read only from the trusted `settings.toml` (`TrustedPaths::settings_file`, relocated by
  `FAIL2COMMIT_HOME` for tests). A missing file means on. A malformed file fails closed.
- Never read from a repository. `.fail2commit/settings.toml`, `fail2commit.toml`, `.npmrc`,
  `pip.conf`, package metadata and script output cannot change it.
- Every command takes one snapshot at start (`Ctx.settings`). Flipping the file later affects
  the next command, never a job already running.

## Changing it

| Client | How |
|---|---|
| CLI | `fail2commit sandbox on`, `off`, `status` |
| Tray (T-009), VS Code (T-010) | run `fail2commit sandbox on\|off`, or `Settings::update` |

`on` and `off` use `Settings::update` under the settings lock. `status` prints the snapshot
setting, the backend name, availability and each probe control (`--json` gives the same data).

## Decision table (`policy::script_decision`, applied by `exec::authorize_scripts`)

| Situation | Sandbox on, backend available | Sandbox on, unavailable | Sandbox off |
|---|---|---|---|
| No scripts | `NoScripts` (no sandbox, no probe) | `NoScripts` | `NoScripts` |
| Scripts, not required | `Sandboxed` | `IsolationUnavailable` | `Skipped` |
| Scripts, required | `Sandboxed` | `IsolationUnavailable` | separate **Run on host once** approval, else `Rejected` |
| Flagged force-push script | `Rejected` (Deny finding) | `Rejected` | `Rejected` |

- Failure to set up isolation is a denial. There is no automatic host fallback.
- The host prompt is a separate `ApprovalKind::HostExecution` request offering only
  `RunOnHostOnce`, bound to the operation digest. It states that the code gains the current
  user's access and does not run in the sandbox. A changed plan changes the digest and
  invalidates the approval. An unreachable approval channel is a denial.
- Explicit `fail2commit run` ignores the toggle and always requires isolation
  (`policy::explicit_run_allowed`).

## Always active, in both modes

Turning the sandbox off only changes how scripts run. These checks never depend on it:

- advisory and malware scans of exact package versions (FR-006),
- artifact integrity and plan checks (FR-004, FR-005),
- Git secret, force-push and protected-ref checks (FR-001, FR-003),
- the flagged-script hard deny.

## Tests

`crates/fail2commit/tests/sandbox_setting_*.rs` (TC-008): trusted-only setting with decoy repo
files, snapshot immunity, fail-closed on, off skips unless approved, declined host run, flagged
scripts in both modes, explicit run isolation.
