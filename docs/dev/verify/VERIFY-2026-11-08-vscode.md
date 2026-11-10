# Verify Report: VS Code integration (2026-11-09)

> **Requirements covered:** FR-010 (SPEC-010, TC-010)
> **Commit / branch:** f451f50 on `DansPK/f2c-t010-vscode` (base fe411ba); docs added in the following commit
> **Verified by:** Claude worker T-010
> **Platform:** Windows 11, Node v24.22.0, npm 12.2.0

---

## 1. Commands Run

```text
cd extensions/vscode
npm ci                                  -> exit 0
npm test                                -> exit 0 (tsc, then node --test out/test/*.test.js: 8 tests, 8 pass, 0 fail)
node node_modules/@vscode/vsce/vsce package --allow-missing-repository --skip-license   -> exit 0 (same command `npm run package` runs via npx; once the npm wrapper did not return, so the direct form was used)
Get-FileHash fail2commit-0.1.0.vsix -Algorithm SHA256
```

VSIX: `extensions/vscode/fail2commit-0.1.0.vsix` (7 files, 8020 bytes, gitignored).
SHA-256: `62C6B5277BD456550067C81CC37E3225E52DD52A33801C575B0D62B1931238D2`

## 2. Results

| TC ID | Requirement | Result | Evidence |
|-------|-------------|--------|----------|
| TC-010 unit/integration (fake CLI) | FR-010 | Pass | `client.test.ts`: no shell and argv array (`shell:false`, args `["api"]`); password only on stdin, absent from argv, env and logs; echoes request_id/nonce/digest; dismiss/throw/not-offered sends Cancel; 300 KiB line rejected; LineSplitter bound; workspace-scoped cliPath ignored, in-workspace and symlinked candidates rejected (Linux and Windows path rules); manifest declares machine scope, untrusted/virtual unsupported, `extensionKind: ["workspace"]` |
| TC-010 SCM path | FR-010 | Pass (hook invocation only) | `scm-hook.test.ts`: plain `git push` runs `pre-push` and a failing hook blocks the push, with a disposable repo and bare remote. Does not run the real fail2commit hook |
| TC-010 Windows, built CLI | FR-010 | Pending | Needs the built `fail2commit.exe` with a working `api` approver (T-002) and installed hook (T-001); belongs to T-011 |
| TC-010 Linux/WSL, built CLI | FR-010 | Pending | Same, plus the Linux CLI in WSL Ubuntu; confirms Linux CLI selection under Remote-WSL; T-011 |
| Real VS Code UI (modal, input box, command palette) | FR-010 | Pending | `@vscode/test-electron` smoke test not written; needs a VS Code download. `extension.ts` is compile-checked only |
| pip argv shape | FR-010 | Pending | Depends on T-005's `Args` (assumed `pip install --python <interp> …`) |

## 3. Traceability Check

Not run in this worker (the shared board and matrix belong to the coordinator).

## 4. Issues Found

None open. The fake CLI initially mis-sliced argv (fixed). No contract change requested.

## 5. Verdict

- [ ] **Verified**
- [x] **Not verified:** unit/integration evidence passes; real-CLI Windows and Linux/WSL runs and the UI smoke test are Pending.
