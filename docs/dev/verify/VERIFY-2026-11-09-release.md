# Verify Report: MVP release candidate (2026-11-09)

> **Requirements covered:** FR-001 to FR-011, NFR-012
> **Current release candidate:** RC2 built from `d4ca070` on `DansPK/f2-commit-coordinator` (section 3a); CI green on `82004af` (section 5d).
> **Original commit / branch:** release commit `4559bab` (`DansPK/f2c-release-a026090`) = integration commit `a026090` plus regenerated notices and docs. Product code is unchanged since the gated commit `d15f559`; the only later changes are two test files and documentation, each re-run.
> **Verified by:** Orca coordinator (gates, release builds, VM run); independent reviewers per area (see section 4)

---

## 1. Hosts and tools

| Platform | Details |
|---|---|
| Windows | Windows 11 Pro 10.0.26200, Rust 1.99.1 (`x86_64-pc-windows-gnu`), Git 2.56.0.windows.2, Node 24.22, Python 3.12.10 |
| Linux (container) | `f2c-linux-test:1` = `rust:1` (Debian) + python3-venv, pip 25.1, Node 20.19, npm 9.2; Docker 29.8.2 in WSL2 capped at 4 CPUs / 16 GB |
| Linux (real sandbox) | WSL2 Ubuntu 26.04.1, kernel 6.18.54.1-microsoft-standard-WSL2, bubblewrap 0.11.1, unprivileged user namespaces |
| Clean Windows VM | VMware Workstation 17 `win11` (Windows 11 Pro 25H2), reverted to its pre-test snapshot afterwards |

## 2. Commands and results

| Gate | Command (abridged) | Exit | Result |
|---|---|---:|---|
| Format | `cargo fmt --all -- --check` | 0 | at `8f69137` and later |
| Lint | `cargo clippy -j 3 --workspace --all-targets --locked -- -D warnings` | 0 | at `8f69137` and later |
| Windows tests | `<empty stdin> cargo test -j 3 --workspace --locked --no-fail-fast` at `d15f559` | 0 | **503 passed, 0 failed** (includes real AppContainer attack suite and npm e2e through AppContainer) |
| Linux tests | `docker run ... f2c-linux-test:1 cargo test -j 3 --workspace --locked --no-fail-fast` at `d15f559` | 0 | **494 passed, 0 failed** |
| Traceability | `python .claude/hooks/trace_check.py` | 0 | OK |
| Linux real sandbox | `scripts/linux/test.ps1 -Stage container,wsl -Gcc -NoCheck -Filter '^(sandbox_linux\|run_\|e2e_\|resource_)'` with `F2C_REQUIRE_SANDBOX=1` | 1 then 0 | all sandbox, run, e2e and resource suites pass in WSL bwrap; the one failure (native C build needed the CR-012 approval) was fixed in `a026090` and `e2e_npm_sandbox` re-run **6/6** with `F2C_REQUIRE_SANDBOX=1 F2C_REQUIRE_NATIVE_BUILD=1` |
| Windows sandbox attack suite | `cargo test -p fail2commit --test sandbox_windows_matrix --test review_t007b_* -- --include-ignored` | 0 | 12/12, including live external TCP denial with a host positive control (`Test-NetConnection 1.1.1.1 -Port 443` = True) |
| Windows release build | `scripts/release/build-windows.ps1`; `packaging/windows/build.ps1 -Makensis <portable NSIS 3.11>` | 0 | CLI and Setup.exe built |
| .deb build | `scripts/release/build-deb.sh HEAD target/dist` (cargo-deb 3.8.0 in `rust:1`) | 0 | built |
| .deb verify | `scripts/release/verify-deb.sh` (clean `ubuntu:24.04`: install, `status`, remove, purge, third-party files kept) | 0 | passed |
| Source tarball | `scripts/release/source-tarball.sh`; `verify-source-tarball.sh` (`--network none`, vendored) | 0 | offline build passed |
| Reproducibility | `scripts/release/reproducible-linux.sh HEAD` (two independent target volumes) | 0 | `.deb` and Linux binary bit-identical across builds and equal to the released hashes |
| VSIX | `npm ci; npm run compile; npm test; npx @vscode/vsce package` | 0 | packaged; tests 13/13 against the Windows release CLI and 13/13 against the Linux release CLI (`F2C_BIN`) |
| Clean Windows 11 install/uninstall | `C:\f2c\f2c-vm-test.ps1` in the `win11` VM | see section 5 | see section 5 |

## 3. Artifacts (`target/dist/SHA256SUMS`)

### 3a0. GitHub release-candidate run (current), built from `2888aec` on `main`

`release.yml` run [42685056421](https://github.com/DansPK/fail2commit/actions/runs/42685056421) succeeded:
- **windows:** fmt, clippy, tests, release build, NSIS 3.11 installer.
- **linux:** fmt, clippy, tests, notices, then each package plus its check: the `.deb` and its clean-Ubuntu verify; the source tarball and its offline rebuild; the Arch package and its clean-archlinux verify.
- **vsix** and **hashes** also passed.

The two earlier runs failed only in packaging, fixed by PRs #4 and #5:
- `windows-latest` no longer ships NSIS;
- a recursive glob matched test binaries.

`SHA256SUMS` from the run:

```
3ddf9be5c28fe27dad143a5dc76eea25222ad1dd68934a047064e56ed2fa40c5  LICENSE
f55e059611ca38d5fc77a0f645f9fd43c10d8a6c9e576ba09210d9c21db56df5  NOTICE
1ccbfb4c66bc58874472e5648cb2144e0ba269aab3b2d881917095641ae18cb5  THIRD-PARTY-NOTICES.md
5140b9f4b0266f6374a13813ca3925ffd790fb7c6534046711df75eb3a474011  fail2commit-0.1.0-1-x86_64.pkg.tar.zst
3a7c657f75b4245e52cbcd5f710ed18ab06ab00ff982343b4255f493c48af7e0  fail2commit-0.1.0-linux-amd64
bb0f5a35c9863369f3338daa91e6ef0ab1ad07b7877c93ac4f1b3e3fb6cd128a  fail2commit-0.1.0-setup.exe
b651f013787b4f342d9546687224cc66702d96b22655a66ba4fc19a82d71c7fa  fail2commit-0.1.0-src.tar.gz
be0a7dde757e29abbb72b40607b8e22083959c3f231391e431b84b08e12f4ef5  fail2commit-0.1.0.vsix
9e574ff246561e9696854496dbfef09136048d19def24abb9b7b5f248eb89cca  fail2commit-windows-x86_64.exe
de052a145c23d5fe6ebb5fa3a6a7abf705e3b8f225104a54265733cce75878fa  fail2commit_0.1.0_amd64.deb
```

These are CI workflow artifacts. Nothing was published as a GitHub Release. The Windows binaries are still unsigned (TODO P-101).

### 3a. Release candidate 2 (local), built from `d4ca070`

Supersedes the RC1 set below. Includes every fix through `82004af` (Node 22 npm path, quoted-secret detector, `run -- cmd.exe`, probe stage cleanup) and the license notices from `5885ca8`. Built with `scripts/release/build-windows.ps1`, `packaging/windows/build.ps1` (NSIS 3.11), `build-deb.sh`, `source-tarball.sh`, `vsce package`, and `hashes.sh`.

```text
910990ec9bb50433f3971c78dd7c640b03383a234da725d93e0533c6ffd7a667  fail2commit-0.1.0-setup.exe
972e7fb8cf86eb24b5e29b98932281994e47d4d31971d087218f251cce98e59e  fail2commit-windows-x86_64.exe
03c2a1dc7001bfa0cf841a9029d4273691391491792d0d89846b7b16ceb37f2b  fail2commit_0.1.0_amd64.deb
ecb58747c45dbb20156bcd5c3be0d1fd5771ea379dfe9caa0c3f1c1ca383fdae  fail2commit-0.1.0-linux-amd64
e8d896afa57b64eb6d3b765aec2d3c20f0fd5e4e3842eb562d4668cfd577f9d4  fail2commit-0.1.0-src.tar.gz
21873d0da408f540efa37612931ff36a48719004c4ecee27e752ac51e7152414  fail2commit-0.1.0.vsix
3ddf9be5c28fe27dad143a5dc76eea25222ad1dd68934a047064e56ed2fa40c5  LICENSE
a6a1eae9bdf7c7e23c4f83fcafef66b2bb60f422f3244efe7cc2cdec978e2368  NOTICE
ae48a34bed6918e659ccb44b6399901974f50eee6dc6eccb484d7ba813f71431  THIRD-PARTY-NOTICES.md
```

| Check on RC2 | Result |
|---|---|
| `.deb` verify (clean `ubuntu:24.04` install, status, remove, purge) | passed; package contains `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.md`, `LICENSE.template-MIT` |
| Source tarball offline build | passed |
| Reproducibility (`reproducible-linux.sh`) | `.deb`, Linux binary and notices bit-identical across two builds and equal to the released hashes |
| VSIX tests against the RC2 CLIs | 13/13 Windows, 13/13 Linux (container, Node 20.19); VSIX carries `extension/LICENSE.txt`, no `node_modules` |
| Clean win11 (25H2) and win10 (LTSC 21H2) install / guard / uninstall | all checks pass on both; `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.txt` installed and the notices include the MinGW-w64 runtime |
| Interactive sandbox, win11 and win10 | available, all 9 controls; `run -- cmd.exe` now works; secret read `Access is denied.`; external TCP `Failed to connect` with host control `http=301`; benign x4 plus adversarial: 0 Defender detections on both |
| Linux full flow with the RC2 `.deb` (fresh Ubuntu 24.04 WSL distro, bubblewrap 0.9.0) | every step of section 5c passes again; all 13 sandbox controls ok; the secret push now reports both `github-token` and the quoted `#` password (`generic-assignment`), values redacted |

### 3b. Release candidate 1 (superseded; do not publish: no third-party notices in the Windows installer or beside the binaries)

```text
f19ad03b254ff5dcd2f3ce27a2f0b19882e592ffca548f525da525ca6ac64218  fail2commit-0.1.0-setup.exe
816e25a23e3adb31289443f0bce1eeca62aa031e13a2c42cfbd6d09d404f958c  fail2commit-windows-x86_64.exe
f52ddf7638c40894595d1c38a84dfd4ebc24fea0afbc179daaaba1ee23ee0815  fail2commit_0.1.0_amd64.deb
e2be5a408d5d1f42846c05b430cca39162a53dc0bbbc38ce9aeb49e61a694cd7  fail2commit-0.1.0-linux-amd64
4496e68130607e665b47db5007f338032c4d327703b992ea4d34d386ead5f4fa  fail2commit-0.1.0-src.tar.gz
1d9473c5b20b449074ede3dd1cf638fff535590e269ece429f27612c852a2814  fail2commit-0.1.0.vsix
```

Nothing was published or pushed.

## 4. Security review trail

Every security-sensitive area was reviewed by an agent that did not write it, and fixed until a narrow re-review closed the finding class:

| Area | Reviews | Outcome |
|---|---|---|
| Git guard, approval, server, tray, VS Code (wave 1) | review, re-review, re-review 2 | closed (`REVIEW/REREVIEW/REREVIEW2-2026-11-09-*`) |
| npm, pip, scanner, Linux sandbox (wave 2) | review, then per-area re-reviews (npm 3 rounds, pip 2 rounds) | closed; structural fixes CR-005, CR-008 |
| Windows AppContainer | review, fix, coordinator re-run of the attack suite | closed (CR-006, CR-007) |
| Approval relay | review, re-review, fix | closed (CR-010; CR-011 residual risk accepted) |
| Coordinator's own last fixes | independent review | closed (CF-001..003 fixed) |

All reviewer reproductions are permanent regression tests. Change requests CR-001 to CR-012 are in `docs/dev/change-requests.md`.

## 5. Clean Windows 11 install and uninstall

VMware `win11` (Windows 11 Pro 25H2, NT 10.0.26200), snapshot `pre-f2c-test` taken first and reverted afterwards. Script `f2c-vm-test.ps1` (run through VMware Tools as the normal user). MinGit 2.47.1 was unpacked inside the VM for the Git integration. A third-party global `core.hooksPath` with its own pre-push hook was planted before install.

| Check | Result |
|---|---|
| `fail2commit-0.1.0-setup.exe /S` | exit 0; CLI, tray, uninstaller and HKCU uninstall entry present |
| `fail2commit --json status` | `ok`; integrations `git:True,npm:True,pip:True,tray-startup:False` |
| Global hooks and PATH | `core.hooksPath` = fail2commit's hooks dir; shim dir on the user PATH |
| Normal push to a local bare remote | exit 0; **the third-party pre-push hook was chained and ran** |
| Unattended `git push --force` | exit 1, `Approve ForceIntent: explicit force intent: --force`; remote unchanged (fails closed) |
| `uninstall.exe /S _?=<dir>` | exit 0; CLI, tray, uninstall entry and Run value removed |
| Third-party state after uninstall | `core.hooksPath` restored to the third-party value; its hook file intact; user PATH identical to before |
| Leftover | `uninstall.exe` only, because `_?=` keeps the uninstaller in place for a waitable silent run |

Finding: `fail2commit sandbox status` in this session reported the AppContainer backend unavailable: `CreateAppContainerProfile failed: HRESULT 0x80070002`. The session was a VMware Tools guest operation: `NT AUTHORITY\BATCH` logon, session 0, with the user's registry hives (including `_Classes`) not loaded. `CreateAppContainerProfile` needs that profile. The backend failed closed as designed. In an interactive session on the development host the same backend passes 12/12 attack tests. Documented as a known limitation in docs/sandbox-windows.md: batch or service logons without a loaded profile report the sandbox unavailable and fail closed.

## 5b. Windows 10 and interactive-session runs (same release artifacts)

VMware `win10` (Windows 10 IoT Enterprise LTSC 2021, 21H2, NT 10.0.19044.7725) and `win11` again, each from a fresh `pre-f2c-test` snapshot and reverted afterwards. MinGit 2.47.1 was downloaded on the host (SHA-256 `50b04b55425b5c465d076cdb184f63a0cd0f86f6ec8bb4d5860114a713d2c29a`, equal to the release notes) and copied in. Interactive probes ran as a scheduled task with `LogonType Interactive` in the signed-in console session (`NT AUTHORITY\INTERACTIVE`, session 1): on win10 as a new standard user `f2cuser` signed in by auto-logon, on win11 as the VM's own console user.

| Check | Windows 10 LTSC 21H2 | Windows 11 25H2 |
|---|---|---|
| `f2c-vm-test.ps1` install, guard, uninstall (section 5 checks) | all pass: install exit 0; normal push exit 0 with the third-party hook chained; unattended `--force` exit 1 `Approve ForceIntent`, remote unchanged; uninstall exit 0; hooksPath, hook file and user PATH restored | passed earlier (section 5) |
| `sandbox status` in the interactive session | available; all 9 AppContainer controls `ok` | available; all 9 controls `ok` |
| `run -- cmd /d /c ...` reading `C:\f2c\secret.txt` (synthetic) outside the input | `Access is denied.`; secret not exported | `Access is denied.`; secret not exported |
| Network from inside the sandbox (`curl http://1.1.1.1/`) with host control | inconclusive (curl ran silent; see Defender finding) | denied: `curl: (7) Failed to connect`; host control `http=301` |
| Benign workload x4 (`status` + `run`), Defender detections | 0 | 0 |
| Re-export onto an existing file | refused: `cannot create destination: The file exists` (by design) | same |

Findings:

1. **`run -- cmd.exe` failed** with `cmd.exe was not found on PATH`, because `toolpath::find_real` appended `.exe` to a name that already had it (`cmd` worked). Fixed after the release candidate in `11be0a6` (FR-007) with a regression test; `.bat`/`.cmd` stay unresolvable. Host re-run: core lib 151/151, `run_cli` 3/3, `sandbox_windows_matrix` 7/7 including ignored. The 0.1.0 artifacts above predate this fix.
2. **Microsoft Defender quarantined the unsigned `fail2commit.exe`** on win10 (`Behavior:Win32/DefenseEvasion.A!ml`, severity 5, signatures 1.463.203.0) during the third run of the adversarial probe, whose sandboxed `cmd` reads a file named `secret.txt` and connects to a bare IP. Afterwards the same hash was blocked as soon as it was written to disk. From a fresh snapshot, the benign workload produced no detection on win10 or win11, and on win11 the adversarial probe ran without detection. The machine-learning verdict therefore depends on what the sandboxed child does, which for fail2commit is untrusted package code. Release prerequisite: Authenticode signing and a Microsoft false-positive submission (section 6).

## 5c. Linux full user flow with real bubblewrap (released `.deb`)

A disposable WSL distro `f2c-e2e` imported from the official Ubuntu 24.04 WSL rootfs (SHA-256 `8251e27f...15ea`, equal to Canonical's `SHA256SUMS`); kernel 6.18.54.1-microsoft-standard-WSL2, bubblewrap 0.9.0 (Ubuntu package), Node 18.19.1, npm 9.2.0, Python 3.12.3, Git 2.43.0. The released `fail2commit_0.1.0_amd64.deb` (`f52ddf76...0815`) was installed with `dpkg -i`; the flow ran as a new normal user `dev` under `setsid` (no controlling terminal, so unattended paths fail closed), against a loopback npm registry, PyPI index and OSV stub serving synthetic packages, with approvals given through `fail2commit api` exactly as the VS Code client does. Scripts: `setup_root.sh`, `flow.sh`, `secret_probe.sh`, `uninstall_root.sh`, `servers.py`, `approve.py`.

| Step | Result |
|---|---|
| `fail2commit setup`, `status` | exit 0; integrations `git, npm, pip`; sandbox `bubblewrap available=True`; 12 of 13 controls ok, `cgroup_v2_limits` not verified because `wsl --exec` processes are outside a systemd session (`0::/non-systemd`), so limits fell back to rlimits as designed |
| Normal push | exit 0; the third-party `core.hooksPath` pre-push hook ran |
| Unattended `git push --force` | exit 1 `Approve RefRewrite`; remote unchanged |
| Same push, approved once over `api` | asked once with findings `force_intent`, `ref_rewrite`; exit 0; remote updated |
| Secret pushes, unattended | GitHub token, AWS access key, private key and `password = "..."` each exit 1 with the value redacted (`[redacted N chars]`) |
| npm `plain` (no scripts) | exit 0 |
| npm `hello-build` (install script) | exit 0, `scripts: Sandboxed`; artifact `built-in-sandbox:1,4,9` built inside a `sandbox-stage` job and merged into `node_modules` |
| npm `hostile` | exit 0; inside the sandbox: home secret, `~/.ssh` key and the user's repo `ENOENT`; loopback canary `ECONNREFUSED` (0 connections seen by the listener); external TCP `ENETUNREACH`; child environment only npm lifecycle keys; nothing written to the real home |
| npm `advised` (synthetic OSV advisory) | unattended exit 11 `approval_unavailable`, nothing changed; cancel over `api` exit 10, nothing changed; approve once exit 0, installed |
| Sandbox off, npm package with a required install script | exit 11: a host-run approval is required and unattended fails closed; no script ran |
| pip `cleanpkg` wheel into a venv | exit 0, importable |
| pip `pyadvised` (advisory) | unattended exit 11, not installed; approved once over `api` exit 0, installed |
| `fail2commit run` | exit 0; output exported; the home secret, `~/.ssh` key and repo were not visible (`No such file or directory`) |
| `uninstall-integrations`, `dpkg --purge` | exit 0 / 0; binary gone; `core.hooksPath` restored to the third-party directory with its hook intact |

Findings:

1. **Generic secret detector missed quoted values containing `#`, `,` or `;`**: `db_password = "Zq8#vT2kPw9xLmR4sQ7"` was pushed unattended without a finding, because the value pattern stopped at `#`. Fixed (FR-001): a quoted value now runs to its closing quote; unquoted values still treat `#` as a comment. Regression test `quoted_password_with_hash_or_comma_is_flagged`.
2. In a session with a terminal the guard prompts on the terminal and waits, as specified; the first flow attempt (run from a backgrounded console) stopped there.

## 5d. GitHub Actions (PR #1, private repository)

| Run | Commit | scaffold | rust (ubuntu-latest) | rust (windows-latest) |
|---|---|---|---|---|
| 42584670597 | `02fd51f` | pass | pass (494) | fail: `e2e_npm_approval` 4 tests, `EISDIR lstat 'C:'` under the runner's Node 22.23.4 |
| 42592243721 | `7046e37` | pass | pass | fail: `e2e_npm_sandbox` 4 tests |
| 42604881871 | `3ac9f20` | pass | pass | fail: `rereview3_npm` 1 test (8.3 TEMP in a fixture) |
| 42612574385 | `5eccfb3` | pass | pass | fail: `sandbox_windows_matrix` handle-list test (STATUS_INVALID_HANDLE) |
| **42616731444** | **`82004af`** | **pass** | **pass, 497 passed, 0 failed, 3 ignored** | **pass, 507 passed, 0 failed, 3 ignored** |

- `7046e37` (FR-004): npm-cli.js was passed to node in the `\\?\` form; Node 22 cannot resolve it. Reproduced locally with the official Node 22.23.4 zip (old code fails identically, fix passes 3 runs in a row).
- The second run's failures: three came from the test fixture embedding the runner's 8.3 `TEMP` (`RUNNER~1`), which the npm guard correctly refuses; reproduced locally with an 8.3 alias and fixed in the test support (long form). One was a leftover `probe-*` stage: the AppContainer probe stage is now removed with a short retry, and stale `probe-*` stages are swept like `npm-*` and `run-*`.
- `82004af` (FR-007): on the runner the handle-list probe raised `STATUS_INVALID_HANDLE` (strict handle checks) instead of returning `ERROR_INVALID_HANDLE`; both prove the handle was not inherited, and a successful read still fails the test.
- `5885ca8` (FR-011): license audit; the Windows installer and standalone binaries now ship `LICENSE`, `NOTICE` and the third-party notices, which now cover the Rust standard library and the MinGW-w64 runtime (`docs/dev/release.md`, Licensing). The 0.1.0 artifacts in section 3 predate this and must not be published.
- The Linux job does not install bubblewrap, so the hostile-sandbox suites skip there; real-sandbox evidence is section 5c and the WSL runs in section 2.

## 5e. Normal-user flows on real machines (2026-11-09/10)

**Windows 11 25H2 VM** (clean snapshot; Node.js 22.23.4 installed for all users in `C:\Program Files\nodejs` like the official installer; Python 3.12.10 per user from python.org, Authenticode-valid; MinGit 2.47.1). The installer was driven through its GUI with the keyboard, with the defaults plus "Start the tray at sign-in", and the UAC prompt was approved:

| Step | Result |
|---|---|
| Installer | Logo on installer, uninstaller, title bar and taskbar; log stays on screen; setup installed `git, npm, pip, shell, tray-startup`; UAC prompt "Publisher: Unknown" (unsigned); machine shims installed in `C:\Program Files\fail2commit\shims` |
| New PowerShell window | `npm`, `pip` are fail2commit functions; `fail2commit status` sandbox available, no warnings; tray running with no console window |
| Force push | Tray approval dialog with the logo, ref update and finding; Esc cancels ("push canceled; nothing was sent"); with the fixed dialog, focus starts on Cancel, Alt+A approves ("push approved", forced update) |
| Secret push | Dialog shows "github-token in config.py ... [redacted 40 chars]"; Esc cancels |
| `npm install esbuild` | guarded, postinstall sandboxed, 31.8 s, `esbuild --version` 0.28.2 |
| `pip install six` in an activated venv | `pip` is a function; installed into `C:\play\venv` |
| Uninstall through the GUI with UAC | machine and user PATH clean, Program Files folder gone, PowerShell profiles removed, `core.hooksPath` unset, tray stopped, Run value and Apps entry gone |

**Debian 13 VM** (real kernel 6.12, bubblewrap 0.12, Node 20.19, Python 3.13, Git 2.47; provisioned fresh), driven from the tty1 login like an SSH/server user: `.deb` install, `fail2commit setup`; `status` correctly warned that npm/pip were unguarded until `. ~/.profile`; then all 13 sandbox controls ok including `cgroup_v2_limits` (systemd user scope); the terminal prompt showed the operation, ref update, both findings and expiry, and typing `approve` pushed; `npm install esbuild` guarded and sandboxed in 4.5 s; `pip install six` in an activated venv guarded into the venv (after CR-015); `uninstall-integrations` removed the shell block.

Bugs found and fixed in these flows: machine-wide npm/pip bypass (CR-013), npm child processes hanging in the AppContainer (CR-014), venv bypass (CR-015), visible consoles from helpers and the tray, the PATH restore on re-run setup, the installer's tray launch path, silent setup failures, a keyboard trap in the approval dialog, the terminal retitled "npm ci", `\\?\` paths in pip output, and `fail2commit` missing from PATH without the admin step.

## 5f. Supply-chain attack simulation (`scripts/attack-sim/`)

Four malicious packages from a loopback registry, synthetic secrets only: a Shai-Hulud-style obfuscated worm (`color-utils-pro`), a ua-parser-js-style second-stage downloader (`ua-parse-lite`), a plain force-push script (`deploy-helper`) and a known-malware typosquat (`lodahs`, OSV `MAL-`). Token environment variables (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`) were set in the installing shell.

| Attack step | Debian 13, fail2commit | Windows 11, fail2commit | Without fail2commit (control, both) |
|---|---|---|---|
| `lodahs` (known malware) | denied, `malware/deny`; approve over the API refused, no option offered | same | - |
| `deploy-helper` (force push in script) | denied before running, `suspicious_script/deny` | same | - |
| Second-stage download | `blocked:7` (curl, no network) | `blocked:1` (PowerShell) | - |
| Read `.npmrc`, SSH key, AWS, `.git-credentials`, `gh` token | all `ENOENT` (not visible) | all `EPERM` | all stolen |
| Token environment variables | none (only `npm_*`) | none | all three |
| Persistence (`.bashrc`, crontab, Startup folder, Run key) | blocked or confined to the job's throwaway home | all blocked | `.bashrc`, crontab (Linux), Startup `update.cmd` and Run key (Windows) written |
| Backdoor project source, add CI workflow | confined / blocked | blocked | written |
| `git push --force`, `npm publish` | blocked | blocked | push succeeded |
| Exfiltration (loopback canary, HTTPS, DNS) | blocked; canary saw 0 connections | blocked; 0 connections | loopback and HTTPS sent |
| Host after the guarded runs | byte-for-byte unchanged (`.bashrc`, crontab, project, remote) | unchanged (`.bashrc`, Startup, Run key, project, remote) | modified |

A re-run against a rebuilt registry also showed lockfile tamper detection: the re-packed tarball no longer matched `package-lock.json` and the install stopped with `integrity_failure` (exit 13). Both VMs were reverted afterwards.

## 5g. Arch Linux package and full flow (CR-016, 2026-11-10)

Host: VMware VM `arch-f2c`, installed from the official `archlinux-x86_64.iso` (SHA-256 `01bcdcf01af2f7d58f2794899c834770d25c9bfc945bd092b32bb66672a4a216`, checked against the published sum). The tools were kernel 7.2.14-arch1-1, bubblewrap 0.13.1, Node v26.13.0, npm 12.2.2, Python 3.14.9, git 2.56.0 and cargo 1.99.1, on cgroup2. User `dev`, not root, with sudo. The source tarball was built from `856905e`, with `packaging/arch/PKGBUILD`.

| Step | Result |
|---|---|
| `makepkg` natively in the VM | exit 0 in 3m53s; `check()` ran the core unit tests: 148 passed, 0 failed |
| `sudo pacman -U fail2commit-0.1.0-1-x86_64.pkg.tar.zst` | exit 0. `pacman -Qi`: licenses Apache-2.0 and MIT; depends gcc-libs, glibc, git and bubblewrap. Files: `/usr/bin/fail2commit`, 4 license files and 2 docs |
| `fail2commit setup` / `status` | exit 0, `ok`; bubblewrap available; integrations git, npm, pip and shell installed |
| `fail2commit sandbox status` | 13/13 controls ok with the user's systemd manager running. In a VMware guest-ops shell, with no logind session and no user bus, only `cgroup_v2_limits` fails, as expected |
| Git guard | Normal push ok and the third-party hook still ran. Unattended force push stopped (exit 1) with the remote unchanged; approved once, it went through. A secret push was stopped with 2 findings and no secret value in the output |
| npm guard | `hello-build` built in the sandbox (`Sandboxed`, cwd in `sandbox-stage`). `hostile` could not read home, SSH key or repo (`ENOENT`) and had no external or loopback network; 0 canary connections. Unattended `advised` gave `approval_unavailable` (exit 11) and changed nothing; cancel left everything unchanged and approve-once installed it |
| Real registry `npm install esbuild` | exit 0 in 26 s, scripts `Sandboxed`, `esbuild --version` 0.28.2 |
| pip guard | Clean wheel installed into the venv. Advised: unattended exit 11, not installed; approved once, installed |
| venv `pip install` through the CR-015 shell function (interactive bash) | `pip`/`npm` resolve to functions; installed into `~/v2/bin/python3`; import ok |
| `fail2commit run` | Output exported; home secret, SSH key and repo not visible; secret leaked 0 |
| Attack simulation (section 5f) | `lodahs` `malware/deny`, and approval was refused over the API. `deploy-helper` `suspicious_script/deny`. Second stage `blocked:7`. All credentials `ENOENT`, no token env vars, all exfiltration blocked, canary 0. `.bashrc`, crontab, project and remote byte-for-byte unchanged. The unguarded control stole all five credentials and all three token env vars, wrote `.bashrc`, the project source and a CI workflow, and force-pushed |
| `uninstall-integrations`, `pacman -R` | exit 0; `.bashrc` block removed, `core.hooksPath` restored to the user's third-party hooks, `/usr/bin/fail2commit` gone |

Clean-container scripts, run from Windows Docker Desktop against the same source tarball:

- `bash scripts/release/build-arch.sh target/arch-in/fail2commit-0.1.0-src.tar.gz target/arch-out`: exit 0. `check()` ran 148 tests, all passed. Output `fail2commit-0.1.0-1-x86_64.pkg.tar.zst` (3,305,188 bytes, SHA-256 `4f22761411a1aca91fe8198f3bf41c50b4247549b536a65ab79d9b938a7111c4`). Arch's default `-debug` package was also copied in this run; `build-arch.sh` now copies only the main package.
- `bash scripts/release/verify-arch.sh target/arch-out/fail2commit-0.1.0-1-x86_64.pkg.tar.zst`: exit 0. Install, `status` as a normal user, and removal all passed, with the user's Git config and hooks hash-identical throughout. bubblewrap reports unavailable inside an unprivileged container, as expected.

The VM was reverted to its `clean` snapshot afterwards. One harness artifact was not a product issue: bash's command hash reported `fail2commit` after removal, but the file was gone.

## 6. Pending gates (missing prerequisite)

| Gate | Status | Missing prerequisite |
|---|---|---|
| GitHub Actions `ci.yml` runs | **Passed** on `82004af` (section 5d) | - |
| GitHub `release.yml` run | **Passed** on `2888aec` (section 3a0) | - |
| Linux CI exercising the real sandbox | Pending | Install bubblewrap in the CI job and require the sandbox; on stock Ubuntu 24.04 runners AppArmor may need a bwrap userns profile |
| Stock Ubuntu desktop with AppArmor userns restriction | Pending | A non-WSL Ubuntu 24.04+ host (WSL does not enforce the restriction) |
| GitHub repository rulesets (SPEC-003 hosted path) | Pending | A hosted GitHub repository with admin access |
| VS Code GUI click-through (modal approval, picker) and a real Remote-WSL session | Pending | An interactive desktop session; the extension and protocol are covered against both real CLIs headless |
| Tray GUI click-through (approval dialog) | **Passed** (section 5e); tray menu items not clicked | - |
| Non-WSL Linux | **Passed** on Debian 13 (section 5e) and Arch Linux (section 5g) | - |
| Manjaro / EndeavourOS and other Arch derivatives | Pending | Same pacman package; only vanilla Arch was run |
| Interactive terminal approval prompt on Windows | Pending | A ConPTY harness; terminal approval is covered on Linux with a real pty and by the stdio channel |
| Windows full staged-gcc native build in AppContainer | Pending | The MinGW closure is 961 MB / 11,871 files to stage; a staged native workload and the npm node build pass instead |
| LPAC (less-privileged AppContainer) | Not claimed | Runtime verification of LPAC capability with this backend |
| Live internet tests (OSV live smoke, Linux external TCP control) | Pending (ignored tests) | Explicit authorization to contact live endpoints from tests |
| Windows editions other than Windows 11 Pro 25H2 and Windows 10 IoT Enterprise LTSC 2021 | Pending | Additional Windows hosts (Windows 10 LTSC 21H2 passed in section 5b) |
| Windows sandbox on a clean VM in an interactive sign-in | **Passed** (section 5b) | - |
| Microsoft Defender false positive on the unsigned CLI (`Behavior:Win32/DefenseEvasion.A!ml`) | **Open, release blocker for Windows** | An Authenticode code-signing certificate and a Microsoft false-positive submission; both are outward-facing and need the owner |
| Release artifacts including the post-RC1 fixes | **Done**: RC2 (section 3a) | - |
