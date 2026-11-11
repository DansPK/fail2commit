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

## 0.1.4 additions

### FR-013 — Show install review progress

- **Links** PRD-004
- **Behavior** While a guarded npm or pip install is being reviewed, show the current step and how many packages of the plan that step has finished. Steps: resolve, download and verify, scan code, check advisories, run scripts in the sandbox, apply. On Windows, a tray window shows the same progress when the review has run for 2 seconds; it closes by itself when the review ends, fails or is cancelled. In a terminal the progress is one line on stderr that is redrawn in place; it is not written when stderr is not a terminal or under `--json` / the api channel.
- **Acceptance**
  - Given an interactive terminal, When `npm install <pkg>` is reviewed, Then stderr shows each step with `done/total` and the line is cleared before any approval prompt or result.
  - Given the tray is running and the review takes 2 s or more, When it runs, Then the tray window shows the same step and counts and closes within 1 s after the review ends.
  - Given the review finishes in under 2 s, Then no tray window appears.
  - Given stderr is redirected to a file, or `--json` is set, Then no progress text appears in stdout or stderr.
  - Given `pip install <pkg>`, Then the same terminal and tray progress appears.
  - Given a progress message that fails validation (unknown step, counts out of range, wrong session), Then the tray ignores it and shows nothing.
- **Priority** Must
- **Status:** Draft

### FR-014 — Reach Linux login shells

- **Links** PRD-005
- **Behavior** `fail2commit setup` makes the guard's PATH change and shell functions active in login shells whose startup file is `~/.bash_profile` or `~/.bash_login` (which hide `~/.profile`), as well as in interactive shells.
- **Acceptance**
  - Given an Arch user whose `~/.bash_profile` exists, When they run `bash -l -c 'command -v npm git'` after setup, Then both resolve to the guard.
  - Given `uninstall-integrations`, Then each touched startup file is byte-identical to before setup.
- **Priority** Must
- **Status:** Draft

### FR-015 — Add the shim folder to PATH once

- **Links** PRD-005
- **Behavior** In any combination of login and interactive shells started from each other, the shim folder appears on PATH exactly once.
- **Acceptance** Given Ubuntu after setup, When `bash -l -i -c 'echo $PATH'` runs, Then the shim folder occurs once; the same holds for `zsh -l -i` when `~/.zshrc` exists.
- **Priority** Should
- **Status:** Draft

### FR-016 — Check pushes that skip Git hooks

- **Links** PRD-001
- **Behavior** A `git push --no-verify`, or a push with `core.hooksPath` overridden on the command line, typed in a shell set up by fail2commit is still checked as FR-001 describes, even when a version manager or another directory puts a different `git` earlier on PATH.
- **Acceptance**
  - Given setup on Linux and Windows (PowerShell, Git Bash), When `git push --no-verify` pushes a synthetic secret, Then the push pauses for approval.
  - Given `git -c core.hooksPath=/dev/null push`, Then the push pauses for approval.
  - Given the guard binary was removed, Then `git` runs the real Git and prints nothing extra.
- **Priority** Must
- **Status:** Draft

### NFR-017 — Keep pull-request CI short

- **Links** PRD-003
- **Behavior** The required CI checks of a pull request finish quickly enough to run on every change, without dropping any test that runs today.
- **Acceptance** With a warm cache, the slowest required job finishes in 12 minutes or less and the whole run in 15 minutes or less, measured on 3 consecutive pull requests. The set of tests run is the same as on `main` at 0.1.3 or larger.
- **Priority** Should
- **Status:** Draft

### FR-018 — Update threat data on demand

- **Links** PRD-004
- **Behavior** The user can download the current OSV malicious-package records for npm and PyPI at any time, without a new fail2commit release, and the offline index (CR-020) is replaced with them. The source is fixed in the binary and reached over verified TLS; the download is bounded and parsed as untrusted input; the old index stays in use until the new one is complete and valid. `fail2commit status` shows the index's source, record count and age, and warns when it is older than `threat_data.max_age_days` (default 7). Optionally, a guarded install refreshes an index older than that before it uses it, when `threat_data.auto_update` is on (default off).
- **Acceptance**
  - Given an index from the pinned 0.1.3 data, When the user runs the update and a new upstream record lists package P, Then an offline install of P is a `malware` deny.
  - Given the download is cut off, too large, or not a valid archive, Then the command exits non-zero, names the reason, and the previous index still works.
  - Given the source cannot be reached, Then the command exits non-zero and nothing changes.
  - Given an index older than `max_age_days`, Then `status` warns with its age.
- **Priority** Must
- **Status:** Draft

### FR-019 — Match package files against YARA rules

- **Links** PRD-004
- **Behavior** Every file of every npm package and pip wheel in an install plan is matched against a bundled YARA rule set and against rule files the user places in the fail2commit rules folder. Each match is a `yara_match` finding with action `approve` that names the rule, the package, the file and whether the file runs at install or at load time. Rule files are trusted settings: a workspace cannot add rules. A user rule file that does not compile stops the install with an error naming the file and line; `fail2commit rules check` validates the folder. Matching is bounded per file, per package and per plan, and a file skipped by a bound is reported as an incomplete scan.
- **Acceptance**
  - Given a fixture package with a file matching a bundled rule, When it is installed through the guard (npm and pip), Then a `yara_match` finding names the rule and file and the install waits for approval.
  - Given a user rule matching a string in a clean package, Then the same finding appears.
  - Given a user rule with a syntax error, Then the install stops before any package code runs, naming the file.
  - Given a package with no match, Then no `yara_match` finding appears and the install time grows by no more than NFR-012's recorded scan budget.
- **Priority** Must
- **Status:** Draft

### FR-020 — Contain a catalogue of hostile script behaviours

- **Links** PRD-005
- **Behavior** `docs/dev/sandbox-hostile-catalogue.md` lists hostile behaviours a lifecycle script may try. Each one, run inside the sandbox on every supported platform, fails or is contained, and the run is reported. The catalogue covers at least: reading user secrets outside the job (SSH keys, npm/pip tokens, Git credentials, browser profiles, fail2commit state); writing outside the granted paths, including through links; any network use (DNS, TCP/UDP to the internet and loopback, IPv6, local sockets and named pipes, the approval pipe and relay); outliving the job (detached and daemonised children, scheduled tasks, user services, startup entries); exhausting resources (process count, memory, CPU time, disk written in the stage, output size); reading the host environment's secrets; kernel attack surface on Linux (ptrace, bpf, userfaultfd, keyctl, io_uring, mount and namespace creation); desktop access on Windows (clipboard, other windows' input, screenshots).
- **Acceptance** Given the catalogue's test package, When each behaviour runs as an install script on Windows 11, Windows 10 and Linux (Ubuntu, Arch), Then each one fails or is killed, nothing outside the stage changes, and the install reports the failure. A behaviour that cannot be contained on a platform is listed as a known limit with its reason.
- **Priority** Must
- **Status:** Draft

### FR-021 — Run on Windows 10

- **Links** PRD-003
- **Behavior** The Windows installer, tray, guards and sandbox work on Windows 10 21H2 or later, x64.
- **Acceptance** Given a clean Windows 10 LTSC 2021 (21H2) VM, When the normal user flow runs (install, tray approval, blocked secret push, guarded npm and pip installs with sandboxed scripts, password set and use, uninstall), Then every step behaves as on Windows 11.
- **Priority** Must
- **Status:** Draft

### NFR-022 — Install popular packages unchanged

- **Links** PRD-002
- **Behavior** Popular packages that run install scripts or ship native code install through the guard with the same result as without it, apart from approvals the guard asks for.
- **Acceptance** The list in `docs/dev/tests/real-world-packages.md` (at least 20 npm and 10 pip packages, including esbuild, sharp, bcrypt, sqlite3, puppeteer, numpy, pandas, cryptography, lxml, pillow) installs and imports through the guard on Windows 11, Windows 10, Ubuntu and Arch. Each failure is fixed or listed as a known limit with its reason.
- **Priority** Must
- **Status:** Draft

## Open questions (0.1.4)

- FR-013: should the tray progress window have a Cancel button? Draft: no; Ctrl+C in the terminal cancels.
- FR-018: should the tray menu offer "Update threat data"? Draft: yes, it runs the same command in a console.
- FR-018: should the offline index also hold ordinary vulnerability advisories, not only malware? Draft: no (size); online OSV stays the source for CVEs.
- FR-019: bundled rule set source and licence (own rules first; third-party rule sets only with a compatible licence).
- FR-020: Windows has no per-user disk quota without administrator rights; disk written in the stage may only be measured and killed on overrun.
- FR-002 (Approved, unchanged): the "password fully working" request is covered by new TC rows, not a requirement change.
