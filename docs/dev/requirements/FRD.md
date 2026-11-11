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
- **Behavior** While a guarded npm or pip install is being reviewed, show the current step, how many packages of the plan that step has finished, the package being worked on, the elapsed time and the findings so far. Steps: resolve, download and verify, pre-install checks, scan code, check advisories, run scripts in the sandbox, scan script output, apply. On Windows, the fail2commit process itself opens a progress window as soon as the review starts, whether or not the tray runs; it closes by itself when the review ends with no findings, and stays open showing the result when there were findings, until the user closes it. The trusted setting `ui.progress_window` (default on) turns the window off. In a terminal the progress is one line on stderr that is redrawn in place. Neither the window nor the line appears under `--json`, the api channel, or when there is no interactive desktop or terminal.
- **Acceptance**
  - Given Windows and a guarded `npm install <pkg>` from a terminal, When the review starts, Then a progress window opens within 1 s showing the step and `done/total`, with the tray running or not.
  - Given the review ends with no findings, Then the window closes within 1 s.
  - Given the review ends with findings or an error, Then the window stays open with the result until closed.
  - Given an interactive terminal, Then stderr shows each step with `done/total` and the line is cleared before any approval prompt or result.
  - Given `ui.progress_window = false`, `--json`, or a run from a service with no desktop, Then no window opens.
  - Given stderr is redirected to a file, Then no progress text is written to it.
  - Given `pip install <pkg>`, Then the same window and terminal progress appear.
  - Given a workspace file that sets `ui.progress_window`, Then it has no effect.
- **Priority** Must
- **Status:** Approved (owner, 2026-11-11)

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
- **Behavior** `docs/dev/sandbox-hostile-catalogue.md` lists hostile behaviours a lifecycle script may try. Each one, run inside the sandbox on every supported platform, fails or is contained, and the run is reported. The catalogue covers at least: reading user secrets outside the job (SSH keys, npm/pip tokens, Git credentials, browser profiles, fail2commit state); writing outside the granted paths, including through links; network use other than FR-023 allows (loopback, private and link-local ranges, cloud metadata addresses, multicast, IPv6 local ranges, DNS answers that point to those, local sockets and named pipes, the approval pipe and relay); outliving the job (detached and daemonised children, scheduled tasks, user services, startup entries); exhausting resources (process count, memory, CPU time, disk written in the stage, output size); reading the host environment's secrets; kernel attack surface on Linux (ptrace, bpf, userfaultfd, keyctl, io_uring, mount and namespace creation); desktop access on Windows (clipboard, other windows' input, screenshots).
- **Acceptance**
  - Given the catalogue's test package, When each behaviour runs as an install script on Windows 11, Windows 10 and Linux (Ubuntu, Arch), in the default mode and in hardened mode (FR-027), Then each one fails or is killed, nothing outside the stage changes, and the install reports the failure.
  - The catalogue suite runs in CI on Windows and Linux for every pull request, and on all four platforms before a release.
  - A behaviour that cannot be contained on a platform blocks the release unless the owner accepts it as a known limit with its reason.
  - Nothing the sandbox sets up can stop the host from booting, crash it, or block the host's own network: every system-wide change is removed when fail2commit or its service stops, and is tested by killing them mid-run.
- **Priority** Must
- **Status:** Approved (owner, 2026-11-11)

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

### FR-023 — Allow sandboxed scripts to reach the internet only

- **Links** PRD-005
- **Behavior** Sandboxed lifecycle scripts may open outbound connections to public internet addresses, so they can download dependencies and prebuilt binaries. Every other destination is refused: loopback, private (RFC 1918, CGNAT 100.64/10), link-local, cloud metadata (169.254.169.254, fd00:ec2::254), multicast and broadcast, IPv6 loopback, unique-local and link-local, and any name whose DNS answer is one of those. Listening sockets are not allowed. Each destination a script connected to, or was refused, is recorded for the behaviour report (FR-026). The trusted setting `sandbox.network = "internet" | "none"` chooses this or no network at all; the default is `internet`. Supersedes FR-007's "cannot access network" for the internet only (CR-022).
- **Acceptance**
  - Given a script that downloads from `https://registry.npmjs.org`, Then it succeeds.
  - Given a script that connects to 127.0.0.1, ::1, 10.0.0.1, 192.168.x.x of the host's LAN, 169.254.169.254, or a name resolving to 127.0.0.1, Then each attempt fails and is listed in the report.
  - Given a script that listens on a port, Then it fails.
  - Given `sandbox.network = "none"`, Then every connection fails, including to the internet.
- **Priority** Must
- **Status:** Approved (owner, 2026-11-11)

### FR-024 — Detect scripts that touch bait credentials

- **Links** PRD-005
- **Behavior** Each sandbox job contains realistic fake credentials in the places malware looks for real ones (npm, pip, Git, SSH, cloud CLI, `.env`, browser-profile and wallet paths, and token environment variables such as `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`), with values unique per job. A script that opens one of the bait files, or sends a bait value where fail2commit can see it (a destination name, a DNS query, an unencrypted request), is stopped; the package is denied (`bait_touched`, hard deny) and the report names the file or value and the script. Encrypted request bodies are not inspected. Bait values never match a real credential and are never written outside the job.
- **Acceptance**
  - Given a script that reads the fake `~/.npmrc` token, Then the job is stopped and the install is denied naming the package and file.
  - Given a script that puts the bait `GITHUB_TOKEN` value in a host name it connects to, Then the install is denied.
  - Given a clean native build (node-gyp, esbuild, sharp), Then no bait finding appears.
- **Priority** Must
- **Status:** Approved (owner, 2026-11-11)

### FR-025 — Run pre-install risk checks

- **Links** PRD-004
- **Behavior** Before any package code runs, each package in the plan is checked from registry metadata and the reviewed files, without executing anything: (a) this version adds an install script the previous version did not have; (b) the maintainer or publisher set changed since the previous version; (c) the version was published less than `checks.min_age_hours` ago (default 48); (d) the name is within edit distance 1, or a known homoglyph or separator swap, of a package in the bundled popular-package list but is not that package; (e) code that is obfuscated or minified in this version but was not in the previous version. Each hit is an `approve` finding naming the check and the evidence.
- **Acceptance** Given fixture registry metadata for each case (a)–(e), Then the matching finding appears; given a clean, established package, Then none appears. Checks that need data the registry did not return are reported as not checked, not as clean.
- **Priority** Must
- **Status:** Approved (owner, 2026-11-11)

### FR-026 — Report what sandboxed scripts tried

- **Links** PRD-005
- **Behavior** After each sandbox job, the approval or result shows what its scripts did that the sandbox refused or recorded: refused file accesses outside the job, network destinations (allowed and refused), processes started, bait touches, and limits hit. Bounded to 200 entries per job, redacted (CR-017 redaction rules).
- **Acceptance** Given the catalogue package (FR-020), Then the report lists each attempted behaviour that the platform can observe; behaviours that cannot be observed on a platform without hardened mode are listed in the docs.
- **Priority** Must
- **Status:** Approved (owner, 2026-11-11)

### FR-027 — Offer a hardened sandbox mode

- **Links** PRD-005
- **Behavior** With one administrator approval, `fail2commit hardened install` adds a second boundary: on Windows, sandbox jobs run as a dedicated local account with no access to the user's files, through a minimal service that accepts requests only from the installing user's processes and only starts the sandbox launcher, and network rules for that account are enforced at the system firewall layer (FR-023 ranges); on Linux, jobs run under a dedicated system user when hardened mode is installed. `fail2commit hardened uninstall` removes the account, service and rules completely. If the service is stopped or crashes, its network rules disappear with it and sandbox jobs fail closed; the host's own network is never affected. No kernel driver is installed.
- **Acceptance**
  - Given hardened mode, When the catalogue runs, Then every default-mode result holds, and a script that escapes the AppContainer boundary in a test hook still cannot read a file in the user's profile.
  - Given the service is killed during a job, Then the job ends, no rule remains, and the host network works.
  - Given `hardened uninstall`, Then no account, service, firewall rule or file of hardened mode remains.
  - Given a request to the service from another user or from inside a sandbox, Then it is refused.
- **Priority** Must
- **Status:** Approved (owner, 2026-11-11)

### FR-028 — Scan files that scripts produced

- **Links** PRD-004
- **Behavior** Files that sandboxed scripts created or changed (including downloaded binaries) are scanned with the code rules (CR-017), the YARA rules (FR-019) and the malware data before they are committed into the project.
- **Acceptance** Given a script that downloads a file matching a bundled YARA rule, Then the finding appears before the commit, and cancelling leaves the project unchanged.
- **Priority** Must
- **Status:** Approved (owner, 2026-11-11)

### FR-029 — Offer a virtual-machine sandbox backend

- **Links** PRD-005
- **Behavior** An optional backend runs sandbox jobs inside a disposable virtual machine (Windows Sandbox where the Windows edition has it; a small Linux VM otherwise), with the same grants, network rules, bait and report as the other backends. Not available on systems without hardware virtualization; then the other backends are used.
- **Acceptance** Given a host with the feature, When `sandbox.backend = "vm"`, Then the catalogue suite passes and the VM is gone after the job.
- **Priority** Could (last in 0.1.4; moves to 0.1.5 if it would delay the release)
- **Status:** Approved (owner, 2026-11-11)

## Open questions (0.1.4)

- FR-018: should the tray menu offer "Update threat data"? Draft: yes, it runs the same command in a console.
- FR-018: should the offline index also hold ordinary vulnerability advisories, not only malware? Draft: no (size); online OSV stays the source for CVEs.
- FR-019: bundled rule set source and licence (own rules first; third-party rule sets only with a compatible licence).
- FR-020: Windows has no per-user disk quota without administrator rights; disk written in the stage may only be measured and killed on overrun.
- FR-024: on Windows without hardened mode, bait values sent over the network cannot be seen (no traffic inspection); only file opens are detected.
- FR-023 vs FR-007 (Approved): FR-007's acceptance "cannot access network" is narrowed to "cannot access anything but the public internet" by owner decision, recorded as CR-022.
- FR-002 (Approved, unchanged): the "password fully working" request is covered by new TC rows, not a requirement change.
- Out of scope by owner decision: kernel drivers (crash risk).
