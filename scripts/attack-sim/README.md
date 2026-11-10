# Supply-chain attack simulation

Run only in a disposable VM that you revert afterwards. The run scripts plant
synthetic secrets in the test user's home and finish with a positive control
that executes the worm **without** fail2commit, which really writes
persistence and backdoors the test project.

`attack_world.py` serves a loopback npm registry (127.0.0.1:4873), an OSV stub
(4874) and an exfiltration canary (4876). The packages are modelled on real
incidents:

| Package | Modelled on | What it tries |
|---|---|---|
| `color-utils-pro` | Shai-Hulud worm (2025) | base64 payload run with `eval`; steals `~/.npmrc`, SSH, AWS, `gh` and git credentials and token environment variables; persistence through `.bashrc`, crontab, the Windows Startup folder and the `Run` key; backdoors the user's project and adds a GitHub workflow; `git push --force` and `npm publish`; exfiltration over loopback, HTTPS and DNS |
| `ua-parse-lite` | ua-parser-js hijack (2021) | preinstall downloads and runs a second stage |
| `deploy-helper` | force-push in a lifecycle script | `git push --force` in plain sight |
| `lodahs` | typosquat listed as known malware | must be denied with no approve option |

Every secret is a synthetic string planted by the run script. The only network
targets are the loopback canary and a public address that the sandbox must
block; nothing real is sent.

- Linux: `bash attack_run.sh <dir-with-these-files>` as a normal user with
  fail2commit installed and `fail2commit setup` done.
- Windows: copy the files to `C:\f2c\atk`, install fail2commit, then run
  `attack_run.ps1` in the signed-in user's session.

Expected results are recorded in `docs/dev/verify/VERIFY-2026-11-09-release.md`
(section 5e): with fail2commit every step is blocked and the host is
byte-for-byte unchanged; the unguarded control succeeds at every step.
