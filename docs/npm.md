# Guarded npm installs (FR-004, SPEC-004)

`fail2commit npm ci | install | i [pkg...]` reviews the exact install plan before any
package-controlled code can run. The `npm` shim (`<bin_dir>/npm`, installed by
`fail2commit setup`) routes the real `npm` command here; PATH ordering is set up by the Git
integration. Policy lives in `crates/fail2commit-core/src/npm/`; `cmd/npm.rs` only parses and prints.

## What the guard accepts

| Input | Behavior |
|---|---|
| `ci`, `install`, `i` (and npm's own aliases such as `add`, `isntall`) with registry specs | Guarded flow below. |
| `-D`, `-O`, `-P`, `-E`, `--no-save`, `--ignore-scripts` (and the long forms) | Understood. |
| Git, `github:`, `file:`, `link:`, URL, tarball, `npm:` alias, `workspace:` specs, in arguments, `package.json`, or `overrides` | `UnsupportedInput` (exit 2). Never passed to npm. |
| Any other option, or leading options before the command | `UnsupportedInput`. |
| `update`, `exec`, `rebuild`, `link`, `init`, `audit fix`, ... | `UnsupportedInput`: they could fetch or run packages outside the guard. |
| `run`, `test`, `start`, `ls`, `view`, `config`, `--version`, ... | Pass through to the real npm (they cannot install). |
| npm workspaces, `npm-shrinkwrap.json`, lockfile v1, bundled or aliased packages | `UnsupportedInput`. |

Windows never goes through `cmd.exe`/`npm.cmd`: the guard resolves a trusted `node` with
`toolpath::find_real` and runs `<node dir>/node_modules/npm/bin/npm-cli.js` directly with
structured arguments (on Linux it follows the real `npm` launcher or standard install layouts).

## Flow

1. **Lock and recover.** One lock per project (`<state>/npm/<sha256(project path)>.lock`). An
   interrupted earlier apply is rolled back (or finished) first and reported.
2. **Stage.** Copies `package.json`, `package-lock.json` and the allowlisted project `.npmrc`
   settings into `<cache>/npm-staging/`. npm runs with a cleared environment, a staged
   `--userconfig`/`--globalconfig`, a private `--cache`, and `ignore-scripts=true`.
3. **Pin configuration.** The registry is `registry=` from `<config>/npmrc` (or the user's
   `~/.npmrc`, unless `FAIL2COMMIT_HOME` relocates trusted state), else
   `https://registry.npmjs.org/`. It must be https, or http on loopback. A project `.npmrc` may
   only carry `save-exact`, `save-prefix`, `legacy-peer-deps`, `strict-peer-deps`, `engine-strict`,
   `omit`, `include`, `install-strategy`, `prefer-dedupe`, `loglevel`, `progress`; any other key
   (registry, script-shell, git, auth, ...) stops the command. Values are never echoed.
4. **Resolve.** `npm install --package-lock-only --ignore-scripts` (install). `ci` uses the
   existing lockfile as the plan.
5. **Review the exact graph.** Every `packages` entry must have its name, version, a `resolved`
   URL on the pinned registry (same origin and path prefix, no userinfo/query), and a `sha512`
   integrity. The guard downloads each artifact itself (`ureq`, no redirects, bounded by
   `limits.artifact_max_bytes`) and verifies the SRI: a mismatch is `IntegrityMismatch`, exit 13,
   and cannot be approved. Archives are validated without extraction: no absolute paths, `..`,
   backslashes, drive/stream markers, links, devices or oversize/over-long content. The archive's
   `package.json` name/version must equal the lockfile entry (manifest confusion is a Deny).
   Optional packages that npm would skip on this OS/CPU are reviewed but not downloaded.
6. **Scan.** `preinstall`/`install`/`postinstall` (plus the implicit `node-gyp rebuild` for a
   `binding.gyp`) and the bounded local files they reference go to `scan::inspect_scripts`; the
   whole graph goes to `scan::check_advisories`. Deny findings stop the command; Approve findings
   (advisories, malware, stale or incomplete data) share one approval.
7. **Approve.** One `ApprovalKind::Operation` request bound to a `Digest` over the reviewed plan:
   command, specs, save options, project, pinned registry, project settings, npm version, sandbox
   setting, final `package.json` and lockfile hashes, the ordered artifacts with integrity and
   scripts, and the findings. Any change produces a different digest. Cancel applies nothing.
8. **Scripts.** `exec::authorize_scripts` applies the FR-008 table (sandbox on: run in the
   sandbox; off: skip; off and a `node-gyp` script: separate host-once approval). Failure to
   isolate launches nothing.
9. **Apply offline.** The project fingerprint (`package.json`, lockfile, `.npmrc`) is re-checked;
   a change since review is `IntegrityFailure`. The verified tarballs are put into the private
   cache (`npm cache add <file>`) and `npm ci --offline --ignore-scripts` builds the tree in a
   scratch directory inside the project directory (same volume, so the swap is a rename). The
   tree is checked against the plan (every installed package is in the plan with the same
   name/version and npm's hidden lockfile matches resolved/integrity). Approved lifecycle scripts
   then run through `sandbox::run_job` with npm's context: `npm_lifecycle_event`,
   `npm_lifecycle_script`, `npm_package_name`, `npm_package_version`, `npm_node_execpath`,
   `npm_execpath`, `INIT_CWD`, `.bin` directories on `PATH`, cwd = the package directory.
10. **Commit with a journal.** Original `package.json`/lockfile copies and a journal go under
    `<state>/npm/<key>/`. `node_modules` is renamed aside, the new tree renamed in, `package.json`
    and the lockfile replaced (only if changed), then the backup is deleted. A failure or a crash
    at any step is rolled back to the original bytes on the next run.

## Known limits

- Root-project lifecycle scripts (`prepare`, `postinstall` of the project itself) are not run:
  they are repository-controlled code outside the reviewed graph.
- `node_modules` is replaced as a whole; extras that npm would have left in place (for example
  tool caches inside `node_modules/.cache`) are not carried over.
- Lockfile `resolved` URLs on a different host than the pinned registry are refused, including
  `registry.npmjs.org` URLs when a mirror is pinned.
- Registries that need credentials, redirects on tarball downloads, and proxies are not supported.
- Each npm start is slow on some Windows machines (about 8 s here); a graph needs three
  starts (resolve, cache seeding, offline install).
- The real native build (node-gyp) needs the SPEC-007 sandbox (T-007); see the verify report.
