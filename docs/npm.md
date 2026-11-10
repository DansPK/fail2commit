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
   settings into `<cache>/sandbox-stage/`. npm runs with a cleared environment, a staged
   `--userconfig`/`--globalconfig`, a private `--cache`, and `ignore-scripts=true`.
3. **Pin configuration.** The registry is `registry=` from `<config>/npmrc` (or the user's
   `~/.npmrc`, unless `FAIL2COMMIT_HOME` relocates trusted state), else
   `https://registry.npmjs.org/`. It must be https, or http on loopback. A project `.npmrc` may
   only carry `save-exact`, `save-prefix`, `legacy-peer-deps`, `strict-peer-deps`, `engine-strict`,
   `omit`, `include`, `install-strategy`, `prefer-dedupe`, `loglevel`, `progress`; any other key
   (registry, script-shell, git, auth, ...) stops the command. Values are never echoed.
4. **Resolve.** `npm install --package-lock-only --ignore-scripts` (install). `ci` uses the
   existing lockfile as the plan.
5. **Fetch and extract (CR-008).** Every `packages` entry must have its name, version, a `resolved`
   URL on the pinned registry (same origin and path prefix, no userinfo/query), and a `sha512`
   integrity. The guard downloads each artifact itself (`ureq`, no redirects, bounded by
   `limits.artifact_max_bytes`) and verifies the SRI: a mismatch is `IntegrityMismatch`, exit 13,
   and cannot be approved. The archive pre-checks are defence in depth only (they decide nothing
   about content): every gzip member is read; no absolute paths, `..`, backslashes, drive/stream
   markers, links, devices or oversize content; names are normalized as npm's `strip: 1`
   extraction does; two entries that collide under Unicode case folding or Windows
   trailing-dot/space folding, or an 8.3 short-name shape (`BUILD~1.JS`), are a `deny`. The
   verified tarballs are then put into the private cache (`npm cache add <file>`) and **npm itself
   extracts them**: `npm ci --offline --ignore-scripts` into the staging tree (`ignore-scripts` is
   in the staged userconfig and on the command line, so no package code runs). Optional packages
   that npm would skip on this OS/CPU are reviewed but not downloaded.
6. **Review the extracted tree.** Every content decision is made from `node_modules/**` as npm
   wrote it, never from the archive reader, so a disagreement between a tar reader and npm's `tar`
   (extra gzip members, a lone zero block, directory entries with a body, pacote's
   `.gitignore` -> `.npmignore` rename) cannot hide anything. The tree is checked against the plan:
   every installed package directory is a lockfile entry with the same name and version, nothing
   else is under `node_modules` (a stray directory, a dot-directory other than `.bin`, a file),
   npm's hidden lockfile matches resolved/integrity, and any symlink or junction is a `deny`
   (npm's own `.bin` links are not followed). Then, per installed package: its `package.json`;
   `preinstall`/`install`/`postinstall` (plus the implicit `node-gyp rebuild` for a `binding.gyp`);
   `prepare` and its pre/post hooks (inspected, never run); and the bounded files those commands
   reference, resolved on disk. Lifecycle commands are tokenized as shell words (quotes, escapes,
   `sh -c "..."` text, `;`/`&&`/`|`), and every word is resolved to a package-relative path:
   `.//x`, `./a/../x` and `$PWD`/`${PWD}`/`$INIT_CWD`/`%cd%` prefixes normalize to the package
   root; `*`/`?` globs match files under the package. Each path is a candidate as given and the way
   node resolves it (`.js`, `.cjs`, `.mjs`, `.json`, `<dir>/index.*`, `<dir>/package.json` and its
   `main`); every candidate that exists on disk is read, so the filesystem decides case and
   trailing-dot questions. A path or `main` that escapes the package root or names an 8.3 alias
   (trailing dots and spaces ignored) is an `unsupported_input` `deny`; a path with an unresolvable
   `$VAR`/`$(...)`/backtick prefix is an `incomplete_scan` `deny`. `npm run|run-script <name>`,
   `npm test|start|stop|restart`, `yarn <name>` and `pnpm <name>` are followed through the
   package's own `scripts` map (including `pre<name>`/`post<name>`), up to 8 hops with cycle
   detection; a chain that cannot be fully followed (`-w`/`--workspace`/`--prefix`/`-r`/`--filter`,
   a `$`/glob script name, too deep or too wide) is an `incomplete_scan` `deny`. A referenced file
   over 256 KiB, past 2 MiB in total, or past 32 files yields an `incomplete_scan` `deny`. The
   scripts and files go to `scan::inspect_scripts`; the whole graph goes to
   `scan::check_advisories`. Known malware is a `deny` before approval. Deny findings stop the
   command; Approve findings (advisories, malware, stale or incomplete data) share one approval.
7. **Approve.** One `ApprovalKind::Operation` request bound to a `Digest` over the reviewed plan:
   command, specs, save options, project, pinned registry, project settings, npm version, sandbox
   setting, final `package.json` and lockfile hashes, the ordered artifacts with integrity,
   scripts and the digests of the reviewed on-disk manifest and referenced files, and the
   findings, and the path, size and SHA-256 of every file in the reviewed staging `node_modules`
   tree (RN3-003). Any change produces a different digest. Cancel applies nothing.
8. **Scripts.** `exec::authorize_scripts` applies the FR-008 table (sandbox on: run in the
   sandbox; off: skip; off and a `node-gyp` script: separate host-once approval). Failure to
   isolate launches nothing.
9. **Run scripts in the reviewed tree.** The project fingerprint (`package.json`, lockfile,
   `.npmrc`) is re-checked; a change since review is `IntegrityFailure`. The reviewed manifest and
   referenced files are hashed again and must equal the digests that were approved. Approved
   lifecycle scripts run through `sandbox::run_job` in that same staging tree, with npm's context:
   `npm_lifecycle_event`, `npm_lifecycle_script`, `npm_package_name`, `npm_package_version`,
   `npm_node_execpath`, `npm_execpath`, `INIT_CWD`, `.bin` directories on `PATH`, cwd = the
   package directory. Immediately before the scripts the whole tree is hashed again and must equal
   the reviewed one (any difference is `IntegrityFailure`, nothing is committed); the reviewed
   manifest and referenced files are re-checked before every script. After the scripts the tree is
   validated again: no links, junctions or reparse points, no new package directory, no change to
   any existing `package.json` or reviewed file, and no change outside a planned package's own
   directory; new or changed files inside a package directory are build output, listed in the
   outcome data as `build_output`. Any violation fails the install. Nothing is extracted a second time. The tree's `node_modules` is then moved
   (renamed, or copied across volumes) into a scratch directory inside the project directory.
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

- Only files named by a lifecycle command (or a followed `npm run` chain) are read. A file those scripts `require()` or `import` is not followed, and run helpers other than `npm`/`yarn`/`pnpm` (for example `npm-run-all`) are not understood; the scan rules are evidence, not a boundary (see docs/scan.md).
- Brace and bracket expansion, indirect `$VAR` script names and computed command strings are not resolved.

- `.bin` (RN3-001): a package that installs a `node_modules/.bin` entry (any nested `.bin`) named like an interpreter or core tool (`node`, `npm`, `sh`, `bash`, `cmd`, `powershell`, `python`, `git`, `gcc`, `make`, `node-gyp`, ... case-insensitive, with or without a Windows extension) is a `suspicious_script` `deny`. For any other `.bin` command a lifecycle script invokes as the first word, the entry and the file its package declares in `bin` are reviewed like a referenced script.
- Windows (RN3-002): bare and relative command paths also try the PATHEXT extensions (`.com .exe .bat .cmd .vbs .vbe .js .jse .wsf .wsh .msc .ps1` plus the host PATHEXT); every candidate that exists is read. A candidate that is a PE/ELF/Mach-O image or contains NUL is an `incomplete_scan` `deny`.
- Local command paths (FR-004, FR-006): a command word with a path separator (`./later.sh`, `.\x`), or the script argument of an interpreter (`node later.js`, `sh ./x`), must have at least one existing candidate on disk at review time; otherwise it is an `incomplete_scan` `deny` naming the path, so a file created by an earlier script can never run unreviewed. Bare PATH commands (`node`, `sh`, `echo`) and other arguments are unaffected. Candidates of such paths that are absent at review (for example `./setup` ahead of an existing `setup.js`) are re-checked before every script; one that has appeared fails the install and nothing is committed.
- Not covered: a new nested `package.json` inside a package directory counts as build output.

## Registry signatures and provenance

CR-018 (P-108). Before any artifact in the plan is downloaded, the guard checks the registry's
signature on it. The npm registry signs each version with ECDSA P-256 over
`<name>@<version>:<integrity>`, and so do mirrors that support signing.

- **Keys.** The guard fetches `<registry>/-/npm/v1/keys` and caches the answer in the trusted
  cache directory (`npm-signatures/`) for `signatures.keys_ttl_secs` (default 24 hours). The
  answer may be at most 64 KiB and list at most 32 keys. Keys of a type other than
  `ecdsa-sha2-nistp256` are ignored.
- **Registry does not sign.** If the keys endpoint returns 404, the install gets one
  `incomplete_scan` finding that needs approval: "registry X publishes no signing keys;
  signatures not verified".
- **Keys cannot be read.** Any other failure (a network error, another HTTP status, malformed
  JSON, an empty key list, a bad key) is a `signature_invalid` deny. The check could not run, so
  nothing in the plan counts as verified.
- **Per package.** The guard reads `dist.signatures` for the exact `name@version` from the
  abbreviated metadata (`Accept: application/vnd.npm.install-v1+json`). It falls back to the
  full document when the abbreviated one has no signatures. It also uses the full document when
  the signing key has an expiry, because only that document has the per-version publish `time`.
  A metadata response may be at most 64 MiB. Up to 8 packages are checked at once. Redirects
  are refused.
- **A `signature_invalid` deny** happens for any of these:
  - the version has no signature;
  - no signature has a `keyid` matching a registry key;
  - the signature does not verify;
  - the metadata `dist.integrity` differs from the lockfile integrity;
  - the key had expired when the version was published, or the publish time is missing so expiry
    cannot be checked.

  A deny blocks the install before anything is downloaded, and nothing in the project changes.
  As npm does, expiry is compared with the publish time. A key that has expired since then still
  verifies the versions it signed earlier. On `registry.npmjs.org` that covers most packages
  published before 2025-01-29.
- **Provenance.** A version counts as having build provenance when its metadata has
  `dist.attestations.provenance`. If this version has none but an earlier version of the same
  package does (earlier by semver), the install gets a `provenance_missing` finding that needs
  approval: "earlier versions were published with build provenance; this one was not (possible
  hijacked account)". A package that never had provenance gets no finding.
- **Turning it off.** `signatures.verify = false` in `settings.toml` skips all of the above, and
  `fail2commit status` prints "npm registry signature checks are off".

Limits:

- Sigstore provenance is **not verified**. The guard only reads whether provenance is present.
  It does not check the Fulcio certificate chain, the Rekor transparency-log entry, or which
  repository and workflow built the package.
- The signing keys come from the same registry as the packages. The check catches a tampered
  artifact, metadata or lockfile from a mirror, cache or proxy. It does not catch a registry
  that has itself been compromised.
- Prerelease tags are compared as whole strings when deciding which version is earlier.
