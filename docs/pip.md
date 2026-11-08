# Guarded pip installs (FR-005, SPEC-005)

fail2commit installs only verified registry **wheels**, bound to one
interpreter, after a reviewable plan. Policy lives in Rust; requirement
text, pip config, package metadata and index responses are untrusted.

## Entry points

```sh
fail2commit pip [--python <interpreter>] install <requirement>... | -r requirements.txt
fail2commit pip [--python <interpreter>] recover [--discard]
```

* The `pip` / `pip3` shims (installed by `fail2commit setup`, PATH ordering
  by the Git integration) run exactly this command. Without `--python` the
  interpreter is the Python next to the real `pip` outside the shim dir.
* **A shim cannot intercept `python -m pip` or `py -m pip`.** Use the guarded
  replacement instead:

  ```sh
  fail2commit pip --python python install requests      # instead of: python -m pip install requests
  fail2commit pip --python py install -r requirements.txt
  ```
* Supported `install` options: `-r/--requirement`, `-c/--constraint`,
  `-U/--upgrade`, `--pre`. Anything else is refused.
* Other pip commands: `list show freeze check inspect uninstall help debug`
  and `--version` run through an isolated pip (no index flags). `download`,
  `wheel`, `config`, `index`, … are refused, so no argument reaches an
  unguarded manager path. In `--json` mode their stdout is returned in
  `data.stdout`.

## What is rejected before any resolution (`UnsupportedInput`, exit 2)

Editable installs; VCS and direct URLs; local paths and archives;
`--index-url/-i`, `--extra-index-url`, `--find-links/-f`, `--trusted-host`
in arguments or requirements files; `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`,
`PIP_FIND_LINKS`, `PIP_TRUSTED_HOST` (and `PIP_NO_INDEX`) in the environment;
the same keys in pip config files (user, global, site, `PIP_CONFIG_FILE`);
nested `-r/-c` that are URLs, use `$VAR`, or leave the top-level file's
directory (depth ≤ 4, ≤ 32 files). A value equal to the pinned default index
is tolerated. The resolver never sees the user's text: a sanitized
requirements file is regenerated.

## Pinned index

`https://pypi.org/simple` (files from `files.pythonhosted.org`) unless the
**trusted** `config/pip.toml` under the fail2commit config directory says:

```toml
index_url = "https://pypi.example.org/simple"   # https only (http for loopback tests)
file_hosts = ["files.example.org"]                # extra hosts wheels may come from
```

(`settings.rs` is frozen and rejects unknown keys, so this is a separate
trusted file; it is never read from a workspace.)

## Flow

0. **No `site`, and no code from the target environment, ever.** Every
   interpreter fail2commit starts (probe, dry-run resolution, each apply,
   `verify_installed`, pass-through commands) runs as `python -I -S -c
   <prelude>`. Without `site`, no `*.pth` import line, `sitecustomize` or
   `usercustomize` of the target environment executes inside the guard
   (review W2-001, CR-001). On top of that (re-review RP-003, RP-004):
   * **Guard-owned pip.** The first time an environment is used, before
     anything is installed, `pip/` and its `pip-*.dist-info` are copied from
     the environment into `cache_dir/pip/guard/<id>/site`, precompiled by the
     stdlib, and a SHA-256 manifest of every file is written. Every guard pip
     launch (`Guard::python_c` / `Guard::pip`) re-verifies the manifest first;
     a changed, added or missing file is an `IntegrityFailure` and nothing
     runs. `sys.path` is the snapshot plus the stdlib. The environment's site
     directories are added to `sys.path` only so pip can read
     installed-distribution *metadata* (so "already satisfied", `--upgrade`
     and uninstall of the old version work); a `sys.meta_path` finder refuses to
     import any module from them, so a wheel's `pip/`, `keyring.py`,
     `brotli.py`, … can never run in the guard. A start aborts if the loaded
     `pip` is not the snapshot's. pip installs into the target from the
     running interpreter's scheme (`sys.prefix`, from `pyvenv.cfg` one level
     above the executable), so the target's `site-packages` need not be
     importable; this was exercised on Windows and Linux.
   * Post-install verification (`verify_installed`) lists distributions from
     the `dist-info` directories on disk with `importlib.metadata`
     (explicit paths, stdlib only). Target packages are never imported.
   * The prelude never honours a `pyvenv.cfg` next to the executable (that is
     the wheel `scripts` directory).
   * Pip in a distribution-unbundled layout (vendored libraries outside
     `pip/`, e.g. Debian's `python3-pip` for the system interpreter) is
     refused; use a venv. Upgrading the environment's pip outside fail2commit
     does not change the snapshot; delete `cache_dir/pip/guard/<id>` to take
     a new one.
   * The journal gate is keyed by the interpreter's **canonical identity**
     (implementation, `major.minor`, the real `sys.prefix` reported by the
     probe, canonicalized and case-folded on Windows), not by the spelling of
     the path (RP-006).
1. Parse and reject (above); bind to the interpreter via `python -I -S`
   (`sys.executable`, prefix/venv, platform, pip's vendored
   `packaging.tags.sys_tags()`).
2. **Wheel-only boundary.** A loopback staging index (random-token URL)
   fronts the pinned registry. It lists only `.whl` files that carry a
   SHA-256, hosted on allowed hosts; sdists are never offered. A file is
   served only after it is downloaded (≤ `limits.artifact_max_bytes`),
   matches the index SHA-256, and passes defensive zip checks (path escapes,
   symlinks, entry and uncompressed-size bounds, METADATA name/version equal
   to the filename). A wheel whose `Requires-Dist` is a direct reference
   (`name @ url`, VCS, path) is withheld, which stops transitively supplied
   references before pip can act on them. Redirects fail closed.
3. `python -I -m pip --isolated install --dry-run --report … --only-binary=:all:
   --index-url <staging>` produces the exact versions. Each report entry
   must map to a staged file with the verified hash; anything else is
   `UnsupportedInput`/`IntegrityFailure`. Projects that publish only sdists
   are reported as `UnsupportedInput` (`PyPI:name`). The dry run is never
   trusted for safety: it only ever talks to the staging index.
4. Advisories (`scan::check_advisories`). `Deny` stops. An `Approve`
   finding or an incomplete scan asks for approval of a `Digest` over
   interpreter identity (executable, prefix, tags, platform), the index, the
   requested set and the ordered wheel set with SHA-256. A clean complete
   scan installs without a prompt.
   **Startup files** (`Approve`). Inspection of the reviewed copies flags
   every `*.pth` that `site.addpackage` would execute and every
   `sitecustomize`/`usercustomize` (module, bytecode or package) that the wheel
   would place in `purelib`/`platlib` (root entries, `*.data/purelib`,
   `*.data/platlib`). `.pth` detection follows CPython: UTF-8 with an optional
   BOM, lines split like `str.splitlines` (bare CR, `\x0b`, `\x0c`, `\x1c-\x1e`,
   `\x85`, U+2028/2029 included), a line starting `import ` or `import<TAB>`
   executes. A `.pth` that is not UTF-8 or is too large to inspect is flagged
   (we cannot know how Python would decode it). Each is a `HostExecution`
   finding, source `pip.startup`, naming wheel and file. It is not a hard deny
   because common packages (for example setuptools) ship a `.pth`.
   `exec::authorize_scripts` is called with `has_scripts: false` because
   `has_scripts` describes code the *guard* would run, and none does.
   **Layout violations** (hard `Deny`, `UnsupportedInput`, source
   `pip.layout`, never approvable, nothing installed; RP-003/RP-004). The
   rationale: these entries change how the *next* interpreter start behaves
   or replace the tools the guard and the user rely on, and pip does not stop a
   wheel from writing outside its own files. Denied entries (compared
   case-insensitively on both platforms):
   * `*.data/data/` entries whose first component is `pyvenv.cfg`, `lib`,
     `lib64`, `include`, `bin`, `scripts`, `dlls`, `libs`, `tools` or starts with
     `python` (they resolve into the interpreter prefix: stdlib redirection via
     `home`, the site directories, the executables);
   * any `.pth`, `sitecustomize` or `usercustomize` through the data scheme
     (it would land in a startup location; the allowed data entries such as
     `share/...` are scanned like any other and none of these may exist);
   * `*.data/scripts/` entries that are nested paths, or named `python*`,
     `pip`/`pip3`/`pip3.12`/`pip-script*`, `pyvenv.cfg`, `activate*`/`deactivate*`,
     or equal to the interpreter's own executable name (as spelled and as
     resolved). Ordinary console scripts, including upgrades of ones that
     exist, are allowed;
   * `purelib`/`platlib`/root entries under `pip/` or `pip-<version>.dist-info/`.
     This includes the wheel for **pip itself**: upgrading pip through the
     guard is unsupported, and the finding says so (the guard runs from its own
     snapshot and never replaces the environment's pip).
5. **Apply offline.** Reviewed wheels are copied to a private directory and
   re-hashed; immediately before apply the directory must equal the plan
   byte for byte (changed plan ⇒ `IntegrityFailure`). Each wheel is installed
   with `pip install --no-index --find-links <reviewed> --no-deps
   --require-hashes --only-binary=:all: -r <generated hashes>`. No index, no
   resolution. Afterwards the interpreter's installed set must contain
   every planned name/version.

## Cancel, interrupt, recovery

* **Cancel before apply changes nothing** (the dry run touches no
  environment); the reviewed copies are removed and no journal is written.
* **Cancel during apply** stops at the next wheel boundary: a pip that is
  already installing a wheel finishes it (it is never killed half way). The
  journal (`state/pip/journal-<id>.json`: progress per wheel, `cancelled`)
  and the reviewed wheels are kept. A cancel seen before the first wheel
  removes the fresh journal again.
* **Never rolled forward implicitly (W2-002, CR-002).** While any journal
  exists for the target interpreter's canonical identity (any spelling,
  casing or symlink of the same environment), a guarded `pip install` fails with
  `InvalidInput` and a message pointing to recovery. A crash, a failed wheel
  or a cancel all leave such a journal.
* `fail2commit pip [--python <py>] recover` shows the remaining plan (what is
  installed already, what remains, startup files), re-checks the reviewed
  set byte for byte (tampering ⇒ `IntegrityFailure`, journal kept), re-runs
  the advisory scan on the remaining wheels (`Deny` stops), asks a **fresh
  approval bound to a new digest over the interpreter and the remaining
  wheels**, then installs them and verifies. Cancel or decline changes
  nothing and keeps the journal untouched.
* `recover --discard` removes the journal and the reviewed copies and reports
  which wheels the journal had recorded as installed (they stay installed;
  nothing is rolled back) and which were never installed. No approval is
  needed because nothing is installed or run.
* **The journal is validated whenever it is read (RP-007, RP-008).** It lives
  only under `state_dir/pip/journal-<hash of identity>.json` and carries the
  interpreter facts, index and requested set, so the plan digest is
  recomputed and compared; it must name this environment's identity; its
  `reviewed` directory must be exactly `cache_dir/pip/reviewed/<16 hex>`;
  wheel file names must be plain, and hashes well formed. `recover` also
  re-hashes every wheel in the reviewed set against the journal's SHA-256 and
  re-runs wheel inspection and the layout checks on the remaining wheels
  before asking for approval. A journal that fails is refused with
  `IntegrityFailure` and a message offering `recover --discard`; it keeps
  blocking installs. `--discard` removes only that journal file when it is not
  trusted. There is no MAC: whoever can write the trusted state directory can
  rewrite a consistent journal, which the fresh approval still shows.

## Limits / not covered

* Windows/Linux AppContainer/Bubblewrap are not used: wheels execute no code
  at install time and the guard's interpreters skip `site`. `.pth` files,
  `sitecustomize` and entry points in installed wheels run later, as with any
  Python package; the startup files are named in the approval (above).
* The `pip`/`pip3` shims in the fail2commit bin dir are created only when
  absent or already ours; an existing foreign file there makes `setup` fail
  and is never replaced or removed (W2-006). Ownership is the setup record plus
  a marker in `state_dir/pip/shim-<name>.json` (SHA-256 of the copy on Windows,
  link target on Unix), not equality with the current executable, so setup
  refreshes and uninstall removes our own shims after an in-place upgrade
  (RP-005).
* Index trust beyond HTTPS + SHA-256 from the same index (as PEP 503/691
  provide); no signature checking.
* Recovery is roll-forward (or discard) only; already replaced older versions
  are not restored.
