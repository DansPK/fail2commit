# Security policy

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue.

- Use **GitHub private vulnerability reporting**: the repository's **Security** tab, then **Report a vulnerability**.
- Include:
  - the fail2commit version (`fail2commit --version`) and your OS;
  - the entry point (for example `git push`, `npm ci`, `pip install` or the tray);
  - the control you expected to stop it;
  - a minimal reproduction.
- Use disposable repositories and synthetic secrets only. Keep real credentials, private repository URLs and live tokens out of reports.

You should get a reply within 7 days. Fixes are released as soon as they are ready, and the reporter is credited unless they ask not to be.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (preview) | Yes: fixes go into the next 0.1.x release |

## Scope

fail2commit guards the commands that go through it. These limits are known and documented, so they are not vulnerabilities by themselves:

- A client without the local integration, or a compromised developer account, can push without the hooks. Use the server-side hook ([docs/server.md](docs/server.md)) to enforce protected refs for every client.
- Launchers that bypass the shims are not guarded. These include `python -m pip`, a program running `npm.cmd` by full path, and pip in a venv activated in cmd.exe. See the README.
- Only install time is protected. Code that runs when a package is imported, and files exported from the sandbox, stay untrusted. Running them later needs its own isolation, for example `fail2commit run`.

A way to get past one of these limits that is not listed here is in scope. Getting past the sandbox, the approval binding or the secret scan on a guarded path is in scope.
