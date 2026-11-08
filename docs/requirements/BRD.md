# Business requirements

**Baseline** · Authorized for implementation by the project request. Runtime verification is pending.

| ID | Objective | Evidence |
|---|---|---|
| BR-001 | Prevent accidental Git history loss and secret disclosure | Local and protected-remote tests |
| BR-002 | Contain supply-chain risks before dependency code runs | Advisory, integrity and hostile fixture tests |
| BR-003 | Make protection accessible without a paid dependency | Windows, Linux and VS Code release artifacts |

Developers and maintainers are the primary users. The MVP covers integrated Git and package-manager entry points, approved sandbox execution, and enforcement on explicitly protected remotes.
