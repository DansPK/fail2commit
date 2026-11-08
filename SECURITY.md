# Security

Use disposable test repositories and synthetic credentials when reporting a flaw. Include the version, OS, entry point, expected control and sanitized reproduction. Keep real secrets, private repository URLs and live access tokens out of reports.

Local integrations intercept participating commands. A compromised developer account or unintegrated client can bypass them. Remote policy is required to enforce protected refs across clients. The dependency sandbox protects code executed through the guarded path under its tested policy. Exported artifacts remain untrusted, and later execution requires its own isolation.
