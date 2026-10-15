# Security policy

## Reporting a vulnerability

Do not post exploit details, working credentials, target evidence, or sensitive logs in public issues.

If GitHub's **Security → Report a vulnerability** option is available for this repository, use it to submit a private report. If it is unavailable, open an issue titled **Private security contact requested** without vulnerability details so a maintainer can arrange a private channel. The project has no published security email or guaranteed response SLA yet.

Include the affected revision, component, impact, a minimal reproduction using systems you control, and redacted logs. Useful areas include authentication and role enforcement, scope bypasses, private-network access, permit/lease checks, evidence disclosure, secret redaction, and scanner subprocess handling.

## Supported scope

The project is under active development. Fixes target the current default branch; there is no maintained older-release support matrix. SSO/MFA and multitenant isolation are not implemented.

Only assess systems you are authorized to test. Prefer the isolated native scanner fixture described in [development](docs/development.md). Third-party target findings are not vulnerabilities in Surfacer itself.

## Deployment essentials

- Keep generated secrets, member keys, sessions, backups, and evidence private.
- Use HTTPS before remote exposure and keep backend services off public ports.
- Use individual, expiring member keys rather than sharing the bootstrap owner token.
- Keep scope validation, network isolation, cancellation, redaction, and gateway controls enabled.
- Back up PostgreSQL and evidence together and validate recovery in an isolated environment.

See [operations](docs/operations.md) and [architecture](docs/architecture.md) for the implemented controls and current boundaries.
