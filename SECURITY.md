# Security Policy

ThreatGuard is a security tool, so we take the security of the project itself
seriously. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's built-in channel:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (Private Vulnerability Reporting).
3. Provide the details below.

If private reporting is unavailable, contact a maintainer directly and ask for a
private channel before sharing details.

### What to include

- A clear description of the issue and its impact.
- Steps to reproduce (proof-of-concept preferred).
- Affected component/endpoint and version/commit.
- Any suggested remediation, if you have one.

### What to expect

- Acknowledgement on a best-effort basis, typically within a few days.
- An assessment and, where valid, a fix and coordinated disclosure.
- Credit for your report if you'd like it (let us know your preference).

Please give us reasonable time to remediate before any public disclosure.

## Scope

In scope: the application in `threat-modeler/` — authentication/authorization,
input validation, injection, output encoding, file handling, secrets management,
and dependency/supply-chain issues.

Out of scope: findings that require a compromised host or privileged local
access; issues in third-party services you connect (e.g. your chosen LLM
provider); and self-inflicted misconfiguration (e.g. deploying with a weak
`JWT_SECRET` or `CORS_ORIGINS=*` in production — see hardening notes below).

## Security posture (summary)

The current posture is documented in the audit records under
[`docs/audit/`](docs/audit/). In short:

- **Auth:** JWT with refresh-token rotation and logout revocation; bcrypt
  password hashing; account lockout; per-IP rate limiting on auth endpoints.
- **Authorization:** role-based access control with per-resource ownership;
  every data endpoint requires a session (verified by an automated
  secure-by-default test that calls every route anonymously).
- **Injection/encoding:** parameterised SQL with whitelisted dynamic columns;
  Jinja2 autoescape; the HTML report escapes user-supplied values embedded in
  its inline JSON.
- **Transport/headers:** `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `X-XSS-Protection`, and HSTS on HTTPS.
- **CSRF:** authentication is via the `Authorization: Bearer` header (not
  cookies), so classic CSRF does not apply.

### Hardening for production

- Set a strong, random `JWT_SECRET`.
- Restrict `CORS_ORIGINS` to your actual origins (the `*` default is
  credential-free and intended for local/dev use).
- Serve over HTTPS so HSTS applies.
- Keep dependencies current (Dependabot is enabled).

## Known hardening gaps

Tracked openly in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) and the roadmap —
notably a Content-Security-Policy and CI-based code/dependency scanning, both
planned.
