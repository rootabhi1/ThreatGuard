# Phase 2 — Security Audit Report

_Sprint 1: Public Launch Readiness (v0.1 Community Preview)_
_Audit date: 2026-07-05 · Scope: `threat-modeler/` application on `main`_

## Summary

The application's security posture is strong: parameterised SQL with whitelisted
dynamic columns, in-memory file handling, autoescaped templates, JWT auth with
refresh-token rotation, bcrypt hashing, account lockout, per-IP rate limiting,
RBAC with per-resource ownership, and a verified secure-by-default posture (every
route rejects anonymous access). The audit found **one install-blocking
dependency conflict** and **one CORS misconfiguration**, both now fixed, plus two
hardening recommendations deferred to Phase 7.

## Findings

### 🟠 High

**S1 — `requirements.txt` was un-installable in a clean environment. ✅ Fixed.**
`svglib==2.0.2` requires `reportlab>=4.4.3`, but the file pinned
`reportlab==4.2.5`, so `pip install -r requirements.txt` failed with
`ResolutionImpossible`. Local tests had passed only because the environment
already had a newer reportlab. This would have broken installation for every new
contributor and any clean CI run.
_Fix:_ pinned `reportlab==4.4.10`; the set now resolves cleanly and all 8 test
suites pass (PDF generation included). _(commit: fix(deps) …)_

### 🟡 Medium

**S2 — Wildcard CORS combined with credentials. ✅ Fixed.**
`allow_origins` defaulted to `*` while `allow_credentials=True`. Starlette then
reflects any request Origin and returns `Access-Control-Allow-Credentials: true`,
letting any site make credentialed cross-origin requests. Impact was limited
because auth uses Bearer headers (not cookies), but it is unsafe and would become
exploitable if cookie auth were ever added.
_Fix:_ credentials are enabled only when explicit origins are configured via
`CORS_ORIGINS`; the bare `*` default falls back to no-credentials.
_(commit: fix(security) …)_

**S3 — No Content-Security-Policy header. ⏳ Deferred to Phase 7.**
The app sets `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`,
`Referrer-Policy`, and HSTS, but no CSP. A CSP adds defence-in-depth against XSS.
Deferred deliberately: the UI and the interactive HTML report use inline
scripts/styles, so a naïve CSP would break them. It needs a nonce/hash strategy
and UI testing — appropriate for the Phase 7 hardening pass rather than a rushed
change.

**S4 — Dependency/code scanning not enforced in CI. ⏳ Phase 7.**
Dependabot is configured, but there is no CodeQL, secret scanning, or
`pip-audit` gate in CI (and CI itself is currently misplaced — see Phase 1 H1).
Add these in Phase 7.

### 🟢 Low / Informational

- **S5 — LLM prompt injection (informational).** User system descriptions are
  sent to the model as user-role content. Impact is low: the deterministic rule
  engine is the primary source of threats, LLM output is advisory, and it is
  escaped on render. Recommendation: continue treating model output as untrusted
  input (never render it unescaped, never execute it).
- **S6 — Set `CORS_ORIGINS` explicitly in production** (documented in
  `.env.example`); the `*` default is for local/dev convenience.

## Verified secure (no action needed)

| Area | Result |
|------|--------|
| Hardcoded secrets / keys | None. Only dummy `"k"` values in tests. Secrets come from env; compose fails fast if `JWT_SECRET` / admin creds are unset. |
| Dangerous calls | No `eval` / `exec` / `os.system` / `subprocess` / `pickle` / `yaml.load`. |
| SQL injection | All queries parameterised; dynamic `UPDATE … SET` clauses build column names from **whitelisted** field sets, values always bound. |
| File handling | Uploaded diagrams are read into memory and validated by content-type + size; never written to disk with a user-controlled path. No traversal. |
| Output encoding | Jinja2 autoescape on; the HTML report escapes user-supplied names inside its embedded JSON (`<script>`) block. |
| Authentication | JWT with refresh-token rotation + logout revocation; bcrypt; 15-minute account lockout after repeated failures. |
| Authorization | RBAC + per-resource ownership; IDOR-tested; anonymous secure-by-default sweep confirms no route leaks. |
| Rate limiting | Per-IP limiting on auth endpoints (returns 429). |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`, HSTS on HTTPS. |
| Error handling | Generic messages; no stack traces leaked to clients. |
| Sensitive logging | Request logger records only `method path → status (ms)` + a request ID; no bodies, tokens, or passwords. |

## Security improvement checklist

- [x] Resolve install-blocking dependency conflict (S1)
- [x] Fix wildcard-CORS-with-credentials (S2)
- [x] Confirm no hardcoded secrets
- [x] Confirm SQL parameterisation / whitelisted dynamic columns
- [x] Confirm safe file handling (no traversal)
- [x] Confirm no sensitive logging
- [x] Confirm authz / IDOR / secure-by-default
- [ ] Add Content-Security-Policy with nonces (Phase 7)
- [ ] Add CodeQL + secret scanning + `pip-audit` to CI (Phase 7)
- [ ] Enable GitHub Dependabot **security alerts** (repository setting)
- [ ] Document CSRF posture (header-based auth ⇒ low risk) in SECURITY.md (Phase 3)
