# Independent Final Release Audit — v0.1.0 Community Preview

_Independent Principal Security Engineer review. Prior reports were not trusted;
every finding below was verified directly against the code, git history, and live
repository settings. Date: 2026-07-05._

---

## 1. Executive Summary

The repository is **safe to release** as a v0.1.0 Community Preview, but I found
**two material, non-exploitable issues** an independent auditor should not wave
through for a security tool's public debut. Neither is a vulnerability; both are
easy fixes.

Verified clean, independently: no secrets anywhere in the **full git history**;
no known dependency CVEs (`pip-audit`); no SSRF, XSS, or CSRF exposure; safe
runtime defaults; least-privilege CI; secure-by-default authorization. The app
installs, boots, and runs end-to-end.

**Verdict: 🟡 APPROVE WITH MINOR CHANGES** (see §9). The two changes are: run the
container as non-root, and resolve two unwired modules before tagging.

---

## 2. Security Findings

### Verified clean (evidence)
- **Secrets — none.** `git log -p --all` scanned across the entire history: no
  API keys, tokens, private keys, or passwords. `.env` is gitignored; the only
  pattern hits are documentation placeholders (`sk-ant-xxxx`).
- **No internal IPs / private hosts** in tracked files.
- **Dependencies — no known CVEs.** `pip-audit` on `requirements.txt`: clean
  (jinja2 and python-multipart were already patched).
- **No SSRF.** Outbound calls target operator-configured endpoints only —
  `OPENAI_BASE_URL`, `GITHUB_REPO`, `JIRA_BASE_URL`, `SLACK_WEBHOOK_URL`,
  `SMTP_HOST` — all from environment, never from request input.
- **No XSS/CSRF.** Report output is escaped (`html.escape(quote=True)` +
  JSON-in-`<script>` escaping); auth is `Authorization: Bearer` (no cookies), so
  CSRF does not apply.
- **Safe defaults.** `uvicorn.run(..., reload=False)`; Compose fail-fasts on a
  missing `JWT_SECRET`/admin credentials.

### 🟡 Finding S-1 — Container runs as root (Medium)
`threat-modeler/Dockerfile` has no `USER` directive, so the application runs as
**root** inside the container. For a self-hosted security tool this is an
avoidable blast-radius increase. **Recommended fix** (drop-in, before `CMD`):

```dockerfile
# Create and switch to a non-root user; ensure the data dir is writable.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser
```

_Not applied in this audit because there is no Docker daemon available here to
build-verify the change; the maintainer should apply it and confirm with a
`docker build` + `compose up` (the SQLite dir must remain writable)._

### 🟡 Finding S-2 — Unwired modules handling tokens + network egress (Low/Medium)
`threat_engine/notifications.py` (Slack/email) and
`threat_engine/ticket_export.py` (GitHub/Jira) are **not referenced anywhere**
(0 imports; not wired to any route). They handle secrets (`GITHUB_TOKEN`,
`JIRA_API_TOKEN`, `SMTP_PASS`, `SLACK_WEBHOOK_URL`) and make outbound requests,
yet are untested, undocumented (their env vars are absent from `.env.example`),
and unreachable. This is roadmap pre-work (see `docs/project/FUTURE_IDEAS.md:15`),
so it is intentional — but shipping unwired egress/token code in a security
tool's first release invites "what is this?" from reviewers and creates a latent
path if wired later without review.
**Recommendation:** for the `v0.1.0` tag, either (a) remove these two files and
reintroduce them when wired + tested + documented, or (b) keep them but add a
one-line module docstring marking them experimental/unwired and document their
env vars in `.env.example`. Maintainer's call; (a) is cleaner for a security
project. Zero functionality is affected either way (they are unreachable today).

---

## 3. Engineering Findings

- **CI/CD is sound.** Workflows carry least-privilege `permissions:`
  (`contents: read`; CodeQL `security-events: write`). Actions are pinned to
  major-version tags of trusted publishers (`actions/*`, `github/*`, plus
  `gitleaks/gitleaks-action@v2`, `azure/login@v2`). _Optional hardening (not a
  blocker): pin the two third-party actions to a commit SHA._
- **Tests:** 7 self-executing suites pass on a clean virtualenv; `ruff` clean.
  The runner is script-based by design (no pytest) — acceptable and documented.
- **Repo bloat (minor):** two ~1.4 MB sample HTML reports are tracked, and two
  removed zips (~425 KB) persist in history. Not a security issue; **do not**
  rewrite history for a v0.1 — accept it or trim in a future major cleanup.
- **No dead code elsewhere** — every other `threat_engine` module is referenced.

## 4. Documentation Findings

- **Accurate and consistent.** 83/83 relative links resolve; version is `2.1`
  internally with `v0.1.0` as the public tag (documented); Mermaid diagrams use
  valid `<br>` breaks.
- **Tone is appropriate** for the audience — technical, minimal emoji (one shield
  glyph), honest about limitations. It does not read as marketing copy. No
  unsupported claims found; the "draft, not a sign-off" framing is stated plainly
  and repeatedly. No rewrite necessary.
- **Minor:** the Azure deploy guide uses `threat-modeler-XXX` as a substitution
  placeholder — acceptable, though `<your-app-name>` would read less like a TODO.

## 5. Community Findings

- Governance is complete: `CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`,
  `SUPPORT`, issue forms, PR template, labels, and good-first-issues (#12–#16).
- Discussions, Dependabot, secret scanning + push protection, and branch
  protection are enabled (verified live via the API).
- **Working in practice:** an external contributor already opened PR #17 against
  a good-first-issue, and Dependabot is filing PRs. The on-ramp functions.
- **Minor:** no `CODEOWNERS` or `FUNDING.yml`. Optional for a solo maintainer;
  `CODEOWNERS` becomes useful once reviews are required on PRs.

## 6. Remaining Risks

- **Preview-level posture:** single-instance / SQLite; in-process rate-limit and
  lockout state. Disclosed in `KNOWN_LIMITATIONS.md`. Fine for a preview.
- **Unwired egress modules (S-2)** until removed or gated.
- **Container root (S-1)** until the non-root patch lands.
- **Untriaged inbound:** Dependabot PRs #8–#11 (two are major bumps — test
  before merge) and contributor PR #17 (needs workflow approval).

## 7. Things to Monitor After Launch

- Dependabot/CodeQL alerts on new advisories (esp. `reportlab`, `fastapi`,
  `anthropic`/`openai` majors).
- LLM provider API changes (the provider layer is thin but external).
- First external contributions and issues — response latency shapes reputation.
- Any move to wire the notification/ticket modules — gate that behind a review
  and SSRF/allowlist consideration if webhook URLs ever become user-supplied.

## 8. Top 10 Recommendations for Sprint 2

1. Run the container as **non-root** (S-1) and add a `HEALTHCHECK`.
2. **Resolve the unwired modules** (S-2): remove, or wire + test + document.
3. Add a **Content-Security-Policy** (issue #15) — the last notable web-hardening gap.
4. Neutralize **CSV formula-injection** in the risk-register export (issue #16).
5. Pin third-party GitHub Actions to **commit SHAs**.
6. Add a **`CODEOWNERS`** file once PR review is required by branch protection.
7. Document all real env vars in **`.env.example`**; drop or document the
   notification/ticket vars accordingly.
8. Burn down the deferred **cosmetic lint** ruleset (issue #12) to enable full
   `ruff` enforcement.
9. Provide a **Windows** one-command path (or a devcontainer) to match `make dev`.
10. Plan the **repository flattening** (remove the root/`threat-modeler/` split)
    as a deliberate, tested change.

---

## 9. Final Recommendation

# 🟡 APPROVE WITH MINOR CHANGES

**Evidence:** The release is fundamentally sound and safe — no secrets in history,
no CVEs, no SSRF/XSS/CSRF, safe defaults, least-privilege CI, secure-by-default
authz, and a verified end-to-end product path. It is not a 🔴: nothing found is
exploitable. It is not a clean 🟢 either: an independent auditor should not ship a
security tool that (S-1) runs its container as root and (S-2) carries unwired
modules handling tokens and network egress.

**Before creating the `v0.1.0` tag, do two things:**
1. Apply the non-root Dockerfile patch (S-1) and confirm with a local
   `docker build` + `compose up`.
2. Decide on the two unwired modules (S-2) — remove them from the tag, or mark
   them experimental and document their env vars.

Both are small and low-risk. With them addressed, this is a confident 🟢 for a
public Community Preview.
