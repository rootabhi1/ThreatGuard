# Threat Model Report: Simple API service

**Generated:** 2026-07-05 05:27 UTC
**Methodologies:** STRIDE, OWASP
**LLM-enhanced:** No

## System Description

A user calls a REST API backed by a database.

## Data Flow Diagram

<svg viewBox="0 0 1000 600" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Data Flow Diagram" style="font-family: system-ui, -apple-system, Segoe UI, sans-serif;"><defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L8,3 z" fill="context-stroke"/></marker></defs><rect width="1000" height="600" fill="#fafafa"/><rect x="-12.0" y="228.0" width="224.0" height="144.0" rx="14" ry="14" fill="#fff1f2" fill-opacity="0.5" stroke="#f43f5e" stroke-width="2" stroke-dasharray="8,5"/><rect x="-2.0" y="217.0" rx="3" ry="3" width="74" height="22" fill="#f43f5e"/><text x="7.0" y="232.0" font-size="11" font-weight="600" fill="white" font-family="system-ui,sans-serif">🛡 Internet</text><rect x="388.0" y="228.0" width="224.0" height="144.0" rx="14" ry="14" fill="#faf5ff" fill-opacity="0.5" stroke="#a855f7" stroke-width="2" stroke-dasharray="8,5"/><rect x="398.0" y="217.0" rx="3" ry="3" width="130" height="22" fill="#a855f7"/><text x="407.0" y="232.0" font-size="11" font-weight="600" fill="white" font-family="system-ui,sans-serif">🛡 Application tier</text><rect x="788.0" y="228.0" width="224.0" height="144.0" rx="14" ry="14" fill="#f0f9ff" fill-opacity="0.5" stroke="#0ea5e9" stroke-width="2" stroke-dasharray="8,5"/><rect x="798.0" y="217.0" rx="3" ry="3" width="81" height="22" fill="#0ea5e9"/><text x="807.0" y="232.0" font-size="11" font-weight="600" fill="white" font-family="system-ui,sans-serif">🛡 Data tier</text><path id="path_f1" d="M 165.0,300.0 Q 297.5,314.0 430.0,300.0" fill="none" stroke="#ef4444" stroke-width="2.2" stroke-dasharray="none" marker-end="url(#arrow)"/><path id="lp_f1" d="M 165.0,300.0 Q 297.5,314.0 430.0,300.0" fill="none" stroke="none"/><text font-size="10" fill="#475569" font-family="system-ui,sans-serif"><textPath href="#lp_f1" startOffset="50%" text-anchor="middle"> [HTTPS]</textPath></text><text x="297.5" y="318.0" text-anchor="middle" font-size="11" fill="#ef4444">🔒</text><path id="path_f2" d="M 570.0,300.0 Q 700.0,314.0 830.0,300.0" fill="none" stroke="#ef4444" stroke-width="2.2" stroke-dasharray="5,4" marker-end="url(#arrow)"/><path id="lp_f2" d="M 570.0,300.0 Q 700.0,314.0 830.0,300.0" fill="none" stroke="none"/><text font-size="10" fill="#475569" font-family="system-ui,sans-serif"><textPath href="#lp_f2" startOffset="50%" text-anchor="middle"> [TCP]</textPath></text><text x="700.0" y="318.0" text-anchor="middle" font-size="11" fill="#ef4444">⚠</text><rect x="35.0" y="275.0" width="130" height="50" fill="#eff6ff" stroke="#3b82f6" stroke-width="2"/><text x="100.0" y="296.0" text-anchor="middle" font-size="13" font-weight="600" fill="#1e3a8a" font-family="system-ui,sans-serif">User</text><text x="100.0" y="312.0" text-anchor="middle" font-size="10" fill="#1e3a8a" opacity="0.7" font-family="system-ui,sans-serif">user</text><rect x="430.0" y="272.0" width="140" height="56" rx="10" ry="10" fill="#ecfdf5" stroke="#10b981" stroke-width="2"/><text x="500.0" y="296.0" text-anchor="middle" font-size="13" font-weight="600" fill="#064e3b" font-family="system-ui,sans-serif">REST API</text><text x="500.0" y="312.0" text-anchor="middle" font-size="10" fill="#064e3b" opacity="0.7" font-family="system-ui,sans-serif">api</text><rect x="830.0" y="275.0" width="140" height="50" fill="#eef2ff" stroke="none"/><line x1="830.0" y1="275.0" x2="970.0" y2="275.0" stroke="#6366f1" stroke-width="2"/><line x1="830.0" y1="325.0" x2="970.0" y2="325.0" stroke="#6366f1" stroke-width="2"/><text x="900.0" y="296.0" text-anchor="middle" font-size="13" font-weight="600" fill="#312e81" font-family="system-ui,sans-serif">Database</text><text x="900.0" y="312.0" text-anchor="middle" font-size="10" fill="#312e81" opacity="0.7" font-family="system-ui,sans-serif">database</text></svg>

*Solid lines = encrypted flows · Dashed red lines = unencrypted or boundary-crossing · 🔒 / ⚠ indicate encryption status.*

### Trust Boundaries

- **Internet** — contains: User
- **Application tier** — contains: REST API
- **Data tier** — contains: Database

## Executive Summary

- **Total threats identified:** 64
- **Rule-based:** 64  |  **LLM-enhanced:** 0
- **Cross-boundary threats:** 8

### Threats by severity

| Severity | Count |
|---|---|
| Critical | 18 |
| High | 36 |
| Medium | 10 |
| Low | 0 |
| Info | 0 |

## System Components

| Name | Type | Description |
|---|---|---|
| User | `user` |  |
| REST API | `api` |  |
| Database | `database` |  |

## Data Flows

| From | To | Label | Protocol | Auth | Encrypted | Crosses boundary |
|---|---|---|---|---|---|---|
| User | REST API |  | HTTPS | — | Yes | **Yes** |
| REST API | Database |  | TCP | — | No | **Yes** |

## 🚧 Untrusted-Input Boundary Crossings

Flows where untrusted (or less-trusted) input crosses into an internal trust zone. These are the highest-priority validation points in the system — every byte that enters here must be treated as hostile until proven otherwise.

*No untrusted-input boundary crossings detected.*

## Trust Boundary Analysis

### 🛡 Internet

**Components inside this zone:**

- User (`user`)

**Egress (data leaving this zone):**

- User → REST API () — HTTPS, auth: none, encrypted: yes

### 🛡 Application tier

**Components inside this zone:**

- REST API (`api`)

**Ingress (data entering this zone):**

- User → REST API () — HTTPS, auth: none, encrypted: yes

**Egress (data leaving this zone):**

- REST API → Database () — TCP, auth: none, encrypted: NO

**Cross-boundary threats affecting this zone:** 4

### 🛡 Data tier

**Components inside this zone:**

- Database (`database`)

**Ingress (data entering this zone):**

- REST API → Database () — TCP, auth: none, encrypted: NO

**Cross-boundary threats affecting this zone:** 4

## Identified Threats

### Critical (18)

#### Stored data tampering via injection

- **Methodology / Category:** STRIDE → Tampering
- **Affected component:** Database (`database`)
- **CWE:** [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** SQL/NoSQL/command injection alters records or schema.

**⚔️ Attack scenario:**

1. Attacker reaches an input vector exposed by Database (request body, query string, message queue payload, persisted state).
2. Submits malformed input designed to alter the program's logic or stored data (injection, parameter tampering, deserialization gadgets).
3. Database processes the input without strict validation, and the malicious change takes effect.
4. Tampered data is persisted, executed, or relayed downstream — corrupting integrity beyond the original entry point.

**🛡 How to mitigate:**

- _[preventive]_ **Schema-validate and parameterize all inputs** — JSON Schema / OpenAPI validation at API edges; parameterized queries / prepared statements for SQL; ORM-level validators on persisted models.
- _[preventive]_ **Sign and verify integrity-critical messages** — For commands or state mutations, attach an HMAC or signature so downstream consumers can detect tampering in transit or at rest.
- _[detective]_ **Use append-only / write-once stores for audit-critical data** — Where data must not be silently changed, write to an append-only log (e.g., immutable S3 bucket, CloudTrail-like store) and reconcile against the mutable copy.

**🔗 References:** [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

#### Broken access control / missing authz check

- **Methodology / Category:** STRIDE → Elevation of Privilege
- **Affected component:** Database (`database`)
- **CWE:** [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- **CVSS 3.1:** **7.6** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **CVSS 4.0:** **6.3** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Endpoints fail to verify the caller has permission for the action.

**⚔️ Attack scenario:**

1. Attacker authenticates to Database as a low-privilege user, or reaches an unauthenticated entry point.
2. Identifies an authorization gap — a function that doesn't re-check the caller's role, an IDOR-style URL, an admin endpoint with weak gating.
3. Issues requests to that gap, gaining access to data or actions reserved for higher-privilege roles.
4. Now operating with elevated privilege, attacker can pivot to other components, exfiltrate data, or persist access.

**🛡 How to mitigate:**

- _[preventive]_ **Re-authorize on every action, not just at session start** — Every privileged endpoint checks the current principal's roles/permissions for the specific resource being acted on. No 'logged in = allowed'.
- _[preventive]_ **Apply least-privilege to service identities** — The IAM/role attached to Database should grant only the actions it actually performs. Audit IAM grants quarterly.
- _[detective]_ **Detect anomalous privilege use** — Alert when a principal performs an action they have not performed in the trailing 90 days, or when admin-tier actions originate from non-admin networks.

**🔗 References:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

#### Container / process escape

- **Methodology / Category:** STRIDE → Elevation of Privilege
- **Affected component:** Database (`database`)
- **CWE:** [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- **CVSS 3.1:** **7.6** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **CVSS 4.0:** **6.3** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Attacker breaks out of a sandbox to gain host privileges.

**⚔️ Attack scenario:**

1. Attacker authenticates to Database as a low-privilege user, or reaches an unauthenticated entry point.
2. Identifies an authorization gap — a function that doesn't re-check the caller's role, an IDOR-style URL, an admin endpoint with weak gating.
3. Issues requests to that gap, gaining access to data or actions reserved for higher-privilege roles.
4. Now operating with elevated privilege, attacker can pivot to other components, exfiltrate data, or persist access.

**🛡 How to mitigate:**

- _[preventive]_ **Re-authorize on every action, not just at session start** — Every privileged endpoint checks the current principal's roles/permissions for the specific resource being acted on. No 'logged in = allowed'.
- _[preventive]_ **Apply least-privilege to service identities** — The IAM/role attached to Database should grant only the actions it actually performs. Audit IAM grants quarterly.
- _[detective]_ **Detect anomalous privilege use** — Alert when a principal performs an action they have not performed in the trailing 90 days, or when admin-tier actions originate from non-admin networks.

**🔗 References:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

#### Privilege transit across boundary: REST API → Database 🚧 *cross-boundary*

- **Methodology / Category:** STRIDE → Elevation of Privilege
- **Affected component:** Database (`database`)
- **CWE:** [CWE-441 — Confused Deputy](https://cwe.mitre.org/data/definitions/441.html)
- **CVSS 3.1:** **8.9** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L`
- **CVSS 4.0:** **7.4** (High) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L`
- **Boundary crossing:** Application tier → Data tier
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=10, A=10, D=10 → **Total 47/50**

**📍 Where the threat exists:** On the data flow **REST API → Database** (label: *—*, protocol: TCP, auth: none, encrypted: no), crossing the trust boundary from `Application tier` into `Data tier`. The receiving component is **Database** (`database`).

**📝 Description:** If the receiver in 'Data tier' acts on behalf of the caller, attackers compromising 'Application tier' may inherit the receiver's privileges (confused-deputy).

**⚔️ Attack scenario:**

1. Attacker compromises a low-privilege component in zone `Application tier`.
2. Issues requests to Database that get re-executed with the receiver's higher privileges (classic confused-deputy).
3. Because authorization is checked once at request entry but not per-action against the originating caller, the attacker effectively becomes a privileged actor in `Data tier`.
4. Attacker performs actions far beyond the original principal's permissions.

**🛡 How to mitigate:**

- _[preventive]_ **Use scoped, short-lived delegation tokens** — When Database acts on behalf of a caller, attach a delegation token with the caller's identity, scope (action allow-list), and ≤ 5-min TTL.
- _[preventive]_ **Authorize per-action against the originating caller** — Don't rely on ambient authority of the receiver. Each action checks: (a) the delegation token is valid, (b) the original caller has permission for this specific action, (c) the action is within scope.
- _[detective]_ **Audit each privilege transit** — Log: original caller → delegating component → action performed. Make this queryable for incident response.

**🔗 References:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-441 — Confused Deputy](https://cwe.mitre.org/data/definitions/441.html)

#### Broken access control / missing authz check

- **Methodology / Category:** STRIDE → Elevation of Privilege
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- **CVSS 3.1:** **8.3** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **CVSS 4.0:** **6.3** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Endpoints fail to verify the caller has permission for the action.

**⚔️ Attack scenario:**

1. Attacker authenticates to REST API as a low-privilege user, or reaches an unauthenticated entry point.
2. Identifies an authorization gap — a function that doesn't re-check the caller's role, an IDOR-style URL, an admin endpoint with weak gating.
3. Issues requests to that gap, gaining access to data or actions reserved for higher-privilege roles.
4. Now operating with elevated privilege, attacker can pivot to other components, exfiltrate data, or persist access.

**🛡 How to mitigate:**

- _[preventive]_ **Re-authorize on every action, not just at session start** — Every privileged endpoint checks the current principal's roles/permissions for the specific resource being acted on. No 'logged in = allowed'.
- _[preventive]_ **Apply least-privilege to service identities** — The IAM/role attached to REST API should grant only the actions it actually performs. Audit IAM grants quarterly.
- _[detective]_ **Detect anomalous privilege use** — Alert when a principal performs an action they have not performed in the trailing 90 days, or when admin-tier actions originate from non-admin networks.

**🔗 References:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

#### Container / process escape

- **Methodology / Category:** STRIDE → Elevation of Privilege
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- **CVSS 3.1:** **8.3** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **CVSS 4.0:** **6.3** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Attacker breaks out of a sandbox to gain host privileges.

**⚔️ Attack scenario:**

1. Attacker authenticates to REST API as a low-privilege user, or reaches an unauthenticated entry point.
2. Identifies an authorization gap — a function that doesn't re-check the caller's role, an IDOR-style URL, an admin endpoint with weak gating.
3. Issues requests to that gap, gaining access to data or actions reserved for higher-privilege roles.
4. Now operating with elevated privilege, attacker can pivot to other components, exfiltrate data, or persist access.

**🛡 How to mitigate:**

- _[preventive]_ **Re-authorize on every action, not just at session start** — Every privileged endpoint checks the current principal's roles/permissions for the specific resource being acted on. No 'logged in = allowed'.
- _[preventive]_ **Apply least-privilege to service identities** — The IAM/role attached to REST API should grant only the actions it actually performs. Audit IAM grants quarterly.
- _[detective]_ **Detect anomalous privilege use** — Alert when a principal performs an action they have not performed in the trailing 90 days, or when admin-tier actions originate from non-admin networks.

**🔗 References:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

#### Privilege transit across boundary: User → REST API 🚧 *cross-boundary*

- **Methodology / Category:** STRIDE → Elevation of Privilege
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-441 — Confused Deputy](https://cwe.mitre.org/data/definitions/441.html)
- **CVSS 3.1:** **9.9** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L`
- **CVSS 4.0:** **7.4** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L`
- **Boundary crossing:** Internet → Application tier
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=10, D=10 → **Total 46/50**

**📍 Where the threat exists:** On the data flow **User → REST API** (label: *—*, protocol: HTTPS, auth: none, encrypted: yes), crossing the trust boundary from `Internet` into `Application tier`. The receiving component is **REST API** (`api`).

**📝 Description:** If the receiver in 'Application tier' acts on behalf of the caller, attackers compromising 'Internet' may inherit the receiver's privileges (confused-deputy).

**⚔️ Attack scenario:**

1. Attacker compromises a low-privilege component in zone `Internet`.
2. Issues requests to REST API that get re-executed with the receiver's higher privileges (classic confused-deputy).
3. Because authorization is checked once at request entry but not per-action against the originating caller, the attacker effectively becomes a privileged actor in `Application tier`.
4. Attacker performs actions far beyond the original principal's permissions.

**🛡 How to mitigate:**

- _[preventive]_ **Use scoped, short-lived delegation tokens** — When REST API acts on behalf of a caller, attach a delegation token with the caller's identity, scope (action allow-list), and ≤ 5-min TTL.
- _[preventive]_ **Authorize per-action against the originating caller** — Don't rely on ambient authority of the receiver. Each action checks: (a) the delegation token is valid, (b) the original caller has permission for this specific action, (c) the action is within scope.
- _[detective]_ **Audit each privilege transit** — Log: original caller → delegating component → action performed. Make this queryable for incident response.

**🔗 References:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-441 — Confused Deputy](https://cwe.mitre.org/data/definitions/441.html)

#### Sensitive data stored in plaintext

- **Methodology / Category:** OWASP Top 10 → A02 Cryptographic Failures
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **2.1** (Low) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** PII or passwords stored without encryption.

**⚔️ Attack scenario:**

1. Attacker probes Database via reachable inputs.
2. Identifies the weakness named by this threat (A02 Cryptographic Failures).
3. Crafts an exploit specific to the affected component type (database).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around Database. Review applicability of OWASP ASVS controls for database components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### SQL injection via unsanitised input

- **Methodology / Category:** OWASP Top 10 → A03 Injection
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **2.1** (Low) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Attacker manipulates SQL queries.

**⚔️ Attack scenario:**

1. Attacker probes Database via reachable inputs.
2. Identifies the weakness named by this threat (A03 Injection).
3. Crafts an exploit specific to the affected component type (database).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around Database. Review applicability of OWASP ASVS controls for database components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Command injection via shell execution

- **Methodology / Category:** OWASP Top 10 → A03 Injection
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **2.1** (Low) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** User input passed to OS shell.

**⚔️ Attack scenario:**

1. Attacker probes Database via reachable inputs.
2. Identifies the weakness named by this threat (A03 Injection).
3. Crafts an exploit specific to the affected component type (database).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around Database. Review applicability of OWASP ASVS controls for database components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Default credentials left on service

- **Methodology / Category:** OWASP Top 10 → A05 Security Misconfiguration
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **2.1** (Low) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Admin password left at factory default.

**⚔️ Attack scenario:**

1. Attacker probes Database via reachable inputs.
2. Identifies the weakness named by this threat (A05 Security Misconfiguration).
3. Crafts an exploit specific to the affected component type (database).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around Database. Review applicability of OWASP ASVS controls for database components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Missing function-level access control

- **Methodology / Category:** OWASP Top 10 → A01 Broken Access Control
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Admin endpoints accessible to low-privilege users.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A01 Broken Access Control).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Sensitive data stored in plaintext

- **Methodology / Category:** OWASP Top 10 → A02 Cryptographic Failures
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** PII or passwords stored without encryption.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A02 Cryptographic Failures).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### SQL injection via unsanitised input

- **Methodology / Category:** OWASP Top 10 → A03 Injection
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Attacker manipulates SQL queries.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A03 Injection).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Command injection via shell execution

- **Methodology / Category:** OWASP Top 10 → A03 Injection
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** User input passed to OS shell.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A03 Injection).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Default credentials left on service

- **Methodology / Category:** OWASP Top 10 → A05 Security Misconfiguration
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Admin password left at factory default.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A05 Security Misconfiguration).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Weak or absent MFA on privileged accounts

- **Methodology / Category:** OWASP Top 10 → A07 Authentication Failures
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Admin accounts authenticated by password only.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A07 Authentication Failures).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### SSRF via user-supplied URL parameter

- **Methodology / Category:** OWASP Top 10 → A10 Server-Side Request Forgery
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=9, R=8, E=9, A=9, D=9 → **Total 44/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Attacker makes server fetch internal metadata endpoints.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A10 Server-Side Request Forgery).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

### High (36)

#### Data-in-transit modification

- **Methodology / Category:** STRIDE → Tampering
- **Affected component:** Database (`database`)
- **CWE:** [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Attacker on the network path alters request/response payloads.

**⚔️ Attack scenario:**

1. Attacker reaches an input vector exposed by Database (request body, query string, message queue payload, persisted state).
2. Submits malformed input designed to alter the program's logic or stored data (injection, parameter tampering, deserialization gadgets).
3. Database processes the input without strict validation, and the malicious change takes effect.
4. Tampered data is persisted, executed, or relayed downstream — corrupting integrity beyond the original entry point.

**🛡 How to mitigate:**

- _[preventive]_ **Schema-validate and parameterize all inputs** — JSON Schema / OpenAPI validation at API edges; parameterized queries / prepared statements for SQL; ORM-level validators on persisted models.
- _[preventive]_ **Sign and verify integrity-critical messages** — For commands or state mutations, attach an HMAC or signature so downstream consumers can detect tampering in transit or at rest.
- _[detective]_ **Use append-only / write-once stores for audit-critical data** — Where data must not be silently changed, write to an append-only log (e.g., immutable S3 bucket, CloudTrail-like store) and reconcile against the mutable copy.

**🔗 References:** [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

#### Config / secret tampering

- **Methodology / Category:** STRIDE → Tampering
- **Affected component:** Database (`database`)
- **CWE:** [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Unauthorized changes to runtime config alter security behavior.

**⚔️ Attack scenario:**

1. Attacker reaches an input vector exposed by Database (request body, query string, message queue payload, persisted state).
2. Submits malformed input designed to alter the program's logic or stored data (injection, parameter tampering, deserialization gadgets).
3. Database processes the input without strict validation, and the malicious change takes effect.
4. Tampered data is persisted, executed, or relayed downstream — corrupting integrity beyond the original entry point.

**🛡 How to mitigate:**

- _[preventive]_ **Schema-validate and parameterize all inputs** — JSON Schema / OpenAPI validation at API edges; parameterized queries / prepared statements for SQL; ORM-level validators on persisted models.
- _[preventive]_ **Sign and verify integrity-critical messages** — For commands or state mutations, attach an HMAC or signature so downstream consumers can detect tampering in transit or at rest.
- _[detective]_ **Use append-only / write-once stores for audit-critical data** — Where data must not be silently changed, write to an append-only log (e.g., immutable S3 bucket, CloudTrail-like store) and reconcile against the mutable copy.

**🔗 References:** [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

#### Log tampering

- **Methodology / Category:** STRIDE → Repudiation
- **Affected component:** Database (`database`)
- **CWE:** [CWE-778 — Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- **CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** An attacker with access modifies or deletes audit trails.

**⚔️ Attack scenario:**

1. User performs a sensitive action through Database (a transfer, a permission change, a deletion).
2. Audit logs are absent, incomplete, or modifiable by the same principal who performed the action.
3. User later denies having performed the action, or an attacker covers their tracks.
4. Without tamper-evident logs, neither responsible party can be identified — leading to fraud, dispute, or regulatory exposure.

**🛡 How to mitigate:**

- _[detective]_ **Emit tamper-evident audit logs** — Sign log entries (HMAC chain, hash-linked) so insertion or deletion is detectable. Forward to a separate, append-only system the action's principal cannot administer.
- _[detective]_ **Capture sufficient detail per audit event** — Who (authenticated principal, not just session ID), what (specific action and target), when (UTC, monotonic-clock-corroborated), where (source IP, request ID), why (correlated to the upstream business event).
- _[detective]_ **Periodic log integrity verification** — Schedule daily integrity checks on the audit log chain. Alert on any gap.

**🔗 References:** [A09:2021 — Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-778 — Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

#### Sensitive data exposure in transit

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** PII, secrets, or tokens transmitted over unencrypted channels.

**⚔️ Attack scenario:**

1. Attacker reaches Database via a legitimate or guessable channel.
2. Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).
3. Aggregates leaked information from multiple requests to build a profile of the system or its users.
4. Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.

**🛡 How to mitigate:**

- _[preventive]_ **Apply field-level access control on responses** — The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.
- _[preventive]_ **Strip debug detail from error responses** — Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.
- _[preventive]_ **Encrypt data at rest with key separation** — For database, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Sensitive data exposure at rest

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Stored PII / secrets accessible without proper authorization.

**⚔️ Attack scenario:**

1. Attacker reaches Database via a legitimate or guessable channel.
2. Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).
3. Aggregates leaked information from multiple requests to build a profile of the system or its users.
4. Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.

**🛡 How to mitigate:**

- _[preventive]_ **Apply field-level access control on responses** — The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.
- _[preventive]_ **Strip debug detail from error responses** — Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.
- _[preventive]_ **Encrypt data at rest with key separation** — For database, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Insecure direct object reference (IDOR)

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** User can access another user's resources by guessing IDs.

**⚔️ Attack scenario:**

1. Attacker reaches Database via a legitimate or guessable channel.
2. Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).
3. Aggregates leaked information from multiple requests to build a profile of the system or its users.
4. Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.

**🛡 How to mitigate:**

- _[preventive]_ **Apply field-level access control on responses** — The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.
- _[preventive]_ **Strip debug detail from error responses** — Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.
- _[preventive]_ **Encrypt data at rest with key separation** — For database, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Application-layer DDoS

- **Methodology / Category:** STRIDE → Denial of Service
- **Affected component:** Database (`database`)
- **CWE:** [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)
- **CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Attacker floods expensive endpoints (e.g., search, login).

**⚔️ Attack scenario:**

1. Attacker identifies a costly operation in Database (regex matching, file generation, expensive query, large allocation).
2. Issues many concurrent requests targeting that operation, or a single request with pathological input.
3. Database's resources (CPU, memory, connections, disk) saturate or exhaust.
4. Legitimate users can no longer reach Database; cascading failure may take down dependents.

**🛡 How to mitigate:**

- _[preventive]_ **Apply input limits at the edge** — Maximum request size, body depth, array length, and string length. Reject early — before parsing or business logic runs.
- _[preventive]_ **Rate-limit per principal and per resource** — Token bucket per authenticated user AND per costly endpoint. Adaptive throttling on saturation.
- _[corrective]_ **Set hard timeouts on outbound calls** — No call (DB, downstream service, third-party API) should be able to hang the request handler indefinitely. Use circuit breakers and bulkheads.

**🔗 References:** [A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)

#### Privilege escalation via mass assignment

- **Methodology / Category:** STRIDE → Elevation of Privilege
- **Affected component:** Database (`database`)
- **CWE:** [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- **CVSS 3.1:** **7.6** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **CVSS 4.0:** **6.3** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** User submits extra fields (e.g., role=admin) and they bind to the model.

**⚔️ Attack scenario:**

1. Attacker authenticates to Database as a low-privilege user, or reaches an unauthenticated entry point.
2. Identifies an authorization gap — a function that doesn't re-check the caller's role, an IDOR-style URL, an admin endpoint with weak gating.
3. Issues requests to that gap, gaining access to data or actions reserved for higher-privilege roles.
4. Now operating with elevated privilege, attacker can pivot to other components, exfiltrate data, or persist access.

**🛡 How to mitigate:**

- _[preventive]_ **Re-authorize on every action, not just at session start** — Every privileged endpoint checks the current principal's roles/permissions for the specific resource being acted on. No 'logged in = allowed'.
- _[preventive]_ **Apply least-privilege to service identities** — The IAM/role attached to Database should grant only the actions it actually performs. Audit IAM grants quarterly.
- _[detective]_ **Detect anomalous privilege use** — Alert when a principal performs an action they have not performed in the trailing 90 days, or when admin-tier actions originate from non-admin networks.

**🔗 References:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

#### Unencrypted flow: REST API → Database

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** Database (`database`)
- **CWE:** [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=8, A=7, D=8 → **Total 36/50**

**📍 Where the threat exists:** On the data flow **REST API → Database** (label: *—*, protocol: TCP, auth: none, encrypted: no). The receiving component is **Database** (`database`).

**📝 Description:** Data flow '' uses TCP without encryption.

**⚔️ Attack scenario:**

1. Attacker gains read access to the network path (sniffing on shared LAN, compromised router, hostile cloud tenant, malicious admin).
2. Captures cleartext traffic on the TCP channel.
3. Extracts credentials, session tokens, PII, or business secrets from packet captures.
4. Uses the credentials to impersonate Database or the calling component, or sells/leaks the captured data.

**🛡 How to mitigate:**

- _[preventive]_ **Enable TLS 1.3 (or 1.2 with strong ciphers) on the flow** — Replace plain TCP with its TLS variant. For databases use TLS-enabled drivers; for queues like AMQP/Kafka, configure broker certs and require client TLS.
- _[preventive]_ **Enforce certificate validation** — Verify hostname, validate the chain to a known CA, pin certificates or use a private CA for internal services. Disable cipher fallbacks to NULL/EXPORT/RC4.
- _[detective]_ **Scan for cleartext fallbacks** — Add a network-policy / NetworkPolicy / security-group rule that drops any traffic on the cleartext port. Alert if it ever fires.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

#### Unauthenticated flow: REST API → Database

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** Database (`database`)
- **CWE:** [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=8, A=7, D=8 → **Total 36/50**

**📍 Where the threat exists:** On the data flow **REST API → Database** (label: *—*, protocol: TCP, auth: none, encrypted: no). The receiving component is **Database** (`database`).

**📝 Description:** Data flow has no authentication mechanism declared.

**⚔️ Attack scenario:**

1. Attacker discovers the endpoint at Database (port scan, leaked config, error messages, or DNS enumeration).
2. Sends requests directly without any credentials, since the flow does not require authentication.
3. Database processes the request as if it came from a trusted caller and returns data or executes the action.
4. Attacker enumerates data, modifies records, or chains to other internal services from this entry point.

**🛡 How to mitigate:**

- _[preventive]_ **Require an authentication mechanism on every external-facing flow** — Bearer tokens (OAuth2/OIDC) for human-driven calls, mutual TLS or signed JWT for service-to-service. Block requests that arrive without credentials at the gateway, before they reach the application.
- _[preventive]_ **Reject anonymous traffic at the receiver as well** — Defense in depth: even if the gateway rule fails, the receiving component should reject any request lacking a valid principal.
- _[detective]_ **Rate-limit unauthenticated probes** — Apply a low-tolerance rate limit to requests that lack credentials (5/min per source IP) and alert on sustained failures.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

#### Trust-boundary crossing without strong authn: REST API → Database 🚧 *cross-boundary*

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** Database (`database`)
- **CWE:** [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS 3.1:** **6.8** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
- **CVSS 4.0:** **5.8** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N`
- **Boundary crossing:** Application tier → Data tier
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=8, A=9, D=9 → **Total 39/50**

**📍 Where the threat exists:** On the data flow **REST API → Database** (label: *—*, protocol: TCP, auth: none, encrypted: no), crossing the trust boundary from `Application tier` into `Data tier`. The receiving component is **Database** (`database`).

**📝 Description:** Flow '' crosses trust boundary 'Application tier' → 'Data tier'. Caller identity must be re-verified at the boundary; existing trust does not transit.

**⚔️ Attack scenario:**

1. Attacker positions themselves on the network path between source and destination, or compromises an upstream component in the source zone.
2. Crafts requests with forged or replayed identity claims (cookies, tokens, IP-based trust).
3. Database accepts the request because identity is not re-verified at the boundary, treating the upstream zone as trusted.
4. Attacker can now perform actions as the impersonated principal across the boundary.

**🛡 How to mitigate:**

- _[preventive]_ **Re-authenticate at the boundary** — Require a fresh, audience-bound credential at the receiver. Do not infer identity from network position, source IP, or upstream session.
- _[preventive]_ **Use mutual TLS or signed tokens with audience claims** — For service-to-service calls into Database, terminate mTLS at the boundary and reject any caller without a valid client cert. For human-driven flows, use OAuth2 / OIDC with audience and issuer validation.
- _[detective]_ **Log every cross-boundary auth decision** — Emit an authentication event (success and failure) tagged with both source and destination zone. Forward to SIEM with retention ≥ 90 days.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

#### Cross-boundary input not validated: REST API → Database 🚧 *cross-boundary*

- **Methodology / Category:** STRIDE → Tampering
- **Affected component:** Database (`database`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **8.7** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`
- **CVSS 4.0:** **5.8** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N`
- **Boundary crossing:** Application tier → Data tier
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=8, A=9, D=9 → **Total 39/50**

**📍 Where the threat exists:** On the data flow **REST API → Database** (label: *—*, protocol: TCP, auth: none, encrypted: no), crossing the trust boundary from `Application tier` into `Data tier`. The receiving component is **Database** (`database`).

**📝 Description:** Data crossing the trust boundary into 'Data tier' must be treated as untrusted, even if the source is internal. Implicit trust is the most common cause of injection / SSRF / deserialization bugs.

**⚔️ Attack scenario:**

1. Attacker compromises a less-trusted upstream zone or directly sends malformed input to Database.
2. Sends payloads with unexpected types, lengths, or special characters (e.g. SQL meta-chars, NUL bytes, control sequences).
3. Database processes the input under the assumption that the upstream zone has already validated it — but the boundary changes the security context.
4. Injection, deserialization flaws, or buffer issues trigger; attacker pivots into Database or the zone behind it.

**🛡 How to mitigate:**

- _[preventive]_ **Validate against an allow-list schema at the boundary** — Define an explicit schema (JSON Schema, Protobuf, OpenAPI) for every accepted message at this boundary. Reject anything that doesn't match — type, length, charset, enum values, nested depth.
- _[preventive]_ **Canonicalize before validation** — Decode URL-encoding, Unicode normalization (NFC), trim whitespace, and resolve relative paths before validating. Avoid double-decoding bypasses.
- _[preventive]_ **Apply context-specific output encoding** — Whatever Database does with the input — SQL: parameterized queries, HTML: contextual escaping, OS commands: avoid shell, use exec arrays, LDAP: escape filter chars.

**🔗 References:** [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Cross-boundary data exposure risk: REST API → Database 🚧 *cross-boundary*

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **6.8** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
- **CVSS 4.0:** **5.8** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N`
- **Boundary crossing:** Application tier → Data tier
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=8, A=9, D=9 → **Total 39/50**

**📍 Where the threat exists:** On the data flow **REST API → Database** (label: *—*, protocol: TCP, auth: none, encrypted: no), crossing the trust boundary from `Application tier` into `Data tier`. The receiving component is **Database** (`database`).

**📝 Description:** Information leaving 'Application tier' into 'Data tier' may include data the receiving zone is not authorized to see. Cross-boundary egress is a common data-leak surface.

**⚔️ Attack scenario:**

1. Attacker observes traffic leaving the source zone, or compromises a component in the destination zone.
2. The destination zone receives more data than it strictly needs (over-fetching, verbose error responses, full record dumps).
3. Attacker harvests sensitive fields (PII, secrets, internal IDs) that should never have left the source zone.
4. Data is exfiltrated, sold, or used to plan a deeper attack on the originating zone.

**🛡 How to mitigate:**

- _[preventive]_ **Enforce minimum-data-needed at the egress point** — Whitelist exactly which fields leave the source zone. Strip everything else server-side before serialization.
- _[preventive]_ **Tokenize or redact sensitive fields** — Replace PII / PCI / PHI fields with reversible tokens or one-way hashes when the destination zone doesn't need the cleartext value.
- _[detective]_ **Log cross-boundary data flows for review** — Sample-log the field set crossing this boundary (not the values) so DLP and privacy reviews can audit what's egressing.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Authentication bypass via credential stuffing

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Attackers reuse leaked credentials to impersonate legitimate users.

**⚔️ Attack scenario:**

1. Attacker locates REST API's identity claim mechanism (token format, header name, signing key handling).
2. Forges or replays a token to assert another principal's identity.
3. REST API accepts the claim because verification is missing or weak (e.g., signature not checked, expired tokens accepted, no audience validation).
4. Attacker acts as the spoofed principal — reading data, triggering workflows, or pivoting to internal services.

**🛡 How to mitigate:**

- _[preventive]_ **Validate token signatures with explicit algorithm allow-listing** — Reject 'alg: none', reject HS256 when expecting RS256. Use a vetted JWT library; never hand-roll verification.
- _[preventive]_ **Enforce audience and issuer claims** — Every token must declare which service it's intended for. Reject tokens whose audience doesn't match this component.
- _[preventive]_ **Bind tokens to a session or device** — Use mTLS-bound tokens, DPoP, or token binding to prevent replay if a token is captured.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

#### Session token hijacking

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Attacker steals or predicts a session token to impersonate a user.

**⚔️ Attack scenario:**

1. Attacker locates REST API's identity claim mechanism (token format, header name, signing key handling).
2. Forges or replays a token to assert another principal's identity.
3. REST API accepts the claim because verification is missing or weak (e.g., signature not checked, expired tokens accepted, no audience validation).
4. Attacker acts as the spoofed principal — reading data, triggering workflows, or pivoting to internal services.

**🛡 How to mitigate:**

- _[preventive]_ **Validate token signatures with explicit algorithm allow-listing** — Reject 'alg: none', reject HS256 when expecting RS256. Use a vetted JWT library; never hand-roll verification.
- _[preventive]_ **Enforce audience and issuer claims** — Every token must declare which service it's intended for. Reject tokens whose audience doesn't match this component.
- _[preventive]_ **Bind tokens to a session or device** — Use mTLS-bound tokens, DPoP, or token binding to prevent replay if a token is captured.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

#### API key / service identity spoofing

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** An attacker obtains or forges an API key to act as a trusted service.

**⚔️ Attack scenario:**

1. Attacker locates REST API's identity claim mechanism (token format, header name, signing key handling).
2. Forges or replays a token to assert another principal's identity.
3. REST API accepts the claim because verification is missing or weak (e.g., signature not checked, expired tokens accepted, no audience validation).
4. Attacker acts as the spoofed principal — reading data, triggering workflows, or pivoting to internal services.

**🛡 How to mitigate:**

- _[preventive]_ **Validate token signatures with explicit algorithm allow-listing** — Reject 'alg: none', reject HS256 when expecting RS256. Use a vetted JWT library; never hand-roll verification.
- _[preventive]_ **Enforce audience and issuer claims** — Every token must declare which service it's intended for. Reject tokens whose audience doesn't match this component.
- _[preventive]_ **Bind tokens to a session or device** — Use mTLS-bound tokens, DPoP, or token binding to prevent replay if a token is captured.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

#### Log tampering

- **Methodology / Category:** STRIDE → Repudiation
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-778 — Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** An attacker with access modifies or deletes audit trails.

**⚔️ Attack scenario:**

1. User performs a sensitive action through REST API (a transfer, a permission change, a deletion).
2. Audit logs are absent, incomplete, or modifiable by the same principal who performed the action.
3. User later denies having performed the action, or an attacker covers their tracks.
4. Without tamper-evident logs, neither responsible party can be identified — leading to fraud, dispute, or regulatory exposure.

**🛡 How to mitigate:**

- _[detective]_ **Emit tamper-evident audit logs** — Sign log entries (HMAC chain, hash-linked) so insertion or deletion is detectable. Forward to a separate, append-only system the action's principal cannot administer.
- _[detective]_ **Capture sufficient detail per audit event** — Who (authenticated principal, not just session ID), what (specific action and target), when (UTC, monotonic-clock-corroborated), where (source IP, request ID), why (correlated to the upstream business event).
- _[detective]_ **Periodic log integrity verification** — Schedule daily integrity checks on the audit log chain. Alert on any gap.

**🔗 References:** [A09:2021 — Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-778 — Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

#### Sensitive data exposure in transit

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** PII, secrets, or tokens transmitted over unencrypted channels.

**⚔️ Attack scenario:**

1. Attacker reaches REST API via a legitimate or guessable channel.
2. Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).
3. Aggregates leaked information from multiple requests to build a profile of the system or its users.
4. Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.

**🛡 How to mitigate:**

- _[preventive]_ **Apply field-level access control on responses** — The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.
- _[preventive]_ **Strip debug detail from error responses** — Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.
- _[preventive]_ **Encrypt data at rest with key separation** — For api, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

#### Sensitive data exposure at rest

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Stored PII / secrets accessible without proper authorization.

**⚔️ Attack scenario:**

1. Attacker reaches REST API via a legitimate or guessable channel.
2. Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).
3. Aggregates leaked information from multiple requests to build a profile of the system or its users.
4. Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.

**🛡 How to mitigate:**

- _[preventive]_ **Apply field-level access control on responses** — The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.
- _[preventive]_ **Strip debug detail from error responses** — Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.
- _[preventive]_ **Encrypt data at rest with key separation** — For api, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Insecure direct object reference (IDOR)

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** User can access another user's resources by guessing IDs.

**⚔️ Attack scenario:**

1. Attacker reaches REST API via a legitimate or guessable channel.
2. Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).
3. Aggregates leaked information from multiple requests to build a profile of the system or its users.
4. Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.

**🛡 How to mitigate:**

- _[preventive]_ **Apply field-level access control on responses** — The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.
- _[preventive]_ **Strip debug detail from error responses** — Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.
- _[preventive]_ **Encrypt data at rest with key separation** — For api, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Application-layer DDoS

- **Methodology / Category:** STRIDE → Denial of Service
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Attacker floods expensive endpoints (e.g., search, login).

**⚔️ Attack scenario:**

1. Attacker identifies a costly operation in REST API (regex matching, file generation, expensive query, large allocation).
2. Issues many concurrent requests targeting that operation, or a single request with pathological input.
3. REST API's resources (CPU, memory, connections, disk) saturate or exhaust.
4. Legitimate users can no longer reach REST API; cascading failure may take down dependents.

**🛡 How to mitigate:**

- _[preventive]_ **Apply input limits at the edge** — Maximum request size, body depth, array length, and string length. Reject early — before parsing or business logic runs.
- _[preventive]_ **Rate-limit per principal and per resource** — Token bucket per authenticated user AND per costly endpoint. Adaptive throttling on saturation.
- _[corrective]_ **Set hard timeouts on outbound calls** — No call (DB, downstream service, third-party API) should be able to hang the request handler indefinitely. Use circuit breakers and bulkheads.

**🔗 References:** [A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)

#### Privilege escalation via mass assignment

- **Methodology / Category:** STRIDE → Elevation of Privilege
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- **CVSS 3.1:** **8.3** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **CVSS 4.0:** **6.3** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** User submits extra fields (e.g., role=admin) and they bind to the model.

**⚔️ Attack scenario:**

1. Attacker authenticates to REST API as a low-privilege user, or reaches an unauthenticated entry point.
2. Identifies an authorization gap — a function that doesn't re-check the caller's role, an IDOR-style URL, an admin endpoint with weak gating.
3. Issues requests to that gap, gaining access to data or actions reserved for higher-privilege roles.
4. Now operating with elevated privilege, attacker can pivot to other components, exfiltrate data, or persist access.

**🛡 How to mitigate:**

- _[preventive]_ **Re-authorize on every action, not just at session start** — Every privileged endpoint checks the current principal's roles/permissions for the specific resource being acted on. No 'logged in = allowed'.
- _[preventive]_ **Apply least-privilege to service identities** — The IAM/role attached to REST API should grant only the actions it actually performs. Audit IAM grants quarterly.
- _[detective]_ **Detect anomalous privilege use** — Alert when a principal performs an action they have not performed in the trailing 90 days, or when admin-tier actions originate from non-admin networks.

**🔗 References:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

#### Unauthenticated flow: User → REST API

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** On the data flow **User → REST API** (label: *—*, protocol: HTTPS, auth: none, encrypted: yes). The receiving component is **REST API** (`api`).

**📝 Description:** Data flow has no authentication mechanism declared.

**⚔️ Attack scenario:**

1. Attacker discovers the endpoint at REST API (port scan, leaked config, error messages, or DNS enumeration).
2. Sends requests directly without any credentials, since the flow does not require authentication.
3. REST API processes the request as if it came from a trusted caller and returns data or executes the action.
4. Attacker enumerates data, modifies records, or chains to other internal services from this entry point.

**🛡 How to mitigate:**

- _[preventive]_ **Require an authentication mechanism on every external-facing flow** — Bearer tokens (OAuth2/OIDC) for human-driven calls, mutual TLS or signed JWT for service-to-service. Block requests that arrive without credentials at the gateway, before they reach the application.
- _[preventive]_ **Reject anonymous traffic at the receiver as well** — Defense in depth: even if the gateway rule fails, the receiving component should reject any request lacking a valid principal.
- _[detective]_ **Rate-limit unauthenticated probes** — Apply a low-tolerance rate limit to requests that lack credentials (5/min per source IP) and alert on sustained failures.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

#### Trust-boundary crossing without strong authn: User → REST API 🚧 *cross-boundary*

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS 3.1:** **8.6** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
- **CVSS 4.0:** **8.1** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N`
- **Boundary crossing:** Internet → Application tier
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=9, D=8 → **Total 37/50**

**📍 Where the threat exists:** On the data flow **User → REST API** (label: *—*, protocol: HTTPS, auth: none, encrypted: yes), crossing the trust boundary from `Internet` into `Application tier`. The receiving component is **REST API** (`api`).

**📝 Description:** Flow '' crosses trust boundary 'Internet' → 'Application tier'. Caller identity must be re-verified at the boundary; existing trust does not transit.

**⚔️ Attack scenario:**

1. Attacker positions themselves on the network path between source and destination, or compromises an upstream component in the source zone.
2. Crafts requests with forged or replayed identity claims (cookies, tokens, IP-based trust).
3. REST API accepts the request because identity is not re-verified at the boundary, treating the upstream zone as trusted.
4. Attacker can now perform actions as the impersonated principal across the boundary.

**🛡 How to mitigate:**

- _[preventive]_ **Re-authenticate at the boundary** — Require a fresh, audience-bound credential at the receiver. Do not infer identity from network position, source IP, or upstream session.
- _[preventive]_ **Use mutual TLS or signed tokens with audience claims** — For service-to-service calls into REST API, terminate mTLS at the boundary and reject any caller without a valid client cert. For human-driven flows, use OAuth2 / OIDC with audience and issuer validation.
- _[detective]_ **Log every cross-boundary auth decision** — Emit an authentication event (success and failure) tagged with both source and destination zone. Forward to SIEM with retention ≥ 90 days.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

#### Cross-boundary input not validated: User → REST API 🚧 *cross-boundary*

- **Methodology / Category:** STRIDE → Tampering
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **8.6** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`
- **CVSS 4.0:** **8.1** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:L/SI:H/SA:N`
- **Boundary crossing:** Internet → Application tier
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=9, D=8 → **Total 37/50**

**📍 Where the threat exists:** On the data flow **User → REST API** (label: *—*, protocol: HTTPS, auth: none, encrypted: yes), crossing the trust boundary from `Internet` into `Application tier`. The receiving component is **REST API** (`api`).

**📝 Description:** Data crossing the trust boundary into 'Application tier' must be treated as untrusted, even if the source is internal. Implicit trust is the most common cause of injection / SSRF / deserialization bugs.

**⚔️ Attack scenario:**

1. Attacker compromises a less-trusted upstream zone or directly sends malformed input to REST API.
2. Sends payloads with unexpected types, lengths, or special characters (e.g. SQL meta-chars, NUL bytes, control sequences).
3. REST API processes the input under the assumption that the upstream zone has already validated it — but the boundary changes the security context.
4. Injection, deserialization flaws, or buffer issues trigger; attacker pivots into REST API or the zone behind it.

**🛡 How to mitigate:**

- _[preventive]_ **Validate against an allow-list schema at the boundary** — Define an explicit schema (JSON Schema, Protobuf, OpenAPI) for every accepted message at this boundary. Reject anything that doesn't match — type, length, charset, enum values, nested depth.
- _[preventive]_ **Canonicalize before validation** — Decode URL-encoding, Unicode normalization (NFC), trim whitespace, and resolve relative paths before validating. Avoid double-decoding bypasses.
- _[preventive]_ **Apply context-specific output encoding** — Whatever REST API does with the input — SQL: parameterized queries, HTML: contextual escaping, OS commands: avoid shell, use exec arrays, LDAP: escape filter chars.

**🔗 References:** [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Cross-boundary data exposure risk: User → REST API 🚧 *cross-boundary*

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **8.6** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
- **CVSS 4.0:** **8.1** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N`
- **Boundary crossing:** Internet → Application tier
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=9, D=8 → **Total 37/50**

**📍 Where the threat exists:** On the data flow **User → REST API** (label: *—*, protocol: HTTPS, auth: none, encrypted: yes), crossing the trust boundary from `Internet` into `Application tier`. The receiving component is **REST API** (`api`).

**📝 Description:** Information leaving 'Internet' into 'Application tier' may include data the receiving zone is not authorized to see. Cross-boundary egress is a common data-leak surface.

**⚔️ Attack scenario:**

1. Attacker observes traffic leaving the source zone, or compromises a component in the destination zone.
2. The destination zone receives more data than it strictly needs (over-fetching, verbose error responses, full record dumps).
3. Attacker harvests sensitive fields (PII, secrets, internal IDs) that should never have left the source zone.
4. Data is exfiltrated, sold, or used to plan a deeper attack on the originating zone.

**🛡 How to mitigate:**

- _[preventive]_ **Enforce minimum-data-needed at the egress point** — Whitelist exactly which fields leave the source zone. Strip everything else server-side before serialization.
- _[preventive]_ **Tokenize or redact sensitive fields** — Replace PII / PCI / PHI fields with reversible tokens or one-way hashes when the destination zone doesn't need the cleartext value.
- _[detective]_ **Log cross-boundary data flows for review** — Sample-log the field set crossing this boundary (not the values) so DLP and privacy reviews can audit what's egressing.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Authentication bypass via credential stuffing

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** User (`user`)
- **CWE:** [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=5, D=7 → **Total 32/50**

**📍 Where the threat exists:** Within component **User** (`user`).

**📝 Description:** Attackers reuse leaked credentials to impersonate legitimate users.

**⚔️ Attack scenario:**

1. Attacker obtains valid credentials via phishing, credential stuffing, or a third-party breach.
2. Logs in as the legitimate user/entity at User.
3. Performs actions indistinguishable from the real user (auth events look normal).
4. Damage scales with the impersonated user's permissions; admin accounts cause the most harm.

**🛡 How to mitigate:**

- _[preventive]_ **Validate token signatures with explicit algorithm allow-listing** — Reject 'alg: none', reject HS256 when expecting RS256. Use a vetted JWT library; never hand-roll verification.
- _[preventive]_ **Enforce audience and issuer claims** — Every token must declare which service it's intended for. Reject tokens whose audience doesn't match this component.
- _[preventive]_ **Bind tokens to a session or device** — Use mTLS-bound tokens, DPoP, or token binding to prevent replay if a token is captured.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

#### Session token hijacking

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** User (`user`)
- **CWE:** [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=5, D=7 → **Total 32/50**

**📍 Where the threat exists:** Within component **User** (`user`).

**📝 Description:** Attacker steals or predicts a session token to impersonate a user.

**⚔️ Attack scenario:**

1. Attacker obtains valid credentials via phishing, credential stuffing, or a third-party breach.
2. Logs in as the legitimate user/entity at User.
3. Performs actions indistinguishable from the real user (auth events look normal).
4. Damage scales with the impersonated user's permissions; admin accounts cause the most harm.

**🛡 How to mitigate:**

- _[preventive]_ **Validate token signatures with explicit algorithm allow-listing** — Reject 'alg: none', reject HS256 when expecting RS256. Use a vetted JWT library; never hand-roll verification.
- _[preventive]_ **Enforce audience and issuer claims** — Every token must declare which service it's intended for. Reject tokens whose audience doesn't match this component.
- _[preventive]_ **Bind tokens to a session or device** — Use mTLS-bound tokens, DPoP, or token binding to prevent replay if a token is captured.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

#### API key / service identity spoofing

- **Methodology / Category:** STRIDE → Spoofing
- **Affected component:** User (`user`)
- **CWE:** [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=5, D=7 → **Total 32/50**

**📍 Where the threat exists:** Within component **User** (`user`).

**📝 Description:** An attacker obtains or forges an API key to act as a trusted service.

**⚔️ Attack scenario:**

1. Attacker obtains valid credentials via phishing, credential stuffing, or a third-party breach.
2. Logs in as the legitimate user/entity at User.
3. Performs actions indistinguishable from the real user (auth events look normal).
4. Damage scales with the impersonated user's permissions; admin accounts cause the most harm.

**🛡 How to mitigate:**

- _[preventive]_ **Validate token signatures with explicit algorithm allow-listing** — Reject 'alg: none', reject HS256 when expecting RS256. Use a vetted JWT library; never hand-roll verification.
- _[preventive]_ **Enforce audience and issuer claims** — Every token must declare which service it's intended for. Reject tokens whose audience doesn't match this component.
- _[preventive]_ **Bind tokens to a session or device** — Use mTLS-bound tokens, DPoP, or token binding to prevent replay if a token is captured.

**🔗 References:** [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

#### Cleartext transmission of credentials

- **Methodology / Category:** OWASP Top 10 → A02 Cryptographic Failures
- **Affected component:** Database (`database`)
- **CWE:** [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **2.1** (Low) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Passwords transmitted over HTTP.

**⚔️ Attack scenario:**

1. Attacker probes Database via reachable inputs.
2. Identifies the weakness named by this threat (A02 Cryptographic Failures).
3. Crafts an exploit specific to the affected component type (database).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around Database. Review applicability of OWASP ASVS controls for database components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

#### Unencrypted flow: REST API → Database

- **Methodology / Category:** OWASP Top 10 → Disclosure of information
- **Affected component:** Database (`database`)
- **CWE:** [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=8, A=7, D=8 → **Total 36/50**

**📍 Where the threat exists:** On the data flow **REST API → Database** (label: *—*, protocol: TCP, auth: none, encrypted: no). The receiving component is **Database** (`database`).

**📝 Description:** Data flow '' uses TCP without encryption.

**⚔️ Attack scenario:**

1. Attacker gains read access to the network path (sniffing on shared LAN, compromised router, hostile cloud tenant, malicious admin).
2. Captures cleartext traffic on the TCP channel.
3. Extracts credentials, session tokens, PII, or business secrets from packet captures.
4. Uses the credentials to impersonate Database or the calling component, or sells/leaks the captured data.

**🛡 How to mitigate:**

- _[preventive]_ **Enable TLS 1.3 (or 1.2 with strong ciphers) on the flow** — Replace plain TCP with its TLS variant. For databases use TLS-enabled drivers; for queues like AMQP/Kafka, configure broker certs and require client TLS.
- _[preventive]_ **Enforce certificate validation** — Verify hostname, validate the chain to a known CA, pin certificates or use a private CA for internal services. Disable cipher fallbacks to NULL/EXPORT/RC4.
- _[detective]_ **Scan for cleartext fallbacks** — Add a network-policy / NetworkPolicy / security-group rule that drops any traffic on the cleartext port. Alert if it ever fires.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

#### Unauthenticated flow: REST API → Database

- **Methodology / Category:** OWASP Top 10 → Stage 3 — Application Decomposition
- **Affected component:** Database (`database`)
- **CWE:** [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **CVSS 3.1:** **6.3** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`
- **CVSS 4.0:** **2.1** (Low) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=8, A=7, D=8 → **Total 36/50**

**📍 Where the threat exists:** On the data flow **REST API → Database** (label: *—*, protocol: TCP, auth: none, encrypted: no). The receiving component is **Database** (`database`).

**📝 Description:** Data flow has no authentication mechanism declared.

**⚔️ Attack scenario:**

1. Attacker discovers the endpoint at Database (port scan, leaked config, error messages, or DNS enumeration).
2. Sends requests directly without any credentials, since the flow does not require authentication.
3. Database processes the request as if it came from a trusted caller and returns data or executes the action.
4. Attacker enumerates data, modifies records, or chains to other internal services from this entry point.

**🛡 How to mitigate:**

- _[preventive]_ **Require an authentication mechanism on every external-facing flow** — Bearer tokens (OAuth2/OIDC) for human-driven calls, mutual TLS or signed JWT for service-to-service. Block requests that arrive without credentials at the gateway, before they reach the application.
- _[preventive]_ **Reject anonymous traffic at the receiver as well** — Defense in depth: even if the gateway rule fails, the receiving component should reject any request lacking a valid principal.
- _[detective]_ **Rate-limit unauthenticated probes** — Apply a low-tolerance rate limit to requests that lack credentials (5/min per source IP) and alert on sustained failures.

**🔗 References:** [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

#### Insecure Direct Object Reference (IDOR)

- **Methodology / Category:** OWASP Top 10 → A01 Broken Access Control
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** User accesses other users data by modifying IDs.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A01 Broken Access Control).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Cleartext transmission of credentials

- **Methodology / Category:** OWASP Top 10 → A02 Cryptographic Failures
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Passwords transmitted over HTTP.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A02 Cryptographic Failures).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

#### No rate limiting on login endpoint

- **Methodology / Category:** OWASP Top 10 → A07 Authentication Failures
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Brute-force and credential stuffing possible.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A07 Authentication Failures).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Unauthenticated flow: User → REST API

- **Methodology / Category:** OWASP Top 10 → Stage 3 — Application Decomposition
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=7, R=6, E=7, A=7, D=7 → **Total 34/50**

**📍 Where the threat exists:** On the data flow **User → REST API** (label: *—*, protocol: HTTPS, auth: none, encrypted: yes). The receiving component is **REST API** (`api`).

**📝 Description:** Data flow has no authentication mechanism declared.

**⚔️ Attack scenario:**

1. Attacker discovers the endpoint at REST API (port scan, leaked config, error messages, or DNS enumeration).
2. Sends requests directly without any credentials, since the flow does not require authentication.
3. REST API processes the request as if it came from a trusted caller and returns data or executes the action.
4. Attacker enumerates data, modifies records, or chains to other internal services from this entry point.

**🛡 How to mitigate:**

- _[preventive]_ **Require an authentication mechanism on every external-facing flow** — Bearer tokens (OAuth2/OIDC) for human-driven calls, mutual TLS or signed JWT for service-to-service. Block requests that arrive without credentials at the gateway, before they reach the application.
- _[preventive]_ **Reject anonymous traffic at the receiver as well** — Defense in depth: even if the gateway rule fails, the receiving component should reject any request lacking a valid principal.
- _[detective]_ **Rate-limit unauthenticated probes** — Apply a low-tolerance rate limit to requests that lack credentials (5/min per source IP) and alert on sustained failures.

**🔗 References:** [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

### Medium (10)

#### Insufficient audit logging

- **Methodology / Category:** STRIDE → Repudiation
- **Affected component:** Database (`database`)
- **CWE:** [CWE-778 — Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- **CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Critical user actions cannot be reliably attributed after the fact.

**⚔️ Attack scenario:**

1. User performs a sensitive action through Database (a transfer, a permission change, a deletion).
2. Audit logs are absent, incomplete, or modifiable by the same principal who performed the action.
3. User later denies having performed the action, or an attacker covers their tracks.
4. Without tamper-evident logs, neither responsible party can be identified — leading to fraud, dispute, or regulatory exposure.

**🛡 How to mitigate:**

- _[detective]_ **Emit tamper-evident audit logs** — Sign log entries (HMAC chain, hash-linked) so insertion or deletion is detectable. Forward to a separate, append-only system the action's principal cannot administer.
- _[detective]_ **Capture sufficient detail per audit event** — Who (authenticated principal, not just session ID), what (specific action and target), when (UTC, monotonic-clock-corroborated), where (source IP, request ID), why (correlated to the upstream business event).
- _[detective]_ **Periodic log integrity verification** — Schedule daily integrity checks on the audit log chain. Alert on any gap.

**🔗 References:** [A09:2021 — Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-778 — Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

#### Verbose error messages / stack traces

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Error responses leak implementation details to attackers.

**⚔️ Attack scenario:**

1. Attacker reaches Database via a legitimate or guessable channel.
2. Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).
3. Aggregates leaked information from multiple requests to build a profile of the system or its users.
4. Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.

**🛡 How to mitigate:**

- _[preventive]_ **Apply field-level access control on responses** — The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.
- _[preventive]_ **Strip debug detail from error responses** — Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.
- _[preventive]_ **Encrypt data at rest with key separation** — For database, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Resource exhaustion via unbounded input

- **Methodology / Category:** STRIDE → Denial of Service
- **Affected component:** Database (`database`)
- **CWE:** [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)
- **CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Large payloads or unbounded loops exhaust CPU/memory.

**⚔️ Attack scenario:**

1. Attacker identifies a costly operation in Database (regex matching, file generation, expensive query, large allocation).
2. Issues many concurrent requests targeting that operation, or a single request with pathological input.
3. Database's resources (CPU, memory, connections, disk) saturate or exhaust.
4. Legitimate users can no longer reach Database; cascading failure may take down dependents.

**🛡 How to mitigate:**

- _[preventive]_ **Apply input limits at the edge** — Maximum request size, body depth, array length, and string length. Reject early — before parsing or business logic runs.
- _[preventive]_ **Rate-limit per principal and per resource** — Token bucket per authenticated user AND per costly endpoint. Adaptive throttling on saturation.
- _[corrective]_ **Set hard timeouts on outbound calls** — No call (DB, downstream service, third-party API) should be able to hang the request handler indefinitely. Use circuit breakers and bulkheads.

**🔗 References:** [A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)

#### Algorithmic complexity attack

- **Methodology / Category:** STRIDE → Denial of Service
- **Affected component:** Database (`database`)
- **CWE:** [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)
- **CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H`
- **CVSS 4.0:** **5.2** (Medium) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** Crafted inputs trigger worst-case algorithm behavior (e.g., regex DoS).

**⚔️ Attack scenario:**

1. Attacker identifies a costly operation in Database (regex matching, file generation, expensive query, large allocation).
2. Issues many concurrent requests targeting that operation, or a single request with pathological input.
3. Database's resources (CPU, memory, connections, disk) saturate or exhaust.
4. Legitimate users can no longer reach Database; cascading failure may take down dependents.

**🛡 How to mitigate:**

- _[preventive]_ **Apply input limits at the edge** — Maximum request size, body depth, array length, and string length. Reject early — before parsing or business logic runs.
- _[preventive]_ **Rate-limit per principal and per resource** — Token bucket per authenticated user AND per costly endpoint. Adaptive throttling on saturation.
- _[corrective]_ **Set hard timeouts on outbound calls** — No call (DB, downstream service, third-party API) should be able to hang the request handler indefinitely. Use circuit breakers and bulkheads.

**🔗 References:** [A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)

#### Insufficient audit logging

- **Methodology / Category:** STRIDE → Repudiation
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-778 — Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Critical user actions cannot be reliably attributed after the fact.

**⚔️ Attack scenario:**

1. User performs a sensitive action through REST API (a transfer, a permission change, a deletion).
2. Audit logs are absent, incomplete, or modifiable by the same principal who performed the action.
3. User later denies having performed the action, or an attacker covers their tracks.
4. Without tamper-evident logs, neither responsible party can be identified — leading to fraud, dispute, or regulatory exposure.

**🛡 How to mitigate:**

- _[detective]_ **Emit tamper-evident audit logs** — Sign log entries (HMAC chain, hash-linked) so insertion or deletion is detectable. Forward to a separate, append-only system the action's principal cannot administer.
- _[detective]_ **Capture sufficient detail per audit event** — Who (authenticated principal, not just session ID), what (specific action and target), when (UTC, monotonic-clock-corroborated), where (source IP, request ID), why (correlated to the upstream business event).
- _[detective]_ **Periodic log integrity verification** — Schedule daily integrity checks on the audit log chain. Alert on any gap.

**🔗 References:** [A09:2021 — Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-778 — Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

#### Verbose error messages / stack traces

- **Methodology / Category:** STRIDE → Information Disclosure
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Error responses leak implementation details to attackers.

**⚔️ Attack scenario:**

1. Attacker reaches REST API via a legitimate or guessable channel.
2. Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).
3. Aggregates leaked information from multiple requests to build a profile of the system or its users.
4. Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.

**🛡 How to mitigate:**

- _[preventive]_ **Apply field-level access control on responses** — The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.
- _[preventive]_ **Strip debug detail from error responses** — Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.
- _[preventive]_ **Encrypt data at rest with key separation** — For api, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.

**🔗 References:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Resource exhaustion via unbounded input

- **Methodology / Category:** STRIDE → Denial of Service
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Large payloads or unbounded loops exhaust CPU/memory.

**⚔️ Attack scenario:**

1. Attacker identifies a costly operation in REST API (regex matching, file generation, expensive query, large allocation).
2. Issues many concurrent requests targeting that operation, or a single request with pathological input.
3. REST API's resources (CPU, memory, connections, disk) saturate or exhaust.
4. Legitimate users can no longer reach REST API; cascading failure may take down dependents.

**🛡 How to mitigate:**

- _[preventive]_ **Apply input limits at the edge** — Maximum request size, body depth, array length, and string length. Reject early — before parsing or business logic runs.
- _[preventive]_ **Rate-limit per principal and per resource** — Token bucket per authenticated user AND per costly endpoint. Adaptive throttling on saturation.
- _[corrective]_ **Set hard timeouts on outbound calls** — No call (DB, downstream service, third-party API) should be able to hang the request handler indefinitely. Use circuit breakers and bulkheads.

**🔗 References:** [A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)

#### Algorithmic complexity attack

- **Methodology / Category:** STRIDE → Denial of Service
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)
- **CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CVSS 4.0:** **7.0** (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** Crafted inputs trigger worst-case algorithm behavior (e.g., regex DoS).

**⚔️ Attack scenario:**

1. Attacker identifies a costly operation in REST API (regex matching, file generation, expensive query, large allocation).
2. Issues many concurrent requests targeting that operation, or a single request with pathological input.
3. REST API's resources (CPU, memory, connections, disk) saturate or exhaust.
4. Legitimate users can no longer reach REST API; cascading failure may take down dependents.

**🛡 How to mitigate:**

- _[preventive]_ **Apply input limits at the edge** — Maximum request size, body depth, array length, and string length. Reject early — before parsing or business logic runs.
- _[preventive]_ **Rate-limit per principal and per resource** — Token bucket per authenticated user AND per costly endpoint. Adaptive throttling on saturation.
- _[corrective]_ **Set hard timeouts on outbound calls** — No call (DB, downstream service, third-party API) should be able to hang the request handler indefinitely. Use circuit breakers and bulkheads.

**🔗 References:** [A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [STRIDE reference](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) · [CWE-400 — Uncontrolled Resource Consumption (DoS)](https://cwe.mitre.org/data/definitions/400.html)

#### Missing security headers

- **Methodology / Category:** OWASP Top 10 → A05 Security Misconfiguration
- **Affected component:** Database (`database`)
- **CWE:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **CVSS 3.1:** **5.7** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CVSS 4.0:** **2.1** (Low) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **Database** (`database`).

**📝 Description:** CSP, X-Frame-Options, HSTS absent.

**⚔️ Attack scenario:**

1. Attacker probes Database via reachable inputs.
2. Identifies the weakness named by this threat (A05 Security Misconfiguration).
3. Crafts an exploit specific to the affected component type (database).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around Database. Review applicability of OWASP ASVS controls for database components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

#### Missing security headers

- **Methodology / Category:** OWASP Top 10 → A05 Security Misconfiguration
- **Affected component:** REST API (`api`)
- **CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- **CVSS 3.1:** **0.0** (None) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS 4.0:** **5.5** (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Source:** rule-based
- **DREAD:** D=5, R=4, E=5, A=5, D=5 → **Total 24/50**

**📍 Where the threat exists:** Within component **REST API** (`api`).

**📝 Description:** CSP, X-Frame-Options, HSTS absent.

**⚔️ Attack scenario:**

1. Attacker probes REST API via reachable inputs.
2. Identifies the weakness named by this threat (A05 Security Misconfiguration).
3. Crafts an exploit specific to the affected component type (api).
4. Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.

**🛡 How to mitigate:**

- _[preventive]_ **Apply defense-in-depth controls** — Layer authentication, authorization, validation, and monitoring around REST API. Review applicability of OWASP ASVS controls for api components.
- _[detective]_ **Add monitoring for the threat indicators** — Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.

**🔗 References:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
