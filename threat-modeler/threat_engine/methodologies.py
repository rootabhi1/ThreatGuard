
# NOTE: The OWASP Top 10 is a standard *awareness document* — a ranked list of the
# most critical web-application security risks. It is NOT a threat-modeling
# methodology, nor a threat generator. In this tool it is a **reference mapping
# only**: individual findings from the real methodologies are cross-linked to the
# relevant Top-10 risk (see detail.OWASP_LINKS and the "references" a threat
# carries). It is therefore registered with kind "reference" and empty
# `categories`, so it is never selectable and never produces threat rows of its
# own. It must never be presented as a threat-modeling methodology or framework.
OWASP_TOP10 = {
    "name": "OWASP Top 10",
    "kind": "reference",
    "description": "Reference mapping — findings are cross-linked to the relevant OWASP Top 10 (2021) risk. An awareness reference, not a threat-modeling methodology, and not a threat generator.",
    "categories": {},
}
"""Threat modeling methodology catalogs.

Each methodology defines categories and the rule patterns that map
component types / data flow attributes to applicable threats.
"""

# ---------- STRIDE ----------
STRIDE = {
    "name": "STRIDE",
    "kind": "methodology",
    "description": "Microsoft's threat model: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege",
    "categories": {
        "Spoofing": {
            "description": "Impersonating someone or something",
            "applies_to": ["user", "external_entity", "api", "auth_service", "webapp", "mobile_app"],
            "threats": [
                {
                    "title": "Authentication bypass via credential stuffing",
                    "description": "Attackers reuse leaked credentials to impersonate legitimate users.",
                    "severity": "High",
                    "mitigations": ["Implement MFA", "Rate-limit login attempts", "Monitor for credential stuffing patterns", "Use passkeys / WebAuthn where possible"],
                },
                {
                    "title": "Session token hijacking",
                    "description": "Attacker steals or predicts a session token to impersonate a user.",
                    "severity": "High",
                    "mitigations": ["Use HTTPOnly + Secure + SameSite cookies", "Rotate tokens on privilege change", "Bind tokens to client fingerprint"],
                },
                {
                    "title": "API key / service identity spoofing",
                    "description": "An attacker obtains or forges an API key to act as a trusted service.",
                    "severity": "High",
                    "mitigations": ["Use short-lived tokens (mTLS / JWT with rotation)", "Store keys in a secrets manager", "Audit key usage and anomalous source IPs"],
                },
            ],
        },
        "Tampering": {
            "description": "Modifying data or code",
            "applies_to": ["database", "datastore", "data_flow", "queue", "cache", "filesystem", "config"],
            "threats": [
                {
                    "title": "Data-in-transit modification",
                    "description": "Attacker on the network path alters request/response payloads.",
                    "severity": "High",
                    "mitigations": ["Enforce TLS 1.2+ on all flows", "Use HSTS", "Pin certificates for service-to-service calls"],
                },
                {
                    "title": "Stored data tampering via injection",
                    "description": "SQL/NoSQL/command injection alters records or schema.",
                    "severity": "Critical",
                    "mitigations": ["Use parameterized queries", "Validate and sanitize inputs", "Apply least-privilege DB users"],
                },
                {
                    "title": "Config / secret tampering",
                    "description": "Unauthorized changes to runtime config alter security behavior.",
                    "severity": "High",
                    "mitigations": ["Sign config bundles", "Audit config changes", "Restrict write access via IAM"],
                },
            ],
        },
        "Repudiation": {
            "description": "Denying having performed an action",
            "applies_to": ["api", "webapp", "auth_service", "database", "payment_service"],
            "threats": [
                {
                    "title": "Insufficient audit logging",
                    "description": "Critical user actions cannot be reliably attributed after the fact.",
                    "severity": "Medium",
                    "mitigations": ["Log auth, privilege changes, and write operations", "Ship logs to tamper-evident storage", "Include user, timestamp, source IP, action"],
                },
                {
                    "title": "Log tampering",
                    "description": "An attacker with access modifies or deletes audit trails.",
                    "severity": "High",
                    "mitigations": ["Stream logs off-host immediately", "Use append-only / WORM log storage", "Sign log batches"],
                },
            ],
        },
        "Information Disclosure": {
            "description": "Exposing information to unauthorized parties",
            "applies_to": ["database", "datastore", "api", "webapp", "data_flow", "cache", "filesystem", "external_entity"],
            "threats": [
                {
                    "title": "Sensitive data exposure in transit",
                    "description": "PII, secrets, or tokens transmitted over unencrypted channels.",
                    "severity": "High",
                    "mitigations": ["Enforce TLS for all internal & external flows", "Disable plaintext fallbacks", "Inspect with DLP scanners"],
                },
                {
                    "title": "Sensitive data exposure at rest",
                    "description": "Stored PII / secrets accessible without proper authorization.",
                    "severity": "High",
                    "mitigations": ["Encrypt at rest (AES-256)", "Tokenize / hash sensitive fields", "Apply row-level access control"],
                },
                {
                    "title": "Verbose error messages / stack traces",
                    "description": "Error responses leak implementation details to attackers.",
                    "severity": "Medium",
                    "mitigations": ["Return generic errors to clients", "Log detailed errors server-side only", "Disable debug mode in production"],
                },
                {
                    "title": "Insecure direct object reference (IDOR)",
                    "description": "User can access another user's resources by guessing IDs.",
                    "severity": "High",
                    "mitigations": ["Enforce object-level authz on every request", "Use unguessable IDs (UUIDs)", "Add object-ownership tests in CI"],
                },
            ],
        },
        "Denial of Service": {
            "description": "Making a service unavailable",
            "applies_to": ["webapp", "api", "database", "external_entity", "queue", "auth_service"],
            "threats": [
                {
                    "title": "Resource exhaustion via unbounded input",
                    "description": "Large payloads or unbounded loops exhaust CPU/memory.",
                    "severity": "Medium",
                    "mitigations": ["Set request size limits", "Apply timeouts on all I/O", "Use circuit breakers on downstreams"],
                },
                {
                    "title": "Application-layer DDoS",
                    "description": "Attacker floods expensive endpoints (e.g., search, login).",
                    "severity": "High",
                    "mitigations": ["Rate-limit per IP/user/key", "Front with WAF/CDN with DDoS protection", "Add CAPTCHA on abusive endpoints"],
                },
                {
                    "title": "Algorithmic complexity attack",
                    "description": "Crafted inputs trigger worst-case algorithm behavior (e.g., regex DoS).",
                    "severity": "Medium",
                    "mitigations": ["Avoid catastrophic regex patterns", "Cap input sizes", "Use timeouts on parsers"],
                },
            ],
        },
        "Elevation of Privilege": {
            "description": "Gaining capabilities without proper authorization",
            "applies_to": ["api", "webapp", "auth_service", "admin_panel", "database"],
            "threats": [
                {
                    "title": "Broken access control / missing authz check",
                    "description": "Endpoints fail to verify the caller has permission for the action.",
                    "severity": "Critical",
                    "mitigations": ["Centralize authz in middleware", "Default-deny on new routes", "Add automated authz tests per endpoint"],
                },
                {
                    "title": "Privilege escalation via mass assignment",
                    "description": "User submits extra fields (e.g., role=admin) and they bind to the model.",
                    "severity": "High",
                    "mitigations": ["Use explicit allow-lists for input binding", "Separate admin and user DTOs", "Review ORM model exposure"],
                },
                {
                    "title": "Container / process escape",
                    "description": "Attacker breaks out of a sandbox to gain host privileges.",
                    "severity": "Critical",
                    "mitigations": ["Run as non-root", "Drop Linux capabilities", "Apply seccomp / AppArmor profiles"],
                },
            ],
        },
    },
}

# ---------- DREAD (risk-scoring lens, NOT a threat generator) ----------
# DREAD is a risk-*rating* model, not a threat-enumeration methodology: it scores
# an already-identified threat on five axes (Damage, Reproducibility,
# Exploitability, Affected users, Discoverability). It does not, on its own,
# produce threats. In this tool DREAD is therefore applied as a scoring lens over
# every threat found by the real methodologies (see analyzer._score_dread), rather
# than as a selectable generator. `categories` is intentionally empty so that
# selecting DREAD never fabricates axis-named pseudo-threats.
DREAD = {
    "name": "DREAD",
    "kind": "scoring",
    "description": "Risk-scoring lens applied to identified threats — Damage, Reproducibility, Exploitability, Affected users, Discoverability (1-10 each). Not a threat generator; every threat already carries a DREAD score.",
    "categories": {},
}

# ---------- LINDDUN (privacy) ----------
LINDDUN = {
    "name": "LINDDUN",
    "kind": "methodology",
    "description": "Privacy threat model: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness, Non-compliance",
    "categories": {
        "Linkability": {
            "description": "Linking data items or actions to the same subject without their consent",
            "applies_to": ["database", "api", "webapp", "data_flow"],
            "threats": [
                {
                    "title": "Cross-service user linkability",
                    "description": "Identifiers (emails, device IDs) let separate datasets be joined to profile a user.",
                    "severity": "Medium",
                    "mitigations": ["Use per-context pseudonyms", "Avoid global IDs in analytics", "Apply k-anonymity for shared datasets"],
                },
            ],
        },
        "Identifiability": {
            "description": "Identifying a subject from supposedly anonymous data",
            "applies_to": ["database", "datastore", "data_flow", "external_entity"],
            "threats": [
                {
                    "title": "Re-identification of anonymized data",
                    "description": "Quasi-identifiers (zip, DOB, gender) re-identify users in 'anonymous' exports.",
                    "severity": "High",
                    "mitigations": ["Apply differential privacy on aggregates", "Generalize quasi-identifiers", "Audit re-identification risk before release"],
                },
            ],
        },
        "Non-repudiation": {
            "description": "Inability to deny a claim — adverse for privacy",
            "applies_to": ["webapp", "api", "auth_service"],
            "threats": [
                {
                    "title": "Forced attribution of sensitive actions",
                    "description": "User cannot deny a sensitive action even when they should have plausible deniability.",
                    "severity": "Low",
                    "mitigations": ["Offer ephemeral / deniable modes where appropriate", "Avoid logging more than needed"],
                },
            ],
        },
        "Detectability": {
            "description": "Distinguishing whether an item / action exists",
            "applies_to": ["api", "webapp", "auth_service"],
            "threats": [
                {
                    "title": "Account enumeration via differential responses",
                    "description": "Login / signup / password reset reveal whether an account exists.",
                    "severity": "Medium",
                    "mitigations": ["Return identical responses regardless of account existence", "Constant-time comparisons"],
                },
            ],
        },
        "Disclosure of information": {
            "description": "Exposing information beyond what is necessary",
            "applies_to": ["database", "datastore", "api", "data_flow", "webapp"],
            "threats": [
                {
                    "title": "Excessive data collection",
                    "description": "System collects more PII than needed for its purpose.",
                    "severity": "Medium",
                    "mitigations": ["Apply data minimization", "Document lawful basis per field", "Run privacy impact assessments"],
                },
                {
                    "title": "Third-party data leakage",
                    "description": "PII shared with analytics/ad SDKs without consent.",
                    "severity": "High",
                    "mitigations": ["Vendor review + DPAs", "Consent management platform", "Block third-party trackers by default"],
                },
            ],
        },
        "Unawareness": {
            "description": "Subject is unaware of data being collected / used",
            "applies_to": ["webapp", "mobile_app", "api"],
            "threats": [
                {
                    "title": "Lack of transparent privacy notice",
                    "description": "Users don't know what data is collected or for what purpose.",
                    "severity": "Medium",
                    "mitigations": ["Clear, layered privacy notice", "Just-in-time consent prompts", "Subject access / export tooling"],
                },
            ],
        },
        "Non-compliance": {
            "description": "Failure to meet regulatory or contractual privacy obligations",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "GDPR / CCPA / HIPAA gaps",
                    "description": "Missing DSAR handling, retention policies, or data residency controls.",
                    "severity": "High",
                    "mitigations": ["Map data flows to applicable regs", "Automate DSAR pipeline", "Set retention TTLs by data class"],
                },
            ],
        },
    },
}

# ---------- PASTA (7-stage process scaffold) ----------
# PASTA is a process-oriented, 7-stage methodology. A static rule engine cannot
# *execute* a multi-stage risk process, so this tool does not claim to. What it
# provides is an honest scaffold: for each stage it emits a checklist item that
# states plainly whether the tool auto-derived anything for that stage or whether
# the stage still requires manual work. Only Stage 3 (Decomposition) is genuinely
# automated here — it is backed by the real DFD, trust-boundary inference, and the
# cross-boundary rules in analyzer.py. Every other stage is flagged as manual so a
# reader is never misled into thinking a full PASTA process was performed.
PASTA = {
    "name": "PASTA",
    "kind": "methodology",
    "description": "Process for Attack Simulation and Threat Analysis — a 7-stage risk-centric process. This tool automates Stage 3 (decomposition) and surfaces the remaining stages as a manual checklist scaffold; it does not execute the full process end-to-end.",
    "categories": {
        "Stage 1 — Business Objectives": {
            "description": "Identify business impact of compromise (manual stage)",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Manual step — map business impact & asset owners",
                    "description": "PASTA Stage 1 requires defining business objectives and impact tiers. The tool does NOT determine this automatically: assign an owner and a business-impact tier to each component, and record revenue/regulatory exposure.",
                    "severity": "Info",
                    "mitigations": ["Assign asset owner", "Tag asset with business impact tier", "Include in BCP/DR scope"],
                },
            ],
        },
        "Stage 2 — Technical Scope": {
            "description": "Define infrastructure and dependencies (manual stage)",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Manual step — enumerate dependencies & run SCA",
                    "description": "PASTA Stage 2 requires a dependency/SBOM inventory and CVE analysis. The tool does NOT scan dependencies: run SCA (e.g. dependabot/trivy) and attach the SBOM to complete this stage.",
                    "severity": "Info",
                    "mitigations": ["Continuous SCA scanning", "Pin and patch dependencies", "Track SBOM"],
                },
            ],
        },
        "Stage 3 — Application Decomposition": {
            "description": "Map data flows, trust boundaries, entry points (auto-derived)",
            "applies_to": ["webapp", "api", "data_flow"],
            "threats": [
                {
                    "title": "Auto-derived — review decomposition & boundary crossings",
                    "description": "PASTA Stage 3 is automated by this tool: see the generated DFD, the inferred trust boundaries, and the per-flow cross-boundary findings. Review them and confirm every entry point and trust boundary is correct.",
                    "severity": "Info",
                    "mitigations": ["Enforce authn at every boundary", "Validate inputs server-side", "Use mTLS between services"],
                },
            ],
        },
        "Stage 4 — Threat Analysis": {
            "description": "Identify likely threat actors and TTPs (manual stage)",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Manual step — define threat actors & TTPs",
                    "description": "PASTA Stage 4 requires profiling plausible adversaries and their techniques. The tool does NOT infer threat actors: map actor tiers (script-kiddie → nation-state) and relevant MITRE ATT&CK TTPs to your surfaces.",
                    "severity": "Info",
                    "mitigations": ["Document actor tiers and motives", "Map TTPs (MITRE ATT&CK) to surfaces"],
                },
            ],
        },
        "Stage 5 — Vulnerability Analysis": {
            "description": "Correlate weaknesses (partially auto-derived)",
            "applies_to": ["webapp", "api", "database", "auth_service"],
            "threats": [
                {
                    "title": "Partial — review STRIDE/OWASP findings, then add testing",
                    "description": "PASTA Stage 5 correlates weaknesses. The STRIDE and OWASP findings in this report are a starting point, but the tool does NOT run SAST/DAST: add dynamic and static testing results to complete the picture.",
                    "severity": "Info",
                    "mitigations": ["Adopt OWASP ASVS", "Run SAST + DAST in CI", "Threat-test on each release"],
                },
            ],
        },
        "Stage 6 — Attack Modeling": {
            "description": "Build attack trees (manual stage)",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Manual step — build attack trees",
                    "description": "PASTA Stage 6 requires constructing attack trees. The tool does NOT generate attack trees: model plausible kill-chains (e.g. phish → token theft → admin) for the highest-risk flows and rank them by likelihood × impact.",
                    "severity": "Info",
                    "mitigations": ["Run purple-team exercises", "Model attack trees and rank by likelihood × impact"],
                },
            ],
        },
        "Stage 7 — Risk & Impact Analysis": {
            "description": "Quantify and prioritize (partially auto-derived)",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Partial — use severity/DREAD scores, then assign risk owners",
                    "description": "PASTA Stage 7 quantifies and prioritizes risk. The tool provides severity and DREAD scores per threat as inputs, but does NOT record risk decisions: track each risk to an explicit accept/mitigate/transfer/avoid decision with an owner.",
                    "severity": "Info",
                    "mitigations": ["Track each risk to a decision (accept/mitigate/transfer/avoid)", "Re-review quarterly"],
                },
            ],
        },
    },
}

METHODOLOGIES = {
    "stride": STRIDE,
    "dread": DREAD,
    "linddun": LINDDUN,
    "pasta": PASTA,
    "owasp": OWASP_TOP10,
}

# ---- Component type taxonomy used by the analyzer/UI ----
COMPONENT_TYPES = [
    "user", "external_entity", "webapp", "mobile_app", "api",
    "auth_service", "admin_panel", "database", "datastore",
    "cache", "queue", "filesystem", "config", "payment_service", "data_flow",
]
