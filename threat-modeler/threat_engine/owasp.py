"""Multi-framework OWASP (and agentic) mapping — the single source of truth that
cross-links each generated threat to the relevant OWASP Top-10 item(s).

Historically only OWASP Web (2021) was mapped, by STRIDE category. This module
extends that to five frameworks and selects the right one(s) by **component type**
and **threat keywords**, so the mapping works identically for precise and free-text
input (both produce component types + threats):

  - OWASP Web Top 10 (2021)          — web-facing components / classic app risks
  - OWASP API Security Top 10 (2023) — api / api_gateway / graphql
  - OWASP Mobile Top 10 (2024)       — mobile_app
  - OWASP LLM Top 10 (2025)          — llm / agentic components + LLM-specific threats
  - OWASP Agentic Threats            — autonomous-agent / tool / memory threats

`map_threat` returns a list of {framework, id, label, url} — a threat can carry
several (e.g. an agent prompt-injection maps to LLM01 *and* Agentic). It is data,
not logic: to track a new framework revision, edit the tables below.
"""
from __future__ import annotations

# framework key -> (display name, catalog {item_id: label}, base url)
_WEB = "https://owasp.org/Top10/"
_API = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
_MOBILE = "https://owasp.org/www-project-mobile-top-10/"
_LLM = "https://genai.owasp.org/llm-top-10/"
_AGENTIC = "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/"

WEB = {
    "A01": "A01:2021 Broken Access Control", "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection", "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration", "A06": "A06:2021 Vulnerable & Outdated Components",
    "A07": "A07:2021 Identification & Authentication Failures",
    "A08": "A08:2021 Software & Data Integrity Failures",
    "A09": "A09:2021 Security Logging & Monitoring Failures", "A10": "A10:2021 SSRF",
}
API = {
    "API1": "API1:2023 Broken Object Level Authorization", "API2": "API2:2023 Broken Authentication",
    "API3": "API3:2023 Broken Object Property Level Authorization",
    "API4": "API4:2023 Unrestricted Resource Consumption",
    "API5": "API5:2023 Broken Function Level Authorization",
    "API6": "API6:2023 Unrestricted Access to Sensitive Business Flows",
    "API7": "API7:2023 Server Side Request Forgery", "API8": "API8:2023 Security Misconfiguration",
    "API9": "API9:2023 Improper Inventory Management", "API10": "API10:2023 Unsafe Consumption of APIs",
}
MOBILE = {
    "M1": "M1:2024 Improper Credential Usage", "M2": "M2:2024 Inadequate Supply Chain Security",
    "M3": "M3:2024 Insecure Authentication/Authorization", "M4": "M4:2024 Insufficient Input/Output Validation",
    "M5": "M5:2024 Insecure Communication", "M6": "M6:2024 Inadequate Privacy Controls",
    "M7": "M7:2024 Insufficient Binary Protections", "M8": "M8:2024 Security Misconfiguration",
    "M9": "M9:2024 Insecure Data Storage", "M10": "M10:2024 Insufficient Cryptography",
}
LLM = {
    "LLM01": "LLM01:2025 Prompt Injection", "LLM02": "LLM02:2025 Sensitive Information Disclosure",
    "LLM03": "LLM03:2025 Supply Chain", "LLM04": "LLM04:2025 Data and Model Poisoning",
    "LLM05": "LLM05:2025 Improper Output Handling", "LLM06": "LLM06:2025 Excessive Agency",
    "LLM07": "LLM07:2025 System Prompt Leakage", "LLM08": "LLM08:2025 Vector and Embedding Weaknesses",
    "LLM09": "LLM09:2025 Misinformation", "LLM10": "LLM10:2025 Unbounded Consumption",
}
AGENTIC = {
    "T1": "Agentic T1 — Memory Poisoning", "T2": "Agentic T2 — Tool Misuse",
    "T3": "Agentic T3 — Privilege Compromise", "T4": "Agentic T4 — Resource Overload",
    "T5": "Agentic T5 — Cascading Hallucination", "T6": "Agentic T6 — Intent Breaking & Goal Manipulation",
    "T8": "Agentic T8 — Repudiation & Untraceability", "T9": "Agentic T9 — Identity Spoofing",
    "T10": "Agentic T10 — Overwhelming Human-in-the-Loop", "T12": "Agentic T12 — Agent Communication Poisoning",
    "T13": "Agentic T13 — Rogue Agents",
}

FRAMEWORKS = {
    "WEB": ("OWASP Web Top 10 (2021)", WEB, _WEB),
    "API": ("OWASP API Security Top 10 (2023)", API, _API),
    "MOBILE": ("OWASP Mobile Top 10 (2024)", MOBILE, _MOBILE),
    "LLM": ("OWASP LLM Top 10 (2025)", LLM, _LLM),
    "AGENTIC": ("OWASP Agentic Threats", AGENTIC, _AGENTIC),
}

# STRIDE / LINDDUN category -> OWASP Web item (baseline mapping, always applied).
_WEB_BY_CATEGORY = {
    "spoofing": "A07", "tampering": "A03", "repudiation": "A09",
    "information disclosure": "A02", "disclosure": "A02", "denial of service": "A05",
    "denial": "A05", "elevation": "A01", "privilege": "A01",
}

# Keyword (in the threat title/category, lowercased) -> [(framework, item_id), ...].
# Ordered; first matches win but all matching keywords contribute.
_KEYWORD_MAP: list[tuple[str, list[tuple[str, str]]]] = [
    ("prompt injection", [("LLM", "LLM01"), ("AGENTIC", "T6")]),
    ("excessive agency", [("LLM", "LLM06"), ("AGENTIC", "T3")]),
    ("agent invokes tool", [("LLM", "LLM06"), ("AGENTIC", "T2")]),
    ("unsandboxed tool", [("LLM", "LLM06"), ("AGENTIC", "T2")]),
    ("tool/code execution", [("AGENTIC", "T2"), ("LLM", "LLM06")]),
    ("output used without validation", [("LLM", "LLM05")]),
    ("insecure output", [("LLM", "LLM05")]),
    ("memory shared", [("LLM", "LLM08"), ("AGENTIC", "T1")]),
    ("memory poison", [("AGENTIC", "T1"), ("LLM", "LLM04")]),
    ("grounding source", [("LLM", "LLM04"), ("LLM", "LLM01")]),
    ("data poison", [("LLM", "LLM04")]),
    ("spawn agents", [("LLM", "LLM10"), ("AGENTIC", "T4")]),
    ("unbounded", [("LLM", "LLM10"), ("AGENTIC", "T4")]),
    ("system prompt", [("LLM", "LLM07")]),
    ("sensitive information", [("LLM", "LLM02")]),
    ("output not filtered", [("LLM", "LLM02")]),
    ("supply chain", [("LLM", "LLM03"), ("WEB", "A06")]),
    ("embedding", [("LLM", "LLM08"), ("AGENTIC", "T1")]),
    ("vector/embedding", [("LLM", "LLM08"), ("AGENTIC", "T1")]),
    ("misinformation", [("LLM", "LLM09"), ("AGENTIC", "T5")]),
    ("overreliance", [("LLM", "LLM09"), ("AGENTIC", "T5")]),
    ("no authorization", [("WEB", "A01"), ("API", "API1"), ("API", "API5")]),
    ("authorization enforcement", [("WEB", "A01"), ("API", "API5")]),
    ("idor", [("WEB", "A01"), ("API", "API1")]),
    ("tenant", [("WEB", "A01"), ("API", "API1")]),
    ("ssrf", [("WEB", "A10"), ("API", "API7")]),
    ("injection", [("WEB", "A03")]),
    ("cross-site scripting", [("WEB", "A03")]),
    ("xss", [("WEB", "A03")]),
    ("csrf", [("WEB", "A01")]),
    ("unencrypted", [("WEB", "A02")]),
    ("cleartext", [("WEB", "A02")]),
    ("no authentication", [("WEB", "A07"), ("API", "API2")]),
    ("unauthenticated", [("WEB", "A07"), ("API", "API2")]),
    ("multi-factor", [("WEB", "A07")]),
    ("rate limit", [("API", "API4"), ("WEB", "A05")]),
    ("logging", [("WEB", "A09")]),
    ("code/artifact integrity", [("WEB", "A08"), ("API", "API8")]),
    ("supply-chain", [("WEB", "A06"), ("LLM", "LLM03")]),
]

_API_TYPES = {"api", "api_gateway", "graphql"}

# Mobile lens. A threat touching a mobile component maps to the OWASP Mobile Top 10
# by keyword first (precise), then STRIDE category (baseline) if no keyword matched —
# mirroring how the Web lens works, so a mobile app never comes back with zero mobile
# coverage. Keyword picks win to keep an in-transit disclosure on M5 (not storage M9).
_MOBILE_KEYWORDS: list[tuple[str, str]] = [
    ("unencrypted", "M5"), ("cleartext", "M5"), ("in transit", "M5"),
    ("transport", "M5"), ("communication", "M5"), ("intercept", "M5"),
    ("at rest", "M9"), ("data storage", "M9"), ("stored", "M9"), ("local storage", "M9"),
    ("cryptograph", "M10"), ("weak cipher", "M10"), ("weak encryption", "M10"),
    ("credential", "M1"), ("api key", "M1"), ("hardcoded", "M1"), ("secret", "M1"),
    ("no authentication", "M3"), ("unauthenticated", "M3"), ("authorization", "M3"),
    ("session token", "M3"), ("privilege", "M3"),
    ("injection", "M4"), ("not validated", "M4"), ("input validation", "M4"),
    ("xss", "M4"), ("output handling", "M4"),
    ("supply", "M2"), ("outdated", "M2"),
    ("misconfig", "M8"), ("logging", "M8"), ("privacy", "M6"),
    ("reverse engineer", "M7"), ("binary protection", "M7"),
]
_MOBILE_BY_CATEGORY = {
    "spoofing": "M3", "elevation": "M3", "privilege": "M3",
    "tampering": "M4",
    "repudiation": "M8", "denial of service": "M8", "denial": "M8",
    "information disclosure": "M9", "disclosure": "M9",
}


def _ref(framework: str, item_id: str) -> dict | None:
    fw = FRAMEWORKS.get(framework)
    if not fw or item_id not in fw[1]:
        return None
    _name, catalog, url = fw
    return {"framework": framework, "id": item_id, "label": catalog[item_id], "url": url}


def map_threat(threat: dict, component: dict | None = None,
               involved_types: set[str] | list[str] | None = None) -> list[dict]:
    """Return the OWASP/agentic framework references for a threat (deduped).

    `involved_types` are all component types this threat touches — its own component
    plus both endpoints of its data flow. Flow threats attach to the *destination*
    component, so without the flow endpoints a mobile/API source is invisible and its
    lens never fires. Callers that have the flow context should pass it; when omitted
    the set falls back to the single `component` (legacy behaviour).
    """
    text = f"{threat.get('title', '')} {threat.get('category', '')}".lower()
    cat = (threat.get("category") or "").lower()
    types = {t for t in (involved_types or []) if t}
    ctype = (component or {}).get("type", "")
    if ctype:
        types.add(ctype)
    picks: list[tuple[str, str]] = []

    # 1) Baseline Web mapping by STRIDE/LINDDUN category.
    for key, item in _WEB_BY_CATEGORY.items():
        if key in cat:
            picks.append(("WEB", item))
            break

    # 2) Keyword-driven mappings (the precise ones).
    for kw, refs in _KEYWORD_MAP:
        if kw in text:
            picks.extend(refs)

    # 2b) Authoritative agentic mapping — data-driven threat classes carry an explicit
    # OWASP-LLM code (and optional Agentic technique), so the mapping never depends on
    # the threat title wording (evidenced vs baseline phrasings map identically).
    if threat.get("owasp"):
        picks.append(("LLM", threat["owasp"]))
    if threat.get("owasp_agentic"):
        picks.append(("AGENTIC", threat["owasp_agentic"]))

    # 3) API lens — access-control threats on any API-typed endpoint of the flow.
    if types & _API_TYPES and ("WEB", "A01") in picks:
        picks.append(("API", "API1"))

    # 4) Mobile lens — a threat touching a mobile component maps to Mobile Top 10:
    #    keyword picks first (precise), STRIDE category as the baseline fallback.
    if "mobile_app" in types:
        mob = [m for kw, m in _MOBILE_KEYWORDS if kw in text]
        if not mob:
            for key, m in _MOBILE_BY_CATEGORY.items():
                if key in cat:
                    mob.append(m)
                    break
        picks.extend(("MOBILE", m) for m in mob)

    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for fw, item in picks:
        if (fw, item) in seen:
            continue
        seen.add((fw, item))
        ref = _ref(fw, item)
        if ref:
            out.append(ref)
    return out
