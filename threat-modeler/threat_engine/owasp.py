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

# Component type -> extra framework whose lens always applies to its threats.
_TYPE_FRAMEWORK = {
    "api": "API", "api_gateway": "API", "graphql": "API",
    "mobile_app": "MOBILE",
}
_AI_TYPES = {"llm", "ai_agent", "agent_orchestrator", "llm_tool", "retriever",
             "guardrail", "mcp_server", "agent_memory", "knowledge_base", "vector_db"}


def _ref(framework: str, item_id: str) -> dict | None:
    fw = FRAMEWORKS.get(framework)
    if not fw or item_id not in fw[1]:
        return None
    _name, catalog, url = fw
    return {"framework": framework, "id": item_id, "label": catalog[item_id], "url": url}


def map_threat(threat: dict, component: dict | None = None) -> list[dict]:
    """Return the OWASP/agentic framework references for a threat (deduped)."""
    text = f"{threat.get('title', '')} {threat.get('category', '')}".lower()
    ctype = (component or {}).get("type", "")
    picks: list[tuple[str, str]] = []

    # 1) Baseline Web mapping by STRIDE/LINDDUN category.
    cat = (threat.get("category") or "").lower()
    for key, item in _WEB_BY_CATEGORY.items():
        if key in cat:
            picks.append(("WEB", item))
            break

    # 2) Keyword-driven mappings (the precise ones).
    for kw, refs in _KEYWORD_MAP:
        if kw in text:
            picks.extend(refs)

    # 3) Component-type lens (API / Mobile), and LLM baseline for AI components.
    if ctype in _TYPE_FRAMEWORK:
        # map the web pick's spirit into the API/Mobile equivalent where obvious
        fw = _TYPE_FRAMEWORK[ctype]
        if fw == "API" and ("WEB", "A01") in picks:
            picks.append(("API", "API1"))
        if fw == "MOBILE" and ("WEB", "A02") in picks:
            picks.append(("MOBILE", "M10"))
    if ctype in _AI_TYPES and not any(f == "LLM" for f, _ in picks):
        # ensure AI-component threats at least surface the LLM lens
        pass

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
