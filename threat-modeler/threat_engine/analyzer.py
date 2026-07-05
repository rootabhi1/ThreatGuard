"""Threat analyzer.

Takes a normalized system model:
{
  "name": "...",
  "description": "...",
  "components": [{"id","name","type","description"}],
  "data_flows": [{"id","from","to","label","protocol","auth","encrypted"}],
  "trust_boundaries": [{"id","name","contains":[component_id,...]}]
}

Applies the requested methodology's rules to produce threats, then
optionally enhances with Claude API if an API key is configured.
"""
from __future__ import annotations

import json
import uuid
import re
import re as _re2
from typing import Any

from .methodologies import METHODOLOGIES


_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _dedup_threats(threats):
    seen = {}
    for t in threats:
        key = (_re2.sub(r"\W+", " ", (t.get("title") or "").lower()).strip(), t.get("component_id", ""))
        if key not in seen or _SEV_RANK.get(t.get("severity", ""), 0) > _SEV_RANK.get(seen[key].get("severity", ""), 0):
            seen[key] = {**t, "methodologies": seen.get(key, {}).get("methodologies", []) + [t.get("methodology", "")]}
        else:
            seen[key]["methodologies"] = list(dict.fromkeys(seen[key]["methodologies"] + [t.get("methodology", "")]))
            seen[key]["mitigations"] = list(dict.fromkeys((seen[key].get("mitigations") or []) + (t.get("mitigations") or [])))
    for t in seen.values():
        t["methodology"] = " + ".join(m for m in t.get("methodologies", []) if m)
    return list(seen.values())


# ---------------------------------------------------------------------------
# Heuristic extraction from a free-text system description.
# Used by the "text description" input mode.
# ---------------------------------------------------------------------------
_TYPE_KEYWORDS = {
    "user":            ["user", "customer", "end user", "client app user"],
    "external_entity": ["third party", "external", "partner", "saas"],
    "webapp":          ["web app", "website", "front-end", "frontend", "portal", "spa", "react app", "next.js"],
    "mobile_app":      ["mobile app", "android", "ios", "react native"],
    "api":             ["api", "backend", "rest service", "graphql", "microservice", "service"],
    "auth_service":    ["auth", "oauth", "sso", "identity provider", "okta", "auth0", "cognito", "keycloak"],
    "admin_panel":     ["admin panel", "admin ui", "back-office", "back office"],
    "database":        ["database", "db", "postgres", "mysql", "mongodb", "dynamodb", "rds"],
    "datastore":       ["s3", "blob storage", "object store", "data lake", "warehouse", "bigquery", "snowflake"],
    "cache":           ["redis", "memcached", "cache"],
    "queue":           ["queue", "kafka", "rabbitmq", "sqs", "pubsub", "event bus"],
    "filesystem":      ["filesystem", "file storage", "nfs"],
    "payment_service": ["stripe", "payment", "paypal", "billing"],
}

def extract_components_from_text(text: str) -> dict:
    """Best-effort extraction. Always good enough for a starting draft —
    user can edit in the UI before running analysis."""
    t = text.lower()
    components: list[dict] = []
    seen_types: set[str] = set()

    for ctype, keywords in _TYPE_KEYWORDS.items():
        for kw in keywords:
            if re.search(r"\b" + re.escape(kw) + r"\b", t):
                if ctype not in seen_types:
                    components.append({
                        "id": f"c_{ctype}",
                        "name": kw.title(),
                        "type": ctype,
                        "description": f"Detected from description (keyword: '{kw}')",
                    })
                    seen_types.add(ctype)
                break

    # Always include a "user" if nothing user-facing detected
    if not any(c["type"] == "user" for c in components):
        components.insert(0, {
            "id": "c_user", "name": "User", "type": "user",
            "description": "Default end user (auto-added)",
        })

    # Heuristic data flows: chain user -> webapp/api -> backing stores
    data_flows: list[dict] = []
    user = next((c for c in components if c["type"] == "user"), None)
    front = next((c for c in components if c["type"] in ("webapp", "mobile_app")), None)
    api = next((c for c in components if c["type"] == "api"), None)
    stores = [c for c in components if c["type"] in ("database", "datastore", "cache")]

    if user and (front or api):
        target = front or api
        data_flows.append({
            "id": f"f_{uuid.uuid4().hex[:6]}",
            "from": user["id"], "to": target["id"],
            "label": "User request", "protocol": "HTTPS",
            "auth": "session", "encrypted": True,
        })
    if front and api:
        data_flows.append({
            "id": f"f_{uuid.uuid4().hex[:6]}",
            "from": front["id"], "to": api["id"],
            "label": "API call", "protocol": "HTTPS",
            "auth": "bearer", "encrypted": True,
        })
    for store in stores:
        if api:
            data_flows.append({
                "id": f"f_{uuid.uuid4().hex[:6]}",
                "from": api["id"], "to": store["id"],
                "label": "Read/write", "protocol": "TCP",
                "auth": "credentials", "encrypted": False,
            })

    return {
        "components": components,
        "data_flows": data_flows,
        "trust_boundaries": _infer_boundaries_for_extracted(components, text),
    }


def _infer_boundaries_for_extracted(components: list[dict], source_text: str) -> list[dict]:
    """Heuristic boundary inference, called from extract_components_from_text.
    LLM mode is reached separately via /api/infer-trust-boundaries."""
    from .trust_boundaries import infer_trust_boundaries_heuristic
    return infer_trust_boundaries_heuristic({"components": components, "data_flows": []})


# ---------------------------------------------------------------------------
# Severity scoring helpers
# ---------------------------------------------------------------------------
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _score_dread(threat: dict, component: dict, flow: dict | None, cross_boundary: bool = False) -> dict:
    """Approximate DREAD scores from threat severity + flow attributes.
    Returns ints 1-10 for D/R/E/A/D and a total."""
    base = {"Critical": 9, "High": 7, "Medium": 5, "Low": 3, "Info": 2}.get(threat["severity"], 5)
    damage = base
    reproducibility = base - 1
    exploitability = base
    affected = base if component["type"] in ("webapp", "api", "auth_service", "database") else base - 2
    discoverability = base
    if flow and not flow.get("encrypted", True):
        discoverability += 1
        exploitability += 1
    if cross_boundary:
        # Crossing trust zones expands the blast radius and discoverability
        affected += 2
        discoverability += 1
    vals = [damage, reproducibility, exploitability, affected, discoverability]
    vals = [max(1, min(10, v)) for v in vals]
    return {
        "D_damage": vals[0],
        "R_reproducibility": vals[1],
        "E_exploitability": vals[2],
        "A_affected_users": vals[3],
        "D_discoverability": vals[4],
        "total": sum(vals),
    }


# ---------------------------------------------------------------------------
# Core rule-based analysis
# ---------------------------------------------------------------------------
def _rule_based_threats(system: dict, methodology_key: str) -> list[dict]:
    methodology = METHODOLOGIES[methodology_key]
    threats: list[dict] = []

    components = system.get("components", [])
    flows = system.get("data_flows", [])
    comp_by_id = {c["id"]: c for c in components}

    # Component-level threats
    for category_name, category in methodology["categories"].items():
        applies = category["applies_to"]
        for component in components:
            if "*" in applies or component["type"] in applies:
                for rule in category["threats"]:
                    threats.append({
                        "id": f"t_{uuid.uuid4().hex[:8]}",
                        "methodology": methodology["name"],
                        "category": category_name,
                        "title": rule["title"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "component_id": component["id"],
                        "component_name": component["name"],
                        "component_type": component["type"],
                        "flow_id": None,
                        "mitigations": rule["mitigations"],
                        "source": "rule-based",
                        "dread": _score_dread(rule, component, None),
                    })

    # Flow-level enrichment: unencrypted flows attract Tampering / Info-Disclosure
    for flow in flows:
        if not flow.get("encrypted", True):
            src = comp_by_id.get(flow["from"])
            dst = comp_by_id.get(flow["to"])
            if not src or not dst:
                continue
            threats.append({
                "id": f"t_{uuid.uuid4().hex[:8]}",
                "methodology": methodology["name"],
                "category": "Information Disclosure" if methodology_key == "stride" else "Disclosure of information",
                "title": f"Unencrypted flow: {src['name']} → {dst['name']}",
                "description": f"Data flow '{flow.get('label','')}' uses {flow.get('protocol','unknown')} without encryption.",
                "severity": "High",
                "component_id": dst["id"],
                "component_name": dst["name"],
                "component_type": dst["type"],
                "flow_id": flow["id"],
                "mitigations": ["Enable TLS on this flow", "If internal, enforce mTLS", "Verify cert pinning where relevant"],
                "source": "rule-based",
                "dread": _score_dread({"severity": "High"}, dst, flow),
            })

        auth_val = (flow.get("auth") or "").strip().lower()
        if auth_val in ("", "none", "n/a"):
            src = comp_by_id.get(flow["from"])
            dst = comp_by_id.get(flow["to"])
            if not src or not dst:
                continue
            threats.append({
                "id": f"t_{uuid.uuid4().hex[:8]}",
                "methodology": methodology["name"],
                "category": "Spoofing" if methodology_key == "stride" else "Stage 3 — Application Decomposition",
                "title": f"Unauthenticated flow: {src['name']} → {dst['name']}",
                "description": f"Data flow has no authentication mechanism declared.",
                "severity": "High",
                "component_id": dst["id"],
                "component_name": dst["name"],
                "component_type": dst["type"],
                "flow_id": flow["id"],
                "mitigations": ["Add token / mTLS auth on this flow", "Validate caller identity at the receiver"],
                "source": "rule-based",
                "dread": _score_dread({"severity": "High"}, dst, flow),
            })

    # ---- Trust-boundary crossing rules ----
    # Build component -> boundary lookup
    boundaries = system.get("trust_boundaries", []) or []
    comp_boundary: dict[str, str] = {}  # component_id -> boundary_id
    boundary_by_id: dict[str, dict] = {b["id"]: b for b in boundaries}
    for b in boundaries:
        for cid in b.get("contains", []):
            comp_boundary[cid] = b["id"]

    def _crosses_boundary(flow):
        a = comp_boundary.get(flow["from"])
        b = comp_boundary.get(flow["to"])
        # crosses if either endpoint is outside any boundary, or they're in different ones
        return a != b

    cross_boundary_threat_templates = {
        "stride": [
            {
                "category": "Spoofing",
                "title_fmt": "Trust-boundary crossing without strong authn: {src} → {dst}",
                "description_fmt": "Flow '{label}' crosses trust boundary '{src_zone}' → '{dst_zone}'. Caller identity must be re-verified at the boundary; existing trust does not transit.",
                "severity": "High",
                "mitigations": ["Require fresh authentication at the boundary (token/mTLS)", "Do not trust source-IP or upstream identity claims", "Sign and verify request integrity"],
            },
            {
                "category": "Tampering",
                "title_fmt": "Cross-boundary input not validated: {src} → {dst}",
                "description_fmt": "Data crossing the trust boundary into '{dst_zone}' must be treated as untrusted, even if the source is internal. Implicit trust is the most common cause of injection / SSRF / deserialization bugs.",
                "severity": "High",
                "mitigations": ["Validate and canonicalize all cross-boundary input", "Apply allow-listing on schema/length/charset", "Re-authorize the caller for each request"],
            },
            {
                "category": "Information Disclosure",
                "title_fmt": "Cross-boundary data exposure risk: {src} → {dst}",
                "description_fmt": "Information leaving '{src_zone}' into '{dst_zone}' may include data the receiving zone is not authorized to see. Cross-boundary egress is a common data-leak surface.",
                "severity": "High" if True else "High",
                "mitigations": ["Apply minimum-data-needed at the boundary", "Tokenize or redact sensitive fields", "Log and review cross-boundary data flows"],
            },
            {
                "category": "Elevation of Privilege",
                "title_fmt": "Privilege transit across boundary: {src} → {dst}",
                "description_fmt": "If the receiver in '{dst_zone}' acts on behalf of the caller, attackers compromising '{src_zone}' may inherit the receiver's privileges (confused-deputy).",
                "severity": "Critical",
                "mitigations": ["Use scoped, short-lived delegation tokens", "Apply caller-bound authorization on every action", "Avoid ambient authority across boundaries"],
            },
        ],
        "linddun": [
            {
                "category": "Disclosure of information",
                "title_fmt": "Cross-boundary PII transfer: {src} → {dst}",
                "description_fmt": "Personal data crossing trust boundaries triggers data-protection obligations (purpose, consent, residency, processor agreements).",
                "severity": "High",
                "mitigations": ["Document lawful basis for the cross-boundary transfer", "Apply minimization before egress", "Verify processor / sub-processor compliance"],
            },
        ],
        "pasta": [
            {
                "category": "Stage 3 — Application Decomposition",
                "title_fmt": "Implicit trust across decomposition boundary: {src} → {dst}",
                "description_fmt": "Decomposition mapped a boundary between '{src_zone}' and '{dst_zone}' but implicit trust persists across it.",
                "severity": "High",
                "mitigations": ["Treat boundary as a real attack surface — authn, authz, validation, monitoring", "Add boundary-crossing flows to attack tree"],
            },
        ],
    }

    cross_templates = cross_boundary_threat_templates.get(methodology_key, [])
    for flow in flows:
        if not _crosses_boundary(flow):
            continue
        src = comp_by_id.get(flow["from"])
        dst = comp_by_id.get(flow["to"])
        if not src or not dst:
            continue
        src_zone = boundary_by_id.get(comp_boundary.get(src["id"], ""), {}).get("name", "External")
        dst_zone = boundary_by_id.get(comp_boundary.get(dst["id"], ""), {}).get("name", "External")
        for tmpl in cross_templates:
            threats.append({
                "id": f"t_{uuid.uuid4().hex[:8]}",
                "methodology": methodology["name"],
                "category": tmpl["category"],
                "title": tmpl["title_fmt"].format(src=src["name"], dst=dst["name"]),
                "description": tmpl["description_fmt"].format(
                    src=src["name"], dst=dst["name"],
                    src_zone=src_zone, dst_zone=dst_zone,
                    label=flow.get("label", "")),
                "severity": tmpl["severity"],
                "component_id": dst["id"],
                "component_name": dst["name"],
                "component_type": dst["type"],
                "flow_id": flow["id"],
                "mitigations": tmpl["mitigations"],
                "source": "rule-based",
                "cross_boundary": True,
                "src_zone": src_zone,
                "dst_zone": dst_zone,
                "dread": _score_dread({"severity": tmpl["severity"]}, dst, flow, cross_boundary=True),
            })

    # De-duplicate (same title + component)
    seen = set()
    unique: list[dict] = []
    for t in threats:
        key = (t["title"], t["component_id"], t["category"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(t)

    # Sort by severity desc, then component
    unique.sort(key=lambda x: (-SEVERITY_RANK.get(x["severity"], 0), x["component_name"]))
    return unique


# ---------------------------------------------------------------------------
# Optional LLM enhancement via Claude API
# ---------------------------------------------------------------------------
def _llm_enhance(system: dict, methodology_key: str, base_threats: list[dict]) -> list[dict]:
    """If an LLM provider is configured, ask it to suggest additional
    context-specific threats. Falls back silently if unavailable."""
    from .llm import complete_text, llm_available, strip_fences
    if not llm_available():
        return []

    methodology = METHODOLOGIES[methodology_key]

    prompt = f"""You are a senior application security architect performing a threat model.

Methodology: {methodology['name']} — {methodology['description']}
Categories: {list(methodology['categories'].keys())}

System under review:
{json.dumps(system, indent=2)}

Existing rule-based threats already identified (do NOT repeat these):
{json.dumps([{"title": t["title"], "component": t["component_name"]} for t in base_threats], indent=2)}

Identify up to 8 ADDITIONAL context-specific threats that the rule engine likely missed.
Focus on threats that depend on the specific architecture, data, or business context.

Respond with ONLY valid JSON — no prose, no markdown fences. Schema:
{{
  "threats": [
    {{
      "category": "<one of {list(methodology['categories'].keys())}>",
      "title": "<short title>",
      "description": "<2-3 sentence description>",
      "severity": "Critical|High|Medium|Low",
      "component_name": "<exact component name from input>",
      "mitigations": ["...", "..."]
    }}
  ]
}}"""

    try:
        text = complete_text(prompt, max_tokens=2000)
        if not text:
            return []
        parsed = json.loads(strip_fences(text))
    except Exception as e:
        print(f"[llm_enhance] failed: {e}")
        return []

    comp_by_name = {c["name"]: c for c in system.get("components", [])}
    out = []
    for t in parsed.get("threats", []):
        comp = comp_by_name.get(t.get("component_name", ""))
        if not comp:
            continue
        out.append({
            "id": f"t_{uuid.uuid4().hex[:8]}",
            "methodology": methodology["name"],
            "category": t.get("category", "Unspecified"),
            "title": t.get("title", "Untitled threat"),
            "description": t.get("description", ""),
            "severity": t.get("severity", "Medium"),
            "component_id": comp["id"],
            "component_name": comp["name"],
            "component_type": comp["type"],
            "flow_id": None,
            "mitigations": t.get("mitigations", []),
            "source": "llm-enhanced",
            "dread": _score_dread({"severity": t.get("severity", "Medium")}, comp, None),
        })
    return out


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def analyze_system(
    system: dict[str, Any],
    methodology_keys: list[str],
    use_llm: bool = False,
) -> dict[str, Any]:
    """Run threat analysis. methodology_keys is a list of any of:
    ['stride','dread','linddun','pasta']."""
    from .scoring import enrich_threat_with_scoring
    from .detail import enrich_threat_with_detail

    # If the model doesn't define trust boundaries, infer them heuristically so
    # the cross-boundary rules, the DFD, and the report all reflect real zones
    # instead of treating everything as one flat trust zone.
    if not (system.get("trust_boundaries") or []):
        from .trust_boundaries import infer_trust_boundaries_heuristic
        inferred = infer_trust_boundaries_heuristic({
            "components": system.get("components", []) or [],
            "data_flows": system.get("data_flows", []) or [],
        })
        if inferred:
            system = {**system, "trust_boundaries": inferred}

    all_threats: list[dict] = []
    components = system.get("components", []) or []
    flows = system.get("data_flows", []) or []
    comp_by_id = {c["id"]: c for c in components}
    flow_by_id = {f["id"]: f for f in flows}

    for mkey in methodology_keys:
        if mkey not in METHODOLOGIES:
            continue
        rule_threats = _rule_based_threats(system, mkey)
        all_threats.extend(rule_threats)

        if use_llm:
            llm_threats = _llm_enhance(system, mkey, rule_threats)
            all_threats.extend(llm_threats)

    # Enrich each threat with CVSS, CWE, and per-threat detail
    for t in all_threats:
        component = comp_by_id.get(t.get("component_id"))
        flow = flow_by_id.get(t.get("flow_id")) if t.get("flow_id") else None
        cb = bool(t.get("cross_boundary"))
        enrich_threat_with_scoring(t, component or {}, flow, cross_boundary=cb)
        enrich_threat_with_detail(
            t, component or {}, flow, components, flows,
            system_name=system.get("name", ""),
            use_llm=use_llm,
        )

    # Summary stats
    summary = {
        "total": len(all_threats),
        "by_severity": {s: 0 for s in ["Critical", "High", "Medium", "Low", "Info"]},
        "by_category": {},
        "by_component": {},
        "by_methodology": {},
        "rule_based": 0,
        "llm_enhanced": 0,
    }
    for t in all_threats:
        summary["by_severity"][t["severity"]] = summary["by_severity"].get(t["severity"], 0) + 1
        summary["by_category"][t["category"]] = summary["by_category"].get(t["category"], 0) + 1
        summary["by_component"][t["component_name"]] = summary["by_component"].get(t["component_name"], 0) + 1
        summary["by_methodology"][t["methodology"]] = summary["by_methodology"].get(t["methodology"], 0) + 1
        if t["source"] == "rule-based":
            summary["rule_based"] += 1
        else:
            summary["llm_enhanced"] += 1

    return {
        "system": system,
        "threats": all_threats,
        "summary": summary,
        "untrusted_crossings": _untrusted_input_crossings(system, all_threats),
        "methodologies_used": methodology_keys,
        "llm_used": use_llm and summary["llm_enhanced"] > 0,
    }


def _untrusted_input_crossings(system: dict, all_threats: list[dict]) -> list[dict]:
    """Identify flows where untrusted input crosses into an internal trust zone.

    'Internal' is heuristic: a zone whose name contains 'internal', 'private',
    'protected', 'core', 'backend', or which contains components of types
    ['database','datastore','cache','queue','filesystem','config'].
    A flow is 'untrusted-input crossing' when its source is either external
    (no boundary) or in a zone we classify as less-trusted (DMZ, public, edge,
    front, customer, partner).
    """
    components = system.get("components", []) or []
    flows = system.get("data_flows", []) or []
    boundaries = system.get("trust_boundaries", []) or []
    comp_by_id = {c["id"]: c for c in components}

    comp_to_boundary: dict[str, dict] = {}
    for b in boundaries:
        for cid in b.get("contains", []):
            comp_to_boundary[cid] = b

    INTERNAL_HINTS = ("internal", "private", "protected", "core", "backend",
                      "secure", "trusted")
    LESS_TRUSTED_HINTS = ("dmz", "public", "edge", "front", "customer",
                          "partner", "external", "untrusted", "perimeter")
    INTERNAL_TYPES = {"database", "datastore", "cache", "queue", "filesystem", "config"}

    def is_internal_boundary(b: dict) -> bool:
        name_low = b["name"].lower()
        if any(h in name_low for h in INTERNAL_HINTS):
            return True
        # Or if it contains internal-type components
        contained_types = {comp_by_id[cid]["type"] for cid in b.get("contains", [])
                           if cid in comp_by_id}
        return bool(contained_types & INTERNAL_TYPES)

    def is_less_trusted_zone(b: dict | None) -> bool:
        if b is None:
            return True   # no boundary = external = untrusted
        name_low = b["name"].lower()
        return any(h in name_low for h in LESS_TRUSTED_HINTS)

    crossings = []
    for f in flows:
        src_b = comp_to_boundary.get(f["from"])
        dst_b = comp_to_boundary.get(f["to"])
        if dst_b is None:
            continue   # destination is external — not what we're flagging
        if not is_internal_boundary(dst_b):
            continue   # destination zone isn't internal
        if src_b == dst_b:
            continue   # not crossing
        if not is_less_trusted_zone(src_b):
            continue   # source is also internal — different concern

        src = comp_by_id.get(f["from"])
        dst = comp_by_id.get(f["to"])
        if not src or not dst:
            continue

        # Threats associated with this flow
        flow_threats = [t for t in all_threats if t.get("flow_id") == f["id"]]
        crossings.append({
            "flow_id": f["id"],
            "source": {"id": src["id"], "name": src["name"], "type": src["type"]},
            "destination": {"id": dst["id"], "name": dst["name"], "type": dst["type"]},
            "source_zone": src_b["name"] if src_b else "External (untrusted)",
            "destination_zone": dst_b["name"],
            "label": f.get("label", ""),
            "protocol": f.get("protocol", ""),
            "auth": f.get("auth") or "none",
            "encrypted": bool(f.get("encrypted")),
            "threat_count": len(flow_threats),
            "highest_severity": (
                "Critical" if any(t["severity"] == "Critical" for t in flow_threats)
                else "High" if any(t["severity"] == "High" for t in flow_threats)
                else "Medium" if any(t["severity"] == "Medium" for t in flow_threats)
                else "Low" if flow_threats else "None"
            ),
            "input_validation_requirements": _input_validation_requirements(dst, f),
        })
    return crossings


def _input_validation_requirements(dst: dict, flow: dict) -> list[str]:
    """Return concrete input-validation requirements for an untrusted flow
    entering a component."""
    dst_type = dst.get("type", "")
    reqs = [
        "Define an explicit allow-list schema (JSON Schema, OpenAPI, Protobuf) for accepted payloads — reject anything that doesn't match.",
        "Validate every field's type, length, charset, and value range BEFORE business logic runs.",
        "Canonicalize input (URL-decode, Unicode NFC, path-resolve) BEFORE validation to defeat bypass tricks.",
    ]
    if dst_type in ("api", "webapp", "admin_panel"):
        reqs += [
            "Use parameterized queries / prepared statements for any SQL touching this input.",
            "Apply contextual output encoding (HTML, JS, URL, attribute) when this input is reflected in responses.",
            "Disallow direct deserialization of untrusted data; use safe formats (JSON without polymorphism, not pickle/Java-serialization).",
        ]
    if dst_type in ("database", "datastore"):
        reqs += [
            "Never construct queries via string concatenation from this input — driver-level parameterization only.",
            "Apply row-level security / tenant scoping enforced by the DB, not the app.",
        ]
    if not flow.get("encrypted"):
        reqs.append("Enable TLS on this flow before any of the above controls — without encryption, on-path attackers can substitute payloads after validation.")
    if (flow.get("auth") or "none") == "none":
        reqs.append("Add authentication on this flow — input validation alone does not establish caller identity.")
    return reqs
