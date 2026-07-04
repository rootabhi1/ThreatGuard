"""Trust boundary inference.

Given a system (components, flows, optional free-text description), partition
components into trust boundaries.

Two modes:
  - heuristic: deterministic rules based on component type + name patterns
  - llm: Claude reasons about each component's trust zone (needs ANTHROPIC_API_KEY)

Returns a list of trust boundaries:
  [{id, name, contains: [component_id, ...]}, ...]

Every component should land in exactly one boundary.
"""
from __future__ import annotations

import os
import json
import uuid
import re
from typing import Any


# ---------------------------------------------------------------------------
# Heuristic mode
# ---------------------------------------------------------------------------

# Boundary name → ordered list of (predicate-name, predicate-fn) checks.
# For each component, the FIRST matching boundary wins, so order matters.
_BOUNDARY_RULES = [
    {
        "name": "Internet",
        "match_types": {"user", "external_entity"},
        "match_name_patterns": [],
    },
    {
        "name": "Third-party / Untrusted services",
        "match_types": {"payment_service"},
        # Well-known SaaS / external APIs by name
        "match_name_patterns": [
            r"\bstripe\b", r"\bpaypal\b", r"\bbraintree\b", r"\badyen\b",
            r"\bopenai\b", r"\banthropic\b", r"\bclaude\b", r"\bgpt\b",
            r"\bgoogle\b", r"\bgmail\b", r"\bgcp\b",
            r"\baws\b", r"\bs3\b(?!\w)",   # S3 is gray — treat as third-party storage
            r"\bazure\b",
            r"\bgithub\b", r"\bgitlab\b", r"\bbitbucket\b",
            r"\bsendgrid\b", r"\bmailgun\b", r"\bmailchimp\b", r"\bsmtp\b",
            r"\btwilio\b", r"\bsns\b", r"\bsqs\b",
            r"\bauth0\b", r"\bokta\b", r"\bcognito\b", r"\bkeycloak\b",
            r"\bdatadog\b", r"\bsplunk\b", r"\bnewrelic\b",
            r"\bcloudflare\b", r"\bfastly\b", r"\bakamai\b",
            r"\bapns\b", r"\bfcm\b",       # push notification services
            r"\bpinecone\b", r"\bweaviate\b", r"\bchroma\b",  # vector DBs (3rd-party)
            r"\bfirebase\b", r"\bsupabase\b",
            r"\bvercel\b", r"\bnetlify\b", r"\bheroku\b",
            r"\bapple\s*pay\b", r"\bgoogle\s*pay\b",
        ],
    },
    {
        "name": "DMZ (public-facing)",
        # Components that face the internet but are owned by the org
        "match_types": {"webapp", "mobile_app", "api_gateway", "load_balancer", "cdn"},
        "match_name_patterns": [
            r"\bgateway\b", r"\bload\s*balancer\b", r"\blb\b", r"\bcdn\b",
            r"\bedge\b", r"\bnginx\b", r"\bproxy\b", r"\bingress\b",
        ],
    },
    {
        "name": "Application tier",
        "match_types": {"api", "service", "auth_service", "admin_panel", "worker"},
        "match_name_patterns": [
            r"\bservice\b", r"\bworker\b", r"\bbackend\b", r"\bapi\b",
            r"\bmicroservice\b", r"\bjob\b", r"\bcron\b",
        ],
    },
    {
        "name": "Data tier",
        "match_types": {"database", "datastore", "cache", "queue", "filesystem", "vector_db", "object_storage"},
        "match_name_patterns": [
            r"\bdatabase\b", r"\bdb\b", r"\bpostgres\b", r"\bmysql\b",
            r"\bmongo\b", r"\bredis\b", r"\bmemcache\b", r"\bcache\b",
            r"\bkafka\b", r"\brabbit\b", r"\bqueue\b",
            r"\bs3\b", r"\bblob\b", r"\bbucket\b", r"\bstorage\b",
            r"\bdatalake\b", r"\bwarehouse\b", r"\belastic\b",
        ],
    },
]


# Component types → severity rank for "what should be most isolated"
_PRIVATE_TYPES = {"database", "datastore", "cache", "queue", "filesystem"}


def _component_matches_boundary(component: dict, rule: dict) -> bool:
    ctype = (component.get("type") or "").lower()
    cname = (component.get("name") or "").lower()
    cdesc = (component.get("description") or "").lower()
    text = f"{cname} {cdesc}"

    if ctype in rule["match_types"]:
        return True
    for pattern in rule["match_name_patterns"]:
        if re.search(pattern, text):
            return True
    return False


def infer_trust_boundaries_heuristic(system: dict) -> list[dict]:
    """Group components by boundary using deterministic rules.

    Strategy:
      1. For each component, check rules in order. First match wins.
      2. Components that match nothing land in "Application tier" (default).
      3. Boundaries with zero components are dropped.
    """
    components = system.get("components", []) or []
    if not components:
        return []

    # Bucket every component into a boundary name
    buckets: dict[str, list[str]] = {}
    boundary_order: list[str] = []   # preserve rule order for stable output

    for c in components:
        cid = c.get("id")
        if not cid:
            continue
        matched = False
        for rule in _BOUNDARY_RULES:
            if _component_matches_boundary(c, rule):
                buckets.setdefault(rule["name"], []).append(cid)
                if rule["name"] not in boundary_order:
                    boundary_order.append(rule["name"])
                matched = True
                break
        if not matched:
            # Default bucket — call it "Application tier" since most unknowns
            # are application-level services
            default_name = "Application tier"
            buckets.setdefault(default_name, []).append(cid)
            if default_name not in boundary_order:
                boundary_order.append(default_name)

    # Build list of boundary dicts, in the rule-defined order
    boundaries = []
    for name in boundary_order:
        if not buckets.get(name):
            continue
        boundaries.append({
            "id": f"b_{re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')}",
            "name": name,
            "contains": buckets[name],
            "description": _BOUNDARY_DESCRIPTIONS.get(name, ""),
        })
    return boundaries


_BOUNDARY_DESCRIPTIONS = {
    "Internet": "Untrusted public network. End users and external entities live here.",
    "Third-party / Untrusted services":
        "External SaaS / vendor APIs. Treat their responses as untrusted input.",
    "DMZ (public-facing)":
        "Owned components exposed to the internet. Validate all incoming requests.",
    "Application tier":
        "Internal services running business logic. Should never be directly internet-accessible.",
    "Data tier":
        "Persistent stores. Highest blast radius — strict access control required.",
}


# ---------------------------------------------------------------------------
# LLM mode
# ---------------------------------------------------------------------------
def infer_trust_boundaries_llm(system: dict, source_text: str = "") -> list[dict] | None:
    """Use the configured LLM to reason about trust zones. Returns None on
    failure (caller should fall back to heuristic)."""
    from .llm import complete_text, llm_available, strip_fences
    if not llm_available():
        return None

    components = system.get("components", []) or []
    if not components:
        return []

    # Build a compact prompt
    comp_summary = [
        {
            "id": c.get("id"),
            "name": c.get("name"),
            "type": c.get("type"),
            "description": (c.get("description") or "")[:120],
        }
        for c in components
    ]

    prompt = (
        "You are a security architect. Group the following system components into "
        "trust boundaries based on network position, data sensitivity, ownership, "
        "and trust level.\n\n"
        f"Original system description:\n{source_text or '(not provided)'}\n\n"
        f"Components:\n{json.dumps(comp_summary, indent=2)}\n\n"
        "Return ONLY valid JSON in this exact structure (no markdown, no commentary):\n"
        "{\n"
        '  "boundaries": [\n'
        '    {"name": "Internet", "contains": ["component_id_1", ...], '
        '"description": "why these belong together"}\n'
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "1. Every component MUST appear in exactly ONE boundary.\n"
        "2. Use clear, conventional boundary names: Internet, DMZ, Application tier, "
        "Data tier, Third-party / Untrusted services, Internal admin, etc.\n"
        "3. External SaaS (Stripe, OpenAI, SendGrid, etc.) belong in 'Third-party'.\n"
        "4. Databases and caches belong in 'Data tier'.\n"
        "5. End users belong in 'Internet'.\n"
        "6. Be specific where it adds value (e.g. 'PCI scope', 'GDPR-restricted').\n"
    )

    try:
        raw = complete_text(prompt, max_tokens=2000)
        if not raw:
            return None
        raw = strip_fences(raw)

        parsed = json.loads(raw)
        boundaries_raw = parsed.get("boundaries", [])
        if not isinstance(boundaries_raw, list):
            return None

        # Validate + normalize
        valid_ids = {c["id"] for c in components if c.get("id")}
        seen_ids: set[str] = set()
        boundaries = []
        for b in boundaries_raw:
            if not isinstance(b, dict):
                continue
            name = (b.get("name") or "").strip()
            contains = b.get("contains", [])
            if not name or not isinstance(contains, list):
                continue
            # Filter to valid component IDs only
            valid_contained = [cid for cid in contains
                               if isinstance(cid, str) and cid in valid_ids and cid not in seen_ids]
            if not valid_contained:
                continue
            seen_ids.update(valid_contained)
            boundaries.append({
                "id": f"b_{re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')}_{uuid.uuid4().hex[:4]}",
                "name": name,
                "contains": valid_contained,
                "description": (b.get("description") or "")[:200],
            })

        # Any component the LLM forgot? Drop them into a default boundary
        # so we don't lose them
        unassigned = [c["id"] for c in components if c.get("id") and c["id"] not in seen_ids]
        if unassigned:
            boundaries.append({
                "id": f"b_unassigned_{uuid.uuid4().hex[:4]}",
                "name": "Unclassified",
                "contains": unassigned,
                "description": "Components the LLM did not place. Review manually.",
            })
        return boundaries

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def infer_trust_boundaries(system: dict, source_text: str = "",
                           use_llm: bool = False) -> list[dict]:
    """Return trust boundaries for the given system.

    If use_llm=True and ANTHROPIC_API_KEY is set, tries LLM first and falls
    back to heuristic on any failure. Otherwise heuristic only.
    """
    if use_llm:
        result = infer_trust_boundaries_llm(system, source_text=source_text)
        if result is not None and len(result) > 0:
            return result
    return infer_trust_boundaries_heuristic(system)
