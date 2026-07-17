"""Threat analyzer.

Takes a normalized system model:
{
  "name": "...",
  "description": "...",
  "components": [{"id","name","type","description","sensitivity"?}],
  "data_flows": [{"id","from","to","label","protocol","auth","encrypted","sensitivity"?}],
  "trust_boundaries": [{"id","name","contains":[component_id,...]}]
}

`sensitivity` (optional) is a data-classification tag — any truthy value such as
["pii","pci","phi","secrets"] — on a component or on a flow. It drives the
"handles_sensitive_data" evidence signal used by the privacy (LINDDUN) rules.

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
    "webapp":          ["web app", "website", "front-end", "frontend", "portal", "spa", "react app",
                        "next.js", "nextjs", "angular", "vue", "svelte", "nuxt"],
    "mobile_app":      ["mobile app", "android", "ios", "react native", "flutter"],
    "api":             ["api", "backend", "rest service", "graphql", "grpc", "microservice", "service",
                        "lambda", "cloud function", "serverless", "fastapi", "express", "flask",
                        "django", "spring", "rails", "gateway"],
    "auth_service":    ["auth", "oauth", "sso", "identity provider", "okta", "auth0", "cognito",
                        "keycloak", "clerk", "ldap", "saml", "firebase auth"],
    "admin_panel":     ["admin panel", "admin ui", "back-office", "back office"],
    "database":        ["database", "db", "postgres", "mysql", "mongodb", "dynamodb", "rds", "cassandra",
                        "cockroach", "mariadb", "sqlite", "mssql", "sql server", "oracle", "spanner",
                        "aurora", "neo4j", "influxdb", "timescale", "scylla"],
    "datastore":       ["s3", "blob storage", "object store", "data lake", "warehouse", "bigquery",
                        "snowflake", "elasticsearch", "opensearch", "clickhouse", "minio", "hdfs",
                        "ceph", "solr", "redshift"],
    "cache":           ["redis", "memcached", "cache", "hazelcast", "varnish"],
    "queue":           ["queue", "kafka", "rabbitmq", "sqs", "pubsub", "event bus", "nats",
                        "activemq", "kinesis", "service bus", "celery"],
    "filesystem":      ["filesystem", "file storage", "nfs"],
    "payment_service": ["stripe", "payment", "paypal", "billing", "square", "adyen", "razorpay", "braintree"],
}

# Cloud / infrastructure component types. These are valid everywhere a system is
# described (structured input, the DFD editor, diagram extraction) even though the
# free-text extractor above collapses most cloud tech into the generic types. They
# let users model cloud architectures explicitly (e.g. a Lambda, an S3 bucket, a WAF).
_EXTRA_TYPES = [
    "config", "service", "worker",
    "api_gateway", "load_balancer", "cdn", "waf",
    "object_storage", "data_warehouse", "vector_db",
    "serverless", "container", "kubernetes",
    "secrets_manager", "iam", "vpc", "monitoring", "notification_service",
    # Second wave — modern services & infra
    "llm", "identity_provider", "email_service", "sms_gateway", "dns",
    "bastion", "iot_device", "data_pipeline", "scheduler",
    "search_service", "service_mesh",
]

# Human-facing list of valid component types for the structured input mode.
VALID_COMPONENT_TYPES = list(_TYPE_KEYWORDS.keys()) + _EXTRA_TYPES

def extract_components_from_text(text: str) -> dict:
    """Best-effort extraction. Always good enough for a starting draft —
    user can edit in the UI before running analysis."""
    t = text.lower()
    components: list[dict] = []
    seen_types: set[str] = set()

    for ctype, keywords in _TYPE_KEYWORDS.items():
        for kw in keywords:
            # Longer keywords match as a prefix so common suffixed forms are caught
            # (e.g. "postgres" → "postgresql", "database" → "databases"); short ones
            # (api, db, s3) stay strict to avoid false positives.
            tail = r"\w*" if len(kw) >= 6 else r"\b"
            if re.search(r"\b" + re.escape(kw) + tail, t):
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


# ---------------------------------------------------------------------------
# Structured input — a precise, deterministic alternative to free-text.
# The user lists components ("Name : type") and flows ("A -> B : attrs"), so
# extraction is exact: no keyword guessing, no same-type collapse, real topology.
# ---------------------------------------------------------------------------
_PROTOCOLS = {"https", "http", "tcp", "udp", "grpc", "wss", "ws", "amqp", "mqtt", "sql", "tls", "ssh"}
_AUTHS = {"none", "session", "bearer", "jwt", "mtls", "api_key", "apikey", "credentials",
          "password", "oauth", "basic", "iam", "sso"}


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return s or "c"


def parse_structured_system(text: str) -> dict:
    """Parse a structured system description into a system model.

    Format (lines; '#' and blank lines ignored):
        Name : type                       -> a component
        From -> To : proto, auth, enc?    -> a data flow (attrs optional)

    Raises ValueError with a clear, line-referenced message on any problem so the
    UI can show the user exactly what to fix."""
    components: list[dict] = []
    by_name: dict[str, dict] = {}       # lowercased name -> component
    flow_lines: list[tuple[int, str]] = []
    valid_types = set(VALID_COMPONENT_TYPES)

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "->" in line:
            flow_lines.append((lineno, line))
            continue
        if ":" not in line:
            raise ValueError(f"Line {lineno}: \"{line}\" — expected 'Name : type' (a component) "
                             f"or 'A -> B' (a flow).")
        name, _, ctype = line.partition(":")
        name, ctype = name.strip(), ctype.strip().lower().replace(" ", "_")
        if not name:
            raise ValueError(f"Line {lineno}: missing a component name before ':'.")
        if ctype not in valid_types:
            raise ValueError(f"Line {lineno}: unknown type '{ctype}' for '{name}'. "
                             f"Valid types: {', '.join(sorted(valid_types))}.")
        if name.lower() in by_name:
            raise ValueError(f"Line {lineno}: duplicate component name '{name}'.")
        comp = {"id": f"c_{_slug(name)}_{len(components)}", "name": name, "type": ctype,
                "description": f"Declared component ({ctype})"}
        components.append(comp)
        by_name[name.lower()] = comp

    if not components:
        raise ValueError("No components found. Add at least one line like 'API : api'.")

    data_flows: list[dict] = []
    for lineno, line in flow_lines:
        endpoints, _, attrs = line.partition(":")
        src_name, _, dst_name = endpoints.partition("->")
        src_name, dst_name = src_name.strip(), dst_name.strip()
        src = by_name.get(src_name.lower())
        dst = by_name.get(dst_name.lower())
        if not src:
            raise ValueError(f"Line {lineno}: flow source '{src_name}' is not a declared component.")
        if not dst:
            raise ValueError(f"Line {lineno}: flow target '{dst_name}' is not a declared component.")
        protocol, auth, encrypted = "HTTPS", "none", True
        for tok in (t.strip().lower() for t in attrs.split(",") if t.strip()):
            if tok in _PROTOCOLS:
                protocol = "HTTPS" if tok == "https" else tok.upper()
            elif tok in _AUTHS:
                auth = tok
            elif tok in ("encrypted", "tls", "encrypt", "secure"):
                encrypted = True
            elif tok in ("plaintext", "unencrypted", "cleartext", "insecure", "no", "none_enc"):
                encrypted = False
        data_flows.append({
            "id": f"f_{len(data_flows)}", "from": src["id"], "to": dst["id"],
            "label": f"{src['name']} → {dst['name']}", "protocol": protocol,
            "auth": auth, "encrypted": encrypted,
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


def _dread_tier(total: int) -> str:
    """Bucket a DREAD total (5-50) into a decision-useful risk tier."""
    if total >= 40:
        return "Critical"
    if total >= 30:
        return "High"
    if total >= 20:
        return "Medium"
    return "Low"


# Zone-name hints reused for DREAD exposure classification (mirrors the notion in
# _untrusted_input_crossings): a component is "exposed" if it sits in a public/edge
# zone, or receives a flow from a less-trusted (or boundary-less) source.
_LESS_TRUSTED_ZONE_HINTS = ("dmz", "public", "edge", "front", "customer",
                            "partner", "external", "untrusted", "perimeter", "internet")


def _dread_context(system: dict) -> tuple[set, dict]:
    """Compute, once per analysis, the signals DREAD's axes depend on:
      - exposed_ids: components reachable from a less-trusted / public zone
      - blast_by_id: how many data flows touch each component (its degree)
    """
    components = system.get("components", []) or []
    flows = system.get("data_flows", []) or []
    boundaries = system.get("trust_boundaries", []) or []

    comp_to_boundary: dict[str, dict] = {}
    for b in boundaries:
        for cid in b.get("contains", []):
            comp_to_boundary[cid] = b

    def _less_trusted(b: dict | None) -> bool:
        if b is None:
            return True  # no boundary = external = untrusted
        return any(h in b["name"].lower() for h in _LESS_TRUSTED_ZONE_HINTS)

    exposed_ids: set = set()
    # Components living in a less-trusted zone are directly exposed.
    for c in components:
        if _less_trusted(comp_to_boundary.get(c["id"])):
            exposed_ids.add(c["id"])

    blast_by_id: dict[str, int] = {}
    for f in flows:
        src, dst = f.get("from"), f.get("to")
        for cid in (src, dst):
            if cid:
                blast_by_id[cid] = blast_by_id.get(cid, 0) + 1
        # A destination that receives input from a less-trusted source is exposed.
        if dst and _less_trusted(comp_to_boundary.get(src)):
            exposed_ids.add(dst)

    return exposed_ids, blast_by_id


# Component types that store/process regulated or otherwise sensitive data —
# raises the Damage axis independently of the threat's severity label.
_SENSITIVE_TYPES = {"database", "datastore", "payment_service", "auth_service", "filesystem",
                    "object_storage", "data_warehouse", "secrets_manager", "iam", "vector_db",
                    "identity_provider", "llm", "search_service"}
# Deterministic threat classes (work identically every attempt) — raises Reproducibility.
_DETERMINISTIC_HINTS = ("injection", "sql", "idor", "access control", "misconfig",
                        "default credential", "hardcoded", "unencrypted", "unauthenticated",
                        "missing authz", "mass assignment")
# Threat classes that advertise their own presence — raises Discoverability.
_SELF_ADVERTISING_HINTS = ("verbose error", "stack trace", "enumeration", "default credential",
                           "missing security header", "unencrypted", "information disclosure")


def _score_dread(threat: dict, component: dict, flow: dict | None, cross_boundary: bool = False,
                 *, exposure: bool | None = None, blast: int | None = None) -> dict:
    """DREAD risk score derived from *independent* signals rather than five copies
    of the severity label. Each axis reads a different property of the model:

      Damage          severity + sensitivity of the data the component holds
      Reproducibility whether the attack is deterministic / the flow is unauthenticated
      Exploitability  reachability from a less-trusted zone + missing transport encryption
      Affected users  blast radius (flow fan-in/out, cross-boundary, central component types)
      Discoverability public/edge exposure + self-advertising threat classes

    `exposure` (reachable from a less-trusted/public zone) and `blast` (number of
    flows touching the component) are optional context computed once per analysis;
    when omitted the function degrades to the local signals it can see. Returns
    ints 1-10 for D/R/E/A/D, a total (5-50), and a risk tier.
    """
    base = {"Critical": 9, "High": 7, "Medium": 5, "Low": 3, "Info": 2}.get(threat.get("severity"), 5)
    ctype = component.get("type", "")
    title_cat = f"{threat.get('title', '')} {threat.get('category', '')}".lower()
    auth = (flow.get("auth") if flow else "") or ""
    auth_low = auth.strip().lower()
    unauthenticated = auth_low in ("", "none", "n/a")
    strong_auth = auth_low in ("mtls", "mutual-tls", "client-cert")
    unencrypted = bool(flow) and not flow.get("encrypted", True)

    # Damage — what's at stake if it's exploited
    damage = base + (1 if ctype in _SENSITIVE_TYPES else 0)

    # Reproducibility — can an attacker repeat it reliably?
    reproducibility = base - 1
    if any(h in title_cat for h in _DETERMINISTIC_HINTS):
        reproducibility += 2
    if flow and unauthenticated:
        reproducibility += 1

    # Exploitability — how much stands between the attacker and the exploit
    exploitability = base
    if exposure:
        exploitability += 2
    if unencrypted:
        exploitability += 1
    if strong_auth:
        exploitability -= 2
    elif flow and unauthenticated:
        exploitability += 1

    # Affected users — blast radius
    affected = base if ctype in ("webapp", "api", "auth_service", "database") else base - 2
    if cross_boundary:
        affected += 2
    if blast:
        affected += min(3, blast // 2)

    # Discoverability — how visible the weakness is
    discoverability = base
    if exposure:
        discoverability += 2
    if unencrypted:
        discoverability += 1
    if any(h in title_cat for h in _SELF_ADVERTISING_HINTS):
        discoverability += 1

    vals = [max(1, min(10, v)) for v in
            (damage, reproducibility, exploitability, affected, discoverability)]
    total = sum(vals)
    return {
        "D_damage": vals[0],
        "R_reproducibility": vals[1],
        "E_exploitability": vals[2],
        "A_affected_users": vals[3],
        "D_discoverability": vals[4],
        "total": total,
        "tier": _dread_tier(total),
    }


# ---------------------------------------------------------------------------
# Applicability evidence
# Distinguishes threats the model *proves* apply ("evidenced") from generic
# component-type templates ("baseline"). Baseline threats are still emitted —
# reports de-emphasize them, never drop them — so recall is preserved.
# ---------------------------------------------------------------------------
_STORE_TYPES = {"database", "datastore", "filesystem", "cache", "queue",
                "object_storage", "data_warehouse", "vector_db", "secrets_manager",
                "search_service"}
_USER_TYPES = {"user", "external_entity"}


def _evidence_context(system: dict) -> dict:
    """Per-analysis signals used to decide whether a component-level threat is
    evidenced by the actual model or is just a type-based baseline check."""
    components = system.get("components", []) or []
    flows = system.get("data_flows", []) or []
    exposed, _blast = _dread_context(system)

    unencrypted_touch: set = set()
    for f in flows:
        if not f.get("encrypted", True):
            for cid in (f.get("from"), f.get("to")):
                if cid:
                    unencrypted_touch.add(cid)

    # Components reachable from a user / external entity by following flows.
    adj: dict[str, list] = {}
    for f in flows:
        adj.setdefault(f.get("from"), []).append(f.get("to"))
    user_reachable: set = set()
    stack = [c["id"] for c in components if c.get("type") in _USER_TYPES]
    while stack:
        for nxt in adj.get(stack.pop(), []):
            if nxt and nxt not in user_reachable:
                user_reachable.add(nxt)
                stack.append(nxt)

    # Data classification (Phase 2): a component "handles sensitive data" when it
    # is tagged `sensitivity` directly, or a flow it is on carries a `sensitivity`
    # tag. We track the *classes* per component (e.g. {"pii","phi"}) so compliance
    # evidence can be class-specific (phi->HIPAA, pii->GDPR/CCPA, pci->PCI-DSS).
    # Untagged models produce empty sets, so nothing regresses.
    sensitive_classes: dict[str, set] = {}

    def _tag(cid, value):
        if not cid or not value:
            return
        classes = value if isinstance(value, (list, tuple, set)) else [value]
        bucket = sensitive_classes.setdefault(cid, set())
        for cls in classes:
            bucket.add(str(cls).strip().lower())

    for c in components:
        _tag(c["id"], c.get("sensitivity"))
    for f in flows:
        if f.get("sensitivity"):
            _tag(f.get("from"), f.get("sensitivity"))
            _tag(f.get("to"), f.get("sensitivity"))

    sensitive_ids = set(sensitive_classes)

    return {"exposed": exposed, "unencrypted_touch": unencrypted_touch,
            "user_reachable": user_reachable, "sensitive_ids": sensitive_ids,
            "sensitive_classes": sensitive_classes}


# Named evidence signals a catalog rule can declare via its "evidence" field.
# Each maps to a check against the per-analysis context / component. This lets a
# rule state its precondition explicitly instead of relying on title keywords.
_EVIDENCE_SIGNALS = {
    "unencrypted_flow": lambda cid, ctype, ctx: cid in ctx["unencrypted_touch"],
    "exposed":          lambda cid, ctype, ctx: cid in ctx["exposed"],
    "user_reachable":   lambda cid, ctype, ctx: cid in ctx["user_reachable"],
    "is_store":         lambda cid, ctype, ctx: ctype in _STORE_TYPES,
    # Phase 2 — data classification. "handles_sensitive_data" is class-agnostic
    # (any tagged class); the class-specific signals drive class-appropriate
    # compliance evidence (phi->HIPAA, pii->GDPR/CCPA, pci->PCI-DSS).
    "handles_sensitive_data": lambda cid, ctype, ctx: cid in ctx.get("sensitive_ids", set()),
    "handles_pii":            lambda cid, ctype, ctx: "pii" in ctx.get("sensitive_classes", {}).get(cid, ()),
    "handles_phi":            lambda cid, ctype, ctx: "phi" in ctx.get("sensitive_classes", {}).get(cid, ()),
    "handles_pci":            lambda cid, ctype, ctx: "pci" in ctx.get("sensitive_classes", {}).get(cid, ()),
    "always":           lambda cid, ctype, ctx: True,
    "none":             lambda cid, ctype, ctx: False,
}


def _component_evidence(rule: dict, component: dict, ctx: dict) -> str:
    """"evidenced" if the model proves this component-level threat's precondition,
    else "baseline".

    A rule declares its precondition with an "evidence" field naming one of
    _EVIDENCE_SIGNALS. Every built-in catalog rule is annotated; a rule with no
    (or an unrecognized) signal — e.g. a user-defined custom rule — defaults to
    "baseline", so it is surfaced but not falsely promoted to evidenced."""
    check = _EVIDENCE_SIGNALS.get(rule.get("evidence"))
    if check is None:
        return "baseline"
    return "evidenced" if check(component.get("id"), component.get("type", ""), ctx) else "baseline"


# ---------------------------------------------------------------------------
# Attribute-driven threats — Microsoft Threat Modeling Tool style. Each element
# can declare security properties (answered yes/no/unknown, or a level) in the
# DFD editor; a "no" on a protective property (or a risky level) generates a
# specific, tailored threat. Rules fire ONLY on explicitly-answered properties,
# so models without attributes are unchanged until the user answers them.
# ---------------------------------------------------------------------------
# Property name -> (label, kind, options). kind: "yn" (yes/no) or "choice".
COMPONENT_ATTRIBUTES = {
    "sensitivity":         ("Data sensitivity", "choice", ["", "low", "medium", "high"]),
    "internet_facing":     ("Internet-facing", "yn", None),
    "authenticates_users": ("Authenticates callers", "yn", None),
    "enforces_authorization": ("Enforces authorization", "yn", None),
    "validates_input":     ("Validates input", "yn", None),
    "encodes_output":      ("Encodes output", "yn", None),
    "stores_credentials":  ("Stores credentials/secrets", "yn", None),
    "encrypted_at_rest":   ("Encrypted at rest", "yn", None),
    "has_backup":          ("Backed up", "yn", None),
    "logs_security_events": ("Logs security events", "yn", None),
    "multi_tenant":        ("Multi-tenant", "yn", None),
    "privilege_level":     ("Privilege level", "choice", ["", "low", "standard", "elevated"]),
    # Second wave
    "csrf_protection":     ("CSRF protection", "yn", None),
    "rate_limited":        ("Rate limited", "yn", None),
    "mfa":                 ("Multi-factor auth", "yn", None),
    "handles_pii":         ("Handles PII", "yn", None),
    "handles_phi":         ("Handles PHI (health)", "yn", None),
    "handles_pci":         ("Handles cardholder data", "yn", None),
    "verifies_code_integrity": ("Verifies code/artifact integrity", "yn", None),
    "removable_media":     ("On removable media", "yn", None),
    "secure_error_handling": ("Safe error handling", "yn", None),
}
FLOW_ATTRIBUTES = {
    "provides_integrity":  ("Provides integrity (signing/HMAC)", "yn", None),
    "validates_input":     ("Receiver validates input", "yn", None),
    # Second wave
    "replay_protection":   ("Replay protection (nonce/timestamp)", "yn", None),
    "validates_certificates": ("Validates TLS certificates", "yn", None),
}


def _yn_no(d: dict, k: str) -> bool:
    return str(d.get(k, "")).strip().lower() == "no"


def _yn_yes(d: dict, k: str) -> bool:
    return str(d.get(k, "")).strip().lower() == "yes"


def _attribute_threats(system: dict, methodology_key: str, comp_by_id: dict) -> list[dict]:
    name = METHODOLOGIES[methodology_key]["name"]
    out: list[dict] = []

    def emit(category, title, description, severity, comp, flow, mitigations):
        out.append({
            "id": f"t_{uuid.uuid4().hex[:8]}",
            "methodology": name,
            "category": category,
            "title": title,
            "description": description,
            "severity": severity,
            "component_id": comp["id"],
            "component_name": comp["name"],
            "component_type": comp.get("type", ""),
            "flow_id": (flow or {}).get("id"),
            "mitigations": mitigations,
            "source": "rule-based",
            "tier": "evidenced",
            "dread": _score_dread({"severity": severity}, comp, flow),
        })

    for c in system.get("components", []):
        is_store = c.get("type") in _STORE_TYPES
        sens = str(c.get("sensitivity", "")).strip().lower()
        priv = str(c.get("privilege_level", "")).strip().lower()

        if _yn_yes(c, "stores_credentials") and _yn_no(c, "encrypted_at_rest"):
            emit("Information Disclosure", f"Credentials stored without encryption at rest: {c['name']}",
                 "This element stores credentials/secrets but is not encrypted at rest. A disk, snapshot, or backup compromise exposes them directly.",
                 "Critical", c, None, ["Encrypt secrets at rest (KMS / envelope encryption)", "Use a dedicated secrets manager instead of a datastore", "Rotate any potentially exposed credentials"])
        if sens == "high" and _yn_no(c, "encrypted_at_rest"):
            emit("Information Disclosure", f"Sensitive data at rest is not encrypted: {c['name']}",
                 "High-sensitivity data is stored without encryption at rest, exposing it to storage-layer compromise.",
                 "High", c, None, ["Enable encryption at rest", "Restrict and audit data access", "Consider field-level encryption for the most sensitive fields"])
        if is_store and _yn_no(c, "has_backup"):
            emit("Denial of Service", f"No backup for data store: {c['name']}",
                 "This data store has no backup, so hardware failure, accidental deletion, or ransomware causes permanent data loss.",
                 "Medium", c, None, ["Configure automated backups", "Regularly test restores", "Keep backups in a separate trust boundary/account"])
        if _yn_yes(c, "internet_facing") and _yn_no(c, "validates_input"):
            emit("Tampering", f"Internet-facing element without input validation: {c['name']}",
                 "An internet-facing element that does not validate input is directly exposed to injection, SSRF, and deserialization attacks.",
                 "High", c, None, ["Validate and canonicalize all input", "Allow-list schema / length / charset", "Front with a WAF"])
        if _yn_no(c, "authenticates_users") and c.get("type") in ("api", "webapp", "auth_service", "admin_panel", "api_gateway"):
            emit("Spoofing", f"No authentication on a user-facing element: {c['name']}",
                 "This element accepts requests without authenticating the caller, allowing identity spoofing and anonymous abuse.",
                 "High", c, None, ["Require authentication (token / session / mTLS)", "Reject unauthenticated requests", "Rate-limit anonymous endpoints"])
        if _yn_no(c, "enforces_authorization"):
            emit("Elevation of Privilege", f"No authorization enforcement: {c['name']}",
                 "Without authorization checks, callers can reach resources they should not — broken access control (OWASP A01), including IDOR.",
                 "High", c, None, ["Enforce per-request authorization", "Deny by default", "Add object-level ownership checks"])
        if c.get("type") == "webapp" and _yn_no(c, "encodes_output"):
            emit("Tampering", f"Output not encoded (XSS risk): {c['name']}",
                 "A web element that does not encode output is vulnerable to cross-site scripting.",
                 "High", c, None, ["Context-aware output encoding", "Content-Security-Policy", "Rely on framework auto-escaping"])
        if _yn_no(c, "logs_security_events"):
            emit("Repudiation", f"No security-event logging: {c['name']}",
                 "Security-relevant actions are not logged, so abuse cannot be detected, investigated, or attributed.",
                 "Medium", c, None, ["Log authentication and privileged actions", "Ship logs to tamper-evident storage", "Alert on anomalies"])
        if priv == "elevated":
            emit("Elevation of Privilege", f"Runs at elevated privilege: {c['name']}",
                 "Running with elevated privilege maximizes blast radius if this element is compromised.",
                 "High", c, None, ["Apply least privilege", "Run as a non-root user / drop capabilities", "Sandbox or isolate the workload"])
        if _yn_yes(c, "multi_tenant") and _yn_no(c, "enforces_authorization"):
            emit("Elevation of Privilege", f"Multi-tenant without tenant isolation: {c['name']}",
                 "A multi-tenant element without authorization/tenant scoping allows cross-tenant data access.",
                 "High", c, None, ["Scope every query by tenant", "Enforce tenant checks server-side", "Test for cross-tenant IDOR"])

        # ---- Second wave ----
        if _yn_no(c, "csrf_protection"):
            emit("Tampering", f"No CSRF protection: {c['name']}",
                 "State-changing requests are not protected against cross-site request forgery, letting an attacker act as a logged-in user.",
                 "High", c, None, ["Use anti-CSRF tokens (synchronizer / double-submit)", "Set SameSite=strict/lax cookies", "Require re-auth for sensitive actions"])
        if _yn_no(c, "rate_limited"):
            emit("Denial of Service", f"No rate limiting: {c['name']}",
                 "Without rate limiting, this element is exposed to brute-force, credential-stuffing, and resource-exhaustion (DoS) attacks.",
                 "Medium", c, None, ["Rate-limit per client / IP / account", "Add exponential backoff and lockouts", "Front with a WAF / API gateway throttle"])
        if _yn_no(c, "mfa") and c.get("type") in ("auth_service", "identity_provider", "admin_panel"):
            emit("Spoofing", f"No multi-factor authentication: {c['name']}",
                 "Single-factor authentication is vulnerable to phishing, credential stuffing, and password reuse — a leading cause of account takeover.",
                 "High", c, None, ["Require MFA (TOTP / WebAuthn / passkeys)", "Enforce MFA for privileged accounts", "Detect and step-up on risky logins"])
        if _yn_yes(c, "handles_phi"):
            emit("Information Disclosure", f"Handles PHI — HIPAA obligations: {c['name']}",
                 "This element processes protected health information, bringing HIPAA requirements (encryption, access control, audit, BAA).",
                 "High", c, None, ["Encrypt PHI in transit and at rest", "Restrict access and keep audit trails", "Sign BAAs with processors; support breach notification"])
        if _yn_yes(c, "handles_pci"):
            emit("Information Disclosure", f"Handles cardholder data — PCI-DSS scope: {c['name']}",
                 "This element processes payment card data, placing it in PCI-DSS scope (segmentation, tokenization, key management).",
                 "High", c, None, ["Tokenize / avoid storing PAN", "Segment the cardholder-data environment", "Apply PCI-DSS controls and scope reduction"])
        if _yn_yes(c, "handles_pii"):
            emit("Information Disclosure", f"Handles PII — privacy obligations: {c['name']}",
                 "This element processes personal data, bringing privacy obligations (GDPR/CCPA: minimization, consent, deletion, breach reporting).",
                 "Medium", c, None, ["Minimize and classify PII", "Support data-subject rights (access/delete)", "Encrypt and restrict access"])
        if _yn_no(c, "verifies_code_integrity") and c.get("type") in ("serverless", "container", "kubernetes", "service", "worker"):
            emit("Tampering", f"Unverified code/artifact integrity: {c['name']}",
                 "Deploying unsigned/unverified images or artifacts allows supply-chain tampering — a malicious dependency or image runs with this element's privileges.",
                 "High", c, None, ["Sign and verify images/artifacts (cosign/Notary)", "Pin dependencies and verify checksums", "Scan images and enforce admission control"])
        if _yn_yes(c, "removable_media"):
            emit("Information Disclosure", f"Data on removable media: {c['name']}",
                 "Data stored on removable media can be physically removed, lost, or copied, bypassing network controls.",
                 "Medium", c, None, ["Encrypt removable media", "Restrict and log media use", "Prefer controlled, audited storage"])
        if _yn_no(c, "secure_error_handling"):
            emit("Information Disclosure", f"Verbose error handling may leak internals: {c['name']}",
                 "Unsafe error handling can expose stack traces, queries, or secrets to callers, aiding attackers.",
                 "Low", c, None, ["Return generic errors to clients", "Log details server-side only", "Disable debug modes in production"])

    for f in system.get("data_flows", []):
        dst = comp_by_id.get(f.get("to"))
        src = comp_by_id.get(f.get("from"))
        if not dst or not src:
            continue
        if _yn_no(f, "provides_integrity"):
            emit("Tampering", f"Flow without integrity protection: {src['name']} → {dst['name']}",
                 "This flow provides no integrity protection (no signing / HMAC), so a man-in-the-middle can alter messages undetected.",
                 "Medium", dst, f, ["Sign messages (HMAC / JWS)", "Use TLS with integrity guarantees", "Verify signatures at the receiver"])
        if _yn_no(f, "validates_input"):
            emit("Tampering", f"Receiver does not validate flow input: {src['name']} → {dst['name']}",
                 "The receiving element does not validate data arriving on this flow, enabling injection and tampering.",
                 "Medium", dst, f, ["Validate input at the receiver", "Allow-list schema and values", "Reject malformed messages"])
        if _yn_no(f, "replay_protection"):
            emit("Spoofing", f"No replay protection: {src['name']} → {dst['name']}",
                 "Without a nonce or timestamp, a captured request on this flow can be replayed to repeat a privileged action.",
                 "Medium", dst, f, ["Add a nonce or timestamp + window", "Use idempotency keys", "Bind requests to a single-use token"])
        if _yn_no(f, "validates_certificates"):
            emit("Spoofing", f"TLS certificates not validated: {src['name']} → {dst['name']}",
                 "Skipping certificate validation lets an attacker present a forged certificate and man-in-the-middle this flow.",
                 "High", dst, f, ["Validate the full certificate chain", "Pin certificates/public keys where practical", "Never disable verification in production"])

    return out


# ---------------------------------------------------------------------------
# Core rule-based analysis
# ---------------------------------------------------------------------------
def _rule_based_threats(system: dict, methodology_key: str) -> list[dict]:
    methodology = METHODOLOGIES[methodology_key]
    threats: list[dict] = []

    components = system.get("components", [])
    flows = system.get("data_flows", [])
    comp_by_id = {c["id"]: c for c in components}
    ev_ctx = _evidence_context(system)

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
                        "tier": _component_evidence(rule, component, ev_ctx),
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
                "tier": "evidenced",
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
                "tier": "evidenced",
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
                "tier": "evidenced",
                "cross_boundary": True,
                "src_zone": src_zone,
                "dst_zone": dst_zone,
                "dread": _score_dread({"severity": tmpl["severity"]}, dst, flow, cross_boundary=True),
            })

    # Attribute-driven threats (Microsoft Threat Modeling Tool style): security
    # properties the user set on elements in the DFD editor generate tailored
    # threats. Only fires on explicitly-answered properties, so attribute-less
    # models are unaffected until the user answers them and re-analyzes.
    threats.extend(_attribute_threats(system, methodology_key, comp_by_id))

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
def _llm_enhance(system: dict, methodology_key: str, base_threats: list[dict]) -> tuple[list[dict], str | None]:
    """If an LLM provider is configured, ask it to suggest additional
    context-specific threats.

    Returns (threats, error). ``error`` is None on success (including the valid
    case of zero additional threats); otherwise it's a short message explaining
    why the LLM step produced nothing, so the caller can report it honestly
    instead of falling back silently."""
    from .llm import complete_text, llm_available, last_error, strip_fences
    if not llm_available():
        return [], "no API key configured"

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
            return [], last_error() or "the model returned an empty response"
        parsed = json.loads(strip_fences(text))
    except Exception as e:
        print(f"[llm_enhance] failed: {e}")
        return [], f"could not parse the model response ({type(e).__name__})"

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
            "tier": "evidenced",
            "dread": _score_dread({"severity": t.get("severity", "Medium")}, comp, None),
        })
    return out, None


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

    llm_error: str | None = None  # first LLM-enhancement failure, if any

    for mkey in methodology_keys:
        if mkey not in METHODOLOGIES:
            continue
        # Only threat-modeling methodologies (STRIDE / PASTA / LINDDUN) enumerate
        # threats. "scoring" (DREAD — applied to every threat below) and "reference"
        # (OWASP Top 10 — cross-linked onto findings as references) never generate
        # rows of their own, so skip them here.
        if METHODOLOGIES[mkey].get("kind", "methodology") != "methodology":
            continue
        rule_threats = _rule_based_threats(system, mkey)
        all_threats.extend(rule_threats)

        if use_llm:
            llm_threats, err = _llm_enhance(system, mkey, rule_threats)
            all_threats.extend(llm_threats)
            if err and llm_error is None:
                llm_error = err

    # Per-analysis context for DREAD's independent axes: which components are
    # exposed to a less-trusted zone, and each component's blast radius (flow degree).
    exposed_ids, blast_by_id = _dread_context(system)

    # Enrich each threat with CVSS, CWE, and per-threat detail
    for t in all_threats:
        component = comp_by_id.get(t.get("component_id"))
        flow = flow_by_id.get(t.get("flow_id")) if t.get("flow_id") else None
        cb = bool(t.get("cross_boundary"))
        # Authoritative DREAD score, now that full system context is available.
        cid = t.get("component_id")
        t["dread"] = _score_dread(t, component or {}, flow, cross_boundary=cb,
                                  exposure=cid in exposed_ids, blast=blast_by_id.get(cid, 0))
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
        "by_tier": {"evidenced": 0, "baseline": 0},
        "rule_based": 0,
        "llm_enhanced": 0,
    }
    for t in all_threats:
        summary["by_severity"][t["severity"]] = summary["by_severity"].get(t["severity"], 0) + 1
        summary["by_category"][t["category"]] = summary["by_category"].get(t["category"], 0) + 1
        summary["by_component"][t["component_name"]] = summary["by_component"].get(t["component_name"], 0) + 1
        summary["by_methodology"][t["methodology"]] = summary["by_methodology"].get(t["methodology"], 0) + 1
        summary["by_tier"][t.get("tier", "baseline")] = summary["by_tier"].get(t.get("tier", "baseline"), 0) + 1
        if t["source"] == "rule-based":
            summary["rule_based"] += 1
        else:
            summary["llm_enhanced"] += 1

    # Honest, self-describing account of what the LLM step actually did, so the
    # UI and reports never silently claim "LLM: No" when the truth is "you asked
    # for it but the call failed" or "it ran but found nothing new".
    from .llm import llm_available as _llm_available, provider as _provider, text_model as _text_model_fn
    added = summary["llm_enhanced"]
    available = _llm_available()
    if not use_llm:
        state = "off"          # user did not ask for LLM enhancement
    elif not available:
        state = "unavailable"  # asked, but no API key configured
    elif llm_error:
        state = "error"        # asked, key present, but the call failed
    elif added > 0:
        state = "enhanced"     # asked and added N context-specific threats
    else:
        state = "no_additions"  # asked, ran cleanly, found nothing beyond rules
    llm_status = {
        "requested": use_llm,
        "available": available,
        "provider": _provider() if available else None,
        "model": _text_model_fn() if available else None,
        "added": added,
        "error": llm_error,
        "state": state,
    }

    return {
        "system": system,
        "threats": all_threats,
        "summary": summary,
        "untrusted_crossings": _untrusted_input_crossings(system, all_threats),
        # Only real methodologies belong in this list — reports render it as
        # "Methodologies:". DREAD (scoring) and OWASP (reference) are excluded even
        # if a caller passes them, so they can never be presented as methodologies.
        "methodologies_used": [k for k in methodology_keys
                               if METHODOLOGIES.get(k, {}).get("kind", "methodology") == "methodology"],
        # True only when the LLM actually contributed threats — kept for
        # backward compatibility with stored analyses and existing callers.
        "llm_used": use_llm and added > 0,
        "llm_status": llm_status,
    }


def summarize_llm_status(analysis: dict) -> str:
    """A short, honest human-readable label for the LLM step, used by reports.

    Falls back to the legacy ``llm_used`` boolean for analyses saved before
    ``llm_status`` existed, so old reports keep rendering."""
    st = analysis.get("llm_status")
    if not st:
        return "Yes" if analysis.get("llm_used") else "No"
    state = st.get("state")
    prov = st.get("provider") or "LLM"
    model = st.get("model") or ""
    tag = f"{prov} · {model}".strip(" ·") if model else prov
    if state == "off":
        return "No (not requested)"
    if state == "unavailable":
        return "No — requested, but no API key configured (rules-only)"
    if state == "error":
        return f"No — requested, but the {prov} call failed: {st.get('error')} (rules-only fallback)"
    if state == "no_additions":
        return f"Yes ({tag}) — no threats beyond the rule engine"
    if state == "enhanced":
        return f"Yes ({tag}) — added {st.get('added')} context-specific threat(s)"
    return "Yes" if analysis.get("llm_used") else "No"


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
