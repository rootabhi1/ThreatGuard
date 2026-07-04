"""Per-threat detail enrichment.

Each threat gets:
  - location: where in the system the threat lives, in plain English
  - attack_scenario: how an attacker would exploit it, as a numbered story
  - specific_mitigations: concrete, actionable controls (not generic advice)
  - references: links to CWE, OWASP, methodology docs

Rule-based by default. If ANTHROPIC_API_KEY is set AND `use_llm=True` in the
analyze call, we also enrich the attack_scenario with Claude.
"""
from __future__ import annotations
import os
import json


# ---------------------------------------------------------------------------
# References — methodology / OWASP cross-links
# ---------------------------------------------------------------------------
METHODOLOGY_LINKS = {
    "STRIDE":  "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats",
    "DREAD":   "https://en.wikipedia.org/wiki/DREAD_(risk_assessment_model)",
    "LINDDUN": "https://linddun.org/",
    "PASTA":   "https://owasp.org/www-pdf-archive/PASTA-Pre-Production-Threat-Modeling.pdf",
}

OWASP_LINKS = {
    "spoofing":              ("A07:2021 — Identification and Authentication Failures", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    "tampering":             ("A03:2021 — Injection",                                   "https://owasp.org/Top10/A03_2021-Injection/"),
    "repudiation":           ("A09:2021 — Security Logging and Monitoring Failures",    "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    "information disclosure":("A02:2021 — Cryptographic Failures",                      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "disclosure":            ("A02:2021 — Cryptographic Failures",                      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "denial of service":     ("A05:2021 — Security Misconfiguration",                   "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "denial":                ("A05:2021 — Security Misconfiguration",                   "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "elevation":             ("A01:2021 — Broken Access Control",                       "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "privilege":             ("A01:2021 — Broken Access Control",                       "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
}


# ---------------------------------------------------------------------------
# Location string — where exactly in the system the threat lives
# ---------------------------------------------------------------------------
def _location(threat: dict, components: list[dict], flows: list[dict]) -> str:
    comp_by_id = {c["id"]: c for c in components}
    flow_id = threat.get("flow_id")
    cid = threat.get("component_id")
    flow = next((f for f in flows if f["id"] == flow_id), None) if flow_id else None
    component = comp_by_id.get(cid)

    if flow and component:
        src = comp_by_id.get(flow["from"], {})
        dst = comp_by_id.get(flow["to"], {})
        zone_info = ""
        if threat.get("cross_boundary"):
            zone_info = f", crossing the trust boundary from `{threat.get('src_zone','External')}` into `{threat.get('dst_zone','External')}`"
        return (f"On the data flow **{src.get('name','?')} → {dst.get('name','?')}** "
                f"(label: *{flow.get('label','—')}*, protocol: {flow.get('protocol','unknown')}, "
                f"auth: {flow.get('auth') or 'none'}, encrypted: {'yes' if flow.get('encrypted') else 'no'})"
                f"{zone_info}. The receiving component is **{component.get('name','?')}** "
                f"(`{component.get('type','')}`).")
    if component:
        zone = ""
        for b in (threat.get("_boundaries") or []):
            zone = f", in trust zone **{b['name']}**"
        return (f"Within component **{component.get('name','?')}** "
                f"(`{component.get('type','')}`){zone}.")
    return "Location unavailable."


# ---------------------------------------------------------------------------
# Attack scenario — how an attacker would exploit it
# ---------------------------------------------------------------------------
# Pattern lookup: regex-ish matching on title + category to produce a 3–4 step scenario.

def _attack_scenario(threat: dict, component: dict, flow: dict | None) -> list[str]:
    title = (threat.get("title") or "").lower()
    cat = (threat.get("category") or "").lower()
    ctype = (component or {}).get("type", "")
    cname = (component or {}).get("name", "the component")

    # Boundary-crossing
    if "trust-boundary crossing without strong authn" in title:
        return [
            f"Attacker positions themselves on the network path between source and destination, or compromises an upstream component in the source zone.",
            f"Crafts requests with forged or replayed identity claims (cookies, tokens, IP-based trust).",
            f"{cname} accepts the request because identity is not re-verified at the boundary, treating the upstream zone as trusted.",
            f"Attacker can now perform actions as the impersonated principal across the boundary.",
        ]
    if "cross-boundary input not validated" in title:
        return [
            f"Attacker compromises a less-trusted upstream zone or directly sends malformed input to {cname}.",
            f"Sends payloads with unexpected types, lengths, or special characters (e.g. SQL meta-chars, NUL bytes, control sequences).",
            f"{cname} processes the input under the assumption that the upstream zone has already validated it — but the boundary changes the security context.",
            f"Injection, deserialization flaws, or buffer issues trigger; attacker pivots into {cname} or the zone behind it.",
        ]
    if "cross-boundary data exposure" in title:
        return [
            f"Attacker observes traffic leaving the source zone, or compromises a component in the destination zone.",
            f"The destination zone receives more data than it strictly needs (over-fetching, verbose error responses, full record dumps).",
            f"Attacker harvests sensitive fields (PII, secrets, internal IDs) that should never have left the source zone.",
            f"Data is exfiltrated, sold, or used to plan a deeper attack on the originating zone.",
        ]
    if "privilege transit across boundary" in title:
        return [
            f"Attacker compromises a low-privilege component in zone `{threat.get('src_zone','source')}`.",
            f"Issues requests to {cname} that get re-executed with the receiver's higher privileges (classic confused-deputy).",
            f"Because authorization is checked once at request entry but not per-action against the originating caller, the attacker effectively becomes a privileged actor in `{threat.get('dst_zone','destination')}`.",
            f"Attacker performs actions far beyond the original principal's permissions.",
        ]
    # Per-flow generic
    if "unencrypted flow" in title:
        return [
            f"Attacker gains read access to the network path (sniffing on shared LAN, compromised router, hostile cloud tenant, malicious admin).",
            f"Captures cleartext traffic on the {flow.get('protocol','unknown') if flow else 'unknown'} channel.",
            f"Extracts credentials, session tokens, PII, or business secrets from packet captures.",
            f"Uses the credentials to impersonate {cname} or the calling component, or sells/leaks the captured data.",
        ]
    if "unauthenticated flow" in title:
        return [
            f"Attacker discovers the endpoint at {cname} (port scan, leaked config, error messages, or DNS enumeration).",
            f"Sends requests directly without any credentials, since the flow does not require authentication.",
            f"{cname} processes the request as if it came from a trusted caller and returns data or executes the action.",
            f"Attacker enumerates data, modifies records, or chains to other internal services from this entry point.",
        ]
    # Component-type-driven scenarios for general STRIDE / LINDDUN / PASTA
    if "spoofing" in cat:
        if ctype in ("user", "external_entity"):
            return [
                f"Attacker obtains valid credentials via phishing, credential stuffing, or a third-party breach.",
                f"Logs in as the legitimate user/entity at {cname}.",
                f"Performs actions indistinguishable from the real user (auth events look normal).",
                f"Damage scales with the impersonated user's permissions; admin accounts cause the most harm.",
            ]
        return [
            f"Attacker locates {cname}'s identity claim mechanism (token format, header name, signing key handling).",
            f"Forges or replays a token to assert another principal's identity.",
            f"{cname} accepts the claim because verification is missing or weak (e.g., signature not checked, expired tokens accepted, no audience validation).",
            f"Attacker acts as the spoofed principal — reading data, triggering workflows, or pivoting to internal services.",
        ]
    if "tampering" in cat:
        return [
            f"Attacker reaches an input vector exposed by {cname} (request body, query string, message queue payload, persisted state).",
            f"Submits malformed input designed to alter the program's logic or stored data (injection, parameter tampering, deserialization gadgets).",
            f"{cname} processes the input without strict validation, and the malicious change takes effect.",
            f"Tampered data is persisted, executed, or relayed downstream — corrupting integrity beyond the original entry point.",
        ]
    if "repudiation" in cat:
        return [
            f"User performs a sensitive action through {cname} (a transfer, a permission change, a deletion).",
            f"Audit logs are absent, incomplete, or modifiable by the same principal who performed the action.",
            f"User later denies having performed the action, or an attacker covers their tracks.",
            f"Without tamper-evident logs, neither responsible party can be identified — leading to fraud, dispute, or regulatory exposure.",
        ]
    if "information disclosure" in cat or "disclosure" in cat:
        return [
            f"Attacker reaches {cname} via a legitimate or guessable channel.",
            f"Triggers an error, edge case, or verbose endpoint that returns more information than necessary (stack traces, internal IDs, debug data, full PII fields).",
            f"Aggregates leaked information from multiple requests to build a profile of the system or its users.",
            f"Uses the harvested information to plan a targeted attack, reset accounts, or commit fraud.",
        ]
    if "denial" in cat:
        return [
            f"Attacker identifies a costly operation in {cname} (regex matching, file generation, expensive query, large allocation).",
            f"Issues many concurrent requests targeting that operation, or a single request with pathological input.",
            f"{cname}'s resources (CPU, memory, connections, disk) saturate or exhaust.",
            f"Legitimate users can no longer reach {cname}; cascading failure may take down dependents.",
        ]
    if "elevation" in cat or "privilege" in cat:
        return [
            f"Attacker authenticates to {cname} as a low-privilege user, or reaches an unauthenticated entry point.",
            f"Identifies an authorization gap — a function that doesn't re-check the caller's role, an IDOR-style URL, an admin endpoint with weak gating.",
            f"Issues requests to that gap, gaining access to data or actions reserved for higher-privilege roles.",
            f"Now operating with elevated privilege, attacker can pivot to other components, exfiltrate data, or persist access.",
        ]
    if "linkability" in cat or "identifiability" in cat:
        return [
            f"Attacker collects records emitted by {cname} (logs, events, telemetry, public outputs).",
            f"Uses quasi-identifiers (timestamps, IPs, device fingerprints, behavioral patterns) to link multiple records to the same individual.",
            f"Builds a behavior profile that reveals identity even though no single record contains an explicit identifier.",
            f"Privacy violation — re-identification, surveillance, or unauthorized profiling.",
        ]
    # Fallback generic
    return [
        f"Attacker probes {cname} via reachable inputs.",
        f"Identifies the weakness named by this threat ({threat.get('category','—')}).",
        f"Crafts an exploit specific to the affected component type ({ctype}).",
        f"Successful exploitation leads to the impact described — loss of confidentiality, integrity, availability, or privacy.",
    ]


# ---------------------------------------------------------------------------
# Specific mitigations — concrete controls, not generic platitudes
# ---------------------------------------------------------------------------
def _specific_mitigations(threat: dict, component: dict, flow: dict | None) -> list[dict]:
    """Each mitigation is {action, detail, control_type}.
    control_type ∈ preventive / detective / corrective / deterrent.
    """
    title = (threat.get("title") or "").lower()
    cat = (threat.get("category") or "").lower()
    ctype = (component or {}).get("type", "")
    out: list[dict] = []

    if "trust-boundary crossing without strong authn" in title:
        out += [
            {"action": "Re-authenticate at the boundary",
             "detail": "Require a fresh, audience-bound credential at the receiver. Do not infer identity from network position, source IP, or upstream session.",
             "control_type": "preventive"},
            {"action": "Use mutual TLS or signed tokens with audience claims",
             "detail": f"For service-to-service calls into {component.get('name','this component')}, terminate mTLS at the boundary and reject any caller without a valid client cert. For human-driven flows, use OAuth2 / OIDC with audience and issuer validation.",
             "control_type": "preventive"},
            {"action": "Log every cross-boundary auth decision",
             "detail": "Emit an authentication event (success and failure) tagged with both source and destination zone. Forward to SIEM with retention ≥ 90 days.",
             "control_type": "detective"},
        ]
    elif "cross-boundary input not validated" in title:
        out += [
            {"action": "Validate against an allow-list schema at the boundary",
             "detail": "Define an explicit schema (JSON Schema, Protobuf, OpenAPI) for every accepted message at this boundary. Reject anything that doesn't match — type, length, charset, enum values, nested depth.",
             "control_type": "preventive"},
            {"action": "Canonicalize before validation",
             "detail": "Decode URL-encoding, Unicode normalization (NFC), trim whitespace, and resolve relative paths before validating. Avoid double-decoding bypasses.",
             "control_type": "preventive"},
            {"action": "Apply context-specific output encoding",
             "detail": f"Whatever {component.get('name','this component')} does with the input — SQL: parameterized queries, HTML: contextual escaping, OS commands: avoid shell, use exec arrays, LDAP: escape filter chars.",
             "control_type": "preventive"},
        ]
    elif "cross-boundary data exposure" in title:
        out += [
            {"action": "Enforce minimum-data-needed at the egress point",
             "detail": "Whitelist exactly which fields leave the source zone. Strip everything else server-side before serialization.",
             "control_type": "preventive"},
            {"action": "Tokenize or redact sensitive fields",
             "detail": "Replace PII / PCI / PHI fields with reversible tokens or one-way hashes when the destination zone doesn't need the cleartext value.",
             "control_type": "preventive"},
            {"action": "Log cross-boundary data flows for review",
             "detail": "Sample-log the field set crossing this boundary (not the values) so DLP and privacy reviews can audit what's egressing.",
             "control_type": "detective"},
        ]
    elif "privilege transit" in title:
        out += [
            {"action": "Use scoped, short-lived delegation tokens",
             "detail": f"When {component.get('name','this component')} acts on behalf of a caller, attach a delegation token with the caller's identity, scope (action allow-list), and ≤ 5-min TTL.",
             "control_type": "preventive"},
            {"action": "Authorize per-action against the originating caller",
             "detail": "Don't rely on ambient authority of the receiver. Each action checks: (a) the delegation token is valid, (b) the original caller has permission for this specific action, (c) the action is within scope.",
             "control_type": "preventive"},
            {"action": "Audit each privilege transit",
             "detail": "Log: original caller → delegating component → action performed. Make this queryable for incident response.",
             "control_type": "detective"},
        ]
    elif "unencrypted flow" in title:
        proto = (flow or {}).get("protocol", "this protocol")
        out += [
            {"action": "Enable TLS 1.3 (or 1.2 with strong ciphers) on the flow",
             "detail": f"Replace plain {proto} with its TLS variant. For databases use TLS-enabled drivers; for queues like AMQP/Kafka, configure broker certs and require client TLS.",
             "control_type": "preventive"},
            {"action": "Enforce certificate validation",
             "detail": "Verify hostname, validate the chain to a known CA, pin certificates or use a private CA for internal services. Disable cipher fallbacks to NULL/EXPORT/RC4.",
             "control_type": "preventive"},
            {"action": "Scan for cleartext fallbacks",
             "detail": "Add a network-policy / NetworkPolicy / security-group rule that drops any traffic on the cleartext port. Alert if it ever fires.",
             "control_type": "detective"},
        ]
    elif "unauthenticated flow" in title:
        out += [
            {"action": "Require an authentication mechanism on every external-facing flow",
             "detail": "Bearer tokens (OAuth2/OIDC) for human-driven calls, mutual TLS or signed JWT for service-to-service. Block requests that arrive without credentials at the gateway, before they reach the application.",
             "control_type": "preventive"},
            {"action": "Reject anonymous traffic at the receiver as well",
             "detail": "Defense in depth: even if the gateway rule fails, the receiving component should reject any request lacking a valid principal.",
             "control_type": "preventive"},
            {"action": "Rate-limit unauthenticated probes",
             "detail": "Apply a low-tolerance rate limit to requests that lack credentials (5/min per source IP) and alert on sustained failures.",
             "control_type": "detective"},
        ]
    elif "spoofing" in cat:
        out += [
            {"action": "Validate token signatures with explicit algorithm allow-listing",
             "detail": "Reject 'alg: none', reject HS256 when expecting RS256. Use a vetted JWT library; never hand-roll verification.",
             "control_type": "preventive"},
            {"action": "Enforce audience and issuer claims",
             "detail": "Every token must declare which service it's intended for. Reject tokens whose audience doesn't match this component.",
             "control_type": "preventive"},
            {"action": "Bind tokens to a session or device",
             "detail": "Use mTLS-bound tokens, DPoP, or token binding to prevent replay if a token is captured.",
             "control_type": "preventive"},
        ]
    elif "tampering" in cat:
        out += [
            {"action": "Schema-validate and parameterize all inputs",
             "detail": "JSON Schema / OpenAPI validation at API edges; parameterized queries / prepared statements for SQL; ORM-level validators on persisted models.",
             "control_type": "preventive"},
            {"action": "Sign and verify integrity-critical messages",
             "detail": "For commands or state mutations, attach an HMAC or signature so downstream consumers can detect tampering in transit or at rest.",
             "control_type": "preventive"},
            {"action": "Use append-only / write-once stores for audit-critical data",
             "detail": "Where data must not be silently changed, write to an append-only log (e.g., immutable S3 bucket, CloudTrail-like store) and reconcile against the mutable copy.",
             "control_type": "detective"},
        ]
    elif "repudiation" in cat:
        out += [
            {"action": "Emit tamper-evident audit logs",
             "detail": "Sign log entries (HMAC chain, hash-linked) so insertion or deletion is detectable. Forward to a separate, append-only system the action's principal cannot administer.",
             "control_type": "detective"},
            {"action": "Capture sufficient detail per audit event",
             "detail": "Who (authenticated principal, not just session ID), what (specific action and target), when (UTC, monotonic-clock-corroborated), where (source IP, request ID), why (correlated to the upstream business event).",
             "control_type": "detective"},
            {"action": "Periodic log integrity verification",
             "detail": "Schedule daily integrity checks on the audit log chain. Alert on any gap.",
             "control_type": "detective"},
        ]
    elif "information disclosure" in cat or "disclosure" in cat:
        out += [
            {"action": "Apply field-level access control on responses",
             "detail": "The data layer enforces what the calling principal is allowed to see. Don't rely on the UI to hide fields.",
             "control_type": "preventive"},
            {"action": "Strip debug detail from error responses",
             "detail": "Production responses return a stable error code and a correlation ID. Stack traces, SQL errors, and internal IDs go to logs only.",
             "control_type": "preventive"},
            {"action": "Encrypt data at rest with key separation",
             "detail": f"For {ctype or 'this component'}, enable storage-level encryption with a CMK distinct from the encryption-at-rest key for adjacent stores. Rotate annually.",
             "control_type": "preventive"},
        ]
    elif "denial" in cat:
        out += [
            {"action": "Apply input limits at the edge",
             "detail": "Maximum request size, body depth, array length, and string length. Reject early — before parsing or business logic runs.",
             "control_type": "preventive"},
            {"action": "Rate-limit per principal and per resource",
             "detail": "Token bucket per authenticated user AND per costly endpoint. Adaptive throttling on saturation.",
             "control_type": "preventive"},
            {"action": "Set hard timeouts on outbound calls",
             "detail": "No call (DB, downstream service, third-party API) should be able to hang the request handler indefinitely. Use circuit breakers and bulkheads.",
             "control_type": "corrective"},
        ]
    elif "elevation" in cat or "privilege" in cat:
        out += [
            {"action": "Re-authorize on every action, not just at session start",
             "detail": "Every privileged endpoint checks the current principal's roles/permissions for the specific resource being acted on. No 'logged in = allowed'.",
             "control_type": "preventive"},
            {"action": "Apply least-privilege to service identities",
             "detail": f"The IAM/role attached to {component.get('name','this component')} should grant only the actions it actually performs. Audit IAM grants quarterly.",
             "control_type": "preventive"},
            {"action": "Detect anomalous privilege use",
             "detail": "Alert when a principal performs an action they have not performed in the trailing 90 days, or when admin-tier actions originate from non-admin networks.",
             "control_type": "detective"},
        ]
    else:
        out += [
            {"action": "Apply defense-in-depth controls",
             "detail": f"Layer authentication, authorization, validation, and monitoring around {component.get('name','this component')}. Review applicability of OWASP ASVS controls for {ctype} components.",
             "control_type": "preventive"},
            {"action": "Add monitoring for the threat indicators",
             "detail": "Define detection signals for this threat and forward to your SIEM. Set thresholds based on baseline traffic.",
             "control_type": "detective"},
        ]
    return out


# ---------------------------------------------------------------------------
# Optional LLM enrichment for the attack scenario
# ---------------------------------------------------------------------------
def _llm_enrich_scenario(threat: dict, component: dict, system_name: str) -> list[str] | None:
    """If an LLM provider is configured, ask it for a more specific 4-step attack
    scenario tailored to this system. Returns None on failure."""
    from .llm import complete_text, llm_available, strip_fences
    if not llm_available():
        return None
    try:
        prompt = (
            f"You are a security engineer writing a threat model. Given this threat in the system "
            f"'{system_name}', write a concise 4-step attack scenario as a JSON array of 4 strings. "
            f"Be specific to the component type and threat title. Don't repeat the threat description.\n\n"
            f"Threat: {threat.get('title')}\n"
            f"Category: {threat.get('category')}\n"
            f"Component: {component.get('name','?')} ({component.get('type','?')})\n"
            f"Cross-boundary: {threat.get('cross_boundary', False)}\n"
            f"Description: {threat.get('description','')}\n\n"
            f"Respond with ONLY a JSON array of 4 strings, no other text."
        )
        text = complete_text(prompt, max_tokens=600)
        if not text:
            return None
        scenario = json.loads(strip_fences(text))
        if isinstance(scenario, list) and len(scenario) >= 3:
            return [str(s) for s in scenario][:5]
    except Exception as e:
        # Silent failure — fall back to rule-based scenario
        print(f"[detail-llm] enrichment failed: {e}")
    return None


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def enrich_threat_with_detail(threat: dict, component: dict, flow: dict | None,
                              components: list[dict], flows: list[dict],
                              system_name: str = "", use_llm: bool = False) -> dict:
    """Add location, attack_scenario, specific_mitigations, references in-place."""
    threat["location"] = _location(threat, components, flows)
    scenario = None
    if use_llm:
        scenario = _llm_enrich_scenario(threat, component or {}, system_name)
    if scenario is None:
        scenario = _attack_scenario(threat, component or {}, flow)
    threat["attack_scenario"] = scenario
    threat["specific_mitigations"] = _specific_mitigations(threat, component or {}, flow)

    # References
    refs = []
    cat_low = (threat.get("category") or "").lower()
    for key, (label, url) in OWASP_LINKS.items():
        if key in cat_low:
            refs.append({"label": label, "url": url})
            break
    methodology = (threat.get("methodology") or "").upper()
    for mkey, url in METHODOLOGY_LINKS.items():
        if mkey in methodology:
            refs.append({"label": f"{mkey} reference", "url": url})
            break
    if threat.get("cwe"):
        refs.append({"label": f"{threat['cwe']['id']} — {threat['cwe']['name']}",
                     "url": threat["cwe"]["url"]})
    threat["references"] = refs
    return threat
