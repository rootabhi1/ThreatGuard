"""Model readiness — turn the generic "standard checks" pile into a productive,
shrinking to-do list.

A baseline (standard) threat exists because the model has not answered the security
property that would confirm or rule it out. This module computes, for each element,
which security questions *apply* (mirroring the DFD editor's contextual fields) and
which are still unanswered — plus an overall completeness score. Answering a question
either promotes a generic check into a precise finding (a risky answer) or clears it
(a safe answer suppresses it), so the noise collapses into signal as the score climbs.

The applicable-attribute logic here is the server-side twin of
`dfd_editor.js::componentAttrFields` — keep the two in sync.
"""
from __future__ import annotations

# --- Which security questions apply to which component type (mirror of the editor) ---
_STORE_TYPES = {"database", "datastore", "cache", "queue", "filesystem", "object_storage",
                "data_warehouse", "vector_db", "secrets_manager", "search_service",
                "agent_memory", "knowledge_base"}
_PROCESS_TYPES = {"api", "webapp", "mobile_app", "service", "worker", "serverless",
                  "auth_service", "admin_panel", "api_gateway", "container", "kubernetes",
                  "llm", "identity_provider", "data_pipeline", "scheduler", "service_mesh",
                  "bastion", "ai_agent", "agent_orchestrator", "llm_tool", "mcp_server",
                  "retriever", "guardrail"}
_DEPLOYABLE_TYPES = {"serverless", "container", "kubernetes", "service", "worker"}
_AGENTIC_ATTRS = {
    "ai_agent": ["autonomy_level", "tool_access", "human_in_the_loop", "prompt_injection_defense",
                 "output_validated", "sandboxed", "can_spawn_agents", "ingests_untrusted_content",
                 "output_filtering", "model_provenance", "system_prompt_hardened", "response_grounding"],
    "agent_orchestrator": ["autonomy_level", "human_in_the_loop", "can_spawn_agents", "output_validated",
                           "output_filtering", "system_prompt_hardened", "response_grounding"],
    "llm": ["ingests_untrusted_content", "prompt_injection_defense", "output_validated",
            "output_filtering", "model_provenance", "system_prompt_hardened", "response_grounding"],
    "llm_tool": ["tool_access", "sandboxed", "output_validated", "model_provenance"],
    "mcp_server": ["tool_access", "sandboxed", "model_provenance"],
    "retriever": ["content_source_trust", "ingests_untrusted_content", "output_filtering",
                  "embedding_access_control"],
    "knowledge_base": ["content_source_trust", "embedding_access_control"],
    "agent_memory": ["memory_scope"],
    "vector_db": ["memory_scope", "embedding_access_control"],
    "guardrail": ["output_validated"],
}
_COMPLIANCE = ["handles_pii", "handles_phi", "handles_pci"]
_COMMON = ["sensitivity", "internet_facing", "logs_security_events", *_COMPLIANCE]
_FLOW_ATTRS = ["provides_integrity", "validates_input", "replay_protection",
               "validates_certificates", "authorization"]

# Human phrasing for each question (component + flow attributes).
_LABELS = {
    "sensitivity": "Data sensitivity", "internet_facing": "Internet-facing?",
    "logs_security_events": "Logs security events?", "handles_pii": "Handles PII?",
    "handles_phi": "Handles PHI (health data)?", "handles_pci": "Handles cardholder data?",
    "stores_credentials": "Stores credentials/secrets?", "encrypted_at_rest": "Encrypted at rest?",
    "has_backup": "Backed up?", "removable_media": "On removable media?",
    "authenticates_users": "Authenticates callers?", "enforces_authorization": "Enforces authorization?",
    "validates_input": "Validates input?", "rate_limited": "Rate limited?",
    "secure_error_handling": "Safe error handling?", "privilege_level": "Privilege level",
    "multi_tenant": "Multi-tenant?", "encodes_output": "Encodes output?",
    "csrf_protection": "CSRF protection?", "mfa": "Multi-factor auth?",
    "verifies_code_integrity": "Verifies code/artifact integrity?",
    "autonomy_level": "Autonomy level", "tool_access": "Tool access",
    "human_in_the_loop": "Human-in-the-loop review?", "prompt_injection_defense": "Prompt-injection defense?",
    "output_validated": "Validates model output before use?", "sandboxed": "Runs sandboxed/isolated?",
    "can_spawn_agents": "Can spawn other agents?", "ingests_untrusted_content": "Ingests untrusted content?",
    "memory_scope": "Memory scope", "content_source_trust": "Content/grounding source",
    "output_filtering": "Filters/redacts sensitive data from responses?",
    "model_provenance": "Model/tool provenance", "system_prompt_hardened": "System prompt hardened (no secrets)?",
    "embedding_access_control": "Per-tenant access control on vector store?",
    "response_grounding": "Responses grounded in verified sources?",
    "provides_integrity": "Provides integrity (signing/HMAC)?", "replay_protection": "Replay protection?",
    "validates_certificates": "Validates TLS certificates?", "authorization": "Authorization model",
}
_YN = ["", "yes", "no"]
_CHOICES = {
    "sensitivity": ["", "low", "medium", "high"],
    "privilege_level": ["", "low", "standard", "elevated"],
    "autonomy_level": ["", "suggest", "act_with_approval", "autonomous"],
    "tool_access": ["", "none", "read", "write", "exec"],
    "memory_scope": ["", "session", "per_user", "cross_user", "cross_tenant"],
    "content_source_trust": ["", "curated", "user_uploaded", "web_scraped"],
    "model_provenance": ["", "first_party", "verified_vendor", "community_hub", "unknown"],
    "authorization": ["", "none", "rbac", "abac", "rebac", "acl", "oauth_scopes", "policy_engine"],
}


def applicable_component_attrs(ctype: str) -> list[str]:
    """Security questions relevant to a component of this type (editor parity)."""
    agentic = _AGENTIC_ATTRS.get(ctype, [])
    if ctype in _STORE_TYPES:
        return [*_COMMON, "stores_credentials", "encrypted_at_rest", "has_backup", "removable_media", *agentic]
    if ctype in _PROCESS_TYPES:
        f = [*_COMMON, "authenticates_users", "enforces_authorization", "validates_input",
             "rate_limited", "secure_error_handling", "privilege_level", "multi_tenant"]
        if ctype == "webapp":
            f += ["encodes_output", "csrf_protection"]
        if ctype in ("api", "api_gateway"):
            f += ["csrf_protection"]
        if ctype in ("auth_service", "identity_provider", "admin_panel"):
            f += ["mfa"]
        if ctype in _DEPLOYABLE_TYPES:
            f += ["verifies_code_integrity"]
        return [*f, *agentic]
    return [*_COMMON, *agentic]


def _answered(value) -> bool:
    """A property counts as answered when it holds a real, non-empty value."""
    if value is None:
        return False
    if isinstance(value, (list, tuple, set)):
        return len([v for v in value if str(v).strip()]) > 0
    return str(value).strip().lower() not in ("", "unknown", "n/a")


def _kind(attr: str) -> dict:
    if attr in _CHOICES:
        return {"kind": "choice", "options": _CHOICES[attr]}
    return {"kind": "yn", "options": _YN}


def compute_readiness(system: dict) -> dict:
    """Return the completeness score and the list of unanswered security questions
    (open questions) across components and flows, so the UI can render a checklist
    and a readiness meter. Deduped compliance questions (PII/PHI/PCI) are dropped to
    a single 'handles_pii' prompt per element to avoid nagging."""
    components = system.get("components", []) or []
    flows = system.get("data_flows", []) or []

    applicable = 0
    answered = 0
    questions: list[dict] = []

    for c in components:
        ctype = c.get("type", "")
        for attr in dict.fromkeys(applicable_component_attrs(ctype)):  # dedupe, keep order
            applicable += 1
            if _answered(c.get(attr)):
                answered += 1
            else:
                questions.append({
                    "scope": "component", "target_id": c.get("id"),
                    "target_name": c.get("name", c.get("id", "?")), "target_type": ctype,
                    "attr": attr, "label": _LABELS.get(attr, attr.replace("_", " ").title()),
                    **_kind(attr),
                })

    for f in flows:
        src = next((c.get("name") for c in components if c.get("id") == f.get("from")), f.get("from"))
        dst = next((c.get("name") for c in components if c.get("id") == f.get("to")), f.get("to"))
        for attr in _FLOW_ATTRS:
            applicable += 1
            if _answered(f.get(attr)):
                answered += 1
            else:
                questions.append({
                    "scope": "flow", "target_id": f.get("id"),
                    "target_name": f"{src} → {dst}", "target_type": "flow",
                    "attr": attr, "label": _LABELS.get(attr, attr.replace("_", " ").title()),
                    **_kind(attr),
                })

    score = round(100 * answered / applicable) if applicable else 100
    return {
        "score": score,
        "answered": answered,
        "applicable": applicable,
        "open_count": len(questions),
        # Cap the surfaced list so a huge model doesn't produce a wall of questions;
        # the count above still reflects the true total.
        "questions": questions[:60],
    }
