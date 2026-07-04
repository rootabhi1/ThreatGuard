"""diagram_extractor.py — Extract system components from an uploaded architecture diagram.

Uses Claude vision API to identify components, data flows, and trust boundaries
from architecture diagrams (PNG/JPG/WebP).
"""
from __future__ import annotations
import base64
import json
import os
import re
import uuid


def extract_from_diagram(image_bytes: bytes, media_type: str, description: str = "") -> dict:
    """Analyze an architecture diagram image and return a system model.
    
    Falls back to a stub if no LLM provider is configured.
    """
    from .llm import complete_vision, llm_available, strip_fences
    if not llm_available():
        return _stub_result(description)

    extra = f"\nAdditional context from user: {description}" if description.strip() else ""

    prompt = f"""You are an expert security architect analyzing an architecture diagram.
Carefully examine this diagram and extract a complete system model for threat modeling.{extra}

Identify:
1. All components (services, databases, users, external systems, caches, queues, etc.)
2. Data flows between components (protocol, whether encrypted, authentication type)
3. Trust boundaries (zones like Public Internet, DMZ, Internal Network, Database Tier, etc.)

Return ONLY valid JSON — no prose, no markdown fences. Use this exact schema:
{{
  "components": [
    {{
      "id": "c_<slug>",
      "name": "<name visible in diagram>",
      "type": "<one of: user|external_entity|webapp|mobile_app|api|auth_service|admin_panel|database|datastore|cache|queue|filesystem|config|payment_service>",
      "description": "<brief description>"
    }}
  ],
  "data_flows": [
    {{
      "id": "f_<slug>",
      "from": "<component id>",
      "to": "<component id>",
      "label": "<what data flows>",
      "protocol": "<HTTPS|HTTP|TCP|WSS|gRPC|etc>",
      "auth": "<bearer|session|mtls|api_key|none>",
      "encrypted": <true|false>
    }}
  ],
  "trust_boundaries": [
    {{
      "id": "b_<slug>",
      "name": "<boundary name>",
      "contains": ["<component id>", ...]
    }}
  ]
}}

Rules:
- Use ONLY the component type values listed above (no others)
- Every data_flow "from" and "to" must reference valid component ids
- Every trust_boundary "contains" list must reference valid component ids
- If you cannot clearly identify something, make your best educated guess
- Ensure ids are unique (use descriptive slugs like c_webapp, c_postgres, f_user_api, b_internet)"""

    try:
        text = complete_vision(prompt, image_bytes, media_type, max_tokens=3000)
        if not text:
            return _stub_result(description)
        text = strip_fences(text)
        result = json.loads(text)
        
        # Validate and clean up
        comp_ids = {c["id"] for c in result.get("components", [])}
        valid_types = {
            "user", "external_entity", "webapp", "mobile_app", "api", "auth_service",
            "admin_panel", "database", "datastore", "cache", "queue", "filesystem",
            "config", "payment_service"
        }
        # Fix invalid types
        for c in result.get("components", []):
            if c.get("type") not in valid_types:
                c["type"] = "api"  # safe default
        
        # Remove flows referencing unknown components
        result["data_flows"] = [
            f for f in result.get("data_flows", [])
            if f.get("from") in comp_ids and f.get("to") in comp_ids
        ]
        # Remove boundaries with unknown components
        for b in result.get("trust_boundaries", []):
            b["contains"] = [cid for cid in b.get("contains", []) if cid in comp_ids]
        result["trust_boundaries"] = [b for b in result.get("trust_boundaries", []) if b.get("contains")]
        
        result["extraction_method"] = "claude-vision"
        return result
    except Exception as e:
        print(f"[diagram_extractor] Claude vision failed: {e}")
        return _stub_result(description)


def _stub_result(description: str) -> dict:
    """Return a minimal stub when Claude API is unavailable."""
    return {
        "components": [
            {"id": "c_user", "name": "User", "type": "user", "description": "End user"},
            {"id": "c_webapp", "name": "Web App", "type": "webapp", "description": "Frontend application"},
            {"id": "c_api", "name": "API", "type": "api", "description": "Backend service"},
            {"id": "c_db", "name": "Database", "type": "database", "description": "Data store"},
        ],
        "data_flows": [
            {"id": "f_1", "from": "c_user", "to": "c_webapp", "label": "HTTP request", "protocol": "HTTPS", "auth": "session", "encrypted": True},
            {"id": "f_2", "from": "c_webapp", "to": "c_api", "label": "API call", "protocol": "HTTPS", "auth": "bearer", "encrypted": True},
            {"id": "f_3", "from": "c_api", "to": "c_db", "label": "Query", "protocol": "TCP", "auth": "credentials", "encrypted": False},
        ],
        "trust_boundaries": [
            {"id": "b_public", "name": "Public Internet", "contains": ["c_user"]},
            {"id": "b_app", "name": "Application Tier", "contains": ["c_webapp", "c_api"]},
            {"id": "b_data", "name": "Data Tier", "contains": ["c_db"]},
        ],
        "extraction_method": "stub-fallback",
        "note": "Set ANTHROPIC_API_KEY to enable real diagram analysis with Claude vision."
    }
