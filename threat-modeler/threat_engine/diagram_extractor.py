"""diagram_extractor.py — Extract system components from an uploaded architecture diagram.

Resolution order:
  1. A vision-capable LLM (best): identifies components, flows, and trust
     boundaries from the image.
  2. Offline OCR (Tesseract, if installed): reads the text labels in the diagram
     and maps them to components via the same keyword rules the text extractor
     uses. Reads labels, not arrows, so flows/boundaries are inferred and can be
     refined in the editor.
  3. A generic editable starter model, if neither is available.
"""
from __future__ import annotations
import json


def extract_from_diagram(image_bytes: bytes, media_type: str, description: str = "") -> dict:
    """Analyze an architecture diagram image and return a system model.

    Uses a vision LLM when configured, else offline OCR, else a starter stub."""
    from .llm import complete_vision, llm_available, strip_fences
    if not llm_available():
        return _ocr_result(image_bytes, description) or _stub_result(description)

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
        
        result["extraction_method"] = "llm_vision"
        return result
    except Exception as e:
        print(f"[diagram_extractor] vision extraction failed: {e}")
        return _ocr_result(image_bytes, description) or _stub_result(description)


def _ocr_result(image_bytes: bytes, description: str = "") -> dict | None:
    """Offline extraction: OCR the diagram's text labels (Tesseract) and build a
    system from them using the text extractor's keyword rules. Returns None when
    OCR is unavailable or finds too little to be useful, so the caller falls back
    to the starter stub."""
    try:
        import io
        import pytesseract
        from PIL import Image
        text = pytesseract.image_to_string(Image.open(io.BytesIO(image_bytes)))
    except Exception as e:
        print(f"[diagram_extractor] OCR unavailable: {e}")
        return None

    combined = f"{text}\n{description}".strip()
    if len(combined) < 3:
        return None
    from .analyzer import extract_components_from_text
    system = extract_components_from_text(combined)
    # Need more than just the auto-added default user to call this a real read.
    non_default = [c for c in system.get("components", []) if c.get("id") != "c_user"]
    if len(non_default) < 1:
        return None
    system["extraction_method"] = "ocr"
    system["note"] = ("Extracted from the diagram's text labels via offline OCR. "
                      "OCR reads labels, not arrows — review the components and add any "
                      "missing connections in the Data Flow Diagram tab.")
    return system


def _stub_result(description: str) -> dict:
    """Return a generic editable starter model when no vision AI or OCR is available."""
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
        "note": "This is a generic starter model — no vision AI or OCR was available to read the diagram. "
                "Edit the components in the Data Flow Diagram tab, or configure an AI provider in Admin → Settings for full diagram analysis."
    }
