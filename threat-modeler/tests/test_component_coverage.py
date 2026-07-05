"""Component coverage test — runs threat analysis against systems representing
each component type (web, mobile, API, AI integration, full-stack) and reports:
  * Total threats found per system
  * Severity breakdown
  * Cross-boundary detection
  * Methodology coverage (STRIDE/DREAD/LINDDUN/PASTA)
  * Whether expected threat categories appear
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from threat_engine import analyze_system

# Component-type systems
SYSTEMS = {
    "Web Application (auth + DB)": {
        "name": "WebApp",
        "components": [
            {"id": "user", "name": "User", "type": "external_entity"},
            {"id": "web", "name": "Web Frontend", "type": "webapp"},
            {"id": "api", "name": "Backend API", "type": "service"},
            {"id": "db", "name": "PostgreSQL", "type": "database"},
            {"id": "cache", "name": "Redis", "type": "cache"},
        ],
        "data_flows": [
            {"id": "f1", "from": "user", "to": "web", "data": "credentials, form input",
             "encrypted": False, "auth": "none"},
            {"id": "f2", "from": "web", "to": "api", "data": "API requests",
             "encrypted": True, "auth": "jwt"},
            {"id": "f3", "from": "api", "to": "db", "data": "SQL queries with PII",
             "encrypted": False, "auth": "service_account"},
            {"id": "f4", "from": "api", "to": "cache", "data": "session tokens",
             "encrypted": False, "auth": "none"},
        ],
        "trust_boundaries": [
            {"id": "b1", "name": "Internet", "contains": ["user"]},
            {"id": "b2", "name": "DMZ", "contains": ["web"]},
            {"id": "b3", "name": "Internal", "contains": ["api", "db", "cache"]},
        ],
    },

    "Mobile Application": {
        "name": "Mobile App",
        "components": [
            {"id": "user", "name": "Mobile User", "type": "external_entity"},
            {"id": "mobile", "name": "iOS/Android App", "type": "mobile_app"},
            {"id": "api", "name": "Mobile API", "type": "api"},
            {"id": "auth", "name": "OAuth Provider", "type": "external_service"},
            {"id": "db", "name": "User Database", "type": "database"},
            {"id": "push", "name": "Push Notification Service", "type": "external_service"},
        ],
        "data_flows": [
            {"id": "f1", "from": "user", "to": "mobile", "data": "PII, biometrics",
             "encrypted": True, "auth": "biometric"},
            {"id": "f2", "from": "mobile", "to": "auth", "data": "OAuth credentials",
             "encrypted": True, "auth": "oauth"},
            {"id": "f3", "from": "mobile", "to": "api", "data": "API calls with auth token",
             "encrypted": True, "auth": "jwt"},
            {"id": "f4", "from": "api", "to": "db", "data": "user data queries",
             "encrypted": False, "auth": "service_account"},
            {"id": "f5", "from": "api", "to": "push", "data": "device tokens",
             "encrypted": True, "auth": "api_key"},
        ],
        "trust_boundaries": [
            {"id": "b1", "name": "Mobile device", "contains": ["user", "mobile"]},
            {"id": "b2", "name": "Cloud (third-party)", "contains": ["auth", "push"]},
            {"id": "b3", "name": "Backend", "contains": ["api", "db"]},
        ],
    },

    "Public REST API": {
        "name": "Public API",
        "components": [
            {"id": "client", "name": "API Client", "type": "external_entity"},
            {"id": "gateway", "name": "API Gateway", "type": "api_gateway"},
            {"id": "api", "name": "Core API Service", "type": "service"},
            {"id": "auth", "name": "Auth Service", "type": "service"},
            {"id": "db", "name": "Data Store", "type": "database"},
            {"id": "queue", "name": "Message Queue", "type": "queue"},
        ],
        "data_flows": [
            {"id": "f1", "from": "client", "to": "gateway", "data": "API requests with API key",
             "encrypted": True, "auth": "api_key"},
            {"id": "f2", "from": "gateway", "to": "auth", "data": "auth check",
             "encrypted": True, "auth": "service_account"},
            {"id": "f3", "from": "gateway", "to": "api", "data": "validated requests",
             "encrypted": False, "auth": "none"},
            {"id": "f4", "from": "api", "to": "db", "data": "queries",
             "encrypted": False, "auth": "service_account"},
            {"id": "f5", "from": "api", "to": "queue", "data": "async events",
             "encrypted": False, "auth": "none"},
        ],
        "trust_boundaries": [
            {"id": "b1", "name": "Internet", "contains": ["client"]},
            {"id": "b2", "name": "Edge", "contains": ["gateway"]},
            {"id": "b3", "name": "Internal services", "contains": ["api", "auth", "db", "queue"]},
        ],
    },

    "AI/LLM Integration": {
        "name": "AI-powered SaaS",
        "components": [
            {"id": "user", "name": "End User", "type": "external_entity"},
            {"id": "web", "name": "Web UI", "type": "webapp"},
            {"id": "api", "name": "Application API", "type": "service"},
            {"id": "llm", "name": "LLM Provider (OpenAI)", "type": "llm_service"},
            {"id": "vec", "name": "Vector DB (Pinecone)", "type": "vector_db"},
            {"id": "rag", "name": "RAG Document Store", "type": "object_storage"},
            {"id": "db", "name": "User Data DB", "type": "database"},
        ],
        "data_flows": [
            {"id": "f1", "from": "user", "to": "web", "data": "prompts (untrusted)",
             "encrypted": True, "auth": "session"},
            {"id": "f2", "from": "web", "to": "api", "data": "user prompt + context",
             "encrypted": True, "auth": "jwt"},
            {"id": "f3", "from": "api", "to": "vec", "data": "embedding queries",
             "encrypted": True, "auth": "api_key"},
            {"id": "f4", "from": "api", "to": "rag", "data": "document fetch",
             "encrypted": False, "auth": "service_account"},
            {"id": "f5", "from": "api", "to": "llm", "data": "prompt + retrieved context",
             "encrypted": True, "auth": "api_key"},
            {"id": "f6", "from": "llm", "to": "api", "data": "LLM response (untrusted output)",
             "encrypted": True, "auth": "api_key"},
            {"id": "f7", "from": "api", "to": "db", "data": "user queries / chat history",
             "encrypted": False, "auth": "service_account"},
        ],
        "trust_boundaries": [
            {"id": "b1", "name": "User browser", "contains": ["user"]},
            {"id": "b2", "name": "App tier", "contains": ["web", "api", "db"]},
            {"id": "b3", "name": "Third-party AI services", "contains": ["llm", "vec"]},
            {"id": "b4", "name": "Storage", "contains": ["rag"]},
        ],
    },

    "Full-stack Microservices": {
        "name": "Distributed System",
        "components": [
            {"id": "user", "name": "User", "type": "external_entity"},
            {"id": "cdn", "name": "CDN", "type": "external_service"},
            {"id": "web", "name": "React SPA", "type": "webapp"},
            {"id": "lb", "name": "Load Balancer", "type": "load_balancer"},
            {"id": "auth", "name": "Auth Service", "type": "service"},
            {"id": "users_svc", "name": "Users Service", "type": "service"},
            {"id": "orders_svc", "name": "Orders Service", "type": "service"},
            {"id": "payments_svc", "name": "Payments Service", "type": "service"},
            {"id": "db_users", "name": "Users DB", "type": "database"},
            {"id": "db_orders", "name": "Orders DB", "type": "database"},
            {"id": "stripe", "name": "Stripe", "type": "external_service"},
            {"id": "queue", "name": "Kafka", "type": "queue"},
            {"id": "s3", "name": "S3 Bucket", "type": "object_storage"},
        ],
        "data_flows": [
            {"id": "f1", "from": "user", "to": "cdn", "data": "static assets", "encrypted": True, "auth": "none"},
            {"id": "f2", "from": "user", "to": "lb", "data": "API requests", "encrypted": True, "auth": "jwt"},
            {"id": "f3", "from": "lb", "to": "auth", "data": "auth check", "encrypted": True, "auth": "service_account"},
            {"id": "f4", "from": "lb", "to": "users_svc", "data": "user requests", "encrypted": False, "auth": "none"},
            {"id": "f5", "from": "lb", "to": "orders_svc", "data": "order requests", "encrypted": False, "auth": "none"},
            {"id": "f6", "from": "users_svc", "to": "db_users", "data": "PII queries", "encrypted": False, "auth": "service_account"},
            {"id": "f7", "from": "orders_svc", "to": "db_orders", "data": "order queries", "encrypted": False, "auth": "service_account"},
            {"id": "f8", "from": "orders_svc", "to": "payments_svc", "data": "charge request", "encrypted": True, "auth": "service_account"},
            {"id": "f9", "from": "payments_svc", "to": "stripe", "data": "card data", "encrypted": True, "auth": "api_key"},
            {"id": "f10", "from": "orders_svc", "to": "queue", "data": "events", "encrypted": False, "auth": "none"},
            {"id": "f11", "from": "users_svc", "to": "s3", "data": "user uploads", "encrypted": True, "auth": "iam_role"},
        ],
        "trust_boundaries": [
            {"id": "b1", "name": "Internet", "contains": ["user"]},
            {"id": "b2", "name": "Edge (CDN)", "contains": ["cdn"]},
            {"id": "b3", "name": "App tier", "contains": ["web", "lb"]},
            {"id": "b4", "name": "Microservices", "contains": ["auth", "users_svc", "orders_svc", "payments_svc"]},
            {"id": "b5", "name": "Data tier", "contains": ["db_users", "db_orders", "queue", "s3"]},
            {"id": "b6", "name": "Third-party (PCI scope)", "contains": ["stripe"]},
        ],
    },
}


def analyze(system, methodologies):
    return analyze_system(system, methodologies, use_llm=False)


def severity_distribution(threats):
    from collections import Counter
    return dict(Counter(t.get("severity", "Unknown") for t in threats))


def category_distribution(threats):
    from collections import Counter
    return dict(Counter(t.get("category", "Unknown") for t in threats))


def cross_boundary_count(threats):
    return sum(1 for t in threats if t.get("cross_boundary"))


def methodology_distribution(threats):
    from collections import Counter
    return dict(Counter(t.get("methodology", "unknown") for t in threats))


def normalize_method(m):
    return (m or "").lower().split()[0]  # 'STRIDE' → 'stride'


print("=" * 80)
print("  COMPONENT COVERAGE TEST — Rule-based threat engine")
print("=" * 80)

ALL_METHODOLOGIES = ["stride", "dread", "linddun", "pasta"]
results_summary = []

for label, system in SYSTEMS.items():
    print(f"\n{'─' * 80}")
    print(f"  {label}")
    print(f"{'─' * 80}")
    print(f"  Components: {len(system['components'])}, "
          f"Data flows: {len(system['data_flows'])}, "
          f"Trust boundaries: {len(system['trust_boundaries'])}")

    result = analyze(system, ALL_METHODOLOGIES)
    threats = result["threats"]
    summary = result["summary"]

    print(f"\n  TOTAL THREATS: {summary['total']}")
    print(f"  Rule-based: {summary['rule_based']}, LLM-enhanced: {summary['llm_enhanced']}")

    sev = severity_distribution(threats)
    print(f"\n  By Severity:")
    for level in ["Critical", "High", "Medium", "Low", "Info"]:
        if level in sev:
            print(f"    {level:8s}: {sev[level]}")

    methods = methodology_distribution(threats)
    methods_norm = {}
    for k, v in methods.items():
        methods_norm[normalize_method(k)] = methods_norm.get(normalize_method(k), 0) + v
    print(f"\n  By Methodology:")
    for m in ALL_METHODOLOGIES:
        n = methods_norm.get(m, 0)
        print(f"    {m.upper():8s}: {n}")

    cb = cross_boundary_count(threats)
    print(f"\n  Cross-boundary threats: {cb}")
    print(f"  Untrusted-input crossings: {len(result.get('untrusted_crossings', []))}")

    cats = category_distribution(threats)
    if cats:
        print(f"\n  Top categories:")
        for cat, n in sorted(cats.items(), key=lambda x: -x[1])[:6]:
            print(f"    {cat:30s}: {n}")

    # Sample 3 highest-severity threats
    high_sev = sorted(threats, key=lambda t: ["Critical","High","Medium","Low","Info"].index(t.get("severity","Info")))[:3]
    print(f"\n  Sample threats (highest severity first):")
    for t in high_sev:
        title = t.get("title", "—")[:65]
        sev_val = t.get("severity", "?")
        loc = t.get("location", "—")[:30]
        print(f"    [{sev_val:8s}] {title}")
        print(f"               at {loc}")

    results_summary.append({
        "system": label,
        "components": len(system["components"]),
        "flows": len(system["data_flows"]),
        "boundaries": len(system["trust_boundaries"]),
        "total_threats": summary["total"],
        "by_severity": sev,
        "cross_boundary": cb,
        "by_methodology": methods_norm,
    })

# Final summary table
print()
print("=" * 80)
print("  COVERAGE SUMMARY")
print("=" * 80)
print(f"{'System':<35s} {'Cmps':>5s} {'Flws':>5s} {'Bnds':>5s} {'Threats':>8s} {'Crit':>5s} {'High':>5s} {'CB':>4s}")
print("─" * 80)
for r in results_summary:
    sev = r["by_severity"]
    print(f"{r['system'][:34]:<35s} {r['components']:>5d} {r['flows']:>5d} {r['boundaries']:>5d} "
          f"{r['total_threats']:>8d} {sev.get('Critical',0):>5d} {sev.get('High',0):>5d} {r['cross_boundary']:>4d}")

# Methodology check
print()
print("=" * 80)
print("  METHODOLOGY COVERAGE")
print("=" * 80)
all_methodologies_used = set()
for r in results_summary:
    all_methodologies_used.update(r["by_methodology"].keys())

print(f"  STRIDE applied:  {'YES' if 'stride' in all_methodologies_used else 'NO'}")
print(f"  DREAD applied:   {'YES' if 'dread' in all_methodologies_used else 'NO'}")
print(f"  LINDDUN applied: {'YES' if 'linddun' in all_methodologies_used else 'NO'}")
print(f"  PASTA applied:   {'YES' if 'pasta' in all_methodologies_used else 'NO'}")

print()
print("=" * 80)
print("  ACCURACY ASSESSMENT")
print("=" * 80)

# What we expect to be flagged
expectations = []
for r in results_summary:
    name = r["system"]
    threats_found = r["total_threats"]
    cross_boundary = r["cross_boundary"]

    # Each system has unencrypted internal flows + trust boundaries — should always flag SOMETHING
    if threats_found == 0:
        expectations.append((name, "FAIL: zero threats found"))
        continue
    if cross_boundary == 0 and r["boundaries"] >= 2:
        expectations.append((name, "WARN: no cross-boundary threats but multi-boundary system"))
        continue
    if r["by_severity"].get("Critical", 0) + r["by_severity"].get("High", 0) == 0:
        expectations.append((name, "WARN: no Critical/High severity threats"))
        continue
    expectations.append((name, "PASS"))

for name, status in expectations:
    icon = "✓" if status == "PASS" else "✗" if status.startswith("FAIL") else "!"
    print(f"  {icon} {name:<40s} {status}")

n_pass = sum(1 for _, s in expectations if s == "PASS")
print()
print(f"  {n_pass}/{len(expectations)} systems passed accuracy heuristics")
print("=" * 80)
