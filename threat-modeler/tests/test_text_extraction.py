"""Golden tests for smarter free-text extraction (0.2 #7).

Free text can't be *exact* (that's what structured input / the editor are for), but it
should be *smart and disclosed*: infer security attributes (PII/PCI/PHI handling,
internet exposure, secrets, at-rest encryption) from the prose so the model produces
evidenced findings instead of a wall of generic checks — and disclose every inference.

Run: python tests/test_text_extraction.py
"""
import os
import sys

os.environ.setdefault("JWT_SECRET", "test-secret")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_engine.analyzer import extract_components_from_text, analyze_system  # noqa: E402

_p = _f = 0


def check(cond, msg):
    global _p, _f
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    _p += bool(cond)
    _f += (not cond)


def comp(m, ctype):
    return next((c for c in m["components"] if c["type"] == ctype), None)


def main():
    txt = ("A public-facing Orders API backed by a Postgres database storing customer "
           "PII and payment card data. Passwords are kept in a secrets Vault. Redis cache in front.")
    m = extract_components_from_text(txt)

    print("=== Security attributes inferred from prose ===")
    db = comp(m, "database")
    api = comp(m, "api")
    vault = comp(m, "secrets_manager")
    check(db and db.get("handles_pii") == "yes", "'customer PII' -> database handles_pii=yes")
    check(db and db.get("handles_pci") == "yes", "'payment card data' -> database handles_pci=yes")
    check(api and api.get("internet_facing") == "yes", "'public-facing ... API' -> api internet_facing=yes")
    check(vault and vault.get("stores_credentials") == "yes", "'passwords ... secrets' -> vault stores_credentials=yes")

    print("=== Proper names captured; lowercase falls back ===")
    check(api and api["name"] == "Orders API", "capitalised phrase becomes the component name ('Orders API')")
    check(db and db["name"] == "Postgres Database", "'Postgres Database' captured as the name")
    m2 = extract_components_from_text("an api talks to a database and a redis cache")
    check(comp(m2, "api")["name"] == "API", "lowercase prose falls back to the keyword display name")

    print("=== Every inference is disclosed (no silent attribute-setting) ===")
    joined = " ".join(m["assumptions"]).lower()
    check("handles pii" in joined and "cardholder" in joined, "PII + cardholder inferences are disclosed")
    check("internet-facing" in joined, "internet-facing inference is disclosed")
    check("credentials" in joined, "credential-store inference is disclosed")

    print("=== Prose now yields evidenced findings, not just generic checks ===")
    r = analyze_system(m, ["stride"])
    titles = [t["title"].lower() for t in r["threats"]]
    check(any("cardholder data" in t and "pci" in t for t in titles), "PCI-DSS finding fires from the prose")
    check(any("handles pii" in t for t in titles), "PII privacy finding fires from the prose")

    print("=== No false attributes when the prose is silent ===")
    plain = extract_components_from_text("a web app calls an api which reads a database")
    check(not any(c.get("handles_pii") for c in plain["components"]), "no PII tag when PII isn't mentioned")
    check(not any(c.get("internet_facing") for c in plain["components"]), "no internet-facing tag when not stated")

    print()
    print("=" * 60)
    print(f"  Free-text extraction golden-model: {_p} passed, {_f} failed")
    print("=" * 60)
    if _f:
        sys.exit(1)


if __name__ == "__main__":
    main()
