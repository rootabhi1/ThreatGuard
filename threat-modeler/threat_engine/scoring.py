"""CVSS 3.1 + 4.0 derivation and CWE mapping for threats.

The scoring is *derived* — we don't ask the user for a CVSS vector. Instead we
infer it from the threat's category, the affected component type, and (when
present) the data flow's attributes. This gives consistent scores across runs
and lets us show severity in the language security teams already use.

References:
  - CVSS 3.1 spec: https://www.first.org/cvss/v3.1/specification-document
  - CVSS 4.0 spec: https://www.first.org/cvss/v4-0/specification-document
  - CWE: https://cwe.mitre.org/
"""
from __future__ import annotations
import math


CWE_TO_ATTACK = {
    "CWE-20":  {"id":"T1190","tactic":"Initial Access","name":"Exploit Public-Facing Application"},
    "CWE-79":  {"id":"T1059.007","tactic":"Execution","name":"JavaScript/XSS"},
    "CWE-89":  {"id":"T1190","tactic":"Initial Access","name":"Exploit Public-Facing Application"},
    "CWE-200": {"id":"T1552","tactic":"Credential Access","name":"Unsecured Credentials"},
    "CWE-287": {"id":"T1110","tactic":"Credential Access","name":"Brute Force"},
    "CWE-311": {"id":"T1557","tactic":"Collection","name":"Adversary-in-the-Middle"},
    "CWE-319": {"id":"T1040","tactic":"Credential Access","name":"Network Sniffing"},
    "CWE-352": {"id":"T1185","tactic":"Collection","name":"Browser Session Hijacking"},
    "CWE-400": {"id":"T1499","tactic":"Impact","name":"Endpoint Denial of Service"},
    "CWE-434": {"id":"T1105","tactic":"Command and Control","name":"Ingress Tool Transfer"},
    "CWE-522": {"id":"T1552","tactic":"Credential Access","name":"Unsecured Credentials"},
    "CWE-601": {"id":"T1566","tactic":"Initial Access","name":"Phishing"},
    "CWE-639": {"id":"T1548","tactic":"Privilege Escalation","name":"Abuse Elevation Control Mechanism"},
    "CWE-798": {"id":"T1552.001","tactic":"Credential Access","name":"Credentials In Files"},
    "CWE-918": {"id":"T1090","tactic":"Command and Control","name":"Proxy"},
}

COMPLIANCE_MAPPING = {
    "CWE-89":  {"soc2":["CC8.1"],"iso27001":["A.14.2.5"],"pci_dss":["6.3.1"]},
    "CWE-287": {"soc2":["CC6.1","CC6.2"],"iso27001":["A.9.2.1","A.9.4.2"],"pci_dss":["8.2","8.6"]},
    "CWE-311": {"soc2":["CC6.7"],"iso27001":["A.10.1.1"],"pci_dss":["3.4","4.1"]},
    "CWE-319": {"soc2":["CC6.7"],"iso27001":["A.10.1.1"],"pci_dss":["4.1"]},
    "CWE-352": {"soc2":["CC6.6"],"iso27001":["A.14.1.2"],"pci_dss":["6.3.2"]},
    "CWE-400": {"soc2":["A1.1","A1.2"],"iso27001":["A.17.1.1"],"pci_dss":["6.3"]},
    "CWE-522": {"soc2":["CC6.1"],"iso27001":["A.9.2.4"],"pci_dss":["8.2.1"]},
    "CWE-601": {"soc2":["CC9.2"],"iso27001":["A.7.2.2"],"pci_dss":["12.6"]},
    "CWE-639": {"soc2":["CC6.3"],"iso27001":["A.9.4.1"],"pci_dss":["7.2"]},
    "CWE-798": {"soc2":["CC6.1"],"iso27001":["A.9.2.4"],"pci_dss":["8.2.1"]},
    "CWE-918": {"soc2":["CC6.6"],"iso27001":["A.13.1.3"],"pci_dss":["1.3"]},
}


# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------
# Map (methodology_category, component_type) and threat-title patterns to CWE.
# Each entry: cwe_id, name, short description, link.

CWE_DB = {
    "CWE-20":  {"id": "CWE-20",  "name": "Improper Input Validation",
                "url": "https://cwe.mitre.org/data/definitions/20.html"},
    "CWE-22":  {"id": "CWE-22",  "name": "Path Traversal",
                "url": "https://cwe.mitre.org/data/definitions/22.html"},
    "CWE-79":  {"id": "CWE-79",  "name": "Cross-site Scripting (XSS)",
                "url": "https://cwe.mitre.org/data/definitions/79.html"},
    "CWE-89":  {"id": "CWE-89",  "name": "SQL Injection",
                "url": "https://cwe.mitre.org/data/definitions/89.html"},
    "CWE-200": {"id": "CWE-200", "name": "Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html"},
    "CWE-209": {"id": "CWE-209", "name": "Information Exposure Through Error Message",
                "url": "https://cwe.mitre.org/data/definitions/209.html"},
    "CWE-269": {"id": "CWE-269", "name": "Improper Privilege Management",
                "url": "https://cwe.mitre.org/data/definitions/269.html"},
    "CWE-285": {"id": "CWE-285", "name": "Improper Authorization",
                "url": "https://cwe.mitre.org/data/definitions/285.html"},
    "CWE-287": {"id": "CWE-287", "name": "Improper Authentication",
                "url": "https://cwe.mitre.org/data/definitions/287.html"},
    "CWE-306": {"id": "CWE-306", "name": "Missing Authentication for Critical Function",
                "url": "https://cwe.mitre.org/data/definitions/306.html"},
    "CWE-311": {"id": "CWE-311", "name": "Missing Encryption of Sensitive Data",
                "url": "https://cwe.mitre.org/data/definitions/311.html"},
    "CWE-319": {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/319.html"},
    "CWE-345": {"id": "CWE-345", "name": "Insufficient Verification of Data Authenticity",
                "url": "https://cwe.mitre.org/data/definitions/345.html"},
    "CWE-352": {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)",
                "url": "https://cwe.mitre.org/data/definitions/352.html"},
    "CWE-359": {"id": "CWE-359", "name": "Privacy Violation",
                "url": "https://cwe.mitre.org/data/definitions/359.html"},
    "CWE-400": {"id": "CWE-400", "name": "Uncontrolled Resource Consumption (DoS)",
                "url": "https://cwe.mitre.org/data/definitions/400.html"},
    "CWE-441": {"id": "CWE-441", "name": "Confused Deputy",
                "url": "https://cwe.mitre.org/data/definitions/441.html"},
    "CWE-502": {"id": "CWE-502", "name": "Deserialization of Untrusted Data",
                "url": "https://cwe.mitre.org/data/definitions/502.html"},
    "CWE-522": {"id": "CWE-522", "name": "Insufficiently Protected Credentials",
                "url": "https://cwe.mitre.org/data/definitions/522.html"},
    "CWE-639": {"id": "CWE-639", "name": "Authorization Bypass through User-Controlled Key",
                "url": "https://cwe.mitre.org/data/definitions/639.html"},
    "CWE-693": {"id": "CWE-693", "name": "Protection Mechanism Failure",
                "url": "https://cwe.mitre.org/data/definitions/693.html"},
    "CWE-732": {"id": "CWE-732", "name": "Incorrect Permission Assignment",
                "url": "https://cwe.mitre.org/data/definitions/732.html"},
    "CWE-778": {"id": "CWE-778", "name": "Insufficient Logging",
                "url": "https://cwe.mitre.org/data/definitions/778.html"},
    "CWE-863": {"id": "CWE-863", "name": "Incorrect Authorization",
                "url": "https://cwe.mitre.org/data/definitions/863.html"},
    "CWE-918": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)",
                "url": "https://cwe.mitre.org/data/definitions/918.html"},
}


def _cwe_for_threat(threat: dict, component: dict) -> dict:
    """Best-effort CWE mapping from threat title + category + component type."""
    title = (threat.get("title") or "").lower()
    cat = (threat.get("category") or "").lower()
    ctype = (component or {}).get("type", "")

    # Specific patterns first
    if "unauthenticated" in title or "no authentication" in title:
        return CWE_DB["CWE-306"]
    if "unencrypted" in title or "cleartext" in title:
        return CWE_DB["CWE-319"]
    if "cross-boundary input" in title or ("cross-boundary" in title and "validat" in title):
        return CWE_DB["CWE-20"]
    if "privilege transit" in title or "confused" in title:
        return CWE_DB["CWE-441"]
    if "spoofing" in cat:
        return CWE_DB["CWE-287"]
    if "tampering" in cat:
        return CWE_DB["CWE-345"]
    if "repudiation" in cat:
        return CWE_DB["CWE-778"]
    if "information disclosure" in cat or "disclosure" in cat:
        # Component type tunes the CWE
        if ctype in ("database", "datastore", "filesystem", "cache"):
            return CWE_DB["CWE-200"]
        return CWE_DB["CWE-319"] if "transit" in title or "flow" in title else CWE_DB["CWE-200"]
    if "denial of service" in cat or "dos" in cat or "denial" in cat:
        return CWE_DB["CWE-400"]
    if "elevation of privilege" in cat or "privilege" in cat:
        return CWE_DB["CWE-269"]
    if "linkability" in cat or "identifiability" in cat or "detectability" in cat:
        return CWE_DB["CWE-359"]
    if "non-repudiation" in cat or "non-compliance" in cat:
        return CWE_DB["CWE-778"]
    if "unawareness" in cat:
        return CWE_DB["CWE-359"]
    # PASTA stages — coarse mapping
    if "stage 3" in cat or "decomposition" in cat:
        return CWE_DB["CWE-693"]
    if "stage 4" in cat or "threat analysis" in cat:
        return CWE_DB["CWE-693"]
    if "stage 5" in cat or "vulnerability" in cat:
        return CWE_DB["CWE-693"]
    # Fallback by component type
    if ctype in ("database", "datastore"):
        return CWE_DB["CWE-200"]
    if ctype in ("api", "webapp", "admin_panel"):
        return CWE_DB["CWE-20"]
    return CWE_DB["CWE-693"]


# ---------------------------------------------------------------------------
# CVSS 3.1 — derive vector + score
# ---------------------------------------------------------------------------
# Vector axes:
#   AV: Network (N), Adjacent (A), Local (L), Physical (P)
#   AC: Low (L), High (H)
#   PR: None (N), Low (L), High (H)
#   UI: None (N), Required (R)
#   S:  Unchanged (U), Changed (C)
#   C/I/A: None (N), Low (L), High (H)

_CVSS31_BASE_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},  # Scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}


def _round_up_1(x: float) -> float:
    """CVSS-style round up to one decimal."""
    int_x = int(x * 100000)
    if int_x % 10000 == 0:
        return int_x / 100000
    return (math.floor(int_x / 10000) + 1) / 10


def _cvss31_compute(metrics: dict) -> tuple[float, str]:
    """Compute the CVSS 3.1 base score from metrics dict. Returns (score, severity)."""
    av = _CVSS31_BASE_WEIGHTS["AV"][metrics["AV"]]
    ac = _CVSS31_BASE_WEIGHTS["AC"][metrics["AC"]]
    pr = _CVSS31_BASE_WEIGHTS["PR_C" if metrics["S"] == "C" else "PR_U"][metrics["PR"]]
    ui = _CVSS31_BASE_WEIGHTS["UI"][metrics["UI"]]
    c = _CVSS31_BASE_WEIGHTS["C"][metrics["C"]]
    i = _CVSS31_BASE_WEIGHTS["I"][metrics["I"]]
    a = _CVSS31_BASE_WEIGHTS["A"][metrics["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    elif metrics["S"] == "U":
        base = _round_up_1(min(impact + exploitability, 10))
    else:
        base = _round_up_1(min(1.08 * (impact + exploitability), 10))

    if base == 0:
        sev = "None"
    elif base < 4.0:
        sev = "Low"
    elif base < 7.0:
        sev = "Medium"
    elif base < 9.0:
        sev = "High"
    else:
        sev = "Critical"
    return round(base, 1), sev


def _cvss31_for_threat(threat: dict, component: dict, flow: dict | None,
                       cross_boundary: bool = False) -> dict:
    """Pick CVSS 3.1 metrics from threat semantics + return vector + score + severity."""
    title = (threat.get("title") or "").lower()
    cat = (threat.get("category") or "").lower()
    ctype = (component or {}).get("type", "")

    # Attack Vector — internal services default to Adjacent, externally-facing to Network
    if ctype in ("user", "external_entity", "webapp", "mobile_app", "admin_panel", "api", "auth_service", "payment_service"):
        av = "N"
    elif ctype in ("database", "datastore", "cache", "queue", "filesystem", "config"):
        av = "A"
    else:
        av = "N"

    # Attack Complexity
    ac = "L"
    if "validat" in title and not cross_boundary:
        ac = "H"

    # Privileges Required
    pr = "N"
    if flow and flow.get("auth") and flow.get("auth") not in ("", "none"):
        pr = "L"
    if "privilege" in cat or "elevation" in cat:
        pr = "L"
    if ctype in ("database", "datastore", "config", "filesystem"):
        pr = "L"  # Internal stores require some access

    # User Interaction
    ui = "N"
    if "csrf" in title or "phishing" in title:
        ui = "R"

    # Scope — Changed when crossing boundaries (different security authority)
    s = "C" if cross_boundary else "U"
    if "privilege transit" in title or "confused" in title:
        s = "C"

    # Impact — Confidentiality / Integrity / Availability
    c = i = a = "N"
    if "disclosure" in cat or "spoofing" in cat or "information" in cat:
        c = "H"
    if "tampering" in cat or "repudiation" in cat:
        i = "H"
    if "denial" in cat:
        a = "H"
    if "elevation" in cat or "privilege" in cat:
        c = i = "H"; a = "L"
    if "stage" in cat or cat in ("application decomposition",):
        c = i = "L"

    # Bump impact for cross-boundary (broader blast radius)
    if cross_boundary:
        if c == "L": c = "H"
        if i == "L": i = "H"

    # Component type sensitivity
    if ctype in ("database", "datastore", "auth_service", "payment_service"):
        if c == "N": c = "L"
        if c == "L": c = "H"

    metrics = {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}
    score, sev = _cvss31_compute(metrics)
    vector = (
        f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/"
        f"C:{c}/I:{i}/A:{a}"
    )
    return {
        "vector": vector,
        "metrics": metrics,
        "score": score,
        "severity": sev,
    }


# ---------------------------------------------------------------------------
# CVSS 4.0 — simplified base derivation
# ---------------------------------------------------------------------------
# CVSS 4.0 has more axes (AT, VC/VI/VA, SC/SI/SA, MAV…). We compute the BASE
# subset deterministically with a published-table-driven approach. To keep the
# implementation tractable without shipping the full lookup table, we use the
# CVSS 4.0 macro-vector / equivalence-class method described in section 8 of
# the spec, mapped to a set of representative scores.

# Mapping macro-vector → score from the published CVSS 4.0 lookup table.
# Source: https://www.first.org/cvss/v4-0/specification-document  Table in §8.2.
# Format: "EQ1 EQ2 EQ3 EQ4 EQ5 EQ6"
_CVSS40_MACRO_SCORES = {
    "000000":10.0,"000001":9.9, "000010":9.8, "000011":9.5, "000020":9.5,"000021":9.2,
    "000100":10.0,"000101":9.6, "000110":9.3, "000111":8.7, "000120":9.1,"000121":8.1,
    "000200":9.3, "000201":9.0, "000210":8.9, "000211":8.0, "000220":8.1,"000221":6.8,
    "001000":9.8, "001001":9.5, "001010":9.5, "001011":9.2, "001020":9.0,"001021":8.4,
    "001100":9.3, "001101":9.2, "001110":8.9, "001111":8.1, "001120":8.1,"001121":6.5,
    "001200":8.8, "001201":8.0, "001210":7.8, "001211":7.0, "001220":6.9,"001221":4.8,
    "002001":9.2, "002011":8.2, "002021":7.2, "002101":7.9, "002111":6.9,"002121":5.0,
    "002201":6.9, "002211":5.5, "002221":2.7,
    "010000":9.9, "010001":9.7, "010010":9.5, "010011":9.2, "010020":9.2,"010021":8.5,
    "010100":9.5, "010101":9.1, "010110":9.0, "010111":8.3, "010120":8.4,"010121":7.1,
    "010200":9.2, "010201":8.1, "010210":8.2, "010211":7.1, "010220":7.2,"010221":5.3,
    "011000":9.5, "011001":9.3, "011010":9.2, "011011":8.5, "011020":8.5,"011021":7.3,
    "011100":9.2, "011101":8.2, "011110":8.0, "011111":7.2, "011120":7.0,"011121":5.9,
    "011200":8.4, "011201":7.0, "011210":7.1, "011211":5.2, "011220":5.0,"011221":3.0,
    "012001":8.6, "012011":7.5, "012021":5.2, "012101":7.1, "012111":5.2,"012121":2.9,
    "012201":6.3, "012211":2.9, "012221":1.7,
    "100000":9.8, "100001":9.5, "100010":9.4, "100011":8.7, "100020":9.1,"100021":8.1,
    "100100":9.4, "100101":8.9, "100110":8.6, "100111":7.4, "100120":7.7,"100121":6.4,
    "100200":8.7, "100201":7.5, "100210":7.4, "100211":6.3, "100220":6.3,"100221":4.9,
    "101000":9.4, "101001":8.9, "101010":8.8, "101011":7.7, "101020":7.6,"101021":6.7,
    "101100":8.6, "101101":7.6, "101110":7.4, "101111":5.8, "101120":5.9,"101121":5.0,
    "101200":7.2, "101201":5.7, "101210":5.7, "101211":5.2, "101220":5.2,"101221":2.5,
    "102001":8.3, "102011":7.0, "102021":5.4, "102101":6.5, "102111":5.8,"102121":2.6,
    "102201":5.3, "102211":2.1, "102221":1.3,
    "110000":9.5, "110001":9.0, "110010":8.8, "110011":7.6, "110020":7.6,"110021":7.0,
    "110100":9.0, "110101":7.7, "110110":7.5, "110111":6.2, "110120":6.1,"110121":5.3,
    "110200":7.7, "110201":6.6, "110210":6.8, "110211":5.9, "110220":5.2,"110221":3.0,
    "111000":8.9, "111001":7.8, "111010":7.6, "111011":6.7, "111020":6.2,"111021":5.8,
    "111100":7.4, "111101":5.9, "111110":5.7, "111111":5.7, "111120":4.7,"111121":2.3,
    "111200":6.1, "111201":5.2, "111210":5.7, "111211":2.9, "111220":2.4,"111221":1.6,
    "112001":7.1, "112011":5.9, "112021":3.0, "112101":5.8, "112111":2.6,"112121":1.5,
    "112201":2.3, "112211":1.3, "112221":0.6,
    "200000":9.3, "200001":8.7, "200010":8.6, "200011":7.2, "200020":7.5,"200021":5.8,
    "200100":8.6, "200101":7.4, "200110":7.4, "200111":6.1, "200120":5.6,"200121":3.4,
    "200200":7.0, "200201":5.4, "200210":5.1, "200211":2.8, "200220":3.1,"200221":1.6,
    "201000":8.8, "201001":7.5, "201010":7.3, "201011":5.3, "201020":6.0,"201021":2.4,
    "201100":7.5, "201101":5.5, "201110":5.8, "201111":2.6, "201120":3.4,"201121":1.3,
    "201200":5.7, "201201":2.9, "201210":2.5, "201211":1.5, "201220":1.7,"201221":0.5,
    "202001":7.7, "202011":4.7, "202021":1.9, "202101":4.6, "202111":2.5,"202121":1.0,
    "202201":2.1, "202211":1.1, "202221":0.4,
    "210000":7.8, "210001":6.9, "210010":6.4, "210011":5.5, "210020":5.5,"210021":3.5,
    "210100":7.0, "210101":5.4, "210110":5.6, "210111":3.7, "210120":3.5,"210121":2.0,
    "210200":4.9, "210201":3.5, "210210":2.9, "210211":1.7, "210220":2.0,"210221":0.4,
    "211000":7.4, "211001":5.4, "211010":5.5, "211011":3.5, "211020":3.6,"211021":1.7,
    "211100":4.9, "211101":3.4, "211110":3.7, "211111":1.7, "211120":1.9,"211121":0.6,
    "211200":3.0, "211201":1.6, "211210":1.7, "211211":0.7, "211220":0.7,"211221":0.2,
    "212001":4.0, "212011":1.4, "212021":0.5, "212101":1.5, "212111":0.4,"212121":0.1,
    "212201":0.5, "212211":0.1, "212221":0.0,
}


def _cvss40_macro(metrics: dict) -> str:
    """Derive macro-vector EQ1..EQ6 string per CVSS 4.0 spec §7.

    Equivalence sets (lower digit = higher severity):
      EQ1: 0 = AV:N+PR:N+UI:N
           1 = (AV:N or PR:N or UI:N) and not (AV:N+PR:N+UI:N) and AV:!P
           2 = AV:P or not(AV:N or PR:N or UI:N)
      EQ2: 0 = AC:L+AT:N
           1 = otherwise
      EQ3: 0 = VC:H+VI:H
           1 = (VC:H or VI:H or VA:H) and not(VC:H+VI:H)
           2 = neither
      EQ4: 0 = MSI:S or MSA:S
           1 = (SC:H or SI:H or SA:H) and not(MSI:S or MSA:S)
           2 = none of the above
      EQ5: 0 = E:A   (we don't model E, default 1)
           1 = E:P
           2 = E:U
      EQ6: 0 = (CR:H+VC:H) or (IR:H+VI:H) or (AR:H+VA:H)
           1 = otherwise
    """
    av, pr, ui = metrics["AV"], metrics["PR"], metrics["UI"]
    ac, at = metrics["AC"], metrics.get("AT", "N")
    vc, vi, va = metrics["VC"], metrics["VI"], metrics["VA"]
    sc, si, sa = metrics["SC"], metrics["SI"], metrics["SA"]
    msi = metrics.get("MSI", "X")
    msa = metrics.get("MSA", "X")
    cr = metrics.get("CR", "X")
    ir = metrics.get("IR", "X")
    ar = metrics.get("AR", "X")

    # EQ1
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = "1"
    else:
        eq1 = "2"

    # EQ2
    eq2 = "0" if (ac == "L" and at == "N") else "1"

    # EQ3
    if vc == "H" and vi == "H":
        eq3 = "0"
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = "1"
    else:
        eq3 = "2"

    # EQ4
    if msi == "S" or msa == "S":
        eq4 = "0"
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = "1"
    else:
        eq4 = "2"

    # EQ5 — Exploit Maturity defaults to "Not Defined" (worst-case → 1)
    eq5 = "1"

    # EQ6 — environmental amplification
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = "0"
    else:
        eq6 = "1"

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _cvss40_for_threat(threat: dict, component: dict, flow: dict | None,
                       cross_boundary: bool = False) -> dict:
    """Derive CVSS 4.0 base. Same threat-semantic mapping as 3.1, expanded axes."""
    cat = (threat.get("category") or "").lower()
    title = (threat.get("title") or "").lower()
    ctype = (component or {}).get("type", "")

    # Attack Vector — same logic as 3.1
    if ctype in ("user", "external_entity", "webapp", "mobile_app", "admin_panel", "api", "auth_service", "payment_service"):
        av = "N"
    elif ctype in ("database", "datastore", "cache", "queue", "filesystem", "config"):
        av = "A"
    else:
        av = "N"

    ac = "L"
    if "validat" in title and not cross_boundary:
        ac = "H"

    # Attack Requirements — new in 4.0 (default None)
    at = "N"
    if "phishing" in title or "csrf" in title:
        at = "P"

    pr = "N"
    if flow and flow.get("auth") and flow.get("auth") not in ("", "none"):
        pr = "L"
    if "privilege" in cat or "elevation" in cat:
        pr = "L"
    if ctype in ("database", "datastore", "config", "filesystem"):
        pr = "L"

    ui = "N"
    if "csrf" in title or "phishing" in title:
        ui = "P"

    # Vulnerable system impact (4.0 splits VC/VI/VA from SC/SI/SA)
    vc = vi = va = "N"
    if "disclosure" in cat or "information" in cat or "spoofing" in cat:
        vc = "H"
    if "tampering" in cat or "repudiation" in cat:
        vi = "H"
    if "denial" in cat:
        va = "H"
    if "elevation" in cat or "privilege" in cat:
        vc = vi = "H"; va = "L"
    if ctype in ("database", "datastore", "auth_service", "payment_service") and vc == "N":
        vc = "L"

    # Subsequent system impact — non-zero when crossing scope (cross-boundary)
    sc = si = sa = "N"
    if cross_boundary:
        sc = vc if vc != "N" else "L"
        si = vi if vi != "N" else "L"
        sa = va

    metrics = {
        "AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
        "VC": vc, "VI": vi, "VA": va,
        "SC": sc, "SI": si, "SA": sa,
    }
    macro = _cvss40_macro(metrics)
    score = _CVSS40_MACRO_SCORES.get(macro, 5.0)

    if score == 0:
        sev = "None"
    elif score < 4.0:
        sev = "Low"
    elif score < 7.0:
        sev = "Medium"
    elif score < 9.0:
        sev = "High"
    else:
        sev = "Critical"

    vector = (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/"
        f"VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
    )
    return {
        "vector": vector,
        "metrics": metrics,
        "macro": macro,
        "score": score,
        "severity": sev,
    }


def enrich_threat_with_scoring(threat: dict, component: dict, flow: dict | None,
                               cross_boundary: bool = False) -> dict:
    """Add cvss31, cvss40, cwe to a threat in-place. Returns the same dict."""
    threat["cvss31"] = _cvss31_for_threat(threat, component, flow, cross_boundary)
    threat["cvss40"] = _cvss40_for_threat(threat, component, flow, cross_boundary)
    threat["cwe"] = _cwe_for_threat(threat, component)
    cwe_id = (threat.get("cwe") or {}).get("id","")
    threat["attack"] = CWE_TO_ATTACK.get(cwe_id)
    threat["compliance"] = COMPLIANCE_MAPPING.get(cwe_id, {})
    return threat
