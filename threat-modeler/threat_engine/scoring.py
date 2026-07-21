"""CWE, MITRE ATT&CK, and compliance-control mapping for threats.

Maps each threat to a CWE (from its category / component / title), then to a MITRE
ATT&CK technique and SOC 2 / ISO 27001 / PCI-DSS controls via curated CWE tables.
Risk ranking is DREAD (computed in the analyzer); no CVSS is produced.

References:
  - CWE: https://cwe.mitre.org/
  - MITRE ATT&CK: https://attack.mitre.org/
"""
from __future__ import annotations


# CWE → MITRE ATT&CK technique. Covers every CWE the engine can assign (CWE_DB),
# so a threat always resolves to a technique/tactic (used in reports + CSV register).
CWE_TO_ATTACK = {
    "CWE-20":  {"id":"T1190","tactic":"Initial Access","name":"Exploit Public-Facing Application"},
    "CWE-22":  {"id":"T1083","tactic":"Discovery","name":"File and Directory Discovery"},
    "CWE-79":  {"id":"T1059.007","tactic":"Execution","name":"JavaScript/XSS"},
    "CWE-89":  {"id":"T1190","tactic":"Initial Access","name":"Exploit Public-Facing Application"},
    "CWE-200": {"id":"T1552","tactic":"Credential Access","name":"Unsecured Credentials"},
    "CWE-209": {"id":"T1592","tactic":"Reconnaissance","name":"Gather Victim Host Information"},
    "CWE-269": {"id":"T1068","tactic":"Privilege Escalation","name":"Exploitation for Privilege Escalation"},
    "CWE-285": {"id":"T1548","tactic":"Privilege Escalation","name":"Abuse Elevation Control Mechanism"},
    "CWE-287": {"id":"T1110","tactic":"Credential Access","name":"Brute Force"},
    "CWE-306": {"id":"T1190","tactic":"Initial Access","name":"Exploit Public-Facing Application"},
    "CWE-311": {"id":"T1557","tactic":"Collection","name":"Adversary-in-the-Middle"},
    "CWE-319": {"id":"T1040","tactic":"Credential Access","name":"Network Sniffing"},
    "CWE-345": {"id":"T1565","tactic":"Impact","name":"Data Manipulation"},
    "CWE-352": {"id":"T1185","tactic":"Collection","name":"Browser Session Hijacking"},
    "CWE-359": {"id":"T1213","tactic":"Collection","name":"Data from Information Repositories"},
    "CWE-400": {"id":"T1499","tactic":"Impact","name":"Endpoint Denial of Service"},
    "CWE-434": {"id":"T1105","tactic":"Command and Control","name":"Ingress Tool Transfer"},
    "CWE-441": {"id":"T1548","tactic":"Privilege Escalation","name":"Abuse Elevation Control Mechanism"},
    "CWE-502": {"id":"T1059","tactic":"Execution","name":"Command and Scripting Interpreter"},
    "CWE-522": {"id":"T1552","tactic":"Credential Access","name":"Unsecured Credentials"},
    "CWE-601": {"id":"T1566","tactic":"Initial Access","name":"Phishing"},
    "CWE-639": {"id":"T1548","tactic":"Privilege Escalation","name":"Abuse Elevation Control Mechanism"},
    "CWE-693": {"id":"T1562","tactic":"Defense Evasion","name":"Impair Defenses"},
    "CWE-732": {"id":"T1222","tactic":"Defense Evasion","name":"File and Directory Permissions Modification"},
    "CWE-778": {"id":"T1562.008","tactic":"Defense Evasion","name":"Impair Defenses: Disable or Modify Cloud Logs"},
    "CWE-798": {"id":"T1552.001","tactic":"Credential Access","name":"Credentials In Files"},
    "CWE-863": {"id":"T1548","tactic":"Privilege Escalation","name":"Abuse Elevation Control Mechanism"},
    "CWE-918": {"id":"T1090","tactic":"Command and Control","name":"Proxy"},
}

# CWE → SOC 2 / ISO 27001 / PCI-DSS controls. Covers every CWE in CWE_DB so a threat
# always carries compliance-control mapping (shown on the card + exported in the CSV).
COMPLIANCE_MAPPING = {
    "CWE-20":  {"soc2":["CC7.1"],"iso27001":["A.14.2.1"],"pci_dss":["6.2.4"]},
    "CWE-22":  {"soc2":["CC6.1"],"iso27001":["A.9.4.1"],"pci_dss":["6.2.4"]},
    "CWE-79":  {"soc2":["CC7.1"],"iso27001":["A.14.2.5"],"pci_dss":["6.2.4"]},
    "CWE-89":  {"soc2":["CC8.1"],"iso27001":["A.14.2.5"],"pci_dss":["6.3.1"]},
    "CWE-200": {"soc2":["CC6.1"],"iso27001":["A.8.2.3"],"pci_dss":["3.4"]},
    "CWE-209": {"soc2":["CC7.2"],"iso27001":["A.14.2.5"],"pci_dss":["6.2.4"]},
    "CWE-269": {"soc2":["CC6.3"],"iso27001":["A.9.2.3"],"pci_dss":["7.1"]},
    "CWE-285": {"soc2":["CC6.3"],"iso27001":["A.9.4.1"],"pci_dss":["7.1"]},
    "CWE-287": {"soc2":["CC6.1","CC6.2"],"iso27001":["A.9.2.1","A.9.4.2"],"pci_dss":["8.2","8.6"]},
    "CWE-306": {"soc2":["CC6.1"],"iso27001":["A.9.4.2"],"pci_dss":["8.2"]},
    "CWE-311": {"soc2":["CC6.7"],"iso27001":["A.10.1.1"],"pci_dss":["3.4","4.1"]},
    "CWE-319": {"soc2":["CC6.7"],"iso27001":["A.10.1.1"],"pci_dss":["4.1"]},
    "CWE-345": {"soc2":["CC7.1"],"iso27001":["A.14.1.2"],"pci_dss":["6.2.4"]},
    "CWE-352": {"soc2":["CC6.6"],"iso27001":["A.14.1.2"],"pci_dss":["6.3.2"]},
    "CWE-359": {"soc2":["CC6.1"],"iso27001":["A.18.1.4"],"pci_dss":["3.4"]},
    "CWE-400": {"soc2":["A1.1","A1.2"],"iso27001":["A.17.1.1"],"pci_dss":["6.3"]},
    "CWE-434": {"soc2":["CC7.1"],"iso27001":["A.14.2.5"],"pci_dss":["6.2.4"]},
    "CWE-441": {"soc2":["CC6.3"],"iso27001":["A.9.4.1"],"pci_dss":["7.1"]},
    "CWE-502": {"soc2":["CC7.1"],"iso27001":["A.14.2.5"],"pci_dss":["6.2.4"]},
    "CWE-522": {"soc2":["CC6.1"],"iso27001":["A.9.2.4"],"pci_dss":["8.2.1"]},
    "CWE-601": {"soc2":["CC9.2"],"iso27001":["A.7.2.2"],"pci_dss":["12.6"]},
    "CWE-639": {"soc2":["CC6.3"],"iso27001":["A.9.4.1"],"pci_dss":["7.2"]},
    "CWE-693": {"soc2":["CC7.1"],"iso27001":["A.14.2.1"],"pci_dss":["6.2.4"]},
    "CWE-732": {"soc2":["CC6.3"],"iso27001":["A.9.2.3"],"pci_dss":["7.1"]},
    "CWE-778": {"soc2":["CC7.2"],"iso27001":["A.12.4.1"],"pci_dss":["10.2"]},
    "CWE-798": {"soc2":["CC6.1"],"iso27001":["A.9.2.4"],"pci_dss":["8.2.1"]},
    "CWE-863": {"soc2":["CC6.3"],"iso27001":["A.9.4.1"],"pci_dss":["7.1"]},
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


def enrich_threat_with_scoring(threat: dict, component: dict, flow: dict | None,
                               cross_boundary: bool = False) -> dict:
    """Attach a CWE, its MITRE ATT&CK technique, and compliance control mapping to a
    threat in-place. Returns the same dict. (Risk ranking is DREAD, computed in the
    analyzer; no CVSS is produced — there is no concrete CVE to score at model stage.)"""
    threat["cwe"] = _cwe_for_threat(threat, component)
    cwe_id = (threat.get("cwe") or {}).get("id", "")
    threat["attack"] = CWE_TO_ATTACK.get(cwe_id)
    threat["compliance"] = COMPLIANCE_MAPPING.get(cwe_id, {})
    return threat
