"""Minimal Jira Cloud integration — create an issue from a threat.

Config lives in the encrypted app-settings store (namespace "jira"):
    base_url            e.g. https://acme.atlassian.net
    email               Atlassian account email
    api_token           Atlassian API token (encrypted at rest)
    project_key         e.g. SEC
    default_issue_type  e.g. Task (default) / Bug

Uses stdlib urllib so it adds no dependency. All failures return a structured
{"ok": False, "error": ...} instead of raising, so the API layer can surface a
clean message.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse


def _config() -> dict:
    from db import settings as S
    return {
        "base_url":  (S.get_value("jira", "base_url", "") or "").rstrip("/"),
        "email":     S.get_value("jira", "email", "") or "",
        "api_token": S.get_secret("jira", "api_token"),
        "project_key": S.get_value("jira", "project_key", "") or "",
        "issue_type": S.get_value("jira", "default_issue_type", "") or "Task",
    }


def is_configured() -> bool:
    c = _config()
    return bool(c["base_url"] and c["email"] and c["api_token"] and c["project_key"])


def validate_base_url(url: str) -> str | None:
    """Return an error string if the URL is unsafe/invalid, else None.

    Guards against SSRF: HTTPS only, real hostname, and never a loopback,
    link-local, or private address (an admin should point this at Jira, not at
    an internal service)."""
    try:
        p = urlparse(url)
    except Exception:
        return "Invalid URL."
    if p.scheme != "https":
        return "Jira URL must use https://."
    if not p.hostname:
        return "Jira URL must include a hostname."
    host = p.hostname
    # Resolve and reject private / loopback / link-local targets.
    try:
        for res in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(res[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return "Jira URL must not resolve to a private/internal address."
    except Exception:
        # DNS failure — let the actual request surface a clean error later.
        pass
    return None


def _auth_header(email: str, token: str) -> str:
    return "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()


def _request(method: str, url: str, email: str, token: str, body: dict | None = None, timeout: int = 20):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": _auth_header(email, token),
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode()
        return r.status, (json.loads(raw) if raw else {})


def test_connection() -> dict:
    """Verify credentials by calling /myself. Returns {ok, ...}."""
    c = _config()
    if not (c["base_url"] and c["email"] and c["api_token"]):
        return {"ok": False, "error": "Jira is not fully configured (need base URL, email, and API token)."}
    err = validate_base_url(c["base_url"])
    if err:
        return {"ok": False, "error": err}
    try:
        status, data = _request("GET", f"{c['base_url']}/rest/api/3/myself", c["email"], c["api_token"])
        if status == 200:
            return {"ok": True, "account": data.get("displayName") or data.get("emailAddress") or "connected",
                    "project_key": c["project_key"] or None}
        return {"ok": False, "error": f"Jira returned HTTP {status}."}
    except urllib.error.HTTPError as e:
        detail = "invalid credentials" if e.code in (401, 403) else f"HTTP {e.code}"
        return {"ok": False, "error": f"Jira authentication failed ({detail})."}
    except Exception as e:
        return {"ok": False, "error": f"Could not reach Jira: {type(e).__name__}."}


_PRIORITY_BY_SEVERITY = {"Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low", "Info": "Lowest"}


def create_issue_from_threat(threat: dict, system_name: str = "") -> dict:
    """Create a Jira issue from a threat dict. Returns {ok, key, url} or {ok:False, error}."""
    c = _config()
    if not is_configured():
        return {"ok": False, "error": "Jira is not configured. Ask an admin to set it up in Admin → Settings."}
    err = validate_base_url(c["base_url"])
    if err:
        return {"ok": False, "error": err}

    sev = threat.get("severity", "Medium")
    title = threat.get("title", "Security threat")
    summary = f"[{sev}] {title}"[:250]
    mitigations = threat.get("mitigations") or []
    desc_lines = [
        f"Threat identified by ThreatGuard{(' for ' + system_name) if system_name else ''}.",
        "",
        f"Severity: {sev}",
        f"Component: {threat.get('component_name', 'n/a')}",
        f"Methodology: {(threat.get('methodology', '') or '').upper()}",
        f"Category: {threat.get('category', 'n/a')}",
        "",
        "Description:",
        threat.get("description", "(none)"),
    ]
    if mitigations:
        desc_lines += ["", "Recommended mitigations:"] + [f"- {m}" for m in mitigations]
    description = "\n".join(desc_lines)

    # Jira Cloud v3 uses Atlassian Document Format for the description.
    adf = {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": description}]}
    ]}
    payload = {"fields": {
        "project": {"key": c["project_key"]},
        "summary": summary,
        "description": adf,
        "issuetype": {"name": c["issue_type"]},
    }}
    try:
        status, data = _request("POST", f"{c['base_url']}/rest/api/3/issue",
                                c["email"], c["api_token"], body=payload)
        if status in (200, 201) and data.get("key"):
            return {"ok": True, "key": data["key"], "url": f"{c['base_url']}/browse/{data['key']}"}
        return {"ok": False, "error": f"Jira returned HTTP {status}."}
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            msg = "; ".join(body.get("errorMessages", [])) or json.dumps(body.get("errors", {}))
        except Exception:
            msg = f"HTTP {e.code}"
        return {"ok": False, "error": f"Jira rejected the issue ({msg})."}
    except Exception as e:
        return {"ok": False, "error": f"Could not reach Jira: {type(e).__name__}."}
