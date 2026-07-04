"""
threat_engine/notifications.py
Send Slack webhook or email alerts when new Critical/High threats appear after
a re-analysis compared to the previous run.

Env vars:
  SLACK_WEBHOOK_URL              — POST new-threat alerts here
  SMTP_HOST / SMTP_PORT          — e.g. smtp.sendgrid.net / 587
  SMTP_USER / SMTP_PASS          — SMTP credentials
  NOTIFY_EMAIL_FROM              — sender address
  NOTIFY_EMAIL_TO                — comma-separated recipient list
  NOTIFY_THRESHOLD               — "critical" | "high" | "all"  (default: high)
"""
from __future__ import annotations
import os, json, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import urllib.request


THRESHOLD_MAP = {"critical": {"Critical"}, "high": {"Critical", "High"}, "all": {"Critical", "High", "Medium", "Low", "Info"}}


def _should_notify(severity: str) -> bool:
    threshold = os.getenv("NOTIFY_THRESHOLD", "high").lower()
    return severity in THRESHOLD_MAP.get(threshold, THRESHOLD_MAP["high"])


def diff_threats(old_threats: list[dict], new_threats: list[dict]) -> list[dict]:
    """Return threats that are new (by title+component) and above the notify threshold."""
    old_keys = {(t.get("title", ""), t.get("component_name", "")) for t in old_threats}
    return [
        t for t in new_threats
        if (t.get("title", ""), t.get("component_name", "")) not in old_keys
        and _should_notify(t.get("severity", ""))
    ]


def notify_slack(new_threats: list[dict], system_name: str) -> bool:
    """POST a Slack message for each new threat. Returns True if sent."""
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook or not new_threats:
        return False

    SEV_EMOJI = {"Critical": "🚨", "High": "⚠️", "Medium": "🔶", "Low": "🔷", "Info": "ℹ️"}
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"🛡 New threats detected — {system_name}"}},
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f"*{len(new_threats)} new threat(s)* found above notification threshold after re-analysis."}},
        {"type": "divider"},
    ]
    for t in new_threats[:5]:  # cap at 5 to avoid huge messages
        emoji = SEV_EMOJI.get(t.get("severity", ""), "⚠️")
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"{emoji} *{t.get('severity')}* | *{t.get('title')}*\n"
                    f"Component: `{t.get('component_name', '?')}` | {t.get('methodology', '').upper()}\n"
                    f"_{t.get('description', '')[:120]}…_"}})
    if len(new_threats) > 5:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"…and {len(new_threats) - 5} more. Open the threat model for the full list."}})

    payload = json.dumps({"blocks": blocks}).encode()
    req = urllib.request.Request(webhook, data=payload,
                                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=8)
        return True
    except Exception as e:
        print(f"[notifications] Slack error: {e}")
        return False


def notify_email(new_threats: list[dict], system_name: str) -> bool:
    """Send an HTML email digest of new threats. Returns True if sent."""
    host    = os.getenv("SMTP_HOST")
    port    = int(os.getenv("SMTP_PORT", "587"))
    user    = os.getenv("SMTP_USER")
    passwd  = os.getenv("SMTP_PASS")
    from_   = os.getenv("NOTIFY_EMAIL_FROM", user or "")
    to_raw  = os.getenv("NOTIFY_EMAIL_TO", "")
    to_list = [e.strip() for e in to_raw.split(",") if e.strip()]

    if not all([host, user, passwd, from_, to_list]) or not new_threats:
        return False

    SEV_COLOR = {"Critical": "#e11d48", "High": "#f97316", "Medium": "#eab308", "Low": "#3b82f6", "Info": "#94a3b8"}
    rows = "".join(
        f'''<tr>
          <td style="padding:8px;border-bottom:1px solid #e2e8f0;font-weight:600;color:{SEV_COLOR.get(t.get("severity",""),"#333")}">
            {t.get("severity","")}
          </td>
          <td style="padding:8px;border-bottom:1px solid #e2e8f0;">{t.get("title","")}</td>
          <td style="padding:8px;border-bottom:1px solid #e2e8f0;color:#64748b;">{t.get("component_name","")}</td>
        </tr>'''
        for t in new_threats
    )
    html_body = f"""
    <html><body style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:24px;">
      <h2 style="color:#0f172a;">🛡 New threats detected — {system_name}</h2>
      <p style="color:#475569;">{len(new_threats)} new threat(s) found above notification threshold.</p>
      <table style="width:100%;border-collapse:collapse;margin-top:16px;">
        <thead><tr>
          <th style="text-align:left;padding:8px;background:#f8fafc;font-size:12px;color:#64748b;">SEVERITY</th>
          <th style="text-align:left;padding:8px;background:#f8fafc;font-size:12px;color:#64748b;">TITLE</th>
          <th style="text-align:left;padding:8px;background:#f8fafc;font-size:12px;color:#64748b;">COMPONENT</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p style="color:#94a3b8;font-size:12px;margin-top:24px;">
        Sent by Automated Threat Modeler
      </p>
    </body></html>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[ATM] {len(new_threats)} new threat(s) in {system_name}"
    msg["From"]    = from_
    msg["To"]      = ", ".join(to_list)
    msg.attach(MIMEText(html_body, "html"))
    try:
        with smtplib.SMTP(host, port) as srv:
            srv.starttls()
            srv.login(user, passwd)
            srv.sendmail(from_, to_list, msg.as_string())
        return True
    except Exception as e:
        print(f"[notifications] Email error: {e}")
        return False


def notify_all(new_threats: list[dict], system_name: str) -> dict:
    """Try both Slack and email. Returns summary of what was sent."""
    slack = notify_slack(new_threats, system_name)
    email = notify_email(new_threats, system_name)
    return {"slack": slack, "email": email, "threats_notified": len(new_threats)}
