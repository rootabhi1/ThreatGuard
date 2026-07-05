"""
threat_engine/executive_report.py
Generate a PDF executive summary report using WeasyPrint (if installed)
or an HTML fallback. Calls Claude to write the narrative sections.
"""
from __future__ import annotations
import json
from datetime import datetime


def _claude_narrative(threats: list[dict], system_name: str) -> dict:
    """Ask the configured LLM to write the exec summary, top risks, and actions."""
    from .llm import complete_text, strip_fences
    sev_counts = {}
    for t in threats:
        s = t.get("severity", "Unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    top5 = sorted(
        [t for t in threats if t.get("severity") in ("Critical", "High")],
        key=lambda t: {"Critical": 0, "High": 1}.get(t.get("severity", ""), 2)
    )[:5]

    prompt = f"""You are a senior security architect writing an executive summary for {system_name}.

Threat model results: {json.dumps({"total": len(threats), "by_severity": sev_counts, "top_threats": [
    {"title": t["title"], "severity": t["severity"], "component": t.get("component_name",""), "description": t.get("description","")} for t in top5
]}, indent=2)}

Write a professional executive summary report with these exact sections:
1. EXECUTIVE_SUMMARY (2-3 sentences, business-level language)
2. KEY_FINDINGS (3-4 bullet points)
3. TOP_RISKS (list top 3 risks with business impact)
4. RECOMMENDED_ACTIONS (prioritised list of 4-5 immediate actions)
5. RISK_POSTURE (one sentence: overall risk level and trend)

Return ONLY valid JSON with these 5 keys, no markdown, no preamble."""

    text = complete_text(prompt, max_tokens=1500)
    if not text:
        raise RuntimeError("no LLM response")
    return json.loads(strip_fences(text))


def generate_executive_report(analysis: dict, api_key: str | None = None) -> str:
    """Generate an executive HTML report. Returns HTML string."""
    threats     = analysis.get("threats", [])
    system_name = analysis.get("system", {}).get("name", "System")
    summary     = analysis.get("summary", {})
    date_str    = datetime.utcnow().strftime("%B %d, %Y")

    sev_colors  = {"Critical": "#e11d48", "High": "#f97316", "Medium": "#eab308", "Low": "#3b82f6", "Info": "#94a3b8"}

    # Try LLM narrative, fall back to template
    from .llm import llm_available
    narrative = None
    if llm_available():
        try:
            narrative = _claude_narrative(threats, system_name)
        except Exception as e:
            print(f"[exec_report] LLM narrative failed: {e}")

    if not narrative:
        crit = summary.get("by_severity", {}).get("Critical", 0)
        high = summary.get("by_severity", {}).get("High", 0)
        narrative = {
            "EXECUTIVE_SUMMARY": f"The threat model for {system_name} identified {summary.get('total', 0)} security threats across {len(set(t.get('component_name','') for t in threats))} components. Immediate attention is required for {crit} Critical and {high} High severity findings.",
            "KEY_FINDINGS": [f"{v} {k} severity threats identified" for k, v in summary.get("by_severity", {}).items() if v],
            "TOP_RISKS":    [f"{t.get('severity')}: {t.get('title')} ({t.get('component_name')})" for t in threats[:3]],
            "RECOMMENDED_ACTIONS": ["Review and remediate all Critical threats immediately", "Assign owners and due dates to High severity findings", "Re-run threat model after architectural changes", "Enable LLM-enhanced analysis for deeper coverage"],
            "RISK_POSTURE": f"Overall risk posture is {'Critical' if crit > 0 else 'High' if high > 0 else 'Medium'} — immediate remediation action required.",
        }

    def li_items(items):
        if isinstance(items, list):
            return "".join(f"<li>{i}</li>" for i in items)
        return f"<li>{items}</li>"

    sev_bars = "".join(
        f'''<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
          <span style="width:80px;text-align:right;font-size:13px;font-weight:600;color:{sev_colors.get(s,"#333")}">{s}</span>
          <div style="flex:1;background:#f1f5f9;border-radius:4px;height:18px;overflow:hidden;">
            <div style="width:{round(c/max(1,summary.get("total",1))*100)}%;height:100%;background:{sev_colors.get(s,"#333")};border-radius:4px;"></div>
          </div>
          <span style="font-size:13px;color:#64748b;width:24px;">{c}</span>
        </div>'''
        for s, c in summary.get("by_severity", {}).items()
    )

    top_threats_rows = "".join(
        f'''<tr>
          <td style="padding:10px;font-weight:700;color:{sev_colors.get(t.get("severity",""),"#333")};border-bottom:1px solid #e2e8f0;">{t.get("severity","")}</td>
          <td style="padding:10px;border-bottom:1px solid #e2e8f0;">{t.get("title","")}</td>
          <td style="padding:10px;color:#64748b;border-bottom:1px solid #e2e8f0;">{t.get("component_name","")}</td>
          <td style="padding:10px;color:#64748b;font-size:12px;border-bottom:1px solid #e2e8f0;">{t.get("methodology","").upper()}</td>
        </tr>'''
        for t in threats if t.get("severity") in ("Critical", "High")
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>Executive Threat Model Report — {system_name}</title>
<style>
  body {{ font-family: Georgia, serif; max-width: 800px; margin: 0 auto; padding: 40px 32px; color: #1e293b; }}
  h1 {{ font-size: 28px; color: #0f172a; border-bottom: 3px solid #6366f1; padding-bottom: 12px; }}
  h2 {{ font-size: 18px; color: #0f172a; margin-top: 32px; }}
  .meta {{ color: #64748b; font-size: 14px; margin-bottom: 32px; }}
  .summary-box {{ background: #f8fafc; border-left: 4px solid #6366f1; padding: 16px 20px; border-radius: 0 8px 8px 0; margin: 16px 0; }}
  ul {{ padding-left: 20px; }} li {{ margin-bottom: 6px; font-size: 14px; line-height: 1.6; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th {{ background: #f1f5f9; text-align: left; padding: 10px; font-size: 12px; color: #64748b; }}
  .risk-posture {{ background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 14px 18px; margin-top: 24px; font-size: 14px; color: #991b1b; font-weight: 600; }}
  .footer {{ color: #94a3b8; font-size: 12px; margin-top: 48px; border-top: 1px solid #e2e8f0; padding-top: 16px; }}
  @media print {{ body {{ padding: 20px; }} }}
</style></head><body>

<h1>Executive Threat Model Report</h1>
<div class="meta">
  <strong>System:</strong> {system_name} &nbsp;|&nbsp;
  <strong>Date:</strong> {date_str} &nbsp;|&nbsp;
  <strong>Total threats:</strong> {summary.get("total", 0)}
</div>

<h2>Executive Summary</h2>
<div class="summary-box">{narrative["EXECUTIVE_SUMMARY"]}</div>

<h2>Severity Breakdown</h2>
{sev_bars}

<h2>Key Findings</h2>
<ul>{li_items(narrative["KEY_FINDINGS"])}</ul>

<h2>Top Risks</h2>
<ul>{li_items(narrative["TOP_RISKS"])}</ul>

<h2>Critical &amp; High Severity Threats</h2>
<table>
  <thead><tr><th>Severity</th><th>Title</th><th>Component</th><th>Framework</th></tr></thead>
  <tbody>{top_threats_rows}</tbody>
</table>

<h2>Recommended Actions</h2>
<ul>{li_items(narrative["RECOMMENDED_ACTIONS"])}</ul>

<div class="risk-posture">⚠ Risk Posture: {narrative["RISK_POSTURE"]}</div>

<div class="footer">Generated by Automated Threat Modeler · {date_str}</div>
</body></html>"""


def html_to_pdf(html: str) -> bytes | None:
    """Convert HTML to PDF bytes using WeasyPrint if available."""
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except ImportError:
        return None
