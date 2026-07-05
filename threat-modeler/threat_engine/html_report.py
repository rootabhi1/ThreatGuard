"""Standalone interactive HTML report.

Produces a single self-contained .html file the user can open offline.
Includes:
  - Embedded DFD as inline SVG (always renders, no external assets)
  - Severity dashboard with hover/animation
  - Filter chips (severity, methodology, cross-boundary, component)
  - Expandable threat cards with CVSS bars, CWE, attack scenario, mitigations
  - Dedicated 'Untrusted input crossings' section
  - Trust Boundary Analysis with ingress/egress per zone

No external CDNs — everything is inline. The page works with file://.
"""
from __future__ import annotations
import json
import html as html_lib
from datetime import datetime

from .dfd import render_dfd_svg


def _esc(s):
    return html_lib.escape(str(s), quote=True) if s is not None else ""


def _sev_class(sev):
    return {"Critical": "sev-crit", "High": "sev-high", "Medium": "sev-med",
            "Low": "sev-low", "Info": "sev-info"}.get(sev, "sev-med")


def to_html(analysis: dict) -> str:
    system = analysis["system"]
    threats = analysis["threats"]
    summary = analysis["summary"]
    boundaries = system.get("trust_boundaries", []) or []
    flows = system.get("data_flows", []) or []
    components = system.get("components", []) or []
    comp_by_id = {c["id"]: c for c in components}
    untrusted_crossings = analysis.get("untrusted_crossings", []) or []

    dfd_svg = render_dfd_svg(system, animated=True, positions=analysis.get("layout"))

    # Build comp_to_boundary map for the boundary section
    comp_to_b: dict[str, dict] = {}
    for b in boundaries:
        for cid in b.get("contains", []):
            comp_to_b[cid] = b

    cb_count = sum(1 for t in threats if t.get("cross_boundary"))

    # Pre-render threat data as JS (for filtering interactivity).
    # Escape <, >, & and JS line separators so attacker-controlled strings
    # (e.g. a component literally named "</script>...") cannot break out of the
    # <script> block. Stays valid JSON — the browser decodes \u003c back to '<'.
    def _json_for_script(obj):
        return (json.dumps(obj, default=str)
                .replace("<", "\\u003c").replace(">", "\\u003e")
                .replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    threats_js = _json_for_script(threats)
    boundaries_js = _json_for_script(boundaries)
    components_js = _json_for_script(components)
    flows_js = _json_for_script(flows)

    # Boundary palette synced with frontend canvas
    boundary_palette = [
        ("#f43f5e", "#fff1f2"), ("#a855f7", "#faf5ff"), ("#0ea5e9", "#f0f9ff"),
        ("#f59e0b", "#fffbeb"), ("#14b8a6", "#f0fdfa"),
    ]

    # Built here (not inline in the template below) because backslashes inside an
    # f-string expression are a SyntaxError on Python 3.11 (allowed only from 3.12).
    meth_chips = "".join(
        f'<span class="chip" data-meth="{_esc(m)}" onclick="setMeth(\'{_esc(m)}\', this)">{_esc(m.upper())}</span>'
        for m in analysis["methodologies_used"]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Threat Model — {_esc(system.get('name','Untitled'))}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    background: #f8fafc;
    color: #0f172a;
    line-height: 1.55;
  }}
  .container {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
  header {{
    background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
    color: #f8fafc;
    padding: 32px 24px;
    margin-bottom: 24px;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
  }}
  header h1 {{ font-size: 1.75rem; margin-bottom: 8px; }}
  header .meta {{ font-size: 0.875rem; color: #cbd5e1; }}
  header .meta span {{ margin-right: 16px; }}
  h2 {{ font-size: 1.4rem; margin: 24px 0 12px; color: #1e293b; }}
  h3 {{ font-size: 1.1rem; margin: 16px 0 8px; color: #334155; }}

  /* Section cards */
  .card {{
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.03);
  }}

  /* Severity dashboard */
  .sev-grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 20px;
  }}
  .sev-card {{
    padding: 16px;
    border-radius: 10px;
    text-align: center;
    color: white;
    cursor: pointer;
    transition: transform 0.15s, box-shadow 0.15s;
    user-select: none;
  }}
  .sev-card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 16px -8px rgba(0,0,0,0.25); }}
  .sev-card.active {{ outline: 3px solid rgba(255,255,255,0.6); }}
  .sev-card .count {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
  .sev-card .label {{ font-size: 0.85rem; margin-top: 4px; opacity: 0.95; }}
  .sev-crit  {{ background: linear-gradient(135deg, #7c1d1d, #b91c1c); }}
  .sev-high  {{ background: linear-gradient(135deg, #b45309, #d97706); }}
  .sev-med   {{ background: linear-gradient(135deg, #a16207, #ca8a04); }}
  .sev-low   {{ background: linear-gradient(135deg, #15803d, #16a34a); }}
  .sev-info  {{ background: linear-gradient(135deg, #0369a1, #0284c7); }}

  @keyframes critical-pulse {{
    0%,100% {{ box-shadow: 0 0 0 0 rgba(127,29,29,0.5); }}
    50%     {{ box-shadow: 0 0 0 8px rgba(127,29,29,0); }}
  }}
  .sev-crit {{ animation: critical-pulse 2s ease-out infinite; }}

  /* Filter chips */
  .filter-bar {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 16px 0;
    padding: 12px;
    background: #f1f5f9;
    border-radius: 8px;
  }}
  .filter-bar label {{ font-size: 0.85rem; color: #475569; margin-right: 4px; align-self: center; }}
  .chip {{
    display: inline-flex; align-items: center;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 0.8rem;
    background: #fff;
    border: 1px solid #cbd5e1;
    cursor: pointer;
    user-select: none;
    transition: all 0.12s;
  }}
  .chip:hover {{ border-color: #94a3b8; }}
  .chip.active {{ background: #0ea5e9; color: white; border-color: #0284c7; }}
  .chip.active.cb {{ background: #f43f5e; border-color: #e11d48; }}

  /* DFD canvas */
  .dfd-wrap {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    overflow: hidden;
  }}
  .dfd-wrap svg {{ display: block; width: 100%; height: auto; }}

  /* Threat cards */
  .threat-card {{
    background: #fff;
    border: 1px solid #e2e8f0;
    border-left: 4px solid #94a3b8;
    border-radius: 8px;
    margin-bottom: 8px;
    padding: 12px 16px;
    transition: box-shadow 0.15s;
    animation: slide-up 0.25s ease-out backwards;
  }}
  .threat-card.hidden {{ display: none; }}
  .threat-card:hover {{ box-shadow: 0 4px 8px -4px rgba(0,0,0,0.12); }}
  .threat-card.severity-Critical {{ border-left-color: #b91c1c; }}
  .threat-card.severity-High     {{ border-left-color: #d97706; }}
  .threat-card.severity-Medium   {{ border-left-color: #ca8a04; }}
  .threat-card.severity-Low      {{ border-left-color: #16a34a; }}
  .threat-card.severity-Info     {{ border-left-color: #0284c7; }}

  @keyframes slide-up {{ from {{ opacity: 0; transform: translateY(8px); }} to {{ opacity: 1; transform: translateY(0); }} }}

  .threat-header {{
    display: flex;
    align-items: flex-start;
    gap: 8px;
    cursor: pointer;
  }}
  .threat-title {{ flex-grow: 1; font-weight: 600; font-size: 0.98rem; }}
  .threat-meta {{
    display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px;
    font-size: 0.78rem; color: #64748b;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 600;
  }}
  .badge-Critical {{ background: #fee2e2; color: #7c1d1d; }}
  .badge-High     {{ background: #fef3c7; color: #b45309; }}
  .badge-Medium   {{ background: #fef3c7; color: #a16207; }}
  .badge-Low      {{ background: #dcfce7; color: #15803d; }}
  .badge-Info     {{ background: #dbeafe; color: #0369a1; }}
  .badge-cb       {{ background: #fce7f3; color: #be185d; }}
  .badge-cwe      {{ background: #ede9fe; color: #5b21b6; cursor: pointer; }}
  .badge-cwe:hover {{ background: #ddd6fe; }}
  .badge-meth     {{ background: #e0e7ff; color: #3730a3; }}
  .badge-source-llm {{ background: #f3e8ff; color: #6b21a8; }}

  @keyframes badge-pulse {{
    0%,100% {{ transform: scale(1); }}
    50%     {{ transform: scale(1.06); }}
  }}
  .badge-Critical {{ animation: badge-pulse 1.4s ease-in-out infinite; }}

  /* Threat detail (expanded) */
  .threat-detail {{
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid #f1f5f9;
    display: none;
  }}
  .threat-card.expanded .threat-detail {{ display: block; }}
  .threat-card.expanded .expand-icon {{ transform: rotate(180deg); }}
  .expand-icon {{ transition: transform 0.2s; color: #94a3b8; user-select: none; }}

  .detail-section {{ margin-bottom: 14px; }}
  .detail-section h4 {{
    font-size: 0.85rem;
    color: #475569;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 6px;
  }}
  .detail-section .icon {{ font-size: 1rem; }}
  .detail-section p, .detail-section ol, .detail-section ul {{ font-size: 0.9rem; }}
  .detail-section ol, .detail-section ul {{ padding-left: 20px; margin-top: 4px; }}
  .detail-section li {{ margin-bottom: 4px; }}

  .cvss-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }}
  .cvss-block {{
    background: #f8fafc;
    border-radius: 6px;
    padding: 10px;
    border: 1px solid #e2e8f0;
  }}
  .cvss-block .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }}
  .cvss-block .name {{ font-weight: 600; font-size: 0.85rem; color: #475569; }}
  .cvss-block .score {{
    font-size: 1.4rem; font-weight: 700;
    padding: 2px 10px; border-radius: 6px;
  }}
  .cvss-block .score.sev-crit  {{ background: #fee2e2; color: #7c1d1d; }}
  .cvss-block .score.sev-high  {{ background: #ffedd5; color: #b45309; }}
  .cvss-block .score.sev-med   {{ background: #fef3c7; color: #a16207; }}
  .cvss-block .score.sev-low   {{ background: #dcfce7; color: #15803d; }}
  .cvss-block .score.sev-none  {{ background: #f1f5f9; color: #64748b; }}
  .cvss-block .vector {{ font-family: monospace; font-size: 0.72rem; color: #64748b; word-break: break-all; }}
  .cvss-meter {{
    height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; margin-top: 6px;
  }}
  .cvss-meter > div {{ height: 100%; transition: width 0.5s ease-out; }}

  .mitigations-list .mitigation {{
    background: #f0fdf4;
    border-left: 3px solid #16a34a;
    padding: 8px 12px;
    margin-bottom: 6px;
    border-radius: 4px;
  }}
  .mitigations-list .mitigation.detective {{ background: #eff6ff; border-left-color: #2563eb; }}
  .mitigations-list .mitigation.corrective {{ background: #fef3c7; border-left-color: #d97706; }}
  .mitigations-list .mitigation.deterrent {{ background: #f5f3ff; border-left-color: #7c3aed; }}
  .mitigations-list .mitigation .ctype {{
    display: inline-block; font-size: 0.65rem; padding: 1px 6px; border-radius: 3px;
    background: rgba(255,255,255,0.7); color: #475569; text-transform: uppercase;
    letter-spacing: 0.04em; margin-bottom: 2px;
  }}
  .mitigations-list .mitigation .action {{ font-weight: 600; font-size: 0.92rem; }}
  .mitigations-list .mitigation .desc {{ font-size: 0.86rem; color: #334155; margin-top: 2px; }}

  .references a {{
    display: inline-block;
    margin-right: 12px; margin-bottom: 4px;
    color: #2563eb; text-decoration: none;
    font-size: 0.85rem;
    border-bottom: 1px dashed #93c5fd;
  }}
  .references a:hover {{ color: #1e40af; border-bottom-style: solid; }}

  /* Trust boundary cards */
  .boundary-card {{
    border-left: 4px solid #f43f5e;
    background: #fff;
    border-radius: 8px;
    padding: 14px;
    margin-bottom: 12px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.03);
  }}
  .boundary-card h4 {{ font-size: 1rem; color: #334155; margin-bottom: 6px; }}
  .boundary-card .stats {{ font-size: 0.85rem; color: #64748b; margin-bottom: 8px; }}
  .boundary-card .stats span {{ margin-right: 12px; }}
  .flow-list {{ font-size: 0.85rem; }}
  .flow-list li {{ margin-bottom: 4px; }}
  .flow-encrypted {{ color: #15803d; font-weight: 600; }}
  .flow-unencrypted {{ color: #b91c1c; font-weight: 600; }}

  /* Untrusted crossings highlights */
  .untrusted-card {{
    background: linear-gradient(135deg, #fff1f2, #ffe4e6);
    border: 1px solid #fda4af;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
  }}
  .untrusted-card h4 {{ color: #9f1239; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }}
  .untrusted-card .arrow {{
    display: inline-block;
    background: #fff;
    padding: 4px 10px;
    border-radius: 6px;
    font-family: monospace;
    margin: 6px 0;
    border: 1px solid #fda4af;
  }}
  .req-list {{ background: #fff; padding: 10px 14px; border-radius: 6px; margin-top: 8px; }}
  .req-list ul {{ padding-left: 18px; }}
  .req-list li {{ font-size: 0.85rem; margin-bottom: 4px; color: #334155; }}

  .empty {{ color: #64748b; font-style: italic; padding: 8px 0; }}
  .toolbar {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }}
  .btn {{
    padding: 6px 14px;
    border-radius: 6px;
    border: 1px solid #cbd5e1;
    background: #fff;
    cursor: pointer;
    font-size: 0.85rem;
    transition: all 0.12s;
  }}
  .btn:hover {{ background: #f1f5f9; }}
  .btn:active {{ transform: scale(0.98); }}

  /* Search */
  .search-box {{
    width: 100%;
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid #cbd5e1;
    font-size: 0.9rem;
  }}
  .search-box:focus {{ outline: 2px solid #0ea5e9; border-color: #0ea5e9; }}

  /* Subtle reveal */
  section {{ animation: fade-in 0.3s ease-out; }}
  @keyframes fade-in {{ from {{ opacity: 0; transform: translateY(4px); }} to {{ opacity: 1; transform: translateY(0); }} }}

  .count-up {{ display: inline-block; }}
</style>
</head>
<body>
<div class="container">

  <header>
    <h1>{_esc(system.get('name','Untitled System'))}</h1>
    <div class="meta">
      <span><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</span>
      <span><strong>Methodologies:</strong> {', '.join(_esc(m.upper()) for m in analysis['methodologies_used'])}</span>
      <span><strong>LLM-enhanced:</strong> {'Yes' if analysis['llm_used'] else 'No'}</span>
    </div>
  </header>

  {f'<section class="card"><h2>System Description</h2><p>{_esc(system.get("description"))}</p></section>' if system.get('description') else ''}

  <section class="card">
    <h2>Severity Overview</h2>
    <div class="sev-grid">
      <div class="sev-card sev-crit"  data-sev="Critical" onclick="filterBySev('Critical', this)">
        <div class="count">{summary['by_severity'].get('Critical', 0)}</div>
        <div class="label">Critical</div>
      </div>
      <div class="sev-card sev-high"  data-sev="High" onclick="filterBySev('High', this)">
        <div class="count">{summary['by_severity'].get('High', 0)}</div>
        <div class="label">High</div>
      </div>
      <div class="sev-card sev-med"   data-sev="Medium" onclick="filterBySev('Medium', this)">
        <div class="count">{summary['by_severity'].get('Medium', 0)}</div>
        <div class="label">Medium</div>
      </div>
      <div class="sev-card sev-low"   data-sev="Low" onclick="filterBySev('Low', this)">
        <div class="count">{summary['by_severity'].get('Low', 0)}</div>
        <div class="label">Low</div>
      </div>
      <div class="sev-card sev-info"  data-sev="Info" onclick="filterBySev('Info', this)">
        <div class="count">{summary['by_severity'].get('Info', 0)}</div>
        <div class="label">Info</div>
      </div>
    </div>
    <div style="font-size:0.9rem;color:#475569">
      <strong>{summary['total']}</strong> total threats — {summary['rule_based']} rule-based, {summary['llm_enhanced']} LLM-enhanced, <strong style="color:#b91c1c">{cb_count}</strong> cross-boundary.
    </div>
  </section>

  <section class="card">
    <h2>Data Flow Diagram</h2>
    <div class="dfd-wrap">
      {dfd_svg}
    </div>
    <div style="font-size:0.78rem;color:#64748b;margin-top:6px">
      Solid lines = encrypted flows · Dashed red lines = unencrypted or boundary-crossing · 🔒 / ⚠ indicate encryption status. Dashes drift to indicate active flows.
    </div>
  </section>

  <section class="card">
    <h2>🚧 Untrusted-Input Boundary Crossings</h2>
    <p style="font-size:0.9rem;color:#475569;margin-bottom:12px">
      Flows where untrusted (or less-trusted) input crosses into an internal trust zone. These are <strong>the highest-priority validation points</strong> in the system — every byte that enters here must be treated as hostile until proven otherwise.
    </p>
    {_render_untrusted_crossings(untrusted_crossings)}
  </section>

  <section class="card">
    <h2>Trust Boundary Analysis</h2>
    {_render_boundaries_section(boundaries, components, flows, threats, comp_to_b, comp_by_id)}
  </section>

  <section class="card">
    <h2>Threats ({summary['total']})</h2>
    <input type="text" id="search" class="search-box" placeholder="Search threats by title, component, category, CWE, or CVSS vector…" oninput="applyFilters()"/>
    <div class="filter-bar">
      <label>Methodology:</label>
      <span class="chip active" data-meth="all" onclick="setMeth('all', this)">All</span>
      {meth_chips}
      <label style="margin-left:16px">Cross-boundary only:</label>
      <span class="chip cb" id="cb-toggle" onclick="toggleCb(this)">Off</span>
      <span style="flex-grow:1"></span>
      <button class="btn" onclick="resetFilters()">Reset filters</button>
      <button class="btn" onclick="expandAll(true)">Expand all</button>
      <button class="btn" onclick="expandAll(false)">Collapse all</button>
    </div>
    <div id="threat-list">
      {''.join(_render_threat_card(t, i) for i, t in enumerate(threats))}
    </div>
  </section>

  <footer style="text-align:center;color:#94a3b8;font-size:0.85rem;margin-top:20px;padding:20px">
    Generated by the Threat Modeler — drag the canvas, refine layouts, re-run analysis.
  </footer>
</div>

<script>
  const filterState = {{ severity: null, methodology: 'all', cb: false, search: '' }};
  const threats = {threats_js};

  function applyFilters() {{
    filterState.search = document.getElementById('search').value.toLowerCase();
    let visible = 0;
    document.querySelectorAll('.threat-card').forEach((card, idx) => {{
      const t = threats[idx];
      if (!t) return;
      const sev = t.severity;
      const meth = (t.methodology || '').toLowerCase().split(' ')[0];
      const cb = !!t.cross_boundary;

      let show = true;
      if (filterState.severity && sev !== filterState.severity) show = false;
      if (filterState.methodology !== 'all' && filterState.methodology !== meth) show = false;
      if (filterState.cb && !cb) show = false;
      if (filterState.search) {{
        const blob = (t.title + ' ' + (t.component_name || '') + ' ' + t.category + ' ' +
                      (t.cwe ? t.cwe.id + ' ' + t.cwe.name : '') + ' ' +
                      (t.cvss31 ? t.cvss31.vector : '')).toLowerCase();
        if (!blob.includes(filterState.search)) show = false;
      }}
      card.classList.toggle('hidden', !show);
      if (show) visible++;
    }});
    document.querySelector('h2').textContent;  // no-op
  }}

  function filterBySev(sev, el) {{
    if (filterState.severity === sev) {{
      filterState.severity = null;
      el.classList.remove('active');
    }} else {{
      document.querySelectorAll('.sev-card').forEach(c => c.classList.remove('active'));
      el.classList.add('active');
      filterState.severity = sev;
    }}
    applyFilters();
  }}

  function setMeth(m, el) {{
    filterState.methodology = m;
    document.querySelectorAll('.chip[data-meth]').forEach(c => c.classList.remove('active'));
    el.classList.add('active');
    applyFilters();
  }}

  function toggleCb(el) {{
    filterState.cb = !filterState.cb;
    el.classList.toggle('active', filterState.cb);
    el.textContent = filterState.cb ? 'On' : 'Off';
    applyFilters();
  }}

  function resetFilters() {{
    filterState.severity = null;
    filterState.methodology = 'all';
    filterState.cb = false;
    filterState.search = '';
    document.getElementById('search').value = '';
    document.querySelectorAll('.sev-card').forEach(c => c.classList.remove('active'));
    document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    document.querySelector('.chip[data-meth="all"]').classList.add('active');
    document.getElementById('cb-toggle').textContent = 'Off';
    applyFilters();
  }}

  function toggleCard(idx) {{
    const cards = document.querySelectorAll('.threat-card');
    cards[idx].classList.toggle('expanded');
  }}

  function expandAll(open) {{
    document.querySelectorAll('.threat-card').forEach(c => {{
      c.classList.toggle('expanded', open);
    }});
  }}

  // Animate counts on load
  document.addEventListener('DOMContentLoaded', () => {{
    document.querySelectorAll('.sev-card .count').forEach(el => {{
      const target = parseInt(el.textContent, 10);
      let cur = 0;
      const step = Math.max(1, Math.floor(target / 24));
      const iv = setInterval(() => {{
        cur += step;
        if (cur >= target) {{ cur = target; clearInterval(iv); }}
        el.textContent = cur;
      }}, 30);
    }});
  }});
</script>
</body>
</html>
"""


def _render_threat_card(t: dict, idx: int) -> str:
    sev = t.get("severity", "Medium")
    cwe = t.get("cwe") or {}
    c31 = t.get("cvss31") or {}
    c40 = t.get("cvss40") or {}
    cb_badge = '<span class="badge badge-cb">⚡ cross-zone</span>' if t.get("cross_boundary") else ""
    src_label = ""
    if t.get("source") == "llm":
        src_label = '<span class="badge badge-source-llm">🤖 LLM</span>'

    # Score class for CVSS blocks
    def _sc(sev):
        return {"Critical": "sev-crit", "High": "sev-high", "Medium": "sev-med",
                "Low": "sev-low", "None": "sev-none"}.get(sev, "sev-med")

    location_html = _esc(t.get("location", "")).replace("**", "<strong>").replace("**", "</strong>")
    # Smarter bold replacement: alternating
    parts = _esc(t.get("location", "")).split("**")
    rebuilt = ""
    for i, p in enumerate(parts):
        if i % 2 == 1:
            rebuilt += f"<strong>{p}</strong>"
        else:
            rebuilt += p
    location_html = rebuilt
    # Backticks → code style
    location_html = _backticks_to_code(location_html)

    scenario_items = "".join(f"<li>{_esc(s)}</li>" for s in t.get("attack_scenario", []))

    mitigations_html = ""
    for m in t.get("specific_mitigations", []):
        ct = m.get("control_type", "preventive")
        mitigations_html += (
            f'<div class="mitigation {ct}">'
            f'<span class="ctype">{_esc(ct)}</span>'
            f'<div class="action">{_esc(m.get("action",""))}</div>'
            f'<div class="desc">{_esc(m.get("detail",""))}</div>'
            f'</div>'
        )

    refs_html = "".join(
        f'<a href="{_esc(r["url"])}" target="_blank" rel="noopener">{_esc(r["label"])} ↗</a>'
        for r in t.get("references", [])
    )

    dread = t.get("dread", {})
    dread_html = ""
    if dread:
        dread_html = (
            f'<div style="font-size:0.85rem;color:#475569;margin-top:6px">'
            f'<strong>DREAD:</strong> '
            f'D={dread.get("D_damage")}, R={dread.get("R_reproducibility")}, '
            f'E={dread.get("E_exploitability")}, A={dread.get("A_affected_users")}, '
            f'D={dread.get("D_discoverability")} · '
            f'<strong>{dread.get("total")}/50</strong>'
            f'</div>'
        )

    cb_zones = ""
    if t.get("cross_boundary"):
        cb_zones = (
            f'<div style="font-size:0.85rem;color:#9f1239;margin-top:4px">'
            f'<strong>Boundary crossing:</strong> '
            f'{_esc(t.get("src_zone","?"))} → {_esc(t.get("dst_zone","?"))}'
            f'</div>'
        )

    return f"""
<div class="threat-card severity-{sev}" data-idx="{idx}">
  <div class="threat-header" onclick="toggleCard({idx})">
    <div style="flex-grow:1">
      <div class="threat-title">{_esc(t.get("title",""))}</div>
      <div class="threat-meta">
        <span class="badge badge-{sev}">{sev}</span>
        <span class="badge badge-meth">{_esc(t.get("methodology","").upper())}</span>
        <span style="color:#94a3b8">·</span>
        <span>{_esc(t.get("category",""))}</span>
        <span style="color:#94a3b8">·</span>
        <span><strong>{_esc(t.get("component_name",""))}</strong> ({_esc(t.get("component_type",""))})</span>
        {f'<span class="badge badge-cwe" title="{_esc(cwe.get("name",""))}">{_esc(cwe.get("id",""))}</span>' if cwe else ''}
        {cb_badge}
        {src_label}
      </div>
    </div>
    <span class="expand-icon">▼</span>
  </div>
  <div class="threat-detail">
    <div class="cvss-grid">
      <div class="cvss-block">
        <div class="header">
          <span class="name">CVSS 3.1</span>
          <span class="score {_sc(c31.get("severity"))}">{c31.get("score","—")}</span>
        </div>
        <div class="cvss-meter"><div style="width:{(c31.get("score") or 0) * 10}%;background:#dc2626"></div></div>
        <div class="vector">{_esc(c31.get("vector",""))}</div>
      </div>
      <div class="cvss-block">
        <div class="header">
          <span class="name">CVSS 4.0</span>
          <span class="score {_sc(c40.get("severity"))}">{c40.get("score","—")}</span>
        </div>
        <div class="cvss-meter"><div style="width:{(c40.get("score") or 0) * 10}%;background:#7c3aed"></div></div>
        <div class="vector">{_esc(c40.get("vector",""))}</div>
      </div>
    </div>
    {dread_html}
    {cb_zones}

    <div class="detail-section">
      <h4><span class="icon">📍</span>Where the threat exists</h4>
      <p>{location_html}</p>
    </div>
    <div class="detail-section">
      <h4><span class="icon">📝</span>Description</h4>
      <p>{_esc(t.get("description",""))}</p>
    </div>
    <div class="detail-section">
      <h4><span class="icon">⚔️</span>Attack scenario</h4>
      <ol>{scenario_items}</ol>
    </div>
    <div class="detail-section">
      <h4><span class="icon">🛡</span>How to mitigate</h4>
      <div class="mitigations-list">{mitigations_html}</div>
    </div>
    {f'<div class="detail-section references"><h4><span class="icon">🔗</span>References</h4>{refs_html}</div>' if refs_html else ''}
  </div>
</div>
"""


def _backticks_to_code(s: str) -> str:
    out = []
    in_code = False
    for ch in s:
        if ch == "`":
            out.append("</code>" if in_code else "<code style='background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:0.85em'>")
            in_code = not in_code
        else:
            out.append(ch)
    if in_code:
        out.append("</code>")
    return "".join(out)


def _render_untrusted_crossings(crossings: list[dict]) -> str:
    if not crossings:
        return '<p class="empty">No untrusted-input boundary crossings detected. Either there are no internal zones defined, or no flows enter them from less-trusted zones.</p>'
    parts = []
    for c in crossings:
        enc_class = "flow-encrypted" if c["encrypted"] else "flow-unencrypted"
        enc_label = "✅ encrypted" if c["encrypted"] else "❌ unencrypted"
        sev = c.get("highest_severity", "None")
        parts.append(f"""
<div class="untrusted-card">
  <h4>🚧 {_esc(c['source']['name'])} → {_esc(c['destination']['name'])}
    {f'<span class="badge badge-{sev}" style="margin-left:8px">{sev}</span>' if sev != "None" else ''}
  </h4>
  <div class="arrow">
    <strong>{_esc(c['source_zone'])}</strong> → <strong>{_esc(c['destination_zone'])}</strong>
  </div>
  <div style="font-size:0.85rem;color:#475569">
    Flow: <em>{_esc(c['label'] or "(unlabeled)")}</em> · Protocol: <code>{_esc(c['protocol'] or "—")}</code> ·
    Auth: <code>{_esc(c['auth'])}</code> · Encryption: <span class="{enc_class}">{enc_label}</span> ·
    {c['threat_count']} threat{'s' if c['threat_count'] != 1 else ''} on this flow
  </div>
  <div class="req-list">
    <strong style="font-size:0.88rem;color:#9f1239">⚠ Validation requirements at the receiver:</strong>
    <ul>
      {"".join(f"<li>{_esc(r)}</li>" for r in c.get('input_validation_requirements', []))}
    </ul>
  </div>
</div>
""")
    return "\n".join(parts)


def _render_boundaries_section(boundaries, components, flows, threats, comp_to_b, comp_by_id):
    if not boundaries:
        return ('<p class="empty">No trust boundaries defined. All components share the same trust zone — '
                'consider whether the system has implicit boundaries (network perimeter, customer/admin separation, '
                'third-party services) that should be modelled.</p>')

    parts = []
    palette_colors = ["#f43f5e", "#a855f7", "#0ea5e9", "#f59e0b", "#14b8a6"]
    for i, b in enumerate(boundaries):
        color = palette_colors[i % len(palette_colors)]
        contained = [comp_by_id[cid] for cid in b.get("contains", []) if cid in comp_by_id]
        ingress, egress = [], []
        for f in flows:
            f_from_b = comp_to_b.get(f["from"])
            f_to_b   = comp_to_b.get(f["to"])
            if f_to_b and f_to_b["id"] == b["id"] and (not f_from_b or f_from_b["id"] != b["id"]):
                ingress.append(f)
            elif f_from_b and f_from_b["id"] == b["id"] and (not f_to_b or f_to_b["id"] != b["id"]):
                egress.append(f)
        zone_threats = [t for t in threats if t.get("cross_boundary") and
                        t.get("component_id") in [c["id"] for c in contained]]

        def _flow_li(f):
            src = comp_by_id.get(f["from"], {}).get("name", "?")
            dst = comp_by_id.get(f["to"], {}).get("name", "?")
            enc = ('<span class="flow-encrypted">encrypted</span>'
                   if f.get("encrypted") else '<span class="flow-unencrypted">UNENCRYPTED</span>')
            return f"<li>{_esc(src)} → {_esc(dst)} ({_esc(f.get('label','—'))}) — {_esc(f.get('protocol',''))}, auth: <code>{_esc(f.get('auth') or 'none')}</code>, {enc}</li>"

        parts.append(f"""
<div class="boundary-card" style="border-left-color:{color}">
  <h4>🛡 {_esc(b['name'])}</h4>
  <div class="stats">
    <span><strong>{len(contained)}</strong> component{'s' if len(contained) != 1 else ''}</span>
    <span><strong>{len(ingress)}</strong> ingress flow{'s' if len(ingress) != 1 else ''}</span>
    <span><strong>{len(egress)}</strong> egress flow{'s' if len(egress) != 1 else ''}</span>
    <span><strong style="color:#b91c1c">{len(zone_threats)}</strong> cross-boundary threat{'s' if len(zone_threats) != 1 else ''}</span>
  </div>
  {f'<div style="font-size:0.85rem;color:#475569"><strong>Contains:</strong> {", ".join(_esc(c["name"]) + " (" + _esc(c["type"]) + ")" for c in contained)}</div>' if contained else ''}
  {f'<div style="margin-top:10px"><strong style="font-size:0.85rem;color:#15803d">⬇ Ingress (data entering this zone):</strong><ul class="flow-list">{"".join(_flow_li(f) for f in ingress)}</ul></div>' if ingress else ''}
  {f'<div style="margin-top:10px"><strong style="font-size:0.85rem;color:#b45309">⬆ Egress (data leaving this zone):</strong><ul class="flow-list">{"".join(_flow_li(f) for f in egress)}</ul></div>' if egress else ''}
</div>
""")
    return "\n".join(parts)
