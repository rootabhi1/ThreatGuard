"""Report generator. Produces Markdown and PDF output from an analysis result."""
from __future__ import annotations

import io
from datetime import datetime

from .dfd import render_dfd_svg, build_flow_legend
from .analyzer import summarize_llm_status


def to_markdown(analysis: dict) -> str:
    system = analysis["system"]
    threats = analysis["threats"]
    summary = analysis["summary"]
    boundaries = system.get("trust_boundaries", []) or []
    flows = system.get("data_flows", []) or []
    components = system.get("components", []) or []
    comp_by_id = {c["id"]: c for c in components}

    lines: list[str] = []
    lines.append(f"# Threat Model Report: {system.get('name','Untitled System')}")
    lines.append("")
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Methodologies:** {', '.join(analysis['methodologies_used']).upper()}")
    lines.append(f"**LLM-enhanced:** {summarize_llm_status(analysis)}")
    lines.append("")

    if system.get("description"):
        lines.append("## System Description")
        lines.append("")
        lines.append(system["description"])
        lines.append("")

    # ---- Model health (what normalization repaired or flagged) ----
    model_issues = analysis.get("model_issues") or []
    if model_issues:
        _icons = {"error": "⛔", "warning": "⚠", "info": "ℹ"}
        _rank = {"error": 0, "warning": 1, "info": 2}
        lines.append("## Model health")
        lines.append("")
        lines.append("The following items were auto-resolved or flagged during analysis:")
        lines.append("")
        for i in sorted(model_issues, key=lambda x: _rank.get(x.get("level"), 3)):
            lines.append(f"- {_icons.get(i.get('level'), 'ℹ')} {i.get('message', '')}")
        lines.append("")

    # ---- Assumptions (what was inferred, not stated) ----
    assumptions = analysis.get("assumptions") or []
    if assumptions:
        lines.append("## Assumptions")
        lines.append("")
        lines.append("_What was inferred when the model was seeded from text, not explicitly stated:_")
        lines.append("")
        for a in assumptions:
            lines.append(f"- {a}")
        lines.append("")

    # ---- Data-flow overview (plain language, before the diagram) ----
    dfs = analysis.get("dataflow_summary")
    if dfs:
        def _md(s):
            return str(s).replace("|", "\\|")
        lines.append("## Data-flow overview")
        lines.append("")
        lines.append(dfs.get("narrative", ""))
        lines.append("")
        st = dfs.get("stats", {})
        lines.append(f"- **Entry points:** {', '.join(dfs.get('entry_points') or ['—'])}")
        lines.append(f"- **Data stores:** {', '.join(dfs.get('data_stores') or ['—'])}")
        lines.append(f"- **External dependencies:** {', '.join(dfs.get('external_deps') or ['—'])}")
        lines.append(f"- **Boundary crossings:** {st.get('crossings', 0)}  |  "
                     f"**Unencrypted flows:** {st.get('unencrypted', 0)}")
        lines.append("")
        risky = dfs.get("risky_flows") or []
        if risky:
            lines.append("### Riskiest flows")
            lines.append("")
            lines.append("| Flow | Why it's risky | Severity |")
            lines.append("|---|---|---|")
            for r in risky[:8]:
                lines.append(f"| {_md(r['from'])} → {_md(r['to'])} | "
                             f"{'; '.join(r['reasons'])} | {r.get('severity') or '—'} |")
            lines.append("")
        hs = dfs.get("hotspots") or []
        if hs:
            lines.append("### Risk hotspots")
            lines.append("")
            for h in hs:
                lines.append(f"- **{h['component']}** — {h['critical']} critical, "
                             f"{h['high']} high ({h['total']} total)")
            lines.append("")
        if dfs.get("assumptions"):
            lines.append(f"> ⚠ {dfs['assumptions']}")
            lines.append("")

    # ---- DFD embed ----
    lines.append("## Data Flow Diagram")
    lines.append("")
    svg = render_dfd_svg(system, animated=False,
                        positions=system.get("layout") or analysis.get("layout"))
    # Embed as INLINE SVG. Renders correctly in GitHub, GitLab, VS Code,
    # Typora, Obsidian — far more compatible than base64 data URIs.
    # We strip the XML declaration line because some Markdown parsers reject it.
    svg_inline = svg
    if svg_inline.startswith("<?xml"):
        svg_inline = svg_inline.split("?>", 1)[-1].lstrip()
    lines.append(svg_inline)
    lines.append("")
    lines.append("*Numbered badges key to the flow legend below · Solid lines = encrypted · "
                 "Dashed red lines / red badges = unencrypted or boundary-crossing.*")
    lines.append("")
    legend = build_flow_legend(system)
    if legend:
        # Collapse a long legend so it doesn't bury the diagram (GitHub/most viewers
        # render <details>); short ones stay open.
        collapse = len(legend) > 8
        if collapse:
            lines.append(f"<details><summary>Flow legend ({len(legend)} flows)</summary>")
            lines.append("")
        else:
            lines.append("### Flow legend")
            lines.append("")
        lines.append("| # | Flow | Protocol | Auth | Security |")
        lines.append("|---|---|---|---|---|")
        for f in legend:
            sec = ("plaintext" if not f["encrypted"] else "encrypted") + \
                  (" · crosses boundary" if f["crosses"] else "")
            lines.append(f"| {f['n']} | {f['from']} → {f['to']} | "
                         f"{f['protocol'] or '—'} | {f['auth']} | {sec} |")
        lines.append("")
        if collapse:
            lines.append("</details>")
            lines.append("")
    # Also list trust boundaries explicitly so even non-SVG-rendering tools see them
    boundaries = system.get("trust_boundaries", []) or []
    if boundaries:
        comp_by_id = {c["id"]: c for c in system.get("components", [])}
        lines.append("### Trust Boundaries")
        lines.append("")
        for b in boundaries:
            contained_names = [comp_by_id.get(cid, {}).get("name", cid)
                              for cid in b.get("contains", [])]
            lines.append(f"- **{b['name']}** — contains: {', '.join(contained_names) or '(none)'}")
        lines.append("")

    # Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Total threats identified:** {summary['total']}")
    lines.append(f"- **Rule-based:** {summary['rule_based']}  |  **LLM-enhanced:** {summary['llm_enhanced']}")
    lines.append(f"- **Cross-boundary threats:** {sum(1 for t in threats if t.get('cross_boundary'))}")
    lines.append("")
    lines.append("### Threats by severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        lines.append(f"| {sev} | {summary['by_severity'].get(sev, 0)} |")
    lines.append("")

    # Framework coverage (OWASP Web/API/Mobile/LLM/Agentic).
    _fw_counts: dict[str, int] = {}
    for t in threats:
        for fr in t.get("frameworks", []):
            _fw_counts[fr["framework"]] = _fw_counts.get(fr["framework"], 0) + 1
    if _fw_counts:
        _fw_names = {"WEB": "OWASP Web", "API": "OWASP API", "MOBILE": "OWASP Mobile",
                     "LLM": "OWASP LLM", "AGENTIC": "OWASP Agentic"}
        lines.append("### Framework coverage")
        lines.append("")
        lines.append(" · ".join(f"**{_fw_names[k]}:** {_fw_counts[k]}"
                                 for k in ["WEB", "API", "MOBILE", "LLM", "AGENTIC"] if k in _fw_counts))
        lines.append("")

    # Components
    lines.append("## System Components")
    lines.append("")
    lines.append("| Name | Type | Description |")
    lines.append("|---|---|---|")
    for c in components:
        desc = (c.get("description") or "").replace("|", "\\|")
        lines.append(f"| {c['name']} | `{c['type']}` | {desc} |")
    lines.append("")

    # Data flows
    if flows:
        lines.append("## Data Flows")
        lines.append("")
        lines.append("| From | To | Label | Protocol | Auth | Encrypted | Crosses boundary |")
        lines.append("|---|---|---|---|---|---|---|")
        comp_boundary = {}
        for b in boundaries:
            for cid in b.get("contains", []):
                comp_boundary[cid] = b["name"]
        for f in flows:
            crosses = comp_boundary.get(f["from"]) != comp_boundary.get(f["to"])
            lines.append(
                f"| {comp_by_id.get(f['from'], {}).get('name', f['from'])} "
                f"| {comp_by_id.get(f['to'], {}).get('name', f['to'])} "
                f"| {f.get('label','')} | {f.get('protocol','')} "
                f"| {f.get('auth') or '—'} | {'Yes' if f.get('encrypted') else 'No'} "
                f"| {'**Yes**' if crosses else 'No'} |"
            )
        lines.append("")

    # ---- Untrusted-Input Boundary Crossings ----
    untrusted = analysis.get("untrusted_crossings", []) or []
    lines.append("## 🚧 Untrusted-Input Boundary Crossings")
    lines.append("")
    lines.append("Flows where untrusted (or less-trusted) input crosses into an internal trust zone. These are the highest-priority validation points in the system — every byte that enters here must be treated as hostile until proven otherwise.")
    lines.append("")
    if not untrusted:
        lines.append("*No untrusted-input boundary crossings detected.*")
        lines.append("")
    else:
        for c in untrusted:
            sev = c.get("highest_severity", "None")
            sev_str = f" — **{sev}**" if sev != "None" else ""
            lines.append(f"### {c['source']['name']} → {c['destination']['name']}{sev_str}")
            lines.append("")
            lines.append(f"**Zones:** `{c['source_zone']}` → `{c['destination_zone']}`  ")
            lines.append(f"**Flow:** *{c['label'] or '(unlabeled)'}* · Protocol `{c['protocol'] or '—'}` · "
                         f"Auth `{c['auth']}` · "
                         f"Encryption: {'**encrypted**' if c['encrypted'] else '**❌ UNENCRYPTED**'}  ")
            lines.append(f"**Threats on this flow:** {c['threat_count']}")
            lines.append("")
            lines.append("**⚠ Validation requirements at the receiver:**")
            lines.append("")
            for r in c.get("input_validation_requirements", []):
                lines.append(f"- {r}")
            lines.append("")

    # ---- Trust Boundary Analysis ----
    lines.append("## Trust Boundary Analysis")
    lines.append("")
    if not boundaries:
        lines.append("*No trust boundaries defined.* All components share the same trust zone — consider whether the system actually has implicit boundaries (network perimeter, customer/admin separation, third-party services) that should be modelled.")
        lines.append("")
    else:
        comp_boundary_map = {}
        for b in boundaries:
            for cid in b.get("contains", []):
                comp_boundary_map[cid] = b
        for b in boundaries:
            lines.append(f"### 🛡 {b['name']}")
            lines.append("")
            contained = [comp_by_id[cid] for cid in b.get("contains", []) if cid in comp_by_id]
            if contained:
                lines.append("**Components inside this zone:**")
                lines.append("")
                for c in contained:
                    lines.append(f"- {c['name']} (`{c['type']}`)")
                lines.append("")
            # Crossing flows for this boundary
            ingress, egress = [], []
            for f in flows:
                f_from_b = comp_boundary_map.get(f["from"])
                f_to_b = comp_boundary_map.get(f["to"])
                if f_to_b and f_to_b["id"] == b["id"] and (not f_from_b or f_from_b["id"] != b["id"]):
                    ingress.append(f)
                elif f_from_b and f_from_b["id"] == b["id"] and (not f_to_b or f_to_b["id"] != b["id"]):
                    egress.append(f)
            if ingress:
                lines.append("**Ingress (data entering this zone):**")
                lines.append("")
                for f in ingress:
                    src = comp_by_id.get(f["from"], {}).get("name", "?")
                    dst = comp_by_id.get(f["to"], {}).get("name", "?")
                    lines.append(f"- {src} → {dst} ({f.get('label','')}) — {f.get('protocol','')}, auth: {f.get('auth') or 'none'}, encrypted: {'yes' if f.get('encrypted') else 'NO'}")
                lines.append("")
            if egress:
                lines.append("**Egress (data leaving this zone):**")
                lines.append("")
                for f in egress:
                    src = comp_by_id.get(f["from"], {}).get("name", "?")
                    dst = comp_by_id.get(f["to"], {}).get("name", "?")
                    lines.append(f"- {src} → {dst} ({f.get('label','')}) — {f.get('protocol','')}, auth: {f.get('auth') or 'none'}, encrypted: {'yes' if f.get('encrypted') else 'NO'}")
                lines.append("")
            # Cross-boundary threats touching components in this zone
            zone_threats = [t for t in threats if t.get("cross_boundary") and
                            (t["component_id"] in [c["id"] for c in contained])]
            if zone_threats:
                lines.append(f"**Cross-boundary threats affecting this zone:** {len(zone_threats)}")
                lines.append("")

    # Threats — grouped by severity
    lines.append("## Identified Threats")
    lines.append("")
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    by_sev: dict[str, list[dict]] = {s: [] for s in severity_order}
    for t in threats:
        by_sev.setdefault(t["severity"], []).append(t)

    for sev in severity_order:
        items = by_sev.get(sev, [])
        if not items:
            continue
        lines.append(f"### {sev} ({len(items)})")
        lines.append("")
        for t in items:
            cb = " 🚧 *cross-boundary*" if t.get("cross_boundary") else ""
            lines.append(f"#### {t['title']}{cb}")
            lines.append("")
            cwe = t.get("cwe") or {}
            c31 = t.get("cvss31") or {}
            c40 = t.get("cvss40") or {}
            lines.append(f"- **Methodology / Category:** {t['methodology']} → {t['category']}")
            lines.append(f"- **Affected component:** {t['component_name']} (`{t['component_type']}`)")
            if cwe:
                lines.append(f"- **CWE:** [{cwe.get('id')} — {cwe.get('name')}]({cwe.get('url')})")
            if c31:
                lines.append(f"- **CVSS 3.1:** **{c31.get('score')}** ({c31.get('severity')}) — `{c31.get('vector')}`")
            if c40:
                lines.append(f"- **CVSS 4.0:** **{c40.get('score')}** ({c40.get('severity')}) — `{c40.get('vector')}`")
            if t.get("cross_boundary"):
                lines.append(f"- **Boundary crossing:** {t.get('src_zone','?')} → {t.get('dst_zone','?')}")
            lines.append(f"- **Source:** {t['source']}")
            d = t.get("dread", {})
            if d:
                lines.append(
                    f"- **DREAD:** D={d.get('D_damage')}, R={d.get('R_reproducibility')}, "
                    f"E={d.get('E_exploitability')}, A={d.get('A_affected_users')}, "
                    f"D={d.get('D_discoverability')} → **Total {d.get('total')}/50**"
                )
            lines.append("")
            if t.get("location"):
                lines.append(f"**📍 Where the threat exists:** {t['location']}")
                lines.append("")
            lines.append(f"**📝 Description:** {t['description']}")
            lines.append("")
            if t.get("attack_scenario"):
                lines.append("**⚔️ Attack scenario:**")
                lines.append("")
                for i, s in enumerate(t["attack_scenario"], 1):
                    lines.append(f"{i}. {s}")
                lines.append("")
            if t.get("specific_mitigations"):
                lines.append("**🛡 How to mitigate:**")
                lines.append("")
                for m in t["specific_mitigations"]:
                    lines.append(f"- _[{m.get('control_type','preventive')}]_ **{m.get('action','')}** — {m.get('detail','')}")
                lines.append("")
            elif t.get("mitigations"):
                # legacy fallback for any threat that hasn't been enriched
                lines.append("**Mitigations:**")
                lines.append("")
                for m in t["mitigations"]:
                    lines.append(f"- {m}")
                lines.append("")
            if t.get("references"):
                refs = " · ".join(f"[{r['label']}]({r['url']})" for r in t["references"])
                lines.append(f"**🔗 References:** {refs}")
                lines.append("")

    return "\n".join(lines)


def to_pdf(analysis: dict) -> bytes:
    """Render a PDF using ReportLab. Self-contained; no external deps beyond the lib."""
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )

    # Try to render the DFD into the PDF. svglib is the standard pairing with ReportLab;
    # if it's not installed we fall back to a textual placeholder.
    dfd_drawing = None
    try:
        from svglib.svglib import svg2rlg
        from reportlab.graphics import renderPDF  # noqa: F401  -- presence-check
        svg_str = render_dfd_svg(analysis["system"], animated=False,
                                 positions=analysis["system"].get("layout") or analysis.get("layout"))
        # svglib requires a file-like object
        dfd_drawing = svg2rlg(io.StringIO(svg_str))
    except Exception as e:
        # silently fall back; reason is logged for the developer
        print(f"[pdf-dfd] svg2rlg unavailable: {e}")
        dfd_drawing = None

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
    )
    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]; h2 = styles["Heading2"]; h3 = styles["Heading3"]
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10, textColor=colors.grey)

    sev_colors = {
        "Critical": colors.HexColor("#7c1d1d"),
        "High":     colors.HexColor("#b45309"),
        "Medium":   colors.HexColor("#a16207"),
        "Low":      colors.HexColor("#15803d"),
        "Info":     colors.HexColor("#0369a1"),
    }

    system = analysis["system"]
    threats = analysis["threats"]
    summary = analysis["summary"]
    boundaries = system.get("trust_boundaries", []) or []
    flows = system.get("data_flows", []) or []
    components = system.get("components", []) or []
    comp_by_id = {c["id"]: c for c in components}
    story = []

    story.append(Paragraph(f"Threat Model Report: {system.get('name','Untitled System')}", h1))
    story.append(Paragraph(
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp; "
        f"Methodologies: {', '.join(analysis['methodologies_used']).upper()} &nbsp;|&nbsp; "
        f"LLM-enhanced: {summarize_llm_status(analysis)}", small))
    story.append(Spacer(1, 0.18 * inch))

    if system.get("description"):
        story.append(Paragraph("System Description", h2))
        story.append(Paragraph(system["description"].replace("\n", "<br/>"), body))
        story.append(Spacer(1, 0.12 * inch))

    def _e(s):
        return (str(s if s is not None else "")
                .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    # ---- Model health (what normalization repaired or flagged) ----
    model_issues = analysis.get("model_issues") or []
    if model_issues:
        _icons = {"error": "!", "warning": "!", "info": "i"}
        _rank = {"error": 0, "warning": 1, "info": 2}
        story.append(Paragraph("Model health", h2))
        story.append(Paragraph(
            "The following items were auto-resolved or flagged during analysis:", small))
        for i in sorted(model_issues, key=lambda x: _rank.get(x.get("level"), 3)):
            story.append(Paragraph(
                f"[{_icons.get(i.get('level'), 'i')}] {_e(i.get('message', ''))}", small))
        story.append(Spacer(1, 0.14 * inch))

    # ---- Assumptions (what was inferred, not stated) ----
    assumptions = analysis.get("assumptions") or []
    if assumptions:
        story.append(Paragraph("Assumptions", h2))
        story.append(Paragraph(
            "What was inferred when the model was seeded from text, not explicitly stated:", small))
        for a in assumptions:
            story.append(Paragraph(f"- {_e(a)}", small))
        story.append(Spacer(1, 0.14 * inch))

    # ---- Data-flow overview (plain-language, before the diagram) ----
    dfs = analysis.get("dataflow_summary")
    if dfs:
        story.append(Paragraph("Data-flow overview", h2))
        story.append(Paragraph(_e(dfs.get("narrative", "")), body))
        st = dfs.get("stats", {})
        story.append(Paragraph(
            f"<b>Entry points:</b> {_e(', '.join(dfs.get('entry_points') or ['-']))} &nbsp;|&nbsp; "
            f"<b>Data stores:</b> {_e(', '.join(dfs.get('data_stores') or ['-']))}", small))
        story.append(Paragraph(
            f"<b>External dependencies:</b> {_e(', '.join(dfs.get('external_deps') or ['-']))} &nbsp;|&nbsp; "
            f"<b>Boundary crossings:</b> {st.get('crossings', 0)} &nbsp;|&nbsp; "
            f"<b>Unencrypted flows:</b> {st.get('unencrypted', 0)}", small))
        risky = dfs.get("risky_flows") or []
        if risky:
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph("<b>Riskiest flows</b>", body))
            for r in risky[:6]:
                sev = f" [{r['severity']}]" if r.get("severity") else ""
                story.append(Paragraph(
                    f"- {_e(r['from'])} to {_e(r['to'])}{sev}: {_e('; '.join(r['reasons']))}", small))
        hs = dfs.get("hotspots") or []
        if hs:
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph("<b>Risk hotspots:</b> " + _e(", ".join(
                f"{h['component']} ({h['critical']}C/{h['high']}H)" for h in hs)), small))
        if dfs.get("assumptions"):
            story.append(Paragraph(f"<i>{_e(dfs['assumptions'])}</i>", small))
        story.append(Spacer(1, 0.18 * inch))

    # ---- DFD ----
    story.append(Paragraph("Data Flow Diagram", h2))
    if dfd_drawing is not None and dfd_drawing.width and dfd_drawing.height:
        # Scale to fit within the page frame in BOTH dimensions. Fitting to width
        # only lets a tall diagram exceed the frame height, which aborts the whole
        # PDF with a reportlab LayoutError (a large model = broken PDF).
        max_w, max_h = 7.0 * inch, 8.0 * inch
        scale = min(max_w / dfd_drawing.width, max_h / dfd_drawing.height, 1.0)
        if scale < 1.0:
            dfd_drawing.width *= scale
            dfd_drawing.height *= scale
            dfd_drawing.scale(scale, scale)
        story.append(dfd_drawing)
    else:
        story.append(Paragraph(
            "<i>(DFD rendering requires the optional <code>svglib</code> package. "
            "Install with <code>pip install svglib</code> to embed the diagram in PDFs.)</i>",
            body))
    story.append(Spacer(1, 0.08 * inch))

    # Flow legend — the diagram carries numbered badges only, so the detail lives here.
    legend = build_flow_legend(system)
    if legend:
        story.append(Paragraph(
            "Numbered badges on the diagram key to this legend "
            "(red badge = unencrypted or boundary-crossing).", small))
        leg_data = [["#", "Flow", "Protocol", "Auth", "Security"]]
        for f in legend:
            sec = ("plaintext" if not f["encrypted"] else "encrypted") + \
                  (" · crosses" if f["crosses"] else "")
            leg_data.append([
                str(f["n"]),
                Paragraph(f"{_e(f['from'])} &#8594; {_e(f['to'])}", small),
                _e(f["protocol"] or "-"), _e(f["auth"]), sec,
            ])
        lt = Table(leg_data, colWidths=[0.3 * inch, 3.1 * inch, 0.9 * inch, 0.9 * inch, 1.3 * inch],
                   repeatRows=1)
        lt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(Spacer(1, 0.04 * inch))
        story.append(lt)
    story.append(Spacer(1, 0.18 * inch))

    # Summary table
    story.append(Paragraph("Executive Summary", h2))
    cb_count = sum(1 for t in threats if t.get("cross_boundary"))
    story.append(Paragraph(
        f"Total threats: <b>{summary['total']}</b> &nbsp; "
        f"(rule-based: {summary['rule_based']}, LLM: {summary['llm_enhanced']}, "
        f"cross-boundary: {cb_count})", body))
    sev_data = [["Severity", "Count"]]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        sev_data.append([sev, str(summary["by_severity"].get(sev, 0))])
    t = Table(sev_data, colWidths=[1.5 * inch, 1.0 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.12 * inch))

    # Framework coverage — how many threats map to each OWASP framework (matches the
    # coloured badges in the HTML report and the coverage strip in the app).
    _fw_counts = {}
    for _t in threats:
        for _fr in _t.get("frameworks") or []:
            _fw_counts[_fr["framework"]] = _fw_counts.get(_fr["framework"], 0) + 1
    if _fw_counts:
        _fw_meta = {
            "WEB":     ("OWASP Web", "#334155"), "API": ("OWASP API", "#0e7490"),
            "MOBILE":  ("OWASP Mobile", "#047857"), "LLM": ("OWASP LLM", "#6d28d9"),
            "AGENTIC": ("OWASP Agentic", "#a21caf"),
        }
        _parts = [
            f"<font color='{_fw_meta[k][1]}'><b>{_fw_meta[k][0]}:</b> {_fw_counts[k]}</font>"
            for k in ["WEB", "API", "MOBILE", "LLM", "AGENTIC"] if _fw_counts.get(k)
        ]
        story.append(Paragraph("<b>Framework coverage</b> &nbsp; " + " &nbsp;·&nbsp; ".join(_parts), body))
        story.append(Paragraph(
            "Threats mapped to each OWASP Top-10 framework. A threat can map to more than one.", small))
    story.append(Spacer(1, 0.18 * inch))

    # Components
    if components:
        story.append(Paragraph("Components", h2))
        comp_data = [["Name", "Type", "Description"]]
        for c in components:
            comp_data.append([c["name"], c["type"], (c.get("description") or "")[:120]])
        t = Table(comp_data, colWidths=[1.5 * inch, 1.2 * inch, 4.0 * inch], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.15 * inch))

    # ---- Untrusted-Input Boundary Crossings ----
    story.append(PageBreak())
    story.append(Paragraph("🚧 Untrusted-Input Boundary Crossings", h2))
    story.append(Paragraph(
        "Flows where untrusted (or less-trusted) input crosses into an internal trust zone. "
        "These are the highest-priority validation points in the system — every byte that enters "
        "here must be treated as hostile until proven otherwise.", body))
    story.append(Spacer(1, 0.1 * inch))
    untrusted = analysis.get("untrusted_crossings", []) or []
    if not untrusted:
        story.append(Paragraph("<i>No untrusted-input boundary crossings detected.</i>", body))
    else:
        for c in untrusted:
            sev_label = c.get("highest_severity", "None")
            sev_color = "#7c1d1d" if sev_label == "Critical" else (
                        "#b45309" if sev_label == "High" else (
                        "#a16207" if sev_label == "Medium" else "#475569"))
            story.append(Paragraph(
                f"<b>{c['source']['name']} → {c['destination']['name']}</b> "
                f"<font size=8 color='{sev_color}'>[{sev_label}]</font>", h3))
            story.append(Paragraph(
                f"<b>Zones:</b> <font color='#7c1d1d'>{c['source_zone']}</font> → "
                f"<font color='#0369a1'>{c['destination_zone']}</font>", body))
            enc_str = "encrypted" if c['encrypted'] else "<font color='#b91c1c'><b>UNENCRYPTED</b></font>"
            story.append(Paragraph(
                f"<font size=9>Flow: <i>{c['label'] or '(unlabeled)'}</i> · Protocol: "
                f"<font face='Courier'>{c['protocol'] or '—'}</font> · "
                f"Auth: <font face='Courier'>{c['auth']}</font> · Encryption: {enc_str} · "
                f"{c['threat_count']} threats on this flow</font>", body))
            story.append(Paragraph("<b>⚠ Validation requirements at the receiver:</b>", body))
            req_items = "<br/>".join(f"• {r}" for r in c.get('input_validation_requirements', []))
            story.append(Paragraph(f"<font size=9>{req_items}</font>", body))
            story.append(Spacer(1, 0.12 * inch))

    # ---- Trust Boundary Analysis ----
    story.append(PageBreak())
    story.append(Paragraph("Trust Boundary Analysis", h2))
    if not boundaries:
        story.append(Paragraph(
            "<i>No trust boundaries defined.</i> All components share the same trust zone — "
            "consider whether the system has implicit boundaries (network perimeter, "
            "customer/admin separation, third-party services) that should be modelled.", body))
    else:
        comp_boundary_map = {}
        for b in boundaries:
            for cid in b.get("contains", []):
                comp_boundary_map[cid] = b
        for b in boundaries:
            story.append(Paragraph(f"🛡 {b['name']}", h3))
            contained = [comp_by_id[cid] for cid in b.get("contains", []) if cid in comp_by_id]
            if contained:
                names = ", ".join(c["name"] for c in contained)
                story.append(Paragraph(f"<b>Contains:</b> {names}", body))
            ingress, egress = [], []
            for f in flows:
                f_from_b = comp_boundary_map.get(f["from"])
                f_to_b = comp_boundary_map.get(f["to"])
                if f_to_b and f_to_b["id"] == b["id"] and (not f_from_b or f_from_b["id"] != b["id"]):
                    ingress.append(f)
                elif f_from_b and f_from_b["id"] == b["id"] and (not f_to_b or f_to_b["id"] != b["id"]):
                    egress.append(f)

            def _flow_line(f):
                src = comp_by_id.get(f["from"], {}).get("name", "?")
                dst = comp_by_id.get(f["to"], {}).get("name", "?")
                enc = "yes" if f.get("encrypted") else "<font color='#b91c1c'><b>NO</b></font>"
                return (f"&nbsp;&nbsp;• {src} → {dst} ({f.get('label','')}) — "
                        f"{f.get('protocol','')}, auth: {f.get('auth') or 'none'}, encrypted: {enc}")

            if ingress:
                story.append(Paragraph("<b>Ingress:</b>", body))
                for f in ingress:
                    story.append(Paragraph(_flow_line(f), body))
            if egress:
                story.append(Paragraph("<b>Egress:</b>", body))
                for f in egress:
                    story.append(Paragraph(_flow_line(f), body))
            zone_threats = [tt for tt in threats if tt.get("cross_boundary") and
                            (tt["component_id"] in [c["id"] for c in contained])]
            story.append(Paragraph(
                f"<i>Cross-boundary threats affecting this zone: <b>{len(zone_threats)}</b></i>", small))
            story.append(Spacer(1, 0.1 * inch))

    # Threats grouped by severity
    story.append(PageBreak())
    story.append(Paragraph("Identified Threats", h2))
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    by_sev: dict[str, list[dict]] = {s: [] for s in severity_order}
    for th in threats:
        by_sev.setdefault(th["severity"], []).append(th)

    for sev in severity_order:
        items = by_sev.get(sev, [])
        if not items:
            continue
        story.append(Spacer(1, 0.12 * inch))
        story.append(Paragraph(
            f'<font color="{sev_colors[sev].hexval()}"><b>{sev}</b></font> &nbsp; ({len(items)})',
            h3))
        for th in items:
            cb_marker = ' &nbsp;<font color="#b91c1c">[cross-boundary]</font>' if th.get("cross_boundary") else ''
            story.append(Paragraph(f"<b>{th['title']}</b>{cb_marker}", body))
            meta = (
                f"<font size=8 color='#666'>"
                f"{th['methodology']} → {th['category']} &nbsp;|&nbsp; "
                f"Component: <b>{th['component_name']}</b> ({th['component_type']}) &nbsp;|&nbsp; "
                f"Source: {th['source']}"
                f"</font>"
            )
            story.append(Paragraph(meta, body))

            # CVSS + CWE block
            cwe = th.get("cwe") or {}
            c31 = th.get("cvss31") or {}
            c40 = th.get("cvss40") or {}
            scoring_lines = []
            if cwe:
                scoring_lines.append(f"<b>CWE:</b> {cwe.get('id')} — {cwe.get('name')}")
            if c31:
                scoring_lines.append(
                    f"<b>CVSS 3.1:</b> {c31.get('score')} ({c31.get('severity')}) "
                    f"<font size=7 color='#666'>{c31.get('vector')}</font>"
                )
            if c40:
                scoring_lines.append(
                    f"<b>CVSS 4.0:</b> {c40.get('score')} ({c40.get('severity')}) "
                    f"<font size=7 color='#666'>{c40.get('vector')}</font>"
                )
            if scoring_lines:
                story.append(Paragraph("<font size=8>" + "<br/>".join(scoring_lines) + "</font>", body))

            if th.get("cross_boundary"):
                story.append(Paragraph(
                    f"<font size=8 color='#b91c1c'>Boundary crossing: "
                    f"{th.get('src_zone','?')} → {th.get('dst_zone','?')}</font>", body))

            if th.get("location"):
                # backticks → italics; ** → bold
                loc = th["location"].replace("**", "")
                # naive bold restoration
                parts = th["location"].split("**")
                loc_html = ""
                for i, p in enumerate(parts):
                    if i % 2 == 1: loc_html += f"<b>{p}</b>"
                    else: loc_html += p
                story.append(Paragraph(f"<font size=9><b>📍 Location:</b> {loc_html}</font>", body))

            story.append(Paragraph(f"<font size=9><b>📝 Description:</b> {th['description']}</font>", body))

            if th.get("attack_scenario"):
                scenario = "<br/>".join(f"{i}. {s}" for i, s in enumerate(th["attack_scenario"], 1))
                story.append(Paragraph(f"<font size=9><b>⚔️ Attack scenario:</b><br/>{scenario}</font>", body))

            d = th.get("dread", {})
            if d:
                story.append(Paragraph(
                    f"<font size=8>DREAD — D:{d.get('D_damage')} R:{d.get('R_reproducibility')} "
                    f"E:{d.get('E_exploitability')} A:{d.get('A_affected_users')} "
                    f"D:{d.get('D_discoverability')} → <b>Total {d.get('total')}/50</b></font>",
                    body))

            if th.get("specific_mitigations"):
                mit_lines = []
                for m in th["specific_mitigations"]:
                    mit_lines.append(
                        f"<font size=8>[<i>{m.get('control_type','preventive')}</i>] "
                        f"<b>{m.get('action','')}</b> — {m.get('detail','')}</font>"
                    )
                story.append(Paragraph(
                    f"<font size=9><b>🛡 How to mitigate:</b></font><br/>" + "<br/>".join(mit_lines), body))
            elif th.get("mitigations"):
                mitig = "<br/>".join(f"• {m}" for m in th["mitigations"])
                story.append(Paragraph(f"<b>Mitigations:</b><br/>{mitig}", body))

            if th.get("references"):
                refs = " &nbsp;|&nbsp; ".join(f"<link href='{r['url']}'>{r['label']}</link>" for r in th["references"])
                story.append(Paragraph(f"<font size=8 color='#2563eb'>{refs}</font>", body))

            story.append(Spacer(1, 0.1 * inch))

    doc.build(story)
    return buf.getvalue()
