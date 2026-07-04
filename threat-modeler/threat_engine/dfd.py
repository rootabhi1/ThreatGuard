"""Server-side DFD renderer.

Produces a self-contained SVG that can be embedded in HTML and PDF reports.
Uses standard DFD notation:
  - Process: rounded rectangle
  - Data store: open-ended parallel lines
  - External entity / user: rectangle (sharp corners)
  - Data flow: arrow with label
  - Trust boundary: dashed rounded rectangle enclosing components

The frontend uses its own interactive renderer; this one is for static output.
"""
from __future__ import annotations
import math
from xml.sax.saxutils import escape as xml_escape


# DFD shape category for each component type
_PROCESS = {"webapp", "mobile_app", "api", "auth_service", "admin_panel", "payment_service"}
_STORE   = {"database", "datastore", "cache", "filesystem", "queue", "config"}
_EXTERN  = {"user", "external_entity"}

# Color per category (matches frontend palette)
_COLORS = {
    "process":  {"fill": "#ecfdf5", "stroke": "#10b981", "text": "#064e3b"},
    "store":    {"fill": "#eef2ff", "stroke": "#6366f1", "text": "#312e81"},
    "extern":   {"fill": "#eff6ff", "stroke": "#3b82f6", "text": "#1e3a8a"},
    "boundary": {"stroke": "#f43f5e", "fill": "#fff1f2"},
}

_BOUNDARY_PALETTE = [
    {"stroke": "#f43f5e", "fill": "#fff1f2"},  # rose
    {"stroke": "#a855f7", "fill": "#faf5ff"},  # purple
    {"stroke": "#0ea5e9", "fill": "#f0f9ff"},  # sky
    {"stroke": "#f59e0b", "fill": "#fffbeb"},  # amber
    {"stroke": "#14b8a6", "fill": "#f0fdfa"},  # teal
]


def _category(component_type: str) -> str:
    if component_type in _STORE:  return "store"
    if component_type in _EXTERN: return "extern"
    return "process"


def _auto_layout(components: list[dict], data_flows: list[dict],
                 width: int = 1000, height: int = 600,
                 padding: int = 100) -> dict[str, dict]:
    """Compute (x,y) for each component using a layered/columnar layout.

    Strategy:
      1. Put external entities (users) on the far left.
      2. Put data stores on the far right.
      3. Processes go in middle columns, ordered topologically by flows.
    """
    if not components:
        return {}

    externs    = [c for c in components if _category(c["type"]) == "extern"]
    stores     = [c for c in components if _category(c["type"]) == "store"]
    processes  = [c for c in components if _category(c["type"]) == "process"]

    # Topo-ish ordering for processes by flow degree
    in_deg = {c["id"]: 0 for c in processes}
    out_deg = {c["id"]: 0 for c in processes}
    for f in data_flows:
        if f["to"] in in_deg:    in_deg[f["to"]] += 1
        if f["from"] in out_deg: out_deg[f["from"]] += 1
    processes.sort(key=lambda c: (in_deg[c["id"]] - out_deg[c["id"]]))

    # Decide number of process columns based on count
    n_proc = max(1, len(processes))
    proc_cols = 1 if n_proc <= 2 else (2 if n_proc <= 5 else 3)

    columns: list[list[dict]] = []
    if externs:
        columns.append(externs)
    # Distribute processes across proc_cols columns
    for ci in range(proc_cols):
        col = processes[ci::proc_cols]
        if col:
            columns.append(col)
    if stores:
        columns.append(stores)

    if not columns:
        columns = [components]

    # Place each column
    positions: dict[str, dict] = {}
    n_cols = len(columns)
    col_gap = (width - 2 * padding) / max(1, n_cols - 1) if n_cols > 1 else 0
    for ci, col in enumerate(columns):
        x = padding + ci * col_gap if n_cols > 1 else width / 2
        n = len(col)
        if n == 1:
            positions[col[0]["id"]] = {"x": x, "y": height / 2}
        else:
            row_gap = (height - 2 * padding) / (n - 1)
            for ri, c in enumerate(col):
                positions[c["id"]] = {"x": x, "y": padding + ri * row_gap}
    return positions


def _node_size(category: str) -> tuple[int, int]:
    if category == "store":  return (140, 50)
    if category == "extern": return (130, 50)
    return (140, 56)  # process


def _draw_node(c: dict, pos: dict) -> str:
    cat = _category(c["type"])
    w, h = _node_size(cat)
    x, y = pos["x"] - w / 2, pos["y"] - h / 2
    col = _COLORS[cat]
    name = xml_escape(c["name"][:20])
    type_label = xml_escape(c["type"])
    parts = []

    if cat == "process":
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w}" height="{h}" rx="10" ry="10" '
            f'fill="{col["fill"]}" stroke="{col["stroke"]}" stroke-width="2"/>'
        )
    elif cat == "store":
        # Open data-store shape: box + two horizontal rules at top/bottom (no left/right vertical)
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w}" height="{h}" '
            f'fill="{col["fill"]}" stroke="none"/>'
        )
        parts.append(
            f'<line x1="{x:.1f}" y1="{y:.1f}" x2="{x+w:.1f}" y2="{y:.1f}" '
            f'stroke="{col["stroke"]}" stroke-width="2"/>'
        )
        parts.append(
            f'<line x1="{x:.1f}" y1="{y+h:.1f}" x2="{x+w:.1f}" y2="{y+h:.1f}" '
            f'stroke="{col["stroke"]}" stroke-width="2"/>'
        )
    else:  # extern
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w}" height="{h}" '
            f'fill="{col["fill"]}" stroke="{col["stroke"]}" stroke-width="2"/>'
        )

    parts.append(
        f'<text x="{pos["x"]:.1f}" y="{pos["y"] - 4:.1f}" text-anchor="middle" '
        f'font-size="13" font-weight="600" fill="{col["text"]}" font-family="system-ui,sans-serif">{name}</text>'
    )
    parts.append(
        f'<text x="{pos["x"]:.1f}" y="{pos["y"] + 12:.1f}" text-anchor="middle" '
        f'font-size="10" fill="{col["text"]}" opacity="0.7" font-family="system-ui,sans-serif">{type_label}</text>'
    )
    return "".join(parts)


def _intersect_node_edge(pos_a: dict, pos_b: dict, w: int, h: int) -> tuple[float, float]:
    """Return the point on the rectangle edge of node-a closest to node-b."""
    dx = pos_b["x"] - pos_a["x"]
    dy = pos_b["y"] - pos_a["y"]
    if dx == 0 and dy == 0:
        return pos_a["x"], pos_a["y"]
    half_w, half_h = w / 2, h / 2
    if abs(dx) * half_h > abs(dy) * half_w:
        # exits left/right edge
        sign = 1 if dx > 0 else -1
        x = pos_a["x"] + sign * half_w
        y = pos_a["y"] + dy * (half_w / abs(dx))
    else:
        sign = 1 if dy > 0 else -1
        y = pos_a["y"] + sign * half_h
        x = pos_a["x"] + dx * (half_h / abs(dy))
    return x, y


def _draw_flow(flow: dict, comp_by_id: dict, positions: dict,
               crosses_boundary: bool, anim: bool = False) -> str:
    src = comp_by_id.get(flow["from"])
    dst = comp_by_id.get(flow["to"])
    if not src or not dst: return ""
    p_src, p_dst = positions[src["id"]], positions[dst["id"]]
    sw, sh = _node_size(_category(src["type"]))
    dw, dh = _node_size(_category(dst["type"]))
    x1, y1 = _intersect_node_edge(p_src, p_dst, sw, sh)
    x2, y2 = _intersect_node_edge(p_dst, p_src, dw, dh)

    encrypted = flow.get("encrypted", True)
    color = "#ef4444" if (not encrypted or crosses_boundary) else "#64748b"
    dash = "5,4" if not encrypted else "none"
    width = 2.2 if crosses_boundary else 1.6

    label = flow.get("label", "")
    proto = flow.get("protocol", "")
    auth  = flow.get("auth") or "none"
    full_label = f"{label}" + (f" [{proto}]" if proto else "")
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2

    # Slight curve perpendicular to the line for clarity
    dx, dy = x2 - x1, y2 - y1
    length = max(1.0, math.hypot(dx, dy))
    nx, ny = -dy / length, dx / length
    curve = 14 if abs(dx) > abs(dy) else 10
    cx, cy = mx + nx * curve, my + ny * curve

    path_id = f"path_{flow['id']}"
    parts = []
    parts.append(
        f'<path id="{path_id}" d="M {x1:.1f},{y1:.1f} Q {cx:.1f},{cy:.1f} {x2:.1f},{y2:.1f}" '
        f'fill="none" stroke="{color}" stroke-width="{width}" stroke-dasharray="{dash}" marker-end="url(#arrow)"/>'
    )
    if anim:
        # Animate dash drift along the path
        parts.append(
            f'<path d="M {x1:.1f},{y1:.1f} Q {cx:.1f},{cy:.1f} {x2:.1f},{y2:.1f}" '
            f'fill="none" stroke="{color}" stroke-width="{width}" stroke-dasharray="6 12" stroke-opacity="0.7">'
            f'<animate attributeName="stroke-dashoffset" from="0" to="-36" dur="1.6s" repeatCount="indefinite"/>'
            f'</path>'
        )
    if full_label:
        # A <textPath> follows its path's direction, so a right-to-left flow would
        # render the label upside-down. Bind the label to a dedicated invisible
        # path that always runs left-to-right (endpoints swapped when needed).
        if (x1, y1) <= (x2, y2):
            lx1, ly1, lx2, ly2 = x1, y1, x2, y2
        else:
            lx1, ly1, lx2, ly2 = x2, y2, x1, y1
        label_path_id = f"lp_{flow['id']}"
        parts.append(
            f'<path id="{label_path_id}" d="M {lx1:.1f},{ly1:.1f} Q {cx:.1f},{cy:.1f} {lx2:.1f},{ly2:.1f}" '
            f'fill="none" stroke="none"/>'
        )
        parts.append(
            f'<text font-size="10" fill="#475569" font-family="system-ui,sans-serif">'
            f'<textPath href="#{label_path_id}" startOffset="50%" text-anchor="middle">{xml_escape(full_label)}</textPath>'
            f'</text>'
        )

    # Lock icon (encryption status) at midpoint
    icon = "🔒" if encrypted else "⚠"
    parts.append(
        f'<text x="{cx:.1f}" y="{cy + 4:.1f}" text-anchor="middle" font-size="11" fill="{color}">{icon}</text>'
    )
    return "".join(parts)


def _draw_boundary(boundary: dict, positions: dict, palette: dict,
                   anim: bool = False) -> str:
    contained = [positions[cid] for cid in boundary.get("contains", []) if cid in positions]
    if not contained: return ""
    pad = 32
    xs = [p["x"] for p in contained]; ys = [p["y"] for p in contained]
    x = min(xs) - 80 - pad
    y = min(ys) - 40 - pad
    w = (max(xs) - min(xs)) + 160 + 2 * pad
    h = (max(ys) - min(ys)) + 80 + 2 * pad
    name = xml_escape(boundary.get("name", "Trust boundary"))
    parts = []
    parts.append(
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="14" ry="14" '
        f'fill="{palette["fill"]}" fill-opacity="0.5" stroke="{palette["stroke"]}" '
        f'stroke-width="2" stroke-dasharray="8,5"'
        + (' >'
           f'<animate attributeName="stroke-dashoffset" from="0" to="-26" dur="2.4s" repeatCount="indefinite"/>'
           '</rect>' if anim else '/>')
    )
    parts.append(
        f'<rect x="{x + 10:.1f}" y="{y - 11:.1f}" rx="3" ry="3" '
        f'width="{len(name) * 7 + 18}" height="22" fill="{palette["stroke"]}"/>'
    )
    parts.append(
        f'<text x="{x + 19:.1f}" y="{y + 4:.1f}" font-size="11" font-weight="600" '
        f'fill="white" font-family="system-ui,sans-serif">🛡 {name}</text>'
    )
    return "".join(parts)


def render_dfd_svg(system: dict, *, animated: bool = False,
                   width: int = 1000, height: int = 600,
                   positions: dict | None = None) -> str:
    """Return a complete SVG string for the DFD."""
    components = system.get("components", []) or []
    flows = system.get("data_flows", []) or []
    boundaries = system.get("trust_boundaries", []) or []
    comp_by_id = {c["id"]: c for c in components}

    # Use provided positions if any (for round-tripping with the interactive UI),
    # otherwise auto-layout.
    pos = {}
    if positions:
        pos = {cid: {"x": p["x"], "y": p["y"]} for cid, p in positions.items()
               if cid in comp_by_id}
    missing = [c for c in components if c["id"] not in pos]
    if missing:
        auto = _auto_layout(missing, flows, width=width, height=height)
        pos.update(auto)

    # Build component -> boundary map for cross-boundary highlighting
    comp_boundary = {}
    for b in boundaries:
        for cid in b.get("contains", []):
            comp_boundary[cid] = b["id"]

    def crosses(f):
        return comp_boundary.get(f["from"]) != comp_boundary.get(f["to"])

    parts = []
    parts.append(
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'role="img" aria-label="Data Flow Diagram" '
        f'style="font-family: system-ui, -apple-system, Segoe UI, sans-serif;">'
    )
    parts.append(
        '<defs>'
        '<marker id="arrow" markerWidth="9" markerHeight="9" refX="8" refY="3" '
        'orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L8,3 z" fill="context-stroke"/></marker>'
        '</defs>'
    )
    # Background
    parts.append(f'<rect width="{width}" height="{height}" fill="#fafafa"/>')

    # Trust boundaries first (under everything)
    for i, b in enumerate(boundaries):
        palette = _BOUNDARY_PALETTE[i % len(_BOUNDARY_PALETTE)]
        parts.append(_draw_boundary(b, pos, palette, anim=animated))

    # Flows (under nodes)
    for f in flows:
        parts.append(_draw_flow(f, comp_by_id, pos, crosses(f), anim=animated))

    # Nodes on top
    for c in components:
        if c["id"] in pos:
            parts.append(_draw_node(c, pos[c["id"]]))

    parts.append("</svg>")
    return "".join(parts)


def auto_layout_for_frontend(system: dict, width: int = 1000, height: int = 600) -> dict:
    """Helper exposed to the frontend so initial layout matches what the report uses."""
    return _auto_layout(
        system.get("components", []) or [],
        system.get("data_flows", []) or [],
        width=width, height=height,
    )
