"""Deterministic model normalization — the single place that makes a system model
safe to analyse, render, and report on, and that turns every silent failure into a
visible, disclosed issue.

The problem this solves: components, flows and trust boundaries reach us from three
different input paths (free text, precise text, AI-vision diagram) and from the
interactive DFD editor. Historically each downstream consumer (the rule engine, the
DFD renderer, the data-flow summary) independently decided what to do with a broken
reference — and every one of them chose either to *drop it silently* (so a real flow
vanished from the diagram and its threats were never generated) or to *crash* (a
missing ``id`` raised ``KeyError`` → HTTP 500, killing the whole DFD/analysis/report).

``normalize_system`` replaces all of that with one rule: **never drop anything
silently, never crash on malformed input.** It returns a repaired, self-consistent
copy of the model plus a list of ``issues`` describing exactly what it found and
fixed, so the UI and every report can show the user the truth:

  - Missing ``id``            → assigned a stable one (no more 500s).
  - Duplicate ``id``          → the collision is renamed, both are kept (no silent
                                overwrite in the ``{id: obj}`` lookups downstream).
  - Dangling flow endpoint    → a visible "⚠ Unknown" placeholder component is
                                created and the flow is kept, so it still draws in
                                the DFD and still generates its threats.
  - Boundary → unknown member → dropped from the boundary's ``contains`` (disclosed).
  - Invalid / missing type    → flagged, value preserved (never silently coerced).
  - Components outside every   → surfaced as an informational note (they are treated
    trust boundary               as an external zone, which may or may not be intended).

The pass is deterministic (input order preserved, no randomness) and structurally
idempotent: normalizing an already-clean model returns an equal model with no repair
issues. (Purely informational observations — e.g. "N components sit outside every
trust boundary" — describe the model rather than a defect, so they recur by design.)
"""
from __future__ import annotations

# Issue levels, most→least severe. "error" = data was broken and we repaired it in a
# way that changes what the model contains; "warning" = a reference could not be kept;
# "info" = worth knowing but nothing was lost.
ERROR, WARNING, INFO = "error", "warning", "info"


def _issue(level: str, code: str, message: str, autofixed: bool = True) -> dict:
    return {"level": level, "code": code, "message": message, "autofixed": autofixed}


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def _clean_id(value) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def normalize_system(system: dict | None) -> tuple[dict, list[dict]]:
    """Return ``(clean_system, issues)`` — a repaired, self-consistent copy of
    ``system`` and a list of disclosed issues. Never raises on malformed input;
    never drops an element without recording why.

    ``clean_system`` preserves every top-level key of the input (name, description,
    ``_source_text`` …) and replaces ``components`` / ``data_flows`` /
    ``trust_boundaries`` with normalized lists. Placeholder components created for
    dangling references are appended to ``components`` and marked ``_placeholder``.
    """
    from .analyzer import VALID_COMPONENT_TYPES
    valid_types = set(VALID_COMPONENT_TYPES)

    system = system if isinstance(system, dict) else {}
    issues: list[dict] = []

    raw_components = _as_list(system.get("components"))
    raw_flows = _as_list(system.get("data_flows"))
    raw_boundaries = _as_list(system.get("trust_boundaries"))

    # --- Components -----------------------------------------------------------
    components: list[dict] = []
    seen_ids: set[str] = set()
    n_missing_id = n_dup_id = n_missing_name = 0
    bad_types: list[str] = []

    for idx, raw in enumerate(raw_components):
        if not isinstance(raw, dict):
            issues.append(_issue(ERROR, "component_not_object",
                                 f"Component #{idx + 1} is not a valid object and was dropped."))
            continue
        c = dict(raw)
        cid = _clean_id(c.get("id"))
        if not cid:
            cid = f"c_auto_{idx}"
            n_missing_id += 1
        if cid in seen_ids:
            base, k = cid, 2
            while f"{base}__dup{k}" in seen_ids:
                k += 1
            cid = f"{base}__dup{k}"
            n_dup_id += 1
        seen_ids.add(cid)
        c["id"] = cid

        name = c.get("name")
        if not (isinstance(name, str) and name.strip()):
            c["name"] = cid.replace("c_", "").replace("_", " ").strip().title() or "Unnamed component"
            n_missing_name += 1

        ctype = c.get("type")
        c["type"] = ctype if isinstance(ctype, str) else ""
        if c["type"] not in valid_types:
            bad_types.append(c["name"])

        components.append(c)

    if n_missing_id:
        issues.append(_issue(INFO, "component_missing_id",
                             f"{n_missing_id} component(s) had no id; stable ids were assigned."))
    if n_dup_id:
        issues.append(_issue(WARNING, "component_duplicate_id",
                             f"{n_dup_id} component(s) shared an id; the collisions were renamed so "
                             f"none is silently overwritten."))
    if n_missing_name:
        issues.append(_issue(INFO, "component_missing_name",
                             f"{n_missing_name} component(s) had no name; a name was derived from the id."))
    if bad_types:
        shown = ", ".join(bad_types[:5]) + ("…" if len(bad_types) > 5 else "")
        issues.append(_issue(WARNING, "component_invalid_type",
                             f"{len(bad_types)} component(s) have an unrecognized type "
                             f"({shown}); they render but only attract generic threats.",
                             autofixed=False))

    comp_by_id = {c["id"]: c for c in components}

    # --- Flows (dangling endpoints become visible placeholder nodes) ----------
    placeholders: dict[str, dict] = {}

    def _placeholder_for(ref) -> str:
        """Return the id of a visible placeholder component standing in for an
        undeclared reference ``ref``, creating it once and reusing it thereafter."""
        key = _clean_id(ref) or f"c_unknown_{len(placeholders)}"
        if key not in placeholders:
            ph = {
                "id": key,
                "name": f"⚠ Unknown ({_clean_id(ref) or '?'})",
                "type": "external_entity",
                "description": "Auto-added placeholder for a data flow that referenced an "
                               "undeclared component. Edit the model to resolve it.",
                "_placeholder": True,
            }
            placeholders[key] = ph
            comp_by_id[key] = ph
        return key

    flows: list[dict] = []
    seen_flow_ids: set[str] = set()
    n_flow_missing_id = n_flow_dup_id = 0
    dangling: list[str] = []

    for idx, raw in enumerate(raw_flows):
        if not isinstance(raw, dict):
            issues.append(_issue(ERROR, "flow_not_object",
                                 f"Data flow #{idx + 1} is not a valid object and was dropped."))
            continue
        f = dict(raw)
        fid = _clean_id(f.get("id"))
        if not fid:
            fid = f"f_auto_{idx}"
            n_flow_missing_id += 1
        if fid in seen_flow_ids:
            base, k = fid, 2
            while f"{base}__dup{k}" in seen_flow_ids:
                k += 1
            fid = f"{base}__dup{k}"
            n_flow_dup_id += 1
        seen_flow_ids.add(fid)
        f["id"] = fid

        for end in ("from", "to"):
            ref = _clean_id(f.get(end))
            if ref not in comp_by_id:
                label = f.get("label") or fid
                dangling.append(f"{label} ({end}={ref or 'missing'})")
                f[end] = _placeholder_for(f.get(end))
        flows.append(f)

    # Append placeholders in creation order so downstream ordering stays stable.
    components.extend(placeholders.values())

    if n_flow_missing_id:
        issues.append(_issue(INFO, "flow_missing_id",
                             f"{n_flow_missing_id} data flow(s) had no id; stable ids were assigned."))
    if n_flow_dup_id:
        issues.append(_issue(WARNING, "flow_duplicate_id",
                             f"{n_flow_dup_id} data flow(s) shared an id; the collisions were renamed."))
    if dangling:
        shown = "; ".join(dangling[:5]) + ("…" if len(dangling) > 5 else "")
        issues.append(_issue(ERROR, "flow_dangling_reference",
                             f"{len(dangling)} data flow(s) referenced a component that was never "
                             f"declared ({shown}). A placeholder was added so the flow still appears "
                             f"in the diagram and is still analysed — resolve it by adding the real "
                             f"component or fixing the reference."))

    # --- Trust boundaries -----------------------------------------------------
    boundaries: list[dict] = []
    seen_boundary_ids: set[str] = set()
    n_boundary_missing_id = n_boundary_dup_id = 0
    dropped_members = 0

    for idx, raw in enumerate(raw_boundaries):
        if not isinstance(raw, dict):
            issues.append(_issue(ERROR, "boundary_not_object",
                                 f"Trust boundary #{idx + 1} is not a valid object and was dropped."))
            continue
        b = dict(raw)
        bid = _clean_id(b.get("id"))
        if not bid:
            bid = f"b_auto_{idx}"
            n_boundary_missing_id += 1
        if bid in seen_boundary_ids:
            base, k = bid, 2
            while f"{base}__dup{k}" in seen_boundary_ids:
                k += 1
            bid = f"{base}__dup{k}"
            n_boundary_dup_id += 1
        seen_boundary_ids.add(bid)
        b["id"] = bid
        if not (isinstance(b.get("name"), str) and b["name"].strip()):
            b["name"] = "Trust boundary"

        contains = _as_list(b.get("contains"))
        kept = [cid for cid in (_clean_id(x) for x in contains) if cid in comp_by_id]
        dropped_members += len(contains) - len(kept)
        b["contains"] = kept
        boundaries.append(b)

    if n_boundary_missing_id:
        issues.append(_issue(INFO, "boundary_missing_id",
                             f"{n_boundary_missing_id} trust boundary(ies) had no id; ids were assigned."))
    if n_boundary_dup_id:
        issues.append(_issue(WARNING, "boundary_duplicate_id",
                             f"{n_boundary_dup_id} trust boundary(ies) shared an id; renamed."))
    if dropped_members:
        issues.append(_issue(WARNING, "boundary_unknown_member",
                             f"{dropped_members} trust-boundary membership(s) pointed at an unknown "
                             f"component and were removed."))

    # --- Informational: components outside every boundary ---------------------
    if boundaries:
        in_boundary = {cid for b in boundaries for cid in b["contains"]}
        outside = [c["name"] for c in components
                   if c["id"] not in in_boundary and not c.get("_placeholder")]
        if outside:
            shown = ", ".join(outside[:5]) + ("…" if len(outside) > 5 else "")
            issues.append(_issue(INFO, "component_outside_boundary",
                                 f"{len(outside)} component(s) are outside every trust boundary "
                                 f"({shown}); they are treated as an external/untrusted zone.",
                                 autofixed=False))

    clean = dict(system)
    clean["components"] = components
    clean["data_flows"] = flows
    clean["trust_boundaries"] = boundaries
    return clean, issues


def issues_summary(issues: list[dict] | None) -> dict:
    """Small roll-up for badges/headers: counts per level and a total."""
    issues = issues or []
    out = {"total": len(issues), "error": 0, "warning": 0, "info": 0}
    for i in issues:
        lvl = i.get("level", INFO)
        out[lvl] = out.get(lvl, 0) + 1
    return out
