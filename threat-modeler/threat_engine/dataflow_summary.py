"""Deterministic, plain-language end-to-end data-flow summary of a threat model.

No LLM required: everything here is derived from the components, data flows,
trust boundaries and the analysed threats, so the *same* summary renders in the
UI (detail modal) and in every report format. The goal is that a reader
understands the system — entry points, where data lives, the risky hops, and
the external dependencies — without having to decode a large diagram.
"""
from __future__ import annotations

from .model_health import is_weak_auth as _is_weak_auth, auth_display as _auth_display, \
    protocol_display as _protocol_display

# Component types that hold data at rest (the "where does data live" answer).
_STORE_TYPES = {
    "database", "datastore", "cache", "object_storage", "data_warehouse",
    "vector_db", "queue", "secrets_manager", "filesystem",
}
# Types that represent something outside our trust — actors and third parties.
_ACTOR_TYPES = {"user"}
_EXTERNAL_TYPES = {"external_entity"}
# Trust-zone name hints that mark an internet/edge (attack-surface) zone.
_EDGE_HINTS = ("internet", "dmz", "edge", "public", "perimeter", "front")
_THIRD_PARTY_HINTS = ("third", "external", "untrusted", "partner")

_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
_WEAK_AUTH = {"", "none", "basic"}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _oxford(items: list[str], limit: int = 4) -> str:
    """Join a few names for prose: 'A, B and C' (with '…' when truncated)."""
    items = [i for i in items if i]
    if not items:
        return ""
    shown = items[:limit]
    tail = "" if len(items) <= limit else f" and {len(items) - limit} more"
    if len(shown) == 1:
        return shown[0] + tail
    return ", ".join(shown[:-1]) + " and " + shown[-1] + tail


def build_dataflow_summary(system: dict, threats: list[dict] | None = None,
                           summary: dict | None = None,
                           untrusted: dict | None = None) -> dict:
    """Return a structured, plain-language summary of the system's data flow.

    Robust to partial input (empty system, no analysis) — always returns a
    dict with the same keys so callers can render it unconditionally."""
    system = system or {}
    threats = threats or []
    components = system.get("components") or []
    flows = system.get("data_flows") or []
    boundaries = system.get("trust_boundaries") or []

    by_id = {c.get("id"): c for c in components}

    def name(cid):
        return (by_id.get(cid) or {}).get("name") or str(cid)

    def ctype(cid):
        return (by_id.get(cid) or {}).get("type") or ""

    boundary_of = {}
    for b in boundaries:
        for cid in (b.get("contains") or []):
            boundary_of[cid] = b.get("name") or ""

    def zone(cid):
        return (boundary_of.get(cid) or "").lower()

    # --- Threats per component (for severity annotations / hotspots) ----------
    comp_sev: dict[str, dict[str, int]] = {}
    for t in threats:
        cn = t.get("component_name") or ""
        sev = t.get("severity") or "Info"
        d = comp_sev.setdefault(cn, {"Critical": 0, "High": 0, "Medium": 0,
                                     "Low": 0, "Info": 0, "total": 0})
        d[sev] = d.get(sev, 0) + 1
        d["total"] += 1

    def worst_sev_for(cid):
        d = comp_sev.get(name(cid))
        if not d:
            return None
        for s in ("Critical", "High", "Medium", "Low", "Info"):
            if d.get(s):
                return s
        return None

    # --- Actors, entry points, stores, external deps --------------------------
    actor_ids = {c["id"] for c in components if ctype(c["id"]) in _ACTOR_TYPES}
    external_ids = {c["id"] for c in components
                    if ctype(c["id"]) in _EXTERNAL_TYPES
                    or any(h in zone(c["id"]) for h in _THIRD_PARTY_HINTS)}
    untrusted_sources = actor_ids | {c["id"] for c in components
                                     if ctype(c["id"]) in _EXTERNAL_TYPES}

    # Entry points = the first internal components an outside actor touches,
    # plus anything sitting in an internet/edge zone. This is the attack surface.
    entry_ids = {f.get("to") for f in flows if f.get("from") in untrusted_sources}
    entry_ids |= {c["id"] for c in components
                  if any(h in zone(c["id"]) for h in _EDGE_HINTS)
                  and ctype(c["id"]) not in _ACTOR_TYPES}
    entry_ids = {cid for cid in entry_ids if cid in by_id
                 and ctype(cid) not in _ACTOR_TYPES and cid not in external_ids}
    if not entry_ids:  # fallback: components with an inbound flow but from an actor-less graph
        entry_ids = {f.get("to") for f in flows if f.get("from") in actor_ids}

    store_ids = [c["id"] for c in components if ctype(c["id"]) in _STORE_TYPES]
    external_dep_ids = [cid for cid in external_ids if ctype(cid) in _EXTERNAL_TYPES]

    entry_names = [name(c["id"]) for c in components if c["id"] in entry_ids]
    actor_names = [name(cid) for cid in actor_ids]
    store_names = [name(cid) for cid in store_ids]
    dep_names = [name(cid) for cid in external_dep_ids]

    # --- Flow risk assessment -------------------------------------------------
    def cross_boundary(f):
        a, b = boundary_of.get(f.get("from")), boundary_of.get(f.get("to"))
        return bool(a and b and a != b)

    crossings = sum(1 for f in flows if cross_boundary(f))
    unencrypted = sum(1 for f in flows if f.get("encrypted") is False)

    risky = []
    for f in flows:
        reasons = []
        if f.get("encrypted") is False:
            reasons.append("unencrypted")
        if cross_boundary(f):
            reasons.append("crosses a trust boundary")
        if _is_weak_auth(f):
            reasons.append("no/weak authentication")
        if not reasons:
            continue
        risky.append({
            "from": name(f.get("from")), "to": name(f.get("to")),
            "protocol": _protocol_display(f), "auth": _auth_display(f),
            "encrypted": bool(f.get("encrypted")),
            "cross_boundary": cross_boundary(f),
            "reasons": reasons,
            "severity": worst_sev_for(f.get("to")),
        })
    # Riskiest first: cross-boundary + unencrypted, then by target severity.
    risky.sort(key=lambda r: (len(r["reasons"]),
                              _SEV_RANK.get(r["severity"] or "Info", 0)), reverse=True)

    # --- Hotspots (components carrying the most critical/high risk) -----------
    hotspots = sorted(
        ({"component": cn, "critical": d.get("Critical", 0),
          "high": d.get("High", 0), "total": d.get("total", 0)}
         for cn, d in comp_sev.items() if cn),
        key=lambda h: (h["critical"], h["high"], h["total"]), reverse=True)
    hotspots = [h for h in hotspots if h["critical"] or h["high"]][:4]

    # --- Top risky path (accurate single worst crossing, no guessing) ---------
    top_path = None
    if risky:
        r = risky[0]
        via = " · ".join(r["reasons"])
        sev = f" — {r['severity']} risk at {r['to']}" if r["severity"] else ""
        top_path = f"{r['from']} → {r['to']} ({via}){sev}"

    # --- Assumptions / unknowns -----------------------------------------------
    no_auth = sum(1 for f in flows if _is_weak_auth(f))
    assumptions = None
    if no_auth or unencrypted:
        parts = []
        if no_auth:
            parts.append(_plural(no_auth, "flow") + " with no/weak authentication")
        if unencrypted:
            parts.append(_plural(unencrypted, "unencrypted flow"))
        assumptions = "Treat as unverified: " + "; ".join(parts) + "."

    # --- Narrative (2–3 plain sentences) --------------------------------------
    sents = []
    subj = system.get("name") or "This system"
    n_zone = len(boundaries)
    zone_clause = f" across {_plural(n_zone, 'trust zone')}" if n_zone else ""
    sents.append(
        f"{subj} has {_plural(len(components), 'component')} and "
        f"{_plural(len(flows), 'data flow')}{zone_clause}.")
    bits = []
    if entry_names:
        bits.append(f"requests enter at {_oxford(entry_names)}")
    if store_names:
        bits.append(f"data is stored in {_oxford(store_names)}")
    if dep_names:
        bits.append(f"it depends on external {_oxford(dep_names)}")
    if bits:
        sents.append(_capitalize(", ".join(bits)) + ".")
    risk_bits = []
    if crossings:
        risk_bits.append(_plural(crossings, "trust-boundary crossing"))
    if unencrypted:
        risk_bits.append(_plural(unencrypted, "unencrypted flow"))
    if hotspots:
        h = hotspots[0]
        n = h["critical"] or h["high"]
        kind = "critical" if h["critical"] else "high"
        risk_bits.append(f"the highest-risk component is {h['component']} "
                         f"({n} {kind} finding{'' if n == 1 else 's'})")
    if risk_bits:
        sents.append(_capitalize(", ".join(risk_bits)) + ".")

    return {
        "narrative": " ".join(sents),
        "stats": {
            "components": len(components), "flows": len(flows),
            "boundaries": len(boundaries), "crossings": crossings,
            "unencrypted": unencrypted, "external_deps": len(dep_names),
        },
        "actors": actor_names,
        "entry_points": entry_names,
        "data_stores": store_names,
        "external_deps": dep_names,
        "risky_flows": risky[:8],
        "hotspots": hotspots,
        "top_path": top_path,
        "assumptions": assumptions,
    }


def _capitalize(s: str) -> str:
    return s[:1].upper() + s[1:] if s else s
