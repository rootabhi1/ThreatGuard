"""Domain CRUD: releases, features, threat models, threat status.

Returns dicts (not ORM objects) so the API layer can serialize directly.
Permissions and resource-access are enforced at the API layer, not here.
This module trusts its caller — pass the ID, get the row.
"""
from __future__ import annotations
import json
from datetime import datetime

from db import db_conn, _now


# ---------------------------------------------------------------------------
# Releases
# ---------------------------------------------------------------------------
def create_release(name: str, description: str, target_date: str | None,
                   created_by: int, status: str = "planned") -> dict:
    with db_conn(write=True) as c:
        cur = c.execute(
            "INSERT INTO releases (name, description, status, target_date, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, description, status, target_date, created_by, _now(), _now())
        )
        rid = cur.lastrowid
    return get_release(rid)


def get_release(rid: int) -> dict | None:
    with db_conn() as c:
        row = c.execute("SELECT * FROM releases WHERE id=?", (rid,)).fetchone()
    return dict(row) if row else None


def list_releases() -> list[dict]:
    with db_conn() as c:
        rows = c.execute("SELECT * FROM releases ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def update_release(rid: int, **fields) -> dict | None:
    if not fields:
        return get_release(rid)
    allowed = {"name", "description", "status", "target_date"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return get_release(rid)
    sets = ", ".join(f"{k}=?" for k in fields)
    values = list(fields.values()) + [_now(), rid]
    with db_conn(write=True) as c:
        c.execute(f"UPDATE releases SET {sets}, updated_at=? WHERE id=?", values)
    return get_release(rid)


def delete_release(rid: int):
    with db_conn(write=True) as c:
        c.execute("DELETE FROM releases WHERE id=?", (rid,))


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------
def create_feature(release_id: int, name: str, description: str,
                   created_by: int, status: str = "draft",
                   target_date: str | None = None) -> dict:
    with db_conn(write=True) as c:
        # Verify release exists
        rel = c.execute("SELECT id FROM releases WHERE id=?", (release_id,)).fetchone()
        if not rel:
            raise ValueError(f"Release {release_id} not found")
        cur = c.execute(
            "INSERT INTO features (release_id, name, description, status, target_date, "
            "created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (release_id, name, description, status, target_date,
             created_by, _now(), _now())
        )
        fid = cur.lastrowid
    return get_feature(fid)


def get_feature(fid: int) -> dict | None:
    with db_conn() as c:
        row = c.execute("SELECT * FROM features WHERE id=?", (fid,)).fetchone()
    return dict(row) if row else None


def list_features(release_id: int | None = None,
                  visible_to_user_id: int | None = None,
                  visible_to_role: str | None = None) -> list[dict]:
    """List features. If visible_to_user_id is given AND role is 'user', filter
    to only the ones they created or were granted access to."""
    sql = "SELECT * FROM features"
    args: list = []
    where = []
    if release_id is not None:
        where.append("release_id=?"); args.append(release_id)
    if visible_to_user_id is not None and visible_to_role == "user":
        where.append(
            "(created_by=? OR id IN (SELECT feature_id FROM user_feature_access WHERE user_id=?))"
        )
        args += [visible_to_user_id, visible_to_user_id]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC"
    with db_conn() as c:
        rows = c.execute(sql, args).fetchall()
    return [dict(r) for r in rows]


def update_feature(fid: int, **fields) -> dict | None:
    allowed = {"name", "description", "status", "target_date"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return get_feature(fid)
    sets = ", ".join(f"{k}=?" for k in fields)
    values = list(fields.values()) + [_now(), fid]
    with db_conn(write=True) as c:
        c.execute(f"UPDATE features SET {sets}, updated_at=? WHERE id=?", values)
    return get_feature(fid)


def delete_feature(fid: int):
    with db_conn(write=True) as c:
        c.execute("DELETE FROM features WHERE id=?", (fid,))


def grant_feature_access(user_id: int, feature_id: int, granted_by: int):
    with db_conn(write=True) as c:
        c.execute(
            "INSERT OR IGNORE INTO user_feature_access (user_id, feature_id, granted_by, granted_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, feature_id, granted_by, _now())
        )


def revoke_feature_access(user_id: int, feature_id: int):
    with db_conn(write=True) as c:
        c.execute(
            "DELETE FROM user_feature_access WHERE user_id=? AND feature_id=?",
            (user_id, feature_id)
        )


def list_user_feature_access(user_id: int) -> list[dict]:
    with db_conn() as c:
        rows = c.execute(
            "SELECT f.* FROM features f "
            "JOIN user_feature_access ufa ON ufa.feature_id = f.id "
            "WHERE ufa.user_id=? ORDER BY f.created_at DESC",
            (user_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Threat Models
# ---------------------------------------------------------------------------
def create_threat_model(feature_id: int, owner_id: int, name: str,
                        description: str, system: dict,
                        methodologies: list[str]) -> dict:
    with db_conn(write=True) as c:
        feat = c.execute("SELECT id FROM features WHERE id=?", (feature_id,)).fetchone()
        if not feat:
            raise ValueError(f"Feature {feature_id} not found")
        cur = c.execute(
            "INSERT INTO threat_models (feature_id, owner_id, name, description, "
            "system_json, methodologies, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (feature_id, owner_id, name, description,
             json.dumps(system), json.dumps(methodologies), _now(), _now())
        )
        tid = cur.lastrowid
    return get_threat_model(tid)


def get_threat_model(tid: int) -> dict | None:
    with db_conn() as c:
        row = c.execute("SELECT * FROM threat_models WHERE id=?", (tid,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["system"] = json.loads(d.pop("system_json"))
    d["methodologies"] = json.loads(d.get("methodologies") or '[]')
    if d.get("analysis_json"):
        d["analysis"] = json.loads(d.pop("analysis_json"))
    else:
        d.pop("analysis_json", None)
        d["analysis"] = None
    return d


def list_threat_models(visible_to_user_id: int | None = None,
                       visible_to_role: str | None = None,
                       feature_id: int | None = None) -> list[dict]:
    """List threat models. Filter by user visibility based on role:
      - admin / management: see everything
      - user: see only TMs they own (strict ownership model). Feature grants
        let them CREATE in a feature, but never reveal other users' TMs.
    """
    sql = "SELECT * FROM threat_models"
    args: list = []
    where = []
    if feature_id is not None:
        where.append("feature_id=?"); args.append(feature_id)
    if visible_to_user_id is not None and visible_to_role == "user":
        # Strict: only own TMs. Grants don't extend list visibility.
        where.append("owner_id=?")
        args.append(visible_to_user_id)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC"
    with db_conn() as c:
        rows = c.execute(sql, args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["system"] = json.loads(d.pop("system_json"))
        d["methodologies"] = json.loads(d.get("methodologies") or '[]')
        d.pop("analysis_json", None)
        out.append(d)
    return out


def update_threat_model(tid: int, **fields) -> dict | None:
    allowed = {"name", "description", "system", "methodologies", "analysis", "feature_id"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return get_threat_model(tid)
    # JSON-encode dict/list fields
    if "system" in fields:
        fields["system_json"] = json.dumps(fields.pop("system"))
    if "methodologies" in fields:
        fields["methodologies"] = json.dumps(fields["methodologies"])
    if "analysis" in fields:
        fields["analysis_json"] = json.dumps(fields.pop("analysis"))
    sets = ", ".join(f"{k}=?" for k in fields)
    values = list(fields.values()) + [_now(), tid]
    with db_conn(write=True) as c:
        c.execute(f"UPDATE threat_models SET {sets}, updated_at=? WHERE id=?", values)
    return get_threat_model(tid)


def delete_threat_model(tid: int):
    with db_conn(write=True) as c:
        c.execute("DELETE FROM threat_models WHERE id=?", (tid,))


# ---------------------------------------------------------------------------
# Threat status
# ---------------------------------------------------------------------------
VALID_THREAT_STATUSES = {"open", "in_progress", "mitigated", "accepted_risk", "false_positive"}


# Terminal statuses — when one is reached, mark the threat "closed"
TERMINAL_STATUSES = {"mitigated", "accepted_risk", "false_positive"}


def set_threat_status(threat_model_id: int, threat_id: str, status: str,
                      notes: str | None, updated_by: int) -> dict:
    if status not in VALID_THREAT_STATUSES:
        raise ValueError(f"Invalid status: {status}")

    now = _now()
    now_dt = datetime.fromisoformat(now)

    with db_conn(write=True) as c:
        # Look up the existing row and its email for history
        existing = c.execute(
            "SELECT * FROM threat_status WHERE threat_model_id=? AND threat_id=?",
            (threat_model_id, threat_id)
        ).fetchone()

        actor = c.execute(
            "SELECT email FROM users WHERE id=?", (updated_by,)
        ).fetchone()
        actor_email = actor["email"] if actor else None

        if existing is None:
            # First-time write — initial state. first_opened_at = now.
            closed_at = now if status in TERMINAL_STATUSES else None
            closed_by = updated_by if status in TERMINAL_STATUSES else None
            ttc = 0 if status in TERMINAL_STATUSES else None
            c.execute(
                "INSERT INTO threat_status (threat_model_id, threat_id, status, notes, "
                "updated_by, updated_at, first_opened_at, closed_at, closed_by, time_to_closure_seconds) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (threat_model_id, threat_id, status, notes,
                 updated_by, now, now, closed_at, closed_by, ttc)
            )
            # History: from None → status
            c.execute(
                "INSERT INTO threat_status_history (threat_model_id, threat_id, "
                "from_status, to_status, notes, changed_by, changed_by_email, changed_at, "
                "duration_in_prev_seconds) "
                "VALUES (?, ?, NULL, ?, ?, ?, ?, ?, NULL)",
                (threat_model_id, threat_id, status, notes, updated_by, actor_email, now)
            )
        else:
            # Update existing row
            from_status = existing["status"]
            prev_updated_at = datetime.fromisoformat(existing["updated_at"])
            duration_in_prev = int((now_dt - prev_updated_at).total_seconds())

            # Closure tracking: if entering terminal for first time, set closure
            new_closed_at = existing["closed_at"]
            new_closed_by = existing["closed_by"]
            new_ttc = existing["time_to_closure_seconds"]
            if status in TERMINAL_STATUSES and existing["closed_at"] is None:
                new_closed_at = now
                new_closed_by = updated_by
                first_opened = datetime.fromisoformat(existing["first_opened_at"])
                new_ttc = int((now_dt - first_opened).total_seconds())
            elif status not in TERMINAL_STATUSES and existing["closed_at"] is not None:
                # Reopened — clear closure
                new_closed_at = None
                new_closed_by = None
                new_ttc = None

            c.execute(
                "UPDATE threat_status SET status=?, notes=?, updated_by=?, updated_at=?, "
                "closed_at=?, closed_by=?, time_to_closure_seconds=? "
                "WHERE threat_model_id=? AND threat_id=?",
                (status, notes, updated_by, now,
                 new_closed_at, new_closed_by, new_ttc,
                 threat_model_id, threat_id)
            )
            # Append history
            c.execute(
                "INSERT INTO threat_status_history (threat_model_id, threat_id, "
                "from_status, to_status, notes, changed_by, changed_by_email, changed_at, "
                "duration_in_prev_seconds) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (threat_model_id, threat_id, from_status, status, notes,
                 updated_by, actor_email, now, duration_in_prev)
            )
    return get_threat_status(threat_model_id, threat_id)


def get_threat_status_history(threat_model_id: int, threat_id: str) -> list[dict]:
    """Full history of status changes for a single threat, oldest first."""
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM threat_status_history "
            "WHERE threat_model_id=? AND threat_id=? "
            "ORDER BY id ASC",
            (threat_model_id, threat_id)
        ).fetchall()
    return [dict(r) for r in rows]


def get_threat_status(threat_model_id: int, threat_id: str) -> dict | None:
    with db_conn() as c:
        row = c.execute(
            "SELECT * FROM threat_status WHERE threat_model_id=? AND threat_id=?",
            (threat_model_id, threat_id)
        ).fetchone()
    return dict(row) if row else None


def list_threat_statuses(threat_model_id: int) -> dict[str, dict]:
    """Returns {threat_id: status_dict} for all threats in a model."""
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM threat_status WHERE threat_model_id=?",
            (threat_model_id,)
        ).fetchall()
    return {r["threat_id"]: dict(r) for r in rows}


# ---------------------------------------------------------------------------
# Management view aggregation
# ---------------------------------------------------------------------------
def _extract_owasp_label(refs: list) -> str | None:
    """Return the OWASP Top 10 reference label if present in the threat's references."""
    if not refs:
        return None
    for r in refs:
        label = r.get("label", "") if isinstance(r, dict) else ""
        if "A0" in label and ":" in label and "OWASP" in (r.get("url", "") or "").upper() or label.startswith("A0"):
            return label
    # Also accept labels that look like "A03:2021 — Injection"
    for r in refs:
        label = r.get("label", "") if isinstance(r, dict) else ""
        if label.startswith("A") and ":" in label:
            return label
    return None


def management_overview() -> list[dict]:
    """Per-feature roll-up: feature info + threat counts by severity + status counts.
    Also includes OWASP Top 10 distribution and time-to-closure statistics.
    """
    with db_conn() as c:
        features = c.execute(
            "SELECT f.*, r.name AS release_name, r.status AS release_status "
            "FROM features f JOIN releases r ON r.id = f.release_id "
            "ORDER BY r.created_at DESC, f.created_at DESC"
        ).fetchall()
        out = []
        for f in features:
            tms = c.execute(
                "SELECT id, name, owner_id, analysis_json FROM threat_models WHERE feature_id=?",
                (f["id"],)
            ).fetchall()
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            status_counts = {s: 0 for s in VALID_THREAT_STATUSES}
            owasp_counts: dict[str, int] = {}
            total_threats = 0
            critical_titles: list[str] = []
            ttc_seconds: list[int] = []  # closures we've measured

            for tm in tms:
                if not tm["analysis_json"]:
                    continue
                analysis = json.loads(tm["analysis_json"])
                for t in analysis.get("threats", []):
                    sev = t.get("severity", "Medium")
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                    total_threats += 1
                    if sev == "Critical" and len(critical_titles) < 5:
                        critical_titles.append(t.get("title", "—"))
                    # OWASP distribution
                    owasp = _extract_owasp_label(t.get("references", []))
                    if owasp:
                        owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

                # Statuses + TTC for this threat model
                statuses = c.execute(
                    "SELECT status, time_to_closure_seconds FROM threat_status WHERE threat_model_id=?",
                    (tm["id"],)
                ).fetchall()
                for s in statuses:
                    if s["status"] in status_counts:
                        status_counts[s["status"]] += 1
                    if s["time_to_closure_seconds"] is not None:
                        ttc_seconds.append(s["time_to_closure_seconds"])

            avg_ttc = int(sum(ttc_seconds) / len(ttc_seconds)) if ttc_seconds else None

            out.append({
                "feature_id": f["id"],
                "feature_name": f["name"],
                "feature_status": f["status"],
                "release_name": f["release_name"],
                "release_status": f["release_status"],
                "threat_model_count": len(tms),
                "total_threats": total_threats,
                "by_severity": severity_counts,
                "by_status": status_counts,
                "by_owasp": owasp_counts,            # NEW
                "top_critical_titles": critical_titles,
                "avg_time_to_closure_seconds": avg_ttc,   # NEW
                "closures_count": len(ttc_seconds),        # NEW
            })
        return out

import json as _json_domain

# ---------------------------------------------------------------------------
# E5: Custom threat rule CRUD
# ---------------------------------------------------------------------------
def create_custom_rule(user_id: int, data: dict) -> dict:
    with db_conn(write=True) as c:
        cur = c.execute("INSERT INTO custom_threat_rules (user_id,name,title,severity,category,description,applies_to,mitigations,tags) VALUES (?,?,?,?,?,?,?,?,?)",
            (user_id, data.get("name","Custom Rule"), data.get("title",""), data.get("severity","Medium"),
             data.get("category","Custom"), data.get("description",""),
             _json_domain.dumps(data.get("applies_to",[])), _json_domain.dumps(data.get("mitigations",[])), _json_domain.dumps(data.get("tags",[]))))
        rid = cur.lastrowid
    return get_custom_rule(rid)

def get_custom_rule(rule_id: int) -> dict | None:
    with db_conn() as c:
        row = c.execute("SELECT * FROM custom_threat_rules WHERE id=?", (rule_id,)).fetchone()
    return _parse_custom_rule(dict(row)) if row else None

def list_custom_rules(user_id: int, enabled_only: bool = False) -> list[dict]:
    q = "SELECT * FROM custom_threat_rules WHERE user_id=?" + (" AND enabled=1" if enabled_only else "") + " ORDER BY created_at DESC"
    with db_conn() as c:
        rows = c.execute(q, (user_id,)).fetchall()
    return [_parse_custom_rule(dict(r)) for r in rows]

def update_custom_rule(rule_id: int, user_id: int, data: dict) -> dict | None:
    fields, vals = [], []
    for k, v in data.items():
        if k in ("name","title","severity","category","description","enabled"): fields.append(f"{k}=?"); vals.append(v)
        elif k in ("applies_to","mitigations","tags"): fields.append(f"{k}=?"); vals.append(_json_domain.dumps(v))
    if not fields: return get_custom_rule(rule_id)
    vals += [rule_id, user_id]
    with db_conn(write=True) as c:
        c.execute(f"UPDATE custom_threat_rules SET {', '.join(fields)}, updated_at=datetime('now') WHERE id=? AND user_id=?", vals)
    return get_custom_rule(rule_id)

def delete_custom_rule(rule_id: int, user_id: int) -> bool:
    with db_conn(write=True) as c:
        c.execute("DELETE FROM custom_threat_rules WHERE id=? AND user_id=?", (rule_id, user_id))
    return True

def _parse_custom_rule(row: dict) -> dict:
    for k in ("applies_to","mitigations","tags"):
        if isinstance(row.get(k), str):
            try: row[k] = _json_domain.loads(row[k])
            except: row[k] = []
    return row

# Extended threat status with owner + due_date
def upsert_threat_status(threat_model_id: int, threat_id: str, status: str,
                          notes: str = "", updated_by: int = 0,
                          owner: str | None = None, due_date: str | None = None) -> dict:
    with db_conn(write=True) as c:
        try: c.execute("ALTER TABLE threat_status ADD COLUMN owner TEXT")
        except: pass
        try: c.execute("ALTER TABLE threat_status ADD COLUMN due_date TEXT")
        except: pass
    result = set_threat_status(threat_model_id, threat_id, status, notes, updated_by)
    if owner is not None or due_date is not None:
        updates, vals = [], []
        if owner is not None: updates.append("owner=?"); vals.append(owner)
        if due_date is not None: updates.append("due_date=?"); vals.append(due_date)
        vals += [threat_model_id, threat_id]
        with db_conn(write=True) as c:
            c.execute(f"UPDATE threat_status SET {', '.join(updates)} WHERE threat_model_id=? AND threat_id=?", vals)
        result = get_threat_status(threat_model_id, threat_id)
    return result
