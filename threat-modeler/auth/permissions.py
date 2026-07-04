"""Permission registry — single source of truth for what each role can do.

Adding a new permission: add it to PERMISSIONS, then assign it to whatever roles
need it in ROLE_PERMISSIONS. The decorators in decorators.py reference these names.

Permission naming convention:
    <resource>.<action>[.<scope>]
where scope is 'own', 'released', 'all' or omitted (= no scope filter).

Resource-level checks (does THIS user own THIS specific resource) are
separate — see resource_access.py. Permissions answer "is this role allowed
to do this kind of thing at all," ownership answers "but can they do it to
this specific row."
"""

PERMISSIONS = {
    # Threat-model CRUD
    "threat_model.create",
    "threat_model.read.own",        # Only their own
    "threat_model.read.all",        # Across all users
    "threat_model.update.own",
    "threat_model.update.all",
    "threat_model.delete.own",
    "threat_model.delete.all",

    # Threat status (per-threat state tracking)
    "threat_status.update.own",
    "threat_status.update.all",

    # Reports
    "report.generate.own",
    "report.generate.all",

    # Releases
    "release.create",
    "release.read.all",
    "release.update.all",
    "release.delete.all",

    # Features
    "feature.create",
    "feature.read.own",             # Features they have access to
    "feature.read.all",             # All features
    "feature.update.all",
    "feature.delete.all",

    # User management
    "user.create",
    "user.read.all",
    "user.update.all",
    "user.delete.all",
    "user.feature_access.grant",    # Admin grants users access to features

    # Views
    "view.developer",               # Developer detailed view
    "view.management",              # Management overview view
    "view.admin",                   # Admin console

    # Audit log
    "audit.read",
}


ROLE_PERMISSIONS = {
    "user": {
        "threat_model.create",
        "threat_model.read.own",
        "threat_model.update.own",
        "threat_model.delete.own",
        "threat_status.update.own",
        "report.generate.own",
        "feature.read.own",
        "view.developer",
    },

    "management": {
        # Management is READ-ONLY. They see all threat models and can generate
        # reports, but cannot change anything. Status updates are restricted to
        # the threat model's owner (or admin).
        "threat_model.read.all",
        "report.generate.all",
        "release.read.all",
        "feature.read.all",
        "view.management",
        "view.developer",       # Can switch to dev view if they want to drill in
    },

    "admin": {
        # Admin gets everything except things that don't make sense for them.
        # Listed explicitly — no '*' wildcard so the audit log is precise.
        "threat_model.create",
        "threat_model.read.all",
        "threat_model.update.all",
        "threat_model.delete.all",
        "threat_status.update.all",
        "report.generate.all",
        "release.create", "release.read.all", "release.update.all", "release.delete.all",
        "feature.create", "feature.read.all", "feature.update.all", "feature.delete.all",
        "user.create", "user.read.all", "user.update.all", "user.delete.all",
        "user.feature_access.grant",
        "view.developer", "view.management", "view.admin",
        "audit.read",
    },
}


def role_has_permission(role: str, permission: str) -> bool:
    """Is this role permitted to do this action at all?"""
    if permission not in PERMISSIONS:
        # If we ask about a permission that doesn't exist, fail closed.
        # This catches typos in @require_permission decorators.
        raise ValueError(f"Unknown permission: {permission!r}")
    return permission in ROLE_PERMISSIONS.get(role, set())


def get_role_permissions(role: str) -> set[str]:
    """All permissions for a role. Used by the frontend to know what to show."""
    return ROLE_PERMISSIONS.get(role, set()).copy()
