"""Auth package.

Public API:
    from auth import (
        register_user, login, get_user_by_id, list_users,
        update_user_role, deactivate_user,
        consume_refresh_token, create_access_token, revoke_all_refresh_tokens,
        get_current_user, require_permission, require_role,
        ensure_can_access_threat_model, can_access_threat_model,
        ensure_can_access_feature := can_access_feature,
        ROLE_PERMISSIONS, get_role_permissions,
    )
"""
from auth.auth import (
    register_user, login, get_user_by_id, list_users,
    update_user_role, deactivate_user,
    consume_refresh_token, create_access_token, revoke_all_refresh_tokens,
)
from auth.deps import (
    get_current_user, require_permission, require_role,
    ensure_can_access_threat_model, can_access_threat_model,
    can_access_feature,
)
from auth.permissions import (
    ROLE_PERMISSIONS, PERMISSIONS, role_has_permission, get_role_permissions,
)

__all__ = [
    "register_user", "login", "get_user_by_id", "list_users",
    "update_user_role", "deactivate_user",
    "consume_refresh_token", "create_access_token", "revoke_all_refresh_tokens",
    "get_current_user", "require_permission", "require_role",
    "ensure_can_access_threat_model", "can_access_threat_model",
    "can_access_feature",
    "ROLE_PERMISSIONS", "PERMISSIONS", "role_has_permission", "get_role_permissions",
]
