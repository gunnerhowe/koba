"""
Authentication and Authorization for Koba/VACP

Provides:
- API key authentication
- Role-based access control (RBAC)
- Session management
- Audit logging for operator actions
"""

from vacp.auth.api_keys import (
    APIKeyManager,
    APIKey,
    APIKeyScope,
    APIKeyValidationResult,
)
from vacp.auth.rbac import (
    RBACManager,
    Role,
    Permission,
    PermissionSet,
)
from vacp.auth.sessions import (
    SessionManager,
    Session,
    SessionStatus,
)

__all__ = [
    "APIKeyManager",
    "APIKey",
    "APIKeyScope",
    "APIKeyValidationResult",
    "RBACManager",
    "Role",
    "Permission",
    "PermissionSet",
    "SessionManager",
    "Session",
    "SessionStatus",
]
