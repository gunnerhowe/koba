"""
Role-Based Access Control (RBAC) for Koba/VACP

Provides:
- Role definitions with permissions
- Permission checks
- Role hierarchy support
- Tenant-scoped roles
"""

# DEPRECATED: This RBAC module is not used by the main API server.
# The canonical auth system is vacp.core.auth which provides:
# - UserRole and Permission enums
# - AuthService with JWT, password hashing, and user management
# - UserDatabase with SQLite persistence
# This module is retained for reference but should not be imported for new code.

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import threading


class Permission(str, Enum):
    """Fine-grained permissions for RBAC."""
    # Policy permissions
    POLICY_READ = "policy:read"
    POLICY_CREATE = "policy:create"
    POLICY_UPDATE = "policy:update"
    POLICY_DELETE = "policy:delete"
    POLICY_ACTIVATE = "policy:activate"

    # Agent permissions
    AGENT_READ = "agent:read"
    AGENT_CREATE = "agent:create"
    AGENT_UPDATE = "agent:update"
    AGENT_DELETE = "agent:delete"
    AGENT_SUSPEND = "agent:suspend"

    # Audit permissions
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # Tenant permissions
    TENANT_READ = "tenant:read"
    TENANT_CREATE = "tenant:create"
    TENANT_UPDATE = "tenant:update"
    TENANT_DELETE = "tenant:delete"

    # System permissions
    SYSTEM_CONFIG = "system:config"
    SYSTEM_KILL_SWITCH = "system:kill_switch"
    SYSTEM_ADMIN = "system:admin"

    # Tool permissions
    TOOL_READ = "tool:read"
    TOOL_REGISTER = "tool:register"
    TOOL_APPROVE = "tool:approve"
    TOOL_REVOKE = "tool:revoke"

    # API Key permissions
    APIKEY_READ = "apikey:read"
    APIKEY_CREATE = "apikey:create"
    APIKEY_REVOKE = "apikey:revoke"


class PermissionSet:
    """A set of permissions with easy checking."""

    def __init__(self, permissions: Optional[Set[Permission]] = None):
        self._permissions: Set[Permission] = permissions or set()

    def add(self, permission: Permission) -> None:
        """Add a permission."""
        self._permissions.add(permission)

    def remove(self, permission: Permission) -> None:
        """Remove a permission."""
        self._permissions.discard(permission)

    def has(self, permission: Permission) -> bool:
        """Check if permission exists."""
        return permission in self._permissions

    def has_any(self, *permissions: Permission) -> bool:
        """Check if any of the given permissions exist."""
        return any(p in self._permissions for p in permissions)

    def has_all(self, *permissions: Permission) -> bool:
        """Check if all of the given permissions exist."""
        return all(p in self._permissions for p in permissions)

    def union(self, other: "PermissionSet") -> "PermissionSet":
        """Return union of two permission sets."""
        return PermissionSet(self._permissions | other._permissions)

    def __contains__(self, permission: Permission) -> bool:
        return permission in self._permissions

    def __iter__(self):
        return iter(self._permissions)

    def __len__(self) -> int:
        return len(self._permissions)

    def to_list(self) -> List[str]:
        """Convert to list of permission strings."""
        return [p.value for p in self._permissions]

    @classmethod
    def from_list(cls, permissions: List[str]) -> "PermissionSet":
        """Create from list of permission strings."""
        return cls({Permission(p) for p in permissions})


@dataclass
class Role:
    """Represents a role with permissions."""
    id: str
    name: str
    description: str
    permissions: PermissionSet
    tenant_id: Optional[str] = None  # None = global role
    parent_role_id: Optional[str] = None  # For role hierarchy
    is_system: bool = False  # System roles can't be deleted
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_permission(self, permission: Permission) -> bool:
        """Check if role has a permission."""
        return self.permissions.has(permission)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "permissions": self.permissions.to_list(),
            "tenant_id": self.tenant_id,
            "parent_role_id": self.parent_role_id,
            "is_system": self.is_system,
            "created_at": self.created_at.isoformat(),
        }


# Built-in system roles
SYSTEM_ROLES = {
    "super_admin": Role(
        id="super_admin",
        name="Super Administrator",
        description="Full access to all system functions",
        permissions=PermissionSet({p for p in Permission}),
        is_system=True,
    ),
    "admin": Role(
        id="admin",
        name="Administrator",
        description="Administrative access within a tenant",
        permissions=PermissionSet({
            Permission.POLICY_READ, Permission.POLICY_CREATE,
            Permission.POLICY_UPDATE, Permission.POLICY_DELETE,
            Permission.POLICY_ACTIVATE,
            Permission.AGENT_READ, Permission.AGENT_CREATE,
            Permission.AGENT_UPDATE, Permission.AGENT_DELETE,
            Permission.AGENT_SUSPEND,
            Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
            Permission.TOOL_READ, Permission.TOOL_REGISTER,
            Permission.TOOL_APPROVE, Permission.TOOL_REVOKE,
            Permission.APIKEY_READ, Permission.APIKEY_CREATE,
            Permission.APIKEY_REVOKE,
        }),
        is_system=True,
    ),
    "operator": Role(
        id="operator",
        name="Operator",
        description="Day-to-day operational access",
        permissions=PermissionSet({
            Permission.POLICY_READ,
            Permission.AGENT_READ, Permission.AGENT_UPDATE,
            Permission.AGENT_SUSPEND,
            Permission.AUDIT_READ,
            Permission.TOOL_READ, Permission.TOOL_APPROVE,
        }),
        is_system=True,
    ),
    "auditor": Role(
        id="auditor",
        name="Auditor",
        description="Read-only access to audit logs and policies",
        permissions=PermissionSet({
            Permission.POLICY_READ,
            Permission.AGENT_READ,
            Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
        }),
        is_system=True,
    ),
    "developer": Role(
        id="developer",
        name="Developer",
        description="Access to develop and test tools",
        permissions=PermissionSet({
            Permission.POLICY_READ,
            Permission.AGENT_READ, Permission.AGENT_CREATE,
            Permission.TOOL_READ, Permission.TOOL_REGISTER,
        }),
        is_system=True,
    ),
    "viewer": Role(
        id="viewer",
        name="Viewer",
        description="Read-only access",
        permissions=PermissionSet({
            Permission.POLICY_READ,
            Permission.AGENT_READ,
            Permission.TOOL_READ,
        }),
        is_system=True,
    ),
}


@dataclass
class RoleAssignment:
    """Assignment of a role to a subject (user/service)."""
    subject_id: str
    subject_type: str  # "user", "service", "api_key"
    role_id: str
    tenant_id: Optional[str] = None  # Scope of assignment
    assigned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    assigned_by: Optional[str] = None
    expires_at: Optional[datetime] = None

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


class RBACManager:
    """
    Manages Role-Based Access Control.

    Features:
    - Built-in system roles
    - Custom role creation
    - Role hierarchy
    - Tenant-scoped permissions
    """

    def __init__(self):
        self._roles: Dict[str, Role] = {}
        self._assignments: Dict[str, List[RoleAssignment]] = {}  # subject_id -> assignments
        self._lock = threading.Lock()

        # Initialize with system roles
        for role_id, role in SYSTEM_ROLES.items():
            self._roles[role_id] = role

    def create_role(
        self,
        name: str,
        description: str,
        permissions: PermissionSet,
        tenant_id: Optional[str] = None,
        parent_role_id: Optional[str] = None,
    ) -> Role:
        """Create a new custom role."""
        import secrets
        role_id = secrets.token_hex(8)

        role = Role(
            id=role_id,
            name=name,
            description=description,
            permissions=permissions,
            tenant_id=tenant_id,
            parent_role_id=parent_role_id,
            is_system=False,
        )

        with self._lock:
            self._roles[role_id] = role

        return role

    def get_role(self, role_id: str) -> Optional[Role]:
        """Get a role by ID."""
        with self._lock:
            return self._roles.get(role_id)

    def list_roles(self, tenant_id: Optional[str] = None) -> List[Role]:
        """List all roles, optionally filtered by tenant."""
        with self._lock:
            roles = list(self._roles.values())

        if tenant_id:
            # Include global roles and tenant-specific roles
            roles = [r for r in roles if r.tenant_id is None or r.tenant_id == tenant_id]

        return roles

    def update_role(
        self,
        role_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[PermissionSet] = None,
    ) -> bool:
        """Update a role's properties."""
        with self._lock:
            role = self._roles.get(role_id)
            if role is None or role.is_system:
                return False

            if name is not None:
                role.name = name
            if description is not None:
                role.description = description
            if permissions is not None:
                role.permissions = permissions

            return True

    def delete_role(self, role_id: str) -> bool:
        """Delete a custom role."""
        with self._lock:
            role = self._roles.get(role_id)
            if role is None or role.is_system:
                return False

            del self._roles[role_id]
            return True

    def assign_role(
        self,
        subject_id: str,
        subject_type: str,
        role_id: str,
        tenant_id: Optional[str] = None,
        assigned_by: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> RoleAssignment:
        """Assign a role to a subject."""
        if role_id not in self._roles:
            raise ValueError(f"Role {role_id} does not exist")

        assignment = RoleAssignment(
            subject_id=subject_id,
            subject_type=subject_type,
            role_id=role_id,
            tenant_id=tenant_id,
            assigned_by=assigned_by,
            expires_at=expires_at,
        )

        with self._lock:
            if subject_id not in self._assignments:
                self._assignments[subject_id] = []
            self._assignments[subject_id].append(assignment)

        return assignment

    def revoke_role(
        self,
        subject_id: str,
        role_id: str,
        tenant_id: Optional[str] = None,
    ) -> bool:
        """Revoke a role from a subject."""
        with self._lock:
            if subject_id not in self._assignments:
                return False

            original_count = len(self._assignments[subject_id])
            self._assignments[subject_id] = [
                a for a in self._assignments[subject_id]
                if not (a.role_id == role_id and a.tenant_id == tenant_id)
            ]

            return len(self._assignments[subject_id]) < original_count

    def get_subject_roles(
        self,
        subject_id: str,
        tenant_id: Optional[str] = None,
    ) -> List[Role]:
        """Get all roles assigned to a subject."""
        with self._lock:
            assignments = self._assignments.get(subject_id, [])

        # Filter by tenant and expiration
        valid_assignments = [
            a for a in assignments
            if not a.is_expired() and (tenant_id is None or a.tenant_id == tenant_id)
        ]

        roles = []
        for assignment in valid_assignments:
            role = self.get_role(assignment.role_id)
            if role:
                roles.append(role)

        return roles

    def get_subject_permissions(
        self,
        subject_id: str,
        tenant_id: Optional[str] = None,
    ) -> PermissionSet:
        """Get all permissions for a subject (union of all role permissions)."""
        roles = self.get_subject_roles(subject_id, tenant_id)

        all_permissions = PermissionSet()
        for role in roles:
            all_permissions = all_permissions.union(role.permissions)

            # Include parent role permissions
            if role.parent_role_id:
                parent_role = self.get_role(role.parent_role_id)
                if parent_role:
                    all_permissions = all_permissions.union(parent_role.permissions)

        return all_permissions

    def check_permission(
        self,
        subject_id: str,
        permission: Permission,
        tenant_id: Optional[str] = None,
    ) -> bool:
        """Check if a subject has a specific permission."""
        permissions = self.get_subject_permissions(subject_id, tenant_id)
        return permission in permissions

    def check_any_permission(
        self,
        subject_id: str,
        *permissions: Permission,
        tenant_id: Optional[str] = None,
    ) -> bool:
        """Check if a subject has any of the given permissions."""
        subject_permissions = self.get_subject_permissions(subject_id, tenant_id)
        return subject_permissions.has_any(*permissions)

    def check_all_permissions(
        self,
        subject_id: str,
        *permissions: Permission,
        tenant_id: Optional[str] = None,
    ) -> bool:
        """Check if a subject has all of the given permissions."""
        subject_permissions = self.get_subject_permissions(subject_id, tenant_id)
        return subject_permissions.has_all(*permissions)
