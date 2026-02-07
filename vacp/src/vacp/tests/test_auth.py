"""
Tests for Authentication and Authorization

Tests cover:
- API key creation and validation
- Role-based access control
- Session management
"""

from datetime import datetime, timezone, timedelta

import pytest

from vacp.auth.api_keys import (
    APIKeyManager,
    APIKeyScope,
)
from vacp.auth.rbac import (
    RBACManager,
    Permission,
    PermissionSet,
)
from vacp.auth.sessions import (
    SessionManager,
    SessionStatus,
)


class TestAPIKeyManager:
    """Test API key management."""

    @pytest.fixture
    def manager(self):
        return APIKeyManager()

    def test_create_key_returns_raw_key_and_object(self, manager):
        """Test that create_key returns both raw key and APIKey object."""
        raw_key, api_key = manager.create_key(
            name="Test Key",
            scopes=APIKeyScope.READ,
        )

        assert raw_key.startswith("koba_")
        assert len(raw_key) > 20
        assert api_key.name == "Test Key"
        assert api_key.scopes == APIKeyScope.READ

    def test_validate_key_success(self, manager):
        """Test successful key validation."""
        raw_key, api_key = manager.create_key(
            name="Valid Key",
            scopes=APIKeyScope.READ_WRITE,
        )

        result = manager.validate_key(raw_key)

        assert result.valid
        assert result.key.id == api_key.id
        assert result.error is None

    def test_validate_key_with_scope(self, manager):
        """Test key validation with required scope."""
        raw_key, _ = manager.create_key(
            name="Limited Key",
            scopes=APIKeyScope.READ,
        )

        # Should succeed for READ
        result = manager.validate_key(raw_key, required_scope=APIKeyScope.READ)
        assert result.valid

        # Should fail for WRITE
        result = manager.validate_key(raw_key, required_scope=APIKeyScope.WRITE)
        assert not result.valid
        assert "scope" in result.error.lower()

    def test_validate_invalid_key(self, manager):
        """Test validation of invalid key."""
        result = manager.validate_key("invalid_key")
        assert not result.valid
        assert "format" in result.error.lower()

    def test_validate_nonexistent_key(self, manager):
        """Test validation of non-existent key."""
        result = manager.validate_key("koba_" + "a" * 64)
        assert not result.valid
        assert "not found" in result.error.lower()

    def test_revoke_key(self, manager):
        """Test key revocation."""
        raw_key, api_key = manager.create_key(name="To Revoke")

        # Key should be valid initially
        result = manager.validate_key(raw_key)
        assert result.valid

        # Revoke the key
        success = manager.revoke_key(api_key.id)
        assert success

        # Key should no longer be valid
        result = manager.validate_key(raw_key)
        assert not result.valid
        assert "inactive" in result.error.lower()

    def test_delete_key(self, manager):
        """Test key deletion."""
        raw_key, api_key = manager.create_key(name="To Delete")

        success = manager.delete_key(api_key.id)
        assert success

        result = manager.validate_key(raw_key)
        assert not result.valid
        assert "not found" in result.error.lower()

    def test_key_expiration(self, manager):
        """Test key expiration."""
        # Create key that expires immediately
        raw_key, api_key = manager.create_key(
            name="Expiring Key",
            expires_in_days=0,  # Expires today
        )

        # Manually set expiration to the past
        api_key.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        result = manager.validate_key(raw_key)
        assert not result.valid
        assert "expired" in result.error.lower()

    def test_rate_limiting(self, manager):
        """Test rate limiting."""
        raw_key, _ = manager.create_key(
            name="Rate Limited",
            rate_limit=3,  # 3 requests per minute
        )

        # First 3 requests should succeed
        for _ in range(3):
            result = manager.validate_key(raw_key)
            assert result.valid

        # 4th request should be rate limited
        result = manager.validate_key(raw_key)
        assert not result.valid
        assert result.rate_limited

    def test_list_keys(self, manager):
        """Test listing keys."""
        manager.create_key(name="Key 1", tenant_id="tenant-1")
        manager.create_key(name="Key 2", tenant_id="tenant-1")
        manager.create_key(name="Key 3", tenant_id="tenant-2")

        all_keys = manager.list_keys()
        assert len(all_keys) == 3

        tenant1_keys = manager.list_keys(tenant_id="tenant-1")
        assert len(tenant1_keys) == 2

    def test_update_key(self, manager):
        """Test updating key properties."""
        _, api_key = manager.create_key(
            name="Original",
            scopes=APIKeyScope.READ,
        )

        success = manager.update_key(
            api_key.id,
            name="Updated",
            scopes=APIKeyScope.READ_WRITE,
        )
        assert success

        updated = manager.get_key_by_id(api_key.id)
        assert updated.name == "Updated"
        assert updated.scopes == APIKeyScope.READ_WRITE

    def test_key_scopes(self):
        """Test API key scope combinations."""
        assert APIKeyScope.READ in APIKeyScope.READ_WRITE
        assert APIKeyScope.WRITE in APIKeyScope.READ_WRITE
        assert APIKeyScope.DELETE not in APIKeyScope.READ_WRITE

        full = APIKeyScope.FULL_ACCESS
        assert APIKeyScope.READ in full
        assert APIKeyScope.ADMIN in full


class TestRBAC:
    """Test Role-Based Access Control."""

    @pytest.fixture
    def manager(self):
        return RBACManager()

    def test_system_roles_exist(self, manager):
        """Test that system roles are initialized."""
        admin = manager.get_role("admin")
        assert admin is not None
        assert admin.is_system

        super_admin = manager.get_role("super_admin")
        assert super_admin is not None

    def test_super_admin_has_all_permissions(self, manager):
        """Test that super_admin has all permissions."""
        super_admin = manager.get_role("super_admin")

        for perm in Permission:
            assert super_admin.has_permission(perm)

    def test_create_custom_role(self, manager):
        """Test creating a custom role."""
        permissions = PermissionSet({
            Permission.POLICY_READ,
            Permission.AGENT_READ,
        })

        role = manager.create_role(
            name="Custom Role",
            description="A custom role",
            permissions=permissions,
            tenant_id="tenant-1",
        )

        assert role.name == "Custom Role"
        assert role.has_permission(Permission.POLICY_READ)
        assert not role.has_permission(Permission.POLICY_CREATE)
        assert not role.is_system

    def test_delete_custom_role(self, manager):
        """Test deleting a custom role."""
        role = manager.create_role(
            name="To Delete",
            description="Will be deleted",
            permissions=PermissionSet(),
        )

        success = manager.delete_role(role.id)
        assert success

        assert manager.get_role(role.id) is None

    def test_cannot_delete_system_role(self, manager):
        """Test that system roles cannot be deleted."""
        success = manager.delete_role("admin")
        assert not success

        admin = manager.get_role("admin")
        assert admin is not None

    def test_assign_role(self, manager):
        """Test assigning a role to a subject."""
        assignment = manager.assign_role(
            subject_id="user-123",
            subject_type="user",
            role_id="admin",
            tenant_id="tenant-1",
        )

        assert assignment.subject_id == "user-123"
        assert assignment.role_id == "admin"

    def test_get_subject_roles(self, manager):
        """Test getting roles for a subject."""
        manager.assign_role("user-1", "user", "admin")
        manager.assign_role("user-1", "user", "auditor")

        roles = manager.get_subject_roles("user-1")
        role_ids = {r.id for r in roles}

        assert "admin" in role_ids
        assert "auditor" in role_ids

    def test_get_subject_permissions(self, manager):
        """Test getting combined permissions for a subject."""
        manager.assign_role("user-1", "user", "operator")
        manager.assign_role("user-1", "user", "auditor")

        permissions = manager.get_subject_permissions("user-1")

        # From operator
        assert Permission.AGENT_SUSPEND in permissions
        # From auditor
        assert Permission.AUDIT_EXPORT in permissions

    def test_check_permission(self, manager):
        """Test checking a specific permission."""
        manager.assign_role("user-1", "user", "viewer")

        assert manager.check_permission("user-1", Permission.POLICY_READ)
        assert not manager.check_permission("user-1", Permission.POLICY_CREATE)

    def test_revoke_role(self, manager):
        """Test revoking a role from a subject."""
        manager.assign_role("user-1", "user", "admin")

        assert manager.check_permission("user-1", Permission.POLICY_CREATE)

        success = manager.revoke_role("user-1", "admin")
        assert success

        assert not manager.check_permission("user-1", Permission.POLICY_CREATE)

    def test_tenant_scoped_roles(self, manager):
        """Test that roles can be scoped to tenants."""
        manager.assign_role("user-1", "user", "admin", tenant_id="tenant-1")

        # Should have permissions for tenant-1
        assert manager.check_permission("user-1", Permission.POLICY_CREATE, tenant_id="tenant-1")

        # Should also work without tenant (global check)
        assert manager.check_permission("user-1", Permission.POLICY_CREATE)


class TestPermissionSet:
    """Test PermissionSet operations."""

    def test_add_and_has(self):
        """Test adding and checking permissions."""
        ps = PermissionSet()
        ps.add(Permission.POLICY_READ)

        assert ps.has(Permission.POLICY_READ)
        assert not ps.has(Permission.POLICY_CREATE)

    def test_has_any(self):
        """Test has_any method."""
        ps = PermissionSet({Permission.POLICY_READ, Permission.AGENT_READ})

        assert ps.has_any(Permission.POLICY_READ, Permission.POLICY_CREATE)
        assert not ps.has_any(Permission.POLICY_CREATE, Permission.AGENT_CREATE)

    def test_has_all(self):
        """Test has_all method."""
        ps = PermissionSet({Permission.POLICY_READ, Permission.AGENT_READ})

        assert ps.has_all(Permission.POLICY_READ, Permission.AGENT_READ)
        assert not ps.has_all(Permission.POLICY_READ, Permission.POLICY_CREATE)

    def test_union(self):
        """Test union of permission sets."""
        ps1 = PermissionSet({Permission.POLICY_READ})
        ps2 = PermissionSet({Permission.AGENT_READ})

        combined = ps1.union(ps2)

        assert Permission.POLICY_READ in combined
        assert Permission.AGENT_READ in combined

    def test_to_and_from_list(self):
        """Test serialization."""
        ps = PermissionSet({Permission.POLICY_READ, Permission.AGENT_READ})

        as_list = ps.to_list()
        restored = PermissionSet.from_list(as_list)

        assert Permission.POLICY_READ in restored
        assert Permission.AGENT_READ in restored


class TestSessionManager:
    """Test session management."""

    @pytest.fixture
    def manager(self):
        return SessionManager(
            session_duration=timedelta(hours=1),
            inactivity_timeout=timedelta(minutes=30),
            max_concurrent_sessions=3,
        )

    def test_create_session(self, manager):
        """Test creating a session."""
        session = manager.create_session(
            subject_id="user-123",
            subject_type="user",
            tenant_id="tenant-1",
            ip_address="192.168.1.1",
        )

        assert session.subject_id == "user-123"
        assert session.status == SessionStatus.ACTIVE
        assert session.refresh_token is not None

    def test_get_session(self, manager):
        """Test retrieving a session."""
        session = manager.create_session("user-1", "user")

        retrieved = manager.get_session(session.id)
        assert retrieved is not None
        assert retrieved.id == session.id

    def test_validate_session(self, manager):
        """Test session validation."""
        session = manager.create_session("user-1", "user")

        is_valid, retrieved, error = manager.validate_session(session.id)
        assert is_valid
        assert retrieved.id == session.id
        assert error is None

    def test_validate_nonexistent_session(self, manager):
        """Test validating non-existent session."""
        is_valid, _, error = manager.validate_session("nonexistent")
        assert not is_valid
        assert "not found" in error.lower()

    def test_session_expiration(self, manager):
        """Test session expiration."""
        session = manager.create_session("user-1", "user")

        # Manually expire the session
        session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        is_valid, _, error = manager.validate_session(session.id)
        assert not is_valid
        assert "expired" in error.lower()

    def test_revoke_session(self, manager):
        """Test session revocation."""
        session = manager.create_session("user-1", "user")

        success = manager.revoke_session(session.id)
        assert success

        is_valid, _, error = manager.validate_session(session.id)
        assert not is_valid
        assert "revoked" in error.lower()

    def test_revoke_all_sessions(self, manager):
        """Test revoking all sessions for a subject."""
        manager.create_session("user-1", "user")
        manager.create_session("user-1", "user")
        manager.create_session("user-2", "user")

        count = manager.revoke_all_sessions("user-1")
        assert count == 2

        sessions = manager.get_subject_sessions("user-1")
        assert len(sessions) == 0

    def test_concurrent_session_limit(self, manager):
        """Test that concurrent session limit is enforced."""
        # Create sessions up to the limit
        sessions = []
        for i in range(3):
            session = manager.create_session("user-1", "user")
            sessions.append(session)

        # All should be active
        active = manager.get_subject_sessions("user-1")
        assert len(active) == 3

        # Create one more - oldest should be revoked
        new_session = manager.create_session("user-1", "user")

        active = manager.get_subject_sessions("user-1")
        assert len(active) == 3
        assert new_session.id in [s.id for s in active]
        assert sessions[0].id not in [s.id for s in active]

    def test_refresh_session(self, manager):
        """Test session refresh."""
        session = manager.create_session("user-1", "user")
        refresh_token = session.refresh_token

        # Refresh the session
        new_session = manager.refresh_session(refresh_token)

        assert new_session is not None
        assert new_session.id != session.id
        assert new_session.subject_id == session.subject_id

        # Old session should be revoked
        is_valid, _, _ = manager.validate_session(session.id)
        assert not is_valid

    def test_lock_and_unlock_session(self, manager):
        """Test session locking."""
        session = manager.create_session("user-1", "user")

        # Lock the session
        success = manager.lock_session(session.id)
        assert success

        is_valid, _, error = manager.validate_session(session.id)
        assert not is_valid
        assert "locked" in error.lower()

        # Unlock the session
        success = manager.unlock_session(session.id)
        assert success

        is_valid, _, _ = manager.validate_session(session.id)
        assert is_valid

    def test_extend_session(self, manager):
        """Test extending session expiration."""
        session = manager.create_session("user-1", "user")
        original_expires = session.expires_at

        success = manager.extend_session(session.id, timedelta(hours=2))
        assert success

        assert session.expires_at > original_expires


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
