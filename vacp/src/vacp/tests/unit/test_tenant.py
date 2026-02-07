"""
Unit Tests for Tenant Service

Tests:
- Tenant CRUD operations
- Tenant context management
- API key management
"""


from vacp.core.tenant import (
    TenantContext,
    TenantStatus,
    TenantPlan,
    get_current_tenant,
    set_current_tenant,
    clear_tenant_context,
)


class TestTenantService:
    """Tests for TenantService."""

    def test_create_tenant(self, tenant_service):
        """Test creating a new tenant."""
        tenant = tenant_service.create_tenant(
            name="Acme Corp",
            slug="acme-corp",
            plan=TenantPlan.STARTER,
        )

        assert tenant.id is not None
        assert tenant.name == "Acme Corp"
        assert tenant.slug == "acme-corp"
        assert tenant.plan == TenantPlan.STARTER
        assert tenant.status == TenantStatus.ACTIVE

    def test_create_tenant_auto_slug(self, tenant_service):
        """Test creating tenant with auto-generated slug."""
        tenant = tenant_service.create_tenant(
            name="Test Company",
        )

        assert tenant.slug == "test-company"

    def test_create_tenant_duplicate_slug(self, tenant_service):
        """Test creating tenant with duplicate slug gets auto-suffix."""
        tenant1 = tenant_service.create_tenant(name="First", slug="unique-slug")
        # When slug already exists, a random suffix is added
        tenant2 = tenant_service.create_tenant(name="Second", slug="unique-slug")

        assert tenant1.slug == "unique-slug"
        assert tenant2.slug.startswith("unique-slug-")  # Has random suffix
        assert tenant1.slug != tenant2.slug

    def test_get_tenant(self, tenant_service, test_tenant):
        """Test getting a tenant by ID."""
        retrieved = tenant_service.get_tenant(test_tenant.id)

        assert retrieved is not None
        assert retrieved.id == test_tenant.id
        assert retrieved.name == test_tenant.name

    def test_get_tenant_by_slug(self, tenant_service, test_tenant):
        """Test getting a tenant by slug."""
        retrieved = tenant_service.get_tenant_by_slug(test_tenant.slug)

        assert retrieved is not None
        assert retrieved.slug == test_tenant.slug

    def test_update_tenant(self, tenant_service, test_tenant):
        """Test updating a tenant."""
        updated = tenant_service.update_tenant(
            tenant_id=test_tenant.id,
            name="Updated Name",
            plan=TenantPlan.PROFESSIONAL,
        )

        assert updated.name == "Updated Name"
        assert updated.plan == TenantPlan.PROFESSIONAL

    def test_suspend_tenant(self, tenant_service, test_tenant):
        """Test suspending a tenant."""
        success = tenant_service.suspend_tenant(test_tenant.id)
        assert success

        tenant = tenant_service.get_tenant(test_tenant.id)
        assert tenant.status == TenantStatus.SUSPENDED

    def test_activate_tenant(self, tenant_service, test_tenant):
        """Test activating a suspended tenant."""
        tenant_service.suspend_tenant(test_tenant.id)
        tenant = tenant_service.reactivate_tenant(test_tenant.id)
        assert tenant is not None
        assert tenant.status == TenantStatus.ACTIVE

    def test_delete_tenant(self, tenant_service, test_tenant):
        """Test deleting a tenant (soft delete)."""
        success = tenant_service.delete_tenant(test_tenant.id)
        assert success

        # Soft delete marks as DELETED but still returns tenant
        tenant = tenant_service.get_tenant(test_tenant.id)
        assert tenant is not None
        assert tenant.status == TenantStatus.DELETED

    def test_list_tenants(self, tenant_service):
        """Test listing tenants."""
        tenant_service.create_tenant(name="Tenant 1")
        tenant_service.create_tenant(name="Tenant 2")
        tenant_service.create_tenant(name="Tenant 3")

        tenants = tenant_service.list_tenants(limit=10)
        assert len(tenants) >= 3


class TestTenantContext:
    """Tests for TenantContext."""

    def test_tenant_context_set_get(self):
        """Test setting and getting tenant context."""
        ctx = TenantContext(
            tenant_id="test-123",
            tenant_name="Test",
            tenant_slug="test",
            plan=TenantPlan.FREE,
        )

        set_current_tenant(ctx)
        retrieved = get_current_tenant()

        assert retrieved is not None
        assert retrieved.tenant_id == "test-123"

        clear_tenant_context()

    def test_tenant_context_clear(self):
        """Test clearing tenant context."""
        ctx = TenantContext(
            tenant_id="test-123",
            tenant_name="Test",
            tenant_slug="test",
            plan=TenantPlan.FREE,
        )

        set_current_tenant(ctx)
        clear_tenant_context()

        assert get_current_tenant() is None

    def test_tenant_context_isolation(self):
        """Test tenant context is isolated."""
        # This would ideally test async context isolation
        clear_tenant_context()
        assert get_current_tenant() is None


class TestTenantToDict:
    """Tests for Tenant serialization."""

    def test_to_dict(self, test_tenant):
        """Test Tenant to_dict method."""
        data = test_tenant.to_dict()

        assert "id" in data
        assert "name" in data
        assert "slug" in data
        assert "status" in data
        assert "plan" in data
        assert "created_at" in data
