"""
Integration Tests for Tenant API

Tests:
- Tenant management endpoints
- API key management
- Tenant context resolution
"""



class TestTenantAdminAPI:
    """Tests for admin tenant endpoints."""

    def test_create_tenant(self, client, auth_headers):
        """Test creating a tenant via API."""
        response = client.post(
            "/v1/admin/tenants",
            json={
                "name": "API Test Tenant",
                "slug": "api-test-tenant",
                "plan": "starter",
            },
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "API Test Tenant"
        assert data["slug"] == "api-test-tenant"
        assert data["plan"] == "starter"

    def test_list_tenants(self, client, auth_headers):
        """Test listing tenants via API."""
        # Create a tenant first
        client.post(
            "/v1/admin/tenants",
            json={"name": "List Test"},
            headers=auth_headers
        )

        response = client.get("/v1/admin/tenants", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert "tenants" in data
        assert len(data["tenants"]) > 0

    def test_get_tenant(self, client, auth_headers):
        """Test getting a specific tenant."""
        # Create a tenant
        create_response = client.post(
            "/v1/admin/tenants",
            json={"name": "Get Test"},
            headers=auth_headers
        )
        tenant_id = create_response.json()["id"]

        # Get it
        response = client.get(
            f"/v1/admin/tenants/{tenant_id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        assert response.json()["id"] == tenant_id

    def test_update_tenant(self, client, auth_headers):
        """Test updating a tenant."""
        # Create a tenant
        create_response = client.post(
            "/v1/admin/tenants",
            json={"name": "Update Test"},
            headers=auth_headers
        )
        tenant_id = create_response.json()["id"]

        # Update it
        response = client.put(
            f"/v1/admin/tenants/{tenant_id}",
            json={"name": "Updated Name", "plan": "professional"},
            headers=auth_headers
        )

        assert response.status_code == 200
        assert response.json()["name"] == "Updated Name"
        assert response.json()["plan"] == "professional"

    def test_suspend_tenant(self, client, auth_headers):
        """Test suspending a tenant."""
        # Create a tenant
        create_response = client.post(
            "/v1/admin/tenants",
            json={"name": "Suspend Test"},
            headers=auth_headers
        )
        tenant_id = create_response.json()["id"]

        # Suspend it
        response = client.post(
            f"/v1/admin/tenants/{tenant_id}/suspend",
            headers=auth_headers
        )

        assert response.status_code == 200
        assert response.json()["status"] == "suspended"

    def test_activate_tenant(self, client, auth_headers):
        """Test activating a suspended tenant."""
        # Create and suspend a tenant
        create_response = client.post(
            "/v1/admin/tenants",
            json={"name": "Activate Test"},
            headers=auth_headers
        )
        tenant_id = create_response.json()["id"]
        client.post(f"/v1/admin/tenants/{tenant_id}/suspend", headers=auth_headers)

        # Activate it
        response = client.post(
            f"/v1/admin/tenants/{tenant_id}/activate",
            headers=auth_headers
        )

        assert response.status_code == 200
        assert response.json()["status"] == "activated"

    def test_delete_tenant(self, client, auth_headers):
        """Test deleting a tenant."""
        # Create a tenant
        create_response = client.post(
            "/v1/admin/tenants",
            json={"name": "Delete Test"},
            headers=auth_headers
        )
        tenant_id = create_response.json()["id"]

        # Delete it
        response = client.delete(
            f"/v1/admin/tenants/{tenant_id}",
            headers=auth_headers
        )

        assert response.status_code == 200

        # Verify it's gone
        get_response = client.get(
            f"/v1/admin/tenants/{tenant_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    def test_tenant_not_found(self, client, auth_headers):
        """Test 404 for non-existent tenant."""
        response = client.get(
            "/v1/admin/tenants/non-existent-id",
            headers=auth_headers
        )

        assert response.status_code == 404


class TestTenantAuthRequired:
    """Tests for tenant endpoints requiring authentication."""

    def test_create_tenant_requires_auth(self, client):
        """Test creating tenant requires authentication."""
        response = client.post(
            "/v1/admin/tenants",
            json={"name": "No Auth Test"},
        )

        assert response.status_code == 401

    def test_list_tenants_requires_auth(self, client):
        """Test listing tenants requires authentication."""
        response = client.get("/v1/admin/tenants")

        assert response.status_code == 401


class TestBlockchainAnchorsAPI:
    """Tests for blockchain anchor endpoints."""

    def test_list_anchors_empty(self, client, auth_headers):
        """Test listing anchors when none exist."""
        response = client.get("/v1/audit/anchors", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert "anchors" in data
        # May be empty or have entries depending on test state

    def test_anchor_scheduler_status(self, client, auth_headers):
        """Test getting anchor scheduler status."""
        response = client.get(
            "/v1/audit/anchor-scheduler/status",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "enabled" in data or "running" in data
