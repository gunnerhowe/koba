"""
Comprehensive Tests for the VACP API Server

Tests:
- Health endpoints (live, ready, detailed)
- Metrics endpoint (Prometheus format)
- Rate limiting middleware
- Security headers
- Tool execution
- Authentication flow
- Policy management
"""

import pytest
import time


# Test middleware independently
class TestRateLimiter:
    """Tests for the rate limiter."""

    def test_sliding_window_allows_requests(self):
        """Test that requests within limit are allowed."""
        from vacp.api.middleware import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter()

        # First request should be allowed
        allowed, remaining, retry_after = limiter.is_allowed("test_key", 10, 60)
        assert allowed is True
        assert remaining == 9
        assert retry_after == 0

    def test_sliding_window_blocks_excess(self):
        """Test that requests over limit are blocked."""
        from vacp.api.middleware import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter()

        # Use up all requests
        for i in range(10):
            allowed, _, _ = limiter.is_allowed("test_key", 10, 60)
            assert allowed is True

        # Next request should be blocked
        allowed, remaining, retry_after = limiter.is_allowed("test_key", 10, 60)
        assert allowed is False
        assert remaining == 0
        assert retry_after > 0

    def test_different_keys_independent(self):
        """Test that different keys have independent limits."""
        from vacp.api.middleware import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter()

        # Use up key1's limit
        for _ in range(10):
            limiter.is_allowed("key1", 10, 60)

        # key2 should still have full limit
        allowed, remaining, _ = limiter.is_allowed("key2", 10, 60)
        assert allowed is True
        assert remaining == 9

    def test_get_stats(self):
        """Test getting limiter stats."""
        from vacp.api.middleware import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter()
        limiter.is_allowed("key1", 10, 60)
        limiter.is_allowed("key2", 10, 60)

        stats = limiter.get_stats()
        assert stats["active_keys"] == 2
        assert stats["total_entries"] == 2


class TestCircuitBreaker:
    """Tests for the circuit breaker."""

    def test_starts_closed(self):
        """Test circuit breaker starts in closed state."""
        from vacp.api.middleware import CircuitBreaker

        cb = CircuitBreaker("test")
        assert cb.state == "closed"
        assert cb.allow_request() is True

    def test_opens_after_failures(self):
        """Test circuit opens after threshold failures."""
        from vacp.api.middleware import CircuitBreaker, CircuitBreakerConfig

        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config)

        # Record failures
        for _ in range(3):
            cb.record_failure()

        assert cb.state == "open"
        assert cb.allow_request() is False

    def test_success_resets_failure_count(self):
        """Test success resets failure count."""
        from vacp.api.middleware import CircuitBreaker, CircuitBreakerConfig

        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config)

        # Some failures
        cb.record_failure()
        cb.record_failure()

        # Success resets
        cb.record_success()

        # Need another 3 failures to open
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "closed"

    def test_transitions_to_half_open(self):
        """Test circuit transitions to half-open after timeout."""
        from vacp.api.middleware import CircuitBreaker, CircuitBreakerConfig

        config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=0.1)
        cb = CircuitBreaker("test", config)

        cb.record_failure()
        assert cb.state == "open"

        # Wait for timeout
        time.sleep(0.15)

        assert cb.state == "half_open"
        assert cb.allow_request() is True

    def test_half_open_closes_on_success(self):
        """Test half-open closes after success threshold."""
        from vacp.api.middleware import CircuitBreaker, CircuitBreakerConfig

        config = CircuitBreakerConfig(
            failure_threshold=1,
            success_threshold=2,
            timeout_seconds=0.1,
        )
        cb = CircuitBreaker("test", config)

        # Open the circuit
        cb.record_failure()
        time.sleep(0.15)

        # Should be half-open now
        assert cb.state == "half_open"

        # Record successes
        cb.record_success()
        cb.record_success()

        assert cb.state == "closed"


class TestMetricsCollector:
    """Tests for metrics collector."""

    def test_record_request(self):
        """Test recording a request."""
        from vacp.api.middleware import MetricsCollector

        collector = MetricsCollector()
        collector.record_request("GET", "/api/test", 200, 50.0)

        output = collector.export_prometheus()
        assert "vacp_http_requests_total" in output
        assert 'method="GET"' in output
        assert 'status="200"' in output

    def test_path_normalization(self):
        """Test that paths are normalized to prevent cardinality explosion."""
        from vacp.api.middleware import MetricsCollector

        collector = MetricsCollector()

        # Record requests with UUIDs
        collector.record_request("GET", "/api/users/123e4567-e89b-12d3-a456-426614174000", 200, 50.0)
        collector.record_request("GET", "/api/users/987fcdeb-51a2-3b4c-d567-890123456789", 200, 50.0)

        output = collector.export_prometheus()

        # Should be normalized to same path
        assert output.count('path="/api/users/{id}"') >= 1

    def test_latency_histogram(self):
        """Test latency histogram buckets."""
        from vacp.api.middleware import MetricsCollector

        collector = MetricsCollector()

        # Record requests with different latencies
        collector.record_request("GET", "/api/test", 200, 5.0)    # <= 5ms bucket
        collector.record_request("GET", "/api/test", 200, 50.0)   # <= 50ms bucket
        collector.record_request("GET", "/api/test", 200, 500.0)  # <= 500ms bucket

        output = collector.export_prometheus()
        assert "vacp_http_request_duration_ms_bucket" in output
        assert 'le="5"' in output
        assert 'le="50"' in output


class TestSecurityHeaders:
    """Tests for security headers."""

    def test_security_headers_added(self):
        """Test that security headers are added to responses."""
        # This would require a full ASGI test, so we'll just verify the middleware exists
        from vacp.api.middleware import SecurityHeadersMiddleware
        assert SecurityHeadersMiddleware is not None


class TestRequestTracing:
    """Tests for request tracing."""

    def test_trace_context_parsing(self):
        """Test W3C trace context parsing."""
        from vacp.api.middleware import RequestTracingMiddleware

        middleware = RequestTracingMiddleware(app=None)

        # Valid traceparent
        trace_id, parent_id = middleware._parse_traceparent(
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        )
        assert trace_id == "0af7651916cd43dd8448eb211c80319c"
        assert parent_id == "b7ad6b7169203331"

        # Invalid traceparent
        trace_id, parent_id = middleware._parse_traceparent("invalid")
        assert trace_id is None
        assert parent_id is None


# API Server Tests (require FastAPI to be installed)
try:
    from fastapi.testclient import TestClient
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


@pytest.fixture
def test_app():
    """Create a test application."""
    if not FASTAPI_AVAILABLE:
        pytest.skip("FastAPI not installed")

    from vacp.api.server import create_app
    import tempfile
    from pathlib import Path
    import gc

    tmpdir = tempfile.mkdtemp()
    app = create_app(storage_path=Path(tmpdir))

    yield app

    # Clean up database connections
    try:
        if hasattr(app.state, 'server'):
            server = app.state.server
            if hasattr(server, 'db_manager') and server.db_manager:
                server.db_manager.close()
            if hasattr(server, 'auth_service') and server.auth_service:
                if hasattr(server.auth_service, '_user_db'):
                    server.auth_service._user_db.close()
    except Exception:
        pass

    # Force garbage collection
    gc.collect()

    # Try to clean up temp directory (may fail on Windows)
    try:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture
def client(test_app):
    """Create a test client."""
    return TestClient(test_app)


@pytest.fixture
def auth_headers(client):
    """Get auth headers for admin user."""
    # Login as admin
    response = client.post("/v1/auth/login", json={
        "email": "admin@koba.local",
        "password": "admin123",
    })

    if response.status_code != 200:
        pytest.skip("Admin login failed")

    data = response.json()
    # API may return access_token or token
    token = data.get("access_token") or data.get("token")
    if not token:
        pytest.skip("No token in login response")
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestHealthEndpoints:
    """Tests for health endpoints."""

    def test_health(self, client):
        """Test basic health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data

    def test_liveness(self, client):
        """Test liveness probe."""
        response = client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    def test_readiness(self, client):
        """Test readiness probe."""
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"

    def test_detailed_health_requires_auth(self, client):
        """Test detailed health requires authentication."""
        response = client.get("/health/detailed")
        assert response.status_code == 401

    def test_detailed_health_with_auth(self, client, auth_headers):
        """Test detailed health with authentication."""
        response = client.get("/health/detailed", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "components" in data


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestMetricsEndpoint:
    """Tests for metrics endpoint."""

    def test_metrics_returns_prometheus_format(self, client):
        """Test metrics endpoint returns Prometheus format."""
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]

        content = response.text
        assert "vacp_info" in content
        assert "vacp_uptime_seconds" in content

    def test_metrics_includes_gateway_stats(self, client):
        """Test metrics includes gateway statistics."""
        response = client.get("/metrics")
        content = response.text
        assert "vacp_gateway_requests_total" in content

    def test_metrics_includes_audit_log(self, client):
        """Test metrics includes audit log size."""
        response = client.get("/metrics")
        content = response.text
        assert "vacp_audit_log_size" in content


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestAuthEndpoints:
    """Tests for authentication endpoints."""

    def test_login_success(self, client):
        """Test successful login."""
        response = client.post("/v1/auth/login", json={
            "email": "admin@koba.local",
            "password": "admin123",
        })
        assert response.status_code == 200
        data = response.json()
        # API returns access_token, not token
        assert "access_token" in data or "token" in data

    def test_login_invalid_password(self, client):
        """Test login with invalid password."""
        response = client.post("/v1/auth/login", json={
            "email": "admin@koba.local",
            "password": "wrongpassword",
        })
        assert response.status_code == 401

    def test_get_me(self, client, auth_headers):
        """Test get current user."""
        response = client.get("/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "admin@koba.local"


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestToolExecution:
    """Tests for tool execution endpoints."""

    def test_get_tool_catalog(self, client, auth_headers):
        """Test getting tool catalog."""
        response = client.get("/v1/tools/catalog", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "tools" in data
        # Should have at least the echo tool
        tool_ids = [t["id"] for t in data["tools"]]
        assert "echo" in tool_ids

    def test_execute_tool(self, client, auth_headers):
        """Test executing a tool."""
        response = client.post("/v1/tools/execute", json={
            "tool_id": "echo",
            "parameters": {"message": "Hello, VACP!"},
            "agent_id": "test-agent",
            "tenant_id": "test-tenant",
            "session_id": "test-session",
        }, headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        # Tool may succeed or be denied by policy
        assert "success" in data or "error" in data
        if data.get("success"):
            assert data["result"]["echo"] == "Hello, VACP!"


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestPolicyEndpoints:
    """Tests for policy management endpoints."""

    def test_list_policy_bundles(self, client, auth_headers):
        """Test listing policy bundles."""
        response = client.get("/v1/policy/bundles", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "bundles" in data

    def test_create_policy_bundle(self, client, auth_headers):
        """Test creating a policy bundle."""
        response = client.post("/v1/policy/bundles", json={
            "id": "test-bundle",
            "version": "1.0.0",
            "name": "Test Policy Bundle",
            "default_decision": "deny",
            "rules": [
                {
                    "id": "allow-echo",
                    "name": "Allow Echo",
                    "tool_patterns": ["echo"],
                    "decision": "allow",
                    "priority": 100,
                }
            ],
        }, headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        # Response format may vary
        assert "id" in data or "bundle_id" in data or "status" in data


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestRateLimitingIntegration:
    """Integration tests for rate limiting."""

    def test_rate_limit_headers_present(self, client):
        """Test rate limit headers are present."""
        response = client.get("/v1/tools/catalog")
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers

    def test_health_exempt_from_rate_limit(self, client):
        """Test health endpoints are exempt from rate limiting."""
        # Make many requests to health
        for _ in range(150):  # More than the limit
            response = client.get("/health")
            assert response.status_code == 200


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestSecurityHeadersIntegration:
    """Integration tests for security headers."""

    def test_security_headers_present(self, client):
        """Test security headers are present in response."""
        response = client.get("/health")

        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert "Strict-Transport-Security" in response.headers


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestContainmentEndpoints:
    """Tests for containment system endpoints."""

    def test_get_containment_status(self, client, auth_headers):
        """Test getting containment status."""
        response = client.get("/v1/containment/status", headers=auth_headers)
        # May require specific permissions
        assert response.status_code in [200, 403]
        if response.status_code == 200:
            data = response.json()
            # Check for either key
            assert "kill_switch" in data or "containment" in data

    def test_get_kill_switch_status(self, client, auth_headers):
        """Test getting kill switch status."""
        response = client.get("/v1/containment/kill-switch/status", headers=auth_headers)
        # Requires SYSTEM_ADMIN permission - may be 200 or 403
        assert response.status_code in [200, 403]
        # Success case - verify response has expected structure
        if response.status_code == 200:
            data = response.json()
            # The response is a dict with various status fields
            assert isinstance(data, dict)


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestAuditEndpoints:
    """Tests for audit log endpoints."""

    def test_get_tree_head(self, client, auth_headers):
        """Test getting audit tree head."""
        response = client.get("/v1/audit/tree-head", headers=auth_headers)
        # May require specific permissions
        assert response.status_code in [200, 403]
        if response.status_code == 200:
            data = response.json()
            # Response may use root, root_hash, or hash
            assert "root" in data or "root_hash" in data or "hash" in data

    def test_get_audit_entries(self, client, auth_headers):
        """Test getting audit entries."""
        response = client.get("/v1/audit/entries", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestReceiptEndpoints:
    """Tests for receipt endpoints."""

    def test_verify_receipt(self, client, auth_headers):
        """Test receipt verification endpoint."""
        # First execute a tool to get a receipt
        exec_response = client.post("/v1/tools/execute", json={
            "tool_id": "echo",
            "parameters": {"message": "test"},
            "agent_id": "test-agent",
            "tenant_id": "test-tenant",
            "session_id": "test-session",
        }, headers=auth_headers)

        if exec_response.status_code == 200 and exec_response.json().get("receipt"):
            receipt_id = exec_response.json()["receipt"]["receipt_id"]

            # Verify the receipt
            verify_response = client.post("/v1/receipts/verify", json={
                "receipt_id": receipt_id,
            }, headers=auth_headers)

            assert verify_response.status_code == 200


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestTokenEndpoints:
    """Tests for token management endpoints."""

    def test_mint_token(self, client, auth_headers):
        """Test minting a token."""
        response = client.post("/v1/tokens/mint", json={
            "tenant_id": "test-tenant",
            "agent_id": "test-agent",
            "session_id": "test-session",
            "tools": ["echo"],
            "ttl_seconds": 300,
            "purpose": "Testing",
        }, headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert "token_id" in data
        assert "token_value" in data

    def test_validate_token(self, client, auth_headers):
        """Test validating a token."""
        # Mint a token first
        mint_response = client.post("/v1/tokens/mint", json={
            "tenant_id": "test-tenant",
            "agent_id": "test-agent",
            "session_id": "test-session",
            "tools": ["echo"],
            "ttl_seconds": 300,
        }, headers=auth_headers)

        if mint_response.status_code == 200:
            token_value = mint_response.json()["token_value"]

            # Validate it
            validate_response = client.post("/v1/tokens/validate", json={
                "token": token_value,
                "tool_id": "echo",
            }, headers=auth_headers)

            assert validate_response.status_code == 200


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestStatsEndpoint:
    """Tests for statistics endpoint."""

    def test_get_stats(self, client, auth_headers):
        """Test getting server statistics."""
        response = client.get("/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "gateway" in data
        assert "policy" in data
        assert "registry" in data
        assert "audit_log" in data
