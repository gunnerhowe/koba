"""
Test Configuration and Fixtures

Provides:
- Test fixtures for database, auth, and server
- Async test support
- Test utilities
"""

import asyncio
import os
import sys
import pytest
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Generator

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# Configure for async tests
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test data."""
    # Use ignore_cleanup_errors=True for Windows file locking issues
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_db_path(temp_dir: Path) -> Path:
    """Get test database path."""
    return temp_dir / "test.db"


@pytest.fixture
def test_keypair():
    """Generate a test keypair."""
    from vacp.core.crypto import generate_keypair
    return generate_keypair()


@pytest.fixture
def auth_service(test_db_path: Path):
    """Create an auth service for testing."""
    from vacp.core.auth import create_auth_service
    return create_auth_service(
        db_path=test_db_path,
        jwt_secret="test_jwt_secret_12345678901234567890"
    )


@pytest.fixture
def test_user(auth_service):
    """Create a test user."""
    from vacp.core.auth import UserRole
    return auth_service.register(
        email="test@example.com",
        username="testuser",
        password="testpass123",
        role=UserRole.ADMIN,
    )


@pytest.fixture
def test_admin(auth_service):
    """Create a test admin user."""
    from vacp.core.auth import UserRole
    return auth_service.register(
        email="admin@example.com",
        username="adminuser",
        password="adminpass123",
        role=UserRole.SUPER_ADMIN,
        is_system_admin=True,
    )


@pytest.fixture
def database_manager(test_db_path: Path):
    """Create a database manager for testing."""
    from vacp.core.database import DatabaseManager
    db_url = f"sqlite:///{test_db_path}"
    db = DatabaseManager(database_url=db_url)
    db.create_tables()
    yield db
    # Clean up database connections to avoid Windows file locking
    db.engine.dispose()


@pytest.fixture
def tenant_service(database_manager):
    """Create a tenant service for testing."""
    from vacp.core.tenant import TenantService
    return TenantService(database_manager)


@pytest.fixture
def test_tenant(tenant_service):
    """Create a test tenant."""
    from vacp.core.tenant import TenantPlan
    return tenant_service.create_tenant(
        name="Test Tenant",
        slug="test-tenant",
        plan=TenantPlan.STARTER,
    )


@pytest.fixture
def policy_engine(test_keypair):
    """Create a policy engine for testing."""
    from vacp.core.policy import PolicyEngine, PolicyBundle, PolicyRule, PolicyDecision
    engine = PolicyEngine(keypair=test_keypair)

    # Create a test policy
    bundle = PolicyBundle(
        id="test-policy",
        version="1.0.0",
        name="Test Policy",
        default_decision=PolicyDecision.DENY,
    )
    bundle.add_rule(PolicyRule(
        id="allow-echo",
        name="Allow Echo",
        tool_patterns=["echo"],
        decision=PolicyDecision.ALLOW,
    ))
    bundle.add_rule(PolicyRule(
        id="approve-write",
        name="Approve Writes",
        tool_patterns=["*.write"],
        require_approval=True,
        decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
    ))

    engine.load_bundle(bundle)
    return engine


@pytest.fixture
def tool_registry():
    """Create a tool registry for testing."""
    from vacp.core.registry import (
        ToolRegistry, ToolDefinition, ToolSchema,
        ParameterSchema, ToolCategory, ToolRiskLevel
    )

    registry = ToolRegistry()

    # Register test tools
    echo_tool = ToolDefinition(
        id="echo",
        name="Echo",
        description="Echoes back the input",
        schema=ToolSchema(
            parameters=[
                ParameterSchema(name="message", type="string", required=True),
            ]
        ),
        categories=[ToolCategory.READ],
        risk_level=ToolRiskLevel.LOW,
    )
    registry.register(echo_tool)

    write_tool = ToolDefinition(
        id="file.write",
        name="Write File",
        description="Write to a file",
        schema=ToolSchema(
            parameters=[
                ParameterSchema(name="path", type="string", required=True),
                ParameterSchema(name="content", type="string", required=True),
            ]
        ),
        categories=[ToolCategory.WRITE],
        risk_level=ToolRiskLevel.MEDIUM,
        requires_approval=True,
    )
    registry.register(write_tool)

    return registry


@pytest.fixture
def receipt_service(test_keypair):
    """Create a receipt service for testing."""
    from vacp.core.receipts import ReceiptService
    return ReceiptService(keypair=test_keypair)


@pytest.fixture
def merkle_log(test_keypair):
    """Create a merkle log for testing."""
    from vacp.core.merkle import MerkleLog
    return MerkleLog(keypair=test_keypair)


@pytest.fixture
def audit_log(merkle_log):
    """Create an auditable log for testing."""
    from vacp.core.merkle import AuditableLog
    return AuditableLog(merkle_log=merkle_log)


@pytest.fixture
def gateway(tool_registry, policy_engine, receipt_service, audit_log, test_keypair):
    """Create a tool gateway for testing."""
    from vacp.core.gateway import ToolGateway

    gw = ToolGateway(
        registry=tool_registry,
        policy_engine=policy_engine,
        receipt_service=receipt_service,
        audit_log=audit_log,
        keypair=test_keypair,
    )

    # Register executors
    async def echo_executor(tool_id: str, params: dict) -> dict:
        return {"echo": params.get("message", "")}

    async def write_executor(tool_id: str, params: dict) -> dict:
        return {"written": True, "path": params.get("path")}

    gw.register_executor("echo", echo_executor)
    gw.register_executor("file.write", write_executor)

    return gw


@pytest.fixture
def mock_hedera_service():
    """Create a mock Hedera service for testing."""
    from unittest.mock import AsyncMock, MagicMock
    from vacp.core.blockchain import HederaAnchorService, BlockchainAnchor

    service = MagicMock(spec=HederaAnchorService)
    service.anchor = AsyncMock(return_value=BlockchainAnchor(
        id="test-anchor-123",
        tree_size=100,
        merkle_root="a" * 64,
        tree_head_signature="sig123",
        chain="hedera",
        network="testnet",
        transaction_id="0.0.123@1234567890.123456789",
        topic_id="0.0.456",
        sequence_number=1,
        consensus_timestamp="1234567890.123456789",
        verified=True,
        anchored_at=datetime.now(timezone.utc),
    ))
    service.verify = AsyncMock(return_value=True)

    return service


# HTTP Test Client fixtures
@pytest.fixture
def test_app(temp_dir, test_keypair):
    """Create a test FastAPI application."""
    try:
        from fastapi.testclient import TestClient
        from vacp.api.server import create_app

        app = create_app(
            keypair=test_keypair,
            storage_path=temp_dir,
            jwt_secret="test_jwt_secret_12345678901234567890",
        )
        yield app
        # Clean up database connections to avoid Windows file locking
        if hasattr(app, 'state') and hasattr(app.state, 'server'):
            server = app.state.server
            if hasattr(server, 'db_manager'):
                server.db_manager.engine.dispose()
    except ImportError:
        pytest.skip("FastAPI not installed")


@pytest.fixture
def client(test_app):
    """Create a test client."""
    from fastapi.testclient import TestClient
    return TestClient(test_app)


@pytest.fixture
def auth_headers(client):
    """Get authentication headers for API tests."""
    # Login as default admin
    response = client.post("/v1/auth/login", json={
        "email": "admin@koba.local",
        "password": "admin123",
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
