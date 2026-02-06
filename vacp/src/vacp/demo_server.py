"""
VACP Demo Server

Runs the basic example to populate data, then starts the audit UI
so you can actually see receipts in the dashboard.
"""

import asyncio
from vacp.core.gateway import create_gateway, ToolRequest, ApprovalRequiredError
from vacp.core.registry import (
    ToolDefinition,
    ToolSchema,
    ParameterSchema,
    ToolCategory,
    ToolRiskLevel,
)
from vacp.core.policy import (
    PolicyBundle,
    PolicyRule,
    PolicyDecision,
    Budget,
)
from vacp.ui.audit import run_audit_ui


async def populate_demo_data(gateway, registry, policy_engine):
    """Populate the gateway with demo data."""
    print("Populating demo data...")

    # Register tools
    db_read = ToolDefinition(
        id="db.read",
        name="Database Read",
        description="Read data from the database",
        schema=ToolSchema(
            parameters=[
                ParameterSchema(name="table", type="string", required=True),
                ParameterSchema(name="limit", type="integer", default=100),
            ]
        ),
        categories=[ToolCategory.READ, ToolCategory.DATABASE],
        risk_level=ToolRiskLevel.LOW,
    )
    registry.register(db_read)

    db_write = ToolDefinition(
        id="db.write",
        name="Database Write",
        description="Write data to the database",
        schema=ToolSchema(
            parameters=[
                ParameterSchema(name="table", type="string", required=True),
                ParameterSchema(name="data", type="object", required=True),
            ]
        ),
        categories=[ToolCategory.WRITE, ToolCategory.DATABASE],
        risk_level=ToolRiskLevel.MEDIUM,
        requires_approval=True,
    )
    registry.register(db_write)

    file_read = ToolDefinition(
        id="file.read",
        name="File Read",
        description="Read a file from disk",
        schema=ToolSchema(
            parameters=[
                ParameterSchema(name="path", type="string", required=True),
            ]
        ),
        categories=[ToolCategory.READ, ToolCategory.FILESYSTEM],
        risk_level=ToolRiskLevel.LOW,
    )
    registry.register(file_read)

    api_call = ToolDefinition(
        id="api.get",
        name="API GET",
        description="Make an HTTP GET request",
        schema=ToolSchema(
            parameters=[
                ParameterSchema(name="url", type="string", required=True),
            ]
        ),
        categories=[ToolCategory.READ, ToolCategory.NETWORK],
        risk_level=ToolRiskLevel.MEDIUM,
    )
    registry.register(api_call)

    admin_delete = ToolDefinition(
        id="admin.delete_all",
        name="Delete All Data",
        description="Delete all data from the system",
        categories=[ToolCategory.DELETE, ToolCategory.ADMIN],
        risk_level=ToolRiskLevel.CRITICAL,
    )
    registry.register(admin_delete)

    # Register executors
    async def db_read_executor(tool_id, params):
        return {"rows": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}], "count": 2}

    async def db_write_executor(tool_id, params):
        return {"inserted": True, "id": 123}

    async def file_read_executor(tool_id, params):
        return {"content": "File contents here...", "size": 1024}

    async def api_get_executor(tool_id, params):
        return {"status": 200, "body": {"message": "OK"}}

    async def admin_delete_executor(tool_id, params):
        return {"deleted": "everything"}

    gateway.register_executor("db.read", db_read_executor)
    gateway.register_executor("db.write", db_write_executor)
    gateway.register_executor("file.read", file_read_executor)
    gateway.register_executor("api.get", api_get_executor)
    gateway.register_executor("admin.delete_all", admin_delete_executor)

    # Create custom policy
    custom_policy = PolicyBundle(
        id="demo-policy",
        version="1.0.0",
        name="Demo Security Policy",
        default_decision=PolicyDecision.DENY,
    )

    custom_policy.add_rule(PolicyRule(
        id="allow-reads",
        name="Allow Read Operations",
        tool_patterns=["*.read", "*.get", "*.list"],
        priority=100,
        decision=PolicyDecision.ALLOW,
    ))

    custom_policy.add_rule(PolicyRule(
        id="approve-writes",
        name="Require Approval for Writes",
        tool_patterns=["*.write", "*.create", "*.update"],
        priority=90,
        require_approval=True,
        decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
    ))

    custom_policy.add_rule(PolicyRule(
        id="deny-admin",
        name="Deny Admin Operations",
        tool_patterns=["admin.*"],
        priority=10,
        decision=PolicyDecision.DENY,
    ))

    custom_policy.budgets["default"] = Budget(
        max_calls=100,
        window_seconds=3600,
    )

    policy_engine.load_bundle(custom_policy)

    # Execute some tool calls to populate the audit log
    print("Executing sample tool calls...")

    # Successful reads
    for i in range(3):
        request = ToolRequest(
            tool_id="db.read",
            parameters={"table": "users", "limit": 10},
            agent_id=f"agent-00{i+1}",
            tenant_id="acme-corp",
            session_id=f"session-{i+1}",
        )
        response = await gateway.execute(request)
        print(f"  db.read #{i+1}: {'OK' if response.success else 'FAILED'}")

    # File read
    request = ToolRequest(
        tool_id="file.read",
        parameters={"path": "/etc/config.json"},
        agent_id="agent-001",
        tenant_id="acme-corp",
        session_id="session-1",
    )
    response = await gateway.execute(request)
    print(f"  file.read: {'OK' if response.success else 'FAILED'}")

    # API call
    request = ToolRequest(
        tool_id="api.get",
        parameters={"url": "https://api.example.com/users"},
        agent_id="agent-002",
        tenant_id="acme-corp",
        session_id="session-2",
    )
    response = await gateway.execute(request)
    print(f"  api.get: {'OK' if response.success else 'FAILED'}")

    # Write (requires approval - will be pending)
    try:
        request = ToolRequest(
            tool_id="db.write",
            parameters={"table": "users", "data": {"name": "Charlie"}},
            agent_id="agent-001",
            tenant_id="acme-corp",
            session_id="session-1",
        )
        response = await gateway.execute(request)
        print(f"  db.write: {'OK' if response.success else 'Requires Approval'}")
    except ApprovalRequiredError:
        print("  db.write: Requires Approval (expected)")

    # Admin operation (should be denied)
    request = ToolRequest(
        tool_id="admin.delete_all",
        parameters={},
        agent_id="agent-001",
        tenant_id="acme-corp",
        session_id="session-1",
    )
    response = await gateway.execute(request)
    print(f"  admin.delete_all: {'DENIED' if not response.success else 'ALLOWED (BAD!)'}")

    stats = gateway.get_stats()
    print(f"\nPopulated {stats['total_requests']} receipts")


def main():
    print("=" * 60)
    print("VACP Demo Server")
    print("=" * 60)

    # Create gateway with all components
    gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()

    # Populate demo data
    asyncio.run(populate_demo_data(gateway, registry, policy_engine))

    # Start audit UI
    print("\n" + "=" * 60)
    print("Starting Audit UI...")
    print("Open http://127.0.0.1:8080 in your browser")
    print("Press Ctrl+C to stop")
    print("=" * 60 + "\n")

    run_audit_ui(audit_log, receipt_service, host="127.0.0.1", port=8080)


if __name__ == "__main__":
    main()
