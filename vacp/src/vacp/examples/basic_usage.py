"""
Basic Usage Example for VACP

This example demonstrates:
1. Setting up the gateway and components
2. Registering tools
3. Creating policies
4. Executing tool calls through the gateway
5. Verifying receipts
"""

import asyncio
from vacp.core.gateway import create_gateway, ToolRequest
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


async def main():
    print("=" * 60)
    print("VACP - Verifiable Agent Action Control Plane")
    print("Basic Usage Example")
    print("=" * 60)

    # Step 1: Create the gateway and all components
    print("\n1. Creating gateway and components...")
    gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()
    print("   [OK] Gateway created")
    print("   [OK] Policy engine initialized with default policy")
    print("   [OK] Audit log ready")

    # Step 2: Register some tools
    print("\n2. Registering tools...")

    # A simple read tool
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

    # A write tool (requires approval)
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

    # A dangerous tool (should be denied)
    admin_delete = ToolDefinition(
        id="admin.delete_all",
        name="Delete All Data",
        description="Delete all data from the system",
        categories=[ToolCategory.DELETE, ToolCategory.ADMIN],
        risk_level=ToolRiskLevel.CRITICAL,
    )
    registry.register(admin_delete)

    print("   [OK] db.read registered")
    print("   [OK] db.write registered")
    print("   [OK] admin.delete_all registered")

    # Step 3: Register tool executors (the actual implementations)
    print("\n3. Registering tool executors...")

    async def db_read_executor(tool_id, params):
        # Simulated database read
        return {
            "rows": [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"},
            ],
            "count": 2,
        }

    async def db_write_executor(tool_id, params):
        # Simulated database write
        return {"inserted": True, "id": 123}

    async def admin_delete_executor(tool_id, params):
        # This should never execute due to policy
        return {"deleted": "everything"}

    gateway.register_executor("db.read", db_read_executor)
    gateway.register_executor("db.write", db_write_executor)
    gateway.register_executor("admin.delete_all", admin_delete_executor)
    print("   [OK] Executors registered")

    # Step 4: Create a custom policy
    print("\n4. Creating custom policy...")

    custom_policy = PolicyBundle(
        id="custom-policy",
        version="1.0.0",
        name="Custom Security Policy",
        default_decision=PolicyDecision.DENY,
    )

    # Allow read operations
    custom_policy.add_rule(PolicyRule(
        id="allow-reads",
        name="Allow Read Operations",
        tool_patterns=["*.read", "*.get", "*.list"],
        priority=100,
        decision=PolicyDecision.ALLOW,
    ))

    # Require approval for writes
    custom_policy.add_rule(PolicyRule(
        id="approve-writes",
        name="Require Approval for Writes",
        tool_patterns=["*.write", "*.create", "*.update"],
        priority=90,
        require_approval=True,
        decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
    ))

    # Deny admin operations
    custom_policy.add_rule(PolicyRule(
        id="deny-admin",
        name="Deny Admin Operations",
        tool_patterns=["admin.*"],
        priority=10,
        decision=PolicyDecision.DENY,
    ))

    # Add budget
    custom_policy.budgets["default"] = Budget(
        max_calls=100,
        window_seconds=3600,
    )

    policy_engine.load_bundle(custom_policy)
    print("   [OK] Custom policy loaded")

    # Step 5: Execute tool calls
    print("\n5. Executing tool calls...")

    # Test 1: Read operation (should succeed)
    print("\n   Test 1: db.read (should succeed)")
    request = ToolRequest(
        tool_id="db.read",
        parameters={"table": "users", "limit": 10},
        agent_id="agent-001",
        tenant_id="acme-corp",
        session_id="session-123",
    )
    response = await gateway.execute(request)
    print(f"   Result: {'[OK] Success' if response.success else '[X] Failed'}")
    if response.success:
        print(f"   Data: {response.result}")
    if response.receipt:
        print(f"   Receipt: {response.receipt.receipt_id[:32]}...")

    # Test 2: Write operation (should require approval)
    print("\n   Test 2: db.write (should require approval)")
    request = ToolRequest(
        tool_id="db.write",
        parameters={"table": "users", "data": {"name": "Charlie"}},
        agent_id="agent-001",
        tenant_id="acme-corp",
        session_id="session-123",
    )
    try:
        from vacp.core.gateway import ApprovalRequiredError
        response = await gateway.execute(request)
        print(f"   Result: {'[OK] Success' if response.success else '[X] Requires approval'}")
        if not response.success:
            print(f"   Reason: {response.error}")
    except ApprovalRequiredError as e:
        print(f"   Result: [X] Requires approval (as expected)")
        print(f"   Approval ID: {e.approval_id}")

    # Test 3: Admin operation (should be denied)
    print("\n   Test 3: admin.delete_all (should be denied)")
    request = ToolRequest(
        tool_id="admin.delete_all",
        parameters={},
        agent_id="agent-001",
        tenant_id="acme-corp",
        session_id="session-123",
    )
    response = await gateway.execute(request)
    print(f"   Result: {'[X] Denied' if not response.success else '[OK] Allowed (VULNERABILITY!)'}")
    if not response.success:
        print(f"   Reason: {response.error}")

    # Step 6: Verify receipts
    print("\n6. Verifying receipts...")

    log_size = audit_log.log.size
    print(f"   Audit log contains {log_size} entries")

    for i in range(log_size):
        receipt = audit_log.get_receipt(i)
        if receipt:
            sig_valid = receipt_service.verify_receipt(receipt)
            proof = audit_log.get_proof_for_receipt(receipt.receipt_id)
            proof_valid = audit_log.verify_receipt_in_log(receipt, proof) if proof else False

            print(f"\n   Receipt {i}: {receipt.tool.name}")
            print(f"   - Decision: {receipt.policy.decision.value}")
            print(f"   - Signature: {'[OK] Valid' if sig_valid else '[X] Invalid'}")
            print(f"   - Merkle Proof: {'[OK] Valid' if proof_valid else '[X] Invalid'}")

    # Step 7: Display statistics
    print("\n7. Gateway statistics:")
    stats = gateway.get_stats()
    print(f"   Total requests: {stats['total_requests']}")
    print(f"   Allowed: {stats['allowed']}")
    print(f"   Denied: {stats['denied']}")
    print(f"   Pending approval: {stats['pending_approval']}")

    print("\n" + "=" * 60)
    print("Example complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
