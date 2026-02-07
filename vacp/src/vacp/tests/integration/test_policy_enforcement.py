"""
Integration tests for policy enforcement.

These tests verify that the policy engine ACTUALLY enforces the rules
as advertised. Not just unit tests - these test the full integration.
"""

import pytest

from vacp.core.policy import (
    PolicyEngine,
    PolicyBundle,
    PolicyRule,
    PolicyDecision,
    Budget,
    RateLimit,
    PolicyEvaluationContext,
    create_default_bundle,
)
from vacp.core.gateway import create_gateway, ToolRequest
from vacp.core.registry import ToolDefinition, ToolCategory


class TestPolicyEnforcementIntegration:
    """Test that policy rules actually block/allow actions as expected."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway, self.registry, self.policy_engine, self.receipt_service, self.audit_log = create_gateway()

    def test_default_deny_actually_denies(self):
        """Verify that default-deny actually denies unknown tools."""
        # Register NO tools and try to execute one
        context = PolicyEvaluationContext(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="unknown.dangerous.tool",
        )

        result = self.policy_engine.evaluate(context)

        assert result.decision == PolicyDecision.DENY, \
            f"Expected DENY for unknown tool, got {result.decision}"
        assert "No matching rule" in (result.denial_reason or ""), \
            "Should indicate no matching rule"

    def test_deny_rule_blocks_dangerous_operations(self):
        """Verify that deny rules actually block dangerous tool patterns."""
        bundle = create_default_bundle("test-bundle")
        self.policy_engine.load_bundle(bundle)

        # System-level execution tools should be outright denied
        denied_patterns = [
            "system.exec",
            "os.shell",
        ]

        for tool_name in denied_patterns:
            context = PolicyEvaluationContext(
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
                tool_name=tool_name,
            )

            result = self.policy_engine.evaluate(context)

            assert result.decision == PolicyDecision.DENY, \
                f"Tool '{tool_name}' should be DENIED but got {result.decision}"

        # Write/destructive operations should require approval (not outright denied)
        approval_patterns = [
            "root.admin.delete",
            "user.sudo",
        ]

        for tool_name in approval_patterns:
            context = PolicyEvaluationContext(
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
                tool_name=tool_name,
            )

            result = self.policy_engine.evaluate(context)

            assert result.decision in (
                PolicyDecision.DENY,
                PolicyDecision.PENDING_APPROVAL,
                PolicyDecision.ALLOW_WITH_CONDITIONS,
            ), f"Tool '{tool_name}' should be restricted but got {result.decision}"

    def test_allow_rule_permits_safe_operations(self):
        """Verify that allow rules actually permit safe tool patterns."""
        bundle = create_default_bundle("test-bundle")
        self.policy_engine.load_bundle(bundle)

        # Try safe patterns that should be allowed
        safe_patterns = [
            "database.read",
            "api.get",
            "users.list",
            "search.query",
        ]

        for tool_name in safe_patterns:
            context = PolicyEvaluationContext(
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
                tool_name=tool_name,
            )

            result = self.policy_engine.evaluate(context)

            assert result.decision == PolicyDecision.ALLOW, \
                f"Tool '{tool_name}' should be ALLOWED but got {result.decision}"

    def test_write_operations_require_approval(self):
        """Verify that write operations actually require approval."""
        bundle = create_default_bundle("test-bundle")
        self.policy_engine.load_bundle(bundle)

        # Try write patterns that should require approval
        write_patterns = [
            "database.write",
            "users.create",
            "config.update",
            "records.delete",
        ]

        for tool_name in write_patterns:
            # Without approval
            context = PolicyEvaluationContext(
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
                tool_name=tool_name,
                has_approval=False,
            )

            result = self.policy_engine.evaluate(context)

            assert result.decision in [PolicyDecision.PENDING_APPROVAL, PolicyDecision.ALLOW_WITH_CONDITIONS], \
                f"Tool '{tool_name}' without approval should require approval, got {result.decision}"

    def test_custom_deny_rule_overrides_allow(self):
        """Verify that a custom deny rule with higher priority overrides allow rules."""
        bundle = PolicyBundle(
            id="custom-test",
            version="1.0.0",
            name="Custom Test Policy",
            default_decision=PolicyDecision.DENY,
        )

        # Add allow rule for all reads
        bundle.add_rule(PolicyRule(
            id="allow-all-reads",
            name="Allow All Reads",
            tool_patterns=["*.read"],
            priority=100,
            decision=PolicyDecision.ALLOW,
        ))

        # Add deny rule for sensitive database reads (higher priority = lower number)
        bundle.add_rule(PolicyRule(
            id="deny-sensitive-db",
            name="Deny Sensitive Database Reads",
            tool_patterns=["sensitive_db.read"],
            priority=50,  # Higher priority than allow
            decision=PolicyDecision.DENY,
        ))

        self.policy_engine.load_bundle(bundle)

        # Normal read should be allowed
        context = PolicyEvaluationContext(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="normal_db.read",
        )
        result = self.policy_engine.evaluate(context)
        assert result.decision == PolicyDecision.ALLOW, "Normal read should be allowed"

        # Sensitive read should be denied
        context = PolicyEvaluationContext(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="sensitive_db.read",
        )
        result = self.policy_engine.evaluate(context)
        assert result.decision == PolicyDecision.DENY, "Sensitive read should be denied"


class TestRateLimitingIntegration:
    """Test that rate limiting ACTUALLY limits requests."""

    def test_rate_limit_blocks_after_threshold(self):
        """Verify rate limiting actually blocks requests after threshold."""
        engine = PolicyEngine()

        bundle = PolicyBundle(
            id="rate-test",
            version="1.0.0",
            name="Rate Limit Test",
            default_decision=PolicyDecision.DENY,
        )

        # Rate limit: 5 requests per 60 seconds
        bundle.rate_limits["strict"] = RateLimit(
            max_requests=5,
            window_seconds=60,
        )

        bundle.add_rule(PolicyRule(
            id="allow-with-rate-limit",
            name="Allow with Rate Limit",
            tool_patterns=["*"],
            priority=100,
            decision=PolicyDecision.ALLOW,
            rate_limit_id="strict",
        ))

        engine.load_bundle(bundle)

        # Make 5 requests - all should succeed
        for i in range(5):
            context = PolicyEvaluationContext(
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
                tool_name="any.tool",
            )
            result = engine.evaluate(context)
            assert result.decision == PolicyDecision.ALLOW, \
                f"Request {i+1} should be allowed"
            # Record the action to update rate limit
            engine.record_action(context, result)

        # 6th request should be DENIED due to rate limit
        context = PolicyEvaluationContext(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="any.tool",
        )
        result = engine.evaluate(context)
        assert result.decision == PolicyDecision.DENY, \
            f"6th request should be rate limited, got {result.decision}"
        assert "Rate limit" in (result.denial_reason or ""), \
            "Should indicate rate limit exceeded"


class TestBudgetEnforcementIntegration:
    """Test that budget enforcement ACTUALLY enforces budgets."""

    def test_budget_blocks_after_exceeded(self):
        """Verify budget enforcement actually blocks after budget exceeded."""
        engine = PolicyEngine()

        bundle = PolicyBundle(
            id="budget-test",
            version="1.0.0",
            name="Budget Test",
            default_decision=PolicyDecision.DENY,
        )

        # Budget: 3 calls max
        bundle.budgets["limited"] = Budget(
            max_calls=3,
            window_seconds=3600,
        )

        bundle.add_rule(PolicyRule(
            id="allow-with-budget",
            name="Allow with Budget",
            tool_patterns=["*"],
            priority=100,
            decision=PolicyDecision.ALLOW,
            budget_id="limited",
        ))

        engine.load_bundle(bundle)

        # Make 3 requests - all should succeed
        for i in range(3):
            context = PolicyEvaluationContext(
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
                tool_name="any.tool",
            )
            result = engine.evaluate(context)
            assert result.decision == PolicyDecision.ALLOW, \
                f"Request {i+1} should be allowed"
            engine.record_action(context, result)

        # 4th request should be DENIED due to budget
        context = PolicyEvaluationContext(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="any.tool",
        )
        result = engine.evaluate(context)
        assert result.decision == PolicyDecision.DENY, \
            f"4th request should be budget limited, got {result.decision}"
        assert "budget" in (result.denial_reason or "").lower(), \
            "Should indicate budget exceeded"


class TestGatewayIntegration:
    """Test the full gateway integration - end to end."""

    @pytest.mark.asyncio
    async def test_gateway_denies_unregistered_tool(self):
        """Verify gateway denies tools that aren't registered."""
        gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()

        request = ToolRequest(
            tool_id="unregistered.dangerous.tool",
            parameters={},
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
        )

        response = await gateway.execute(request)

        assert response.success is False, \
            f"Unregistered tool should be denied, got success={response.success}"
        assert "not registered" in (response.error or "").lower(), \
            "Error should indicate tool is not registered"

    @pytest.mark.asyncio
    async def test_gateway_allows_registered_safe_tool(self):
        """Verify gateway allows registered safe tools."""
        gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()

        # Register a safe read tool
        tool = ToolDefinition(
            id="data.read",
            name="Data Reader",
            description="Read data safely",
            categories=[ToolCategory.READ],
        )
        registry.register(tool)

        # Register executor
        async def read_executor(tool_id, params):
            return {"data": "test_result"}
        gateway.register_executor("data.read", read_executor)

        request = ToolRequest(
            tool_id="data.read",
            parameters={},
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
        )

        response = await gateway.execute(request)

        assert response.success is True, \
            f"Safe registered tool should be allowed, got success={response.success}, error={response.error}"
        assert response.result == {"data": "test_result"}, \
            "Should return executor result"

    @pytest.mark.asyncio
    async def test_gateway_issues_valid_receipt(self):
        """Verify gateway issues cryptographically valid receipts."""
        gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()

        # Register a tool
        tool = ToolDefinition(
            id="test.read",
            name="Test Reader",
            categories=[ToolCategory.READ],
        )
        registry.register(tool)

        async def test_executor(tool_id, params):
            return {"result": "ok"}
        gateway.register_executor("test.read", test_executor)

        request = ToolRequest(
            tool_id="test.read",
            parameters={"query": "test"},
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
        )

        response = await gateway.execute(request)

        assert response.receipt is not None, "Should have a receipt"

        # Verify receipt signature
        is_valid = receipt_service.verify_receipt(response.receipt)
        assert is_valid, "Receipt signature should be valid"

    @pytest.mark.asyncio
    async def test_gateway_enforces_policy_deny(self):
        """Verify gateway actually enforces policy deny decisions."""
        gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()

        # Register a dangerous tool (but policy should deny it)
        tool = ToolDefinition(
            id="system.exec",
            name="System Executor",
            description="Execute system commands",
            categories=[ToolCategory.WRITE],
        )
        registry.register(tool)

        # Register executor - but it should never be called
        call_count = {"value": 0}
        async def dangerous_executor(tool_id, params):
            call_count["value"] += 1
            return {"executed": params.get("command")}
        gateway.register_executor("system.exec", dangerous_executor)

        request = ToolRequest(
            tool_id="system.exec",
            parameters={"command": "rm -rf /"},
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
        )

        response = await gateway.execute(request)

        assert response.success is False, \
            f"Dangerous tool should be denied by policy, got success={response.success}"
        assert call_count["value"] == 0, \
            "Executor should NOT be called when policy denies"


class TestAgentIsolation:
    """Test that multi-tenant and multi-agent isolation works."""

    def test_agent_specific_rules_apply_correctly(self):
        """Verify agent-specific rules only apply to that agent."""
        engine = PolicyEngine()

        bundle = PolicyBundle(
            id="isolation-test",
            version="1.0.0",
            name="Isolation Test",
            default_decision=PolicyDecision.DENY,
        )

        # Allow all for trusted agent
        bundle.add_rule(PolicyRule(
            id="allow-trusted",
            name="Allow Trusted Agent",
            agent_patterns=["trusted-*"],
            tool_patterns=["*"],
            priority=50,
            decision=PolicyDecision.ALLOW,
        ))

        # Deny all for untrusted agent
        bundle.add_rule(PolicyRule(
            id="deny-untrusted",
            name="Deny Untrusted Agent",
            agent_patterns=["untrusted-*"],
            tool_patterns=["*"],
            priority=50,
            decision=PolicyDecision.DENY,
        ))

        engine.load_bundle(bundle)

        # Trusted agent should be allowed
        context = PolicyEvaluationContext(
            agent_id="trusted-agent-001",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="any.tool",
        )
        result = engine.evaluate(context)
        assert result.decision == PolicyDecision.ALLOW, \
            "Trusted agent should be allowed"

        # Untrusted agent should be denied
        context = PolicyEvaluationContext(
            agent_id="untrusted-agent-002",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="any.tool",
        )
        result = engine.evaluate(context)
        assert result.decision == PolicyDecision.DENY, \
            "Untrusted agent should be denied"

    def test_tenant_isolation_enforced(self):
        """Verify tenant-specific rules only apply to that tenant."""
        engine = PolicyEngine()

        bundle = PolicyBundle(
            id="tenant-test",
            version="1.0.0",
            name="Tenant Test",
            default_decision=PolicyDecision.DENY,
        )

        # Premium tenant gets full access
        bundle.add_rule(PolicyRule(
            id="allow-premium",
            name="Allow Premium Tenant",
            tenant_patterns=["premium-*"],
            tool_patterns=["*"],
            priority=50,
            decision=PolicyDecision.ALLOW,
        ))

        # Free tenant gets read-only
        bundle.add_rule(PolicyRule(
            id="allow-free-read",
            name="Allow Free Tenant Read Only",
            tenant_patterns=["free-*"],
            tool_patterns=["*.read", "*.get"],
            priority=50,
            decision=PolicyDecision.ALLOW,
        ))

        engine.load_bundle(bundle)

        # Premium tenant can write
        context = PolicyEvaluationContext(
            agent_id="agent",
            tenant_id="premium-corp",
            session_id="test-session",
            tool_name="database.write",
        )
        result = engine.evaluate(context)
        assert result.decision == PolicyDecision.ALLOW, \
            "Premium tenant should be allowed to write"

        # Free tenant can read
        context = PolicyEvaluationContext(
            agent_id="agent",
            tenant_id="free-user",
            session_id="test-session",
            tool_name="database.read",
        )
        result = engine.evaluate(context)
        assert result.decision == PolicyDecision.ALLOW, \
            "Free tenant should be allowed to read"

        # Free tenant CANNOT write
        context = PolicyEvaluationContext(
            agent_id="agent",
            tenant_id="free-user",
            session_id="test-session",
            tool_name="database.write",
        )
        result = engine.evaluate(context)
        assert result.decision == PolicyDecision.DENY, \
            "Free tenant should NOT be allowed to write"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
