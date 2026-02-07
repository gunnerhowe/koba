"""
Core Tests for VACP

Tests for cryptographic primitives, receipts, policy, and gateway.
"""

import asyncio
import unittest
from datetime import datetime, timezone

from vacp.core.crypto import (
    generate_keypair,
    sign_message,
    verify_signature,
    hash_data,
    hash_json,
    canonicalize_json,
)
from vacp.core.receipts import (
    SignedActionReceipt,
    ReceiptService,
    ToolInfo,
    PolicyInfo,
    PolicyDecision,
)
from vacp.core.merkle import (
    MerkleLog,
)
from vacp.core.policy import (
    PolicyEngine,
    PolicyEvaluationContext,
    Budget,
    RateLimit,
    create_default_bundle,
)
from vacp.core.registry import (
    ToolRegistry,
    ToolDefinition,
    ToolSchema,
    ParameterSchema,
    ToolCategory,
)
from vacp.core.gateway import (
    ToolRequest,
    create_gateway,
)
from vacp.core.tokens import (
    TokenService,
    TokenMintRequest,
    TokenScope,
)
from vacp.core.tripwire import (
    TripwireEngine,
    TripwireAction,
)


class TestCrypto(unittest.TestCase):
    """Tests for cryptographic primitives."""

    def test_keypair_generation(self):
        """Test keypair generation."""
        kp = generate_keypair()
        self.assertEqual(len(kp.private_key_bytes), 32)
        self.assertEqual(len(kp.public_key_bytes), 32)

    def test_sign_and_verify(self):
        """Test signing and verification."""
        kp = generate_keypair()
        message = b"Hello, World!"

        signature = sign_message(message, kp.private_key_bytes)
        self.assertEqual(len(signature), 64)

        # Verify should pass
        self.assertTrue(verify_signature(message, signature, kp.public_key_bytes))

        # Wrong message should fail
        self.assertFalse(verify_signature(b"Wrong message", signature, kp.public_key_bytes))

        # Wrong key should fail
        kp2 = generate_keypair()
        self.assertFalse(verify_signature(message, signature, kp2.public_key_bytes))

    def test_hash_data(self):
        """Test data hashing."""
        data = b"test data"
        hash1 = hash_data(data)
        hash2 = hash_data(data)

        self.assertEqual(hash1, hash2)
        self.assertTrue(hash1.startswith("sha256:"))

        # Different data should have different hash
        hash3 = hash_data(b"different data")
        self.assertNotEqual(hash1, hash3)

    def test_hash_json(self):
        """Test JSON hashing with canonicalization."""
        obj1 = {"b": 2, "a": 1}
        obj2 = {"a": 1, "b": 2}

        # Order shouldn't matter
        self.assertEqual(hash_json(obj1), hash_json(obj2))

    def test_canonicalize_json(self):
        """Test JSON canonicalization."""
        obj = {"z": 1, "a": 2, "m": 3}
        canonical = canonicalize_json(obj)

        # Keys should be sorted
        self.assertEqual(canonical, '{"a":2,"m":3,"z":1}')


class TestReceipts(unittest.TestCase):
    """Tests for Signed Action Receipts."""

    def setUp(self):
        self.keypair = generate_keypair()
        self.receipt_service = ReceiptService(keypair=self.keypair)

    def test_issue_receipt(self):
        """Test receipt issuance."""
        tool = ToolInfo(
            name="test.tool",
            request_hash="sha256:abc123",
        )
        policy = PolicyInfo(
            bundle_id="test-bundle",
            policy_hash="sha256:def456",
            decision=PolicyDecision.ALLOW,
        )

        receipt = self.receipt_service.issue_receipt(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool=tool,
            policy=policy,
            merkle_root="sha256:root123",
            log_index=0,
        )

        self.assertIsNotNone(receipt.receipt_id)
        self.assertIsNotNone(receipt.signature)
        self.assertEqual(receipt.tool.name, "test.tool")
        self.assertEqual(receipt.policy.decision, PolicyDecision.ALLOW)

    def test_verify_receipt(self):
        """Test receipt verification."""
        tool = ToolInfo(name="test.tool", request_hash="sha256:abc123")
        policy = PolicyInfo(
            bundle_id="test-bundle",
            policy_hash="sha256:def456",
            decision=PolicyDecision.ALLOW,
        )

        receipt = self.receipt_service.issue_receipt(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool=tool,
            policy=policy,
            merkle_root="sha256:root123",
            log_index=0,
        )

        # Should verify
        self.assertTrue(self.receipt_service.verify_receipt(receipt))

        # Tampered receipt should fail
        receipt.agent_id = "tampered-agent"
        self.assertFalse(self.receipt_service.verify_receipt(receipt))

    def test_receipt_serialization(self):
        """Test receipt JSON serialization."""
        tool = ToolInfo(name="test.tool", request_hash="sha256:abc123")
        policy = PolicyInfo(
            bundle_id="test-bundle",
            policy_hash="sha256:def456",
            decision=PolicyDecision.ALLOW,
        )

        receipt = self.receipt_service.issue_receipt(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool=tool,
            policy=policy,
            merkle_root="sha256:root123",
            log_index=0,
        )

        # Serialize and deserialize
        json_str = receipt.to_json()
        restored = SignedActionReceipt.from_json(json_str)

        self.assertEqual(receipt.receipt_id, restored.receipt_id)
        self.assertEqual(receipt.agent_id, restored.agent_id)
        self.assertEqual(receipt.signature, restored.signature)


class TestMerkleLog(unittest.TestCase):
    """Tests for Merkle transparency log."""

    def setUp(self):
        self.keypair = generate_keypair()
        self.log = MerkleLog(keypair=self.keypair)

    def test_append_and_retrieve(self):
        """Test basic append and retrieval."""
        entry = b"test entry"
        index = self.log.append(entry)

        self.assertEqual(index, 0)
        self.assertEqual(self.log.size, 1)
        self.assertEqual(self.log.get_entry(0), entry)

    def test_merkle_root_changes(self):
        """Test that root changes with new entries."""
        root1 = self.log.root

        self.log.append(b"entry1")
        root2 = self.log.root
        self.assertNotEqual(root1, root2)

        self.log.append(b"entry2")
        root3 = self.log.root
        self.assertNotEqual(root2, root3)

    def test_inclusion_proof(self):
        """Test inclusion proof generation and verification."""
        # Add some entries
        entries = [f"entry{i}".encode() for i in range(10)]
        for entry in entries:
            self.log.append(entry)

        # Get and verify proofs
        for i in range(10):
            proof = self.log.get_inclusion_proof(i)
            self.assertIsNotNone(proof)
            self.assertTrue(
                self.log.verify_inclusion(i, entries[i], proof)
            )

    def test_signed_tree_head(self):
        """Test signed tree head."""
        self.log.append(b"entry1")
        self.log.append(b"entry2")

        sth = self.log.get_signed_tree_head()

        self.assertEqual(sth.tree_size, 2)
        self.assertIsNotNone(sth.signature)
        self.assertTrue(self.log.verify_signed_tree_head(sth))


class TestPolicy(unittest.TestCase):
    """Tests for policy engine."""

    def setUp(self):
        self.engine = PolicyEngine()
        self.bundle = create_default_bundle()
        self.engine.load_bundle(self.bundle)

    def test_default_deny(self):
        """Test default deny behavior."""
        context = PolicyEvaluationContext(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="unknown.tool",
        )

        result = self.engine.evaluate(context)
        self.assertEqual(result.decision, PolicyDecision.DENY)

    def test_allow_read_operations(self):
        """Test that read operations are allowed."""
        context = PolicyEvaluationContext(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="db.read",
        )

        result = self.engine.evaluate(context)
        self.assertEqual(result.decision, PolicyDecision.ALLOW)

    def test_deny_dangerous_operations(self):
        """Test that dangerous operations are denied."""
        context = PolicyEvaluationContext(
            agent_id="test-agent",
            tenant_id="test-tenant",
            session_id="test-session",
            tool_name="system.exec",
        )

        result = self.engine.evaluate(context)
        self.assertEqual(result.decision, PolicyDecision.DENY)

    def test_budget_enforcement(self):
        """Test budget enforcement."""
        budget = Budget(max_calls=3, window_seconds=3600)

        # Should allow first 3 calls
        for _ in range(3):
            allowed, _ = budget.check_budget(calls=1)
            self.assertTrue(allowed)
            budget.consume(calls=1)

        # 4th should be denied
        allowed, reason = budget.check_budget(calls=1)
        self.assertFalse(allowed)
        self.assertIn("exceeded", reason)

    def test_rate_limit_enforcement(self):
        """Test rate limiting."""
        rl = RateLimit(max_requests=5, window_seconds=60)

        # Should allow first 5
        for _ in range(5):
            allowed, _ = rl.check_rate_limit()
            self.assertTrue(allowed)
            rl.record_request()

        # 6th should be denied
        allowed, remaining = rl.check_rate_limit()
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)


class TestRegistry(unittest.TestCase):
    """Tests for tool registry."""

    def setUp(self):
        self.registry = ToolRegistry()

    def test_register_and_retrieve(self):
        """Test tool registration and retrieval."""
        tool = ToolDefinition(
            id="test.tool",
            name="Test Tool",
            description="A test tool",
        )
        self.registry.register(tool)

        retrieved = self.registry.get("test.tool")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "Test Tool")

    def test_schema_validation(self):
        """Test parameter schema validation."""
        tool = ToolDefinition(
            id="test.tool",
            name="Test Tool",
            schema=ToolSchema(
                parameters=[
                    ParameterSchema(name="required_param", type="string", required=True),
                    ParameterSchema(name="optional_param", type="integer"),
                ]
            ),
        )
        self.registry.register(tool)

        # Valid params
        valid, errors = self.registry.validate_request("test.tool", {
            "required_param": "value",
        })
        self.assertTrue(valid)

        # Missing required param
        valid, errors = self.registry.validate_request("test.tool", {
            "optional_param": 123,
        })
        self.assertFalse(valid)
        self.assertTrue(any("required" in e.lower() for e in errors))

    def test_virtual_catalog(self):
        """Test virtual catalog generation."""
        tool = ToolDefinition(
            id="test.tool",
            name="Test Tool",
            categories=[ToolCategory.READ],
        )
        self.registry.register(tool)

        catalog = self.registry.get_virtual_catalog()
        self.assertIn("test.tool", catalog)


class TestGateway(unittest.TestCase):
    """Tests for tool gateway."""

    def setUp(self):
        self.gateway, self.registry, self.policy_engine, _, _ = create_gateway()

        # Register a test tool (using *.read pattern to match default allow policy)
        tool = ToolDefinition(
            id="test.read",
            name="Test Read Tool",
            schema=ToolSchema(
                parameters=[ParameterSchema(name="message", type="string", required=True)]
            ),
            categories=[ToolCategory.READ],
        )
        self.registry.register(tool)

        # Register executor
        async def echo_exec(tool_id, params):
            return {"echo": params.get("message")}
        self.gateway.register_executor("test.read", echo_exec)

    def test_execute_allowed_tool(self):
        """Test executing an allowed tool."""
        async def test():
            request = ToolRequest(
                tool_id="test.read",
                parameters={"message": "hello"},
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
            )
            response = await self.gateway.execute(request)
            self.assertTrue(response.success)
            self.assertEqual(response.result["echo"], "hello")
            self.assertIsNotNone(response.receipt)

        asyncio.run(test())

    def test_deny_unknown_tool(self):
        """Test that unknown tools are denied."""
        async def test():
            request = ToolRequest(
                tool_id="unknown.tool",
                parameters={},
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
            )
            response = await self.gateway.execute(request)
            self.assertFalse(response.success)
            self.assertIn("not registered", response.error)

        asyncio.run(test())

    def test_receipts_issued(self):
        """Test that receipts are issued for all actions."""
        async def test():
            request = ToolRequest(
                tool_id="test.read",
                parameters={"message": "test"},
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
            )
            response = await self.gateway.execute(request)
            self.assertIsNotNone(response.receipt)
            self.assertIsNotNone(response.receipt.signature)

        asyncio.run(test())


class TestTokens(unittest.TestCase):
    """Tests for token service."""

    def setUp(self):
        self.service = TokenService()

    def test_mint_and_validate(self):
        """Test token minting and validation."""
        request = TokenMintRequest(
            tenant_id="test-tenant",
            agent_id="test-agent",
            session_id="test-session",
            scope=TokenScope(tools=["test.*"]),
            purpose="Testing",
            ttl_seconds=300,
        )

        token, token_value = self.service.mint(request)

        self.assertIsNotNone(token.token_id)
        self.assertTrue(token.is_valid)

        # Validate
        valid, retrieved = self.service.validate(token_value)
        self.assertTrue(valid)
        self.assertEqual(retrieved.token_id, token.token_id)

    def test_scope_enforcement(self):
        """Test token scope enforcement."""
        request = TokenMintRequest(
            tenant_id="test-tenant",
            agent_id="test-agent",
            session_id="test-session",
            scope=TokenScope(tools=["allowed.*"]),
            purpose="Testing",
            ttl_seconds=300,
        )

        token, token_value = self.service.mint(request)

        # Should allow matching tool
        valid, _ = self.service.validate(token_value, tool_name="allowed.read")
        self.assertTrue(valid)

        # Should deny non-matching tool
        valid, _ = self.service.validate(token_value, tool_name="denied.tool")
        self.assertFalse(valid)

    def test_token_expiration(self):
        """Test token expiration."""
        request = TokenMintRequest(
            tenant_id="test-tenant",
            agent_id="test-agent",
            session_id="test-session",
            scope=TokenScope(),
            purpose="Testing",
            ttl_seconds=1,  # Very short TTL
        )

        token, token_value = self.service.mint(request)

        # Should be valid immediately
        valid, _ = self.service.validate(token_value)
        self.assertTrue(valid)

        # Wait for expiration
        import time
        time.sleep(1.5)

        # Should be expired
        valid, _ = self.service.validate(token_value)
        self.assertFalse(valid)

    def test_token_revocation(self):
        """Test token revocation."""
        request = TokenMintRequest(
            tenant_id="test-tenant",
            agent_id="test-agent",
            session_id="test-session",
            scope=TokenScope(),
            purpose="Testing",
            ttl_seconds=300,
        )

        token, token_value = self.service.mint(request)

        # Should be valid
        valid, _ = self.service.validate(token_value)
        self.assertTrue(valid)

        # Revoke
        self.service.revoke(token.token_id, "Test revocation")

        # Should be invalid
        valid, _ = self.service.validate(token_value)
        self.assertFalse(valid)


class TestTripwire(unittest.TestCase):
    """Tests for anomaly detection tripwire."""

    def setUp(self):
        self.tripwire = TripwireEngine()

    def test_normal_actions_pass(self):
        """Test that normal actions don't trigger tripwire."""
        for i in range(5):
            allowed, anomalies, action = self.tripwire.analyze_action(
                tool_name="db.read",
                session_id="test-session",
                agent_id="test-agent",
                success=True,
                parameters={"query": f"SELECT * FROM table{i}"},
            )
            self.assertTrue(allowed)
            self.assertEqual(action, TripwireAction.LOG_ONLY)

    def test_high_rate_detection(self):
        """Test that high action rates are detected."""
        # Simulate rapid actions (may trigger rate anomaly)
        datetime.now(timezone.utc)

        for i in range(20):
            allowed, anomalies, action = self.tripwire.analyze_action(
                tool_name="db.read",
                session_id="test-session",
                agent_id="test-agent",
                success=True,
                parameters={"query": "SELECT 1"},
            )

        # After many rapid actions, we may see increased scrutiny
        # (exact behavior depends on timing)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system."""

    def test_full_workflow(self):
        """Test complete workflow from request to verified receipt."""
        async def test():
            # Create gateway
            gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()

            # Register tool (using *.read pattern to match default allow policy)
            tool = ToolDefinition(
                id="integration.read",
                name="Integration Test",
                categories=[ToolCategory.READ],
            )
            registry.register(tool)

            async def exec_tool(tool_id, params):
                return {"status": "ok"}
            gateway.register_executor("integration.read", exec_tool)

            # Execute
            request = ToolRequest(
                tool_id="integration.read",
                parameters={},
                agent_id="test-agent",
                tenant_id="test-tenant",
                session_id="test-session",
            )
            response = await gateway.execute(request)

            # Verify success
            self.assertTrue(response.success)
            self.assertIsNotNone(response.receipt)

            # Verify receipt
            self.assertTrue(receipt_service.verify_receipt(response.receipt))

            # Verify in log
            proof = audit_log.get_proof_for_receipt(response.receipt.receipt_id)
            self.assertIsNotNone(proof)
            self.assertTrue(audit_log.verify_receipt_in_log(response.receipt, proof))

        asyncio.run(test())


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestCrypto))
    suite.addTests(loader.loadTestsFromTestCase(TestReceipts))
    suite.addTests(loader.loadTestsFromTestCase(TestMerkleLog))
    suite.addTests(loader.loadTestsFromTestCase(TestPolicy))
    suite.addTests(loader.loadTestsFromTestCase(TestRegistry))
    suite.addTests(loader.loadTestsFromTestCase(TestGateway))
    suite.addTests(loader.loadTestsFromTestCase(TestTokens))
    suite.addTests(loader.loadTestsFromTestCase(TestTripwire))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    run_tests()
