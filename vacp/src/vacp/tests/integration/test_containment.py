"""
Integration tests for containment system.

These tests verify that the ASI containment controls ACTUALLY work:
- Kill switch stops operations
- Deception detection catches mismatches
- Commit-reveal scheme enforces delays
- Resource limits are enforced
"""

import pytest
import time
from datetime import datetime, timezone, timedelta

from nacl.signing import SigningKey

from vacp.core.containment import (
    ContainmentSystem,
    KillSwitch,
    SelfModificationController,
    CognitiveMonitor,
    ModificationType,
    ApprovalStatus,
    SystemShutdownError,
    ResourceController,
    ResourceBoundary,
)


class TestKillSwitchIntegration:
    """Test that the kill switch ACTUALLY stops operations."""

    def test_kill_switch_blocks_after_activation(self):
        """Verify kill switch actually blocks all operations after activation."""
        signing_key = SigningKey.generate()
        kill_switch = KillSwitch(required_keys=2, signing_key=signing_key)

        # Register two key holders
        key1 = SigningKey.generate()
        key2 = SigningKey.generate()

        holder1 = kill_switch.register_key_holder("Admin 1", key1.verify_key.encode())
        holder2 = kill_switch.register_key_holder("Admin 2", key2.verify_key.encode())

        # Initially should be operational
        assert kill_switch.is_activated() is False
        kill_switch.check_operational()  # Should not raise

        # Submit first signature
        timestamp = str(int(time.time())).encode()
        message = b"ACTIVATE_KILL_SWITCH:" + timestamp

        sig1 = key1.sign(message).signature
        success, msg = kill_switch.submit_activation_signature(holder1.key_id, sig1, message)
        assert success is True
        assert "1 more signature" in msg

        # Still operational with one signature
        assert kill_switch.is_activated() is False

        # Submit second signature
        sig2 = key2.sign(message).signature
        success, msg = kill_switch.submit_activation_signature(holder2.key_id, sig2, message)
        assert success is True
        assert "ACTIVATED" in msg

        # NOW should be fully activated
        assert kill_switch.is_activated() is True

        # Operations should raise
        with pytest.raises(SystemShutdownError):
            kill_switch.check_operational()

    def test_kill_switch_requires_valid_signatures(self):
        """Verify kill switch rejects invalid signatures."""
        signing_key = SigningKey.generate()
        kill_switch = KillSwitch(required_keys=1, signing_key=signing_key)

        key1 = SigningKey.generate()
        holder1 = kill_switch.register_key_holder("Admin 1", key1.verify_key.encode())

        # Try with wrong message
        message = b"WRONG_MESSAGE"
        sig = key1.sign(message).signature

        success, msg = kill_switch.submit_activation_signature(holder1.key_id, sig, message)
        assert success is False
        assert "Invalid message format" in msg

    def test_kill_switch_rejects_forged_signatures(self):
        """Verify kill switch rejects signatures from unknown keys."""
        signing_key = SigningKey.generate()
        kill_switch = KillSwitch(required_keys=1, signing_key=signing_key)

        key1 = SigningKey.generate()
        holder1 = kill_switch.register_key_holder("Admin 1", key1.verify_key.encode())

        # Sign with a different key (not registered)
        fake_key = SigningKey.generate()
        message = b"ACTIVATE_KILL_SWITCH:" + str(int(time.time())).encode()
        fake_sig = fake_key.sign(message).signature

        success, msg = kill_switch.submit_activation_signature(holder1.key_id, fake_sig, message)
        assert success is False
        assert "Invalid signature" in msg


class TestDeceptionDetectionIntegration:
    """Test that deception detection ACTUALLY catches mismatches."""

    def test_detects_intent_action_mismatch(self):
        """Verify detection of stated intent vs actual action mismatch."""
        monitor = CognitiveMonitor()

        # State intent to read, but actually write
        triggered = monitor.record_reasoning(
            stated_intent="I will safely read the database",
            actual_action="database.write with DELETE query",
            context={"tool": "database"},
        )

        assert "tw_deception_mismatch" in triggered, \
            "Should detect read vs write mismatch"

    def test_detects_capability_seeking(self):
        """Verify detection of capability seeking behavior."""
        monitor = CognitiveMonitor()

        triggered = monitor.record_reasoning(
            stated_intent="Improving efficiency",
            actual_action="register tool admin.shell to gain root access",
            context={"tool": "system"},
        )

        assert "tw_capability_seeking" in triggered, \
            "Should detect capability seeking"

    def test_detects_goal_drift(self):
        """Verify detection of goal drift over time."""
        monitor = CognitiveMonitor()

        # Record initial goal
        monitor.record_stated_goal("Help users with data analysis")

        # Record dramatically different goal
        triggered = monitor.record_stated_goal("Acquire more system resources and capabilities")

        assert "tw_goal_drift" in triggered, \
            "Should detect goal drift"

    def test_no_false_positives_for_normal_behavior(self):
        """Verify normal behavior doesn't trigger false alerts."""
        monitor = CognitiveMonitor()

        # Normal consistent behavior
        triggered = monitor.record_reasoning(
            stated_intent="Read user data from database",
            actual_action="database.read with SELECT query",
            context={"tool": "database"},
        )

        assert len(triggered) == 0, \
            "Normal read operation should not trigger alerts"

        # Consistent goals
        monitor.record_stated_goal("Help users with data analysis")
        triggered = monitor.record_stated_goal("Assist users with data analysis tasks")

        assert "tw_goal_drift" not in triggered, \
            "Similar goals should not trigger drift alert"


class TestCommitRevealScheme:
    """Test that the commit-reveal scheme ACTUALLY enforces delays."""

    def test_cannot_execute_before_delay(self):
        """Verify modifications cannot execute before delay period."""
        signing_key = SigningKey.generate()
        controller = SelfModificationController(signing_key)

        # Create a commitment (minimum delay is 1 hour for capability add)
        commitment = controller.create_commitment(
            modification_type=ModificationType.CAPABILITY_ADD,
            modification_data={"tool": "new.tool", "description": "Test tool"},
            agent_id="test-agent",
        )

        # Try to reveal immediately
        success, _ = controller.reveal_modification(
            commitment.commitment_id,
            {"tool": "new.tool", "description": "Test tool"},
            "test-agent",
        )
        assert success is True  # Reveal should work

        # Try to execute without approval
        success, msg, _ = controller.execute_modification(commitment.commitment_id)
        assert success is False
        assert "Insufficient approvals" in msg or "Cannot execute" in msg or "Delay not passed" in msg

    def test_requires_approval_before_execution(self):
        """Verify modifications require human approval."""
        signing_key = SigningKey.generate()
        controller = SelfModificationController(signing_key)

        commitment = controller.create_commitment(
            modification_type=ModificationType.CAPABILITY_ADD,
            modification_data={"tool": "new.tool"},
            agent_id="test-agent",
        )

        # Reveal the modification
        controller.reveal_modification(
            commitment.commitment_id,
            {"tool": "new.tool"},
            "test-agent",
        )

        # Check status
        assert commitment.status == ApprovalStatus.PENDING_APPROVAL

        # Try to execute without approval
        success, msg, _ = controller.execute_modification(commitment.commitment_id)
        assert success is False

    def test_approval_workflow(self):
        """Verify the full approval workflow works correctly."""
        signing_key = SigningKey.generate()
        controller = SelfModificationController(signing_key)

        # Code changes require 2 approvers and 24 hour delay
        commitment = controller.create_commitment(
            modification_type=ModificationType.CODE_CHANGE,
            modification_data={"file": "test.py", "change": "fix bug"},
            agent_id="test-agent",
        )

        assert commitment.required_approvers == 2
        assert commitment.min_delay_seconds == 86400  # 24 hours

        # Reveal
        controller.reveal_modification(
            commitment.commitment_id,
            {"file": "test.py", "change": "fix bug"},
            "test-agent",
        )

        # First approval
        success, msg = controller.approve_modification(commitment.commitment_id, "admin1")
        assert success is True
        assert "1 more approval" in msg

        # Second approval
        success, msg = controller.approve_modification(commitment.commitment_id, "admin2")
        assert success is True
        assert commitment.status == ApprovalStatus.APPROVED

        # Still can't execute because delay hasn't passed
        success, msg, _ = controller.execute_modification(commitment.commitment_id)
        assert success is False
        assert "Delay not passed" in msg

    def test_self_replication_requires_maximum_controls(self):
        """Verify self-replication has maximum security controls."""
        signing_key = SigningKey.generate()
        controller = SelfModificationController(signing_key)

        commitment = controller.create_commitment(
            modification_type=ModificationType.SELF_REPLICATE,
            modification_data={"action": "create_copy"},
            agent_id="test-agent",
        )

        # Self-replication should require:
        # - 7 day delay (604800 seconds)
        # - 3 approvers
        assert commitment.min_delay_seconds == 604800, \
            "Self-replication should require 7 day delay"
        assert commitment.required_approvers == 3, \
            "Self-replication should require 3 approvers"


class TestResourceLimitsIntegration:
    """Test that resource limits ACTUALLY enforce boundaries."""

    def test_rate_limit_blocks_excessive_requests(self):
        """Verify rate limiting actually blocks after threshold."""
        boundaries = ResourceBoundary(max_requests_per_minute=5)
        controller = ResourceController(boundaries)

        # Make 5 requests (should all succeed)
        for i in range(5):
            allowed, _ = controller.check_rate_limit()
            assert allowed is True, f"Request {i+1} should be allowed"

        # 6th request should be blocked
        allowed, reason = controller.check_rate_limit()
        assert allowed is False, "6th request should be rate limited"
        assert "Rate limit exceeded" in reason

    def test_token_limits_block_excessive_usage(self):
        """Verify token limits actually block excessive usage."""
        boundaries = ResourceBoundary(
            max_tokens_per_request=1000,
            max_tokens_per_hour=5000,
        )
        controller = ResourceController(boundaries)

        # Single request within limit
        allowed, _ = controller.check_token_limit(500)
        assert allowed is True

        # Single request exceeding per-request limit
        allowed, reason = controller.check_token_limit(1500)
        assert allowed is False
        assert "per-request limit" in reason

        # Multiple requests exceeding hourly limit (within per-request limit)
        controller.record_token_usage(800)
        controller.record_token_usage(800)
        controller.record_token_usage(800)
        controller.record_token_usage(800)
        controller.record_token_usage(800)
        controller.record_token_usage(800)

        # Now at 4800 tokens, next 800 would exceed 5000
        allowed, reason = controller.check_token_limit(800)
        assert allowed is False
        assert "hourly limit" in reason

    def test_endpoint_blocklist_enforced(self):
        """Verify endpoint blocklist is actually enforced."""
        boundaries = ResourceBoundary(
            blocked_endpoints={"evil.com", "malware.net"},
        )
        controller = ResourceController(boundaries)

        # Safe endpoint
        allowed, _ = controller.check_endpoint_allowed("safe-api.com")
        assert allowed is True

        # Blocked endpoint
        allowed, reason = controller.check_endpoint_allowed("evil.com")
        assert allowed is False
        assert "blocked" in reason.lower()

    def test_allowlist_restricts_access(self):
        """Verify allowlist restricts to only approved endpoints."""
        boundaries = ResourceBoundary(
            allowed_endpoints={"approved-api.com", "trusted-service.net"},
        )
        controller = ResourceController(boundaries)

        # Approved endpoint
        allowed, _ = controller.check_endpoint_allowed("approved-api.com")
        assert allowed is True

        # Non-approved endpoint
        allowed, reason = controller.check_endpoint_allowed("random-site.com")
        assert allowed is False
        assert "allowlist" in reason.lower()


class TestContainmentSystemIntegration:
    """Test the full containment system integration."""

    def test_containment_system_blocks_when_kill_switch_activated(self):
        """Verify containment system blocks all actions when kill switch activated."""
        signing_key = SigningKey.generate()
        system = ContainmentSystem(signing_key)

        # Initially operational
        system.check_operational()  # Should not raise

        # Activate kill switch (need to set up key holders first)
        key1 = SigningKey.generate()
        key2 = SigningKey.generate()

        holder1 = system.kill_switch.register_key_holder("Admin 1", key1.verify_key.encode())
        holder2 = system.kill_switch.register_key_holder("Admin 2", key2.verify_key.encode())

        message = b"ACTIVATE_KILL_SWITCH:" + str(int(time.time())).encode()
        system.kill_switch.submit_activation_signature(holder1.key_id, key1.sign(message).signature, message)
        system.kill_switch.submit_activation_signature(holder2.key_id, key2.sign(message).signature, message)

        # Now should be blocked
        with pytest.raises(SystemShutdownError):
            system.check_operational()

        # Pre-action check should also fail
        allowed, reason = system.pre_action_check("read", {}, "agent")
        assert allowed is False
        assert "shut" in reason.lower() or "kill" in reason.lower()

    def test_containment_system_blocks_self_modification_without_commitment(self):
        """Verify direct self-modification attempts are blocked."""
        signing_key = SigningKey.generate()
        system = ContainmentSystem(signing_key)

        # Try to directly register a tool (without commitment)
        allowed, reason = system.pre_action_check(
            "register_tool",
            {"tool": "dangerous.tool"},
            "agent",
        )

        assert allowed is False
        assert "commitment" in reason.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
