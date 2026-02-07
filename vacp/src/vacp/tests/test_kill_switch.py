"""
Tests for the enhanced kill switch system.

Covers:
- Basic activation via signatures
- Dead man's switch (heartbeat monitoring)
- Multiple activation channels
- State persistence
- Failsafe mechanism
- Distributed coordination
"""

import pytest
import time
import tempfile
import os
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

from nacl.signing import SigningKey

from vacp.core.kill_switch import (
    EnhancedKillSwitch,
    KillSwitchState,
    ActivationChannel,
    DeadManConfig,
    FailsafeConfig,
    SystemShutdownError,
    DistributedKillSwitch,
)


class TestEnhancedKillSwitchBasics:
    """Tests for basic kill switch functionality."""

    def test_initial_state(self):
        """Test initial armed state."""
        ks = EnhancedKillSwitch(required_signatures=2)
        assert ks._state == KillSwitchState.ARMED
        assert not ks.is_activated()

    def test_register_key_holder(self):
        """Test registering a key holder."""
        ks = EnhancedKillSwitch()
        signing_key = SigningKey.generate()
        public_key_bytes = bytes(signing_key.verify_key)

        holder = ks.register_key_holder("Alice", public_key_bytes)
        assert holder.holder_name == "Alice"
        assert holder.is_active

    def test_signature_activation_requires_threshold(self):
        """Test that activation requires the threshold number of signatures."""
        ks = EnhancedKillSwitch(required_signatures=2)

        # Register two key holders
        key1 = SigningKey.generate()
        key2 = SigningKey.generate()

        holder1 = ks.register_key_holder("Alice", bytes(key1.verify_key))
        holder2 = ks.register_key_holder("Bob", bytes(key2.verify_key))

        # Create activation message
        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"ACTIVATE_KILL_SWITCH:{timestamp}".encode()

        # First signature - not enough
        sig1 = key1.sign(message).signature
        success, msg = ks.submit_activation_signature(holder1.key_id, sig1, message)
        assert success
        assert "1 more signature" in msg
        assert not ks.is_activated()

        # Second signature - should activate
        sig2 = key2.sign(message).signature
        success, msg = ks.submit_activation_signature(holder2.key_id, sig2, message)
        assert success
        assert "ACTIVATED" in msg
        assert ks.is_activated()

    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected."""
        ks = EnhancedKillSwitch()
        key = SigningKey.generate()
        holder = ks.register_key_holder("Alice", bytes(key.verify_key))

        message = b"ACTIVATE_KILL_SWITCH:2024-01-01T00:00:00+00:00"
        # Sign with wrong key
        wrong_key = SigningKey.generate()
        bad_sig = wrong_key.sign(message).signature

        success, msg = ks.submit_activation_signature(holder.key_id, bad_sig, message)
        assert not success
        assert "Invalid signature" in msg

    def test_wrong_message_format_rejected(self):
        """Test that wrong message formats are rejected."""
        ks = EnhancedKillSwitch()
        key = SigningKey.generate()
        holder = ks.register_key_holder("Alice", bytes(key.verify_key))

        message = b"WRONG_FORMAT:2024-01-01T00:00:00+00:00"
        sig = key.sign(message).signature

        success, msg = ks.submit_activation_signature(holder.key_id, sig, message)
        assert not success
        assert "Invalid message format" in msg

    def test_old_timestamp_rejected(self):
        """Test that old timestamps are rejected."""
        ks = EnhancedKillSwitch()
        key = SigningKey.generate()
        holder = ks.register_key_holder("Alice", bytes(key.verify_key))

        # Use timestamp from 10 minutes ago
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        message = f"ACTIVATE_KILL_SWITCH:{old_time.isoformat()}".encode()
        sig = key.sign(message).signature

        success, msg = ks.submit_activation_signature(holder.key_id, sig, message)
        assert not success
        assert "too old" in msg

    def test_check_operational_raises_when_activated(self):
        """Test that check_operational raises when activated."""
        ks = EnhancedKillSwitch(required_signatures=1)
        key = SigningKey.generate()
        holder = ks.register_key_holder("Alice", bytes(key.verify_key))

        # Activate
        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"ACTIVATE_KILL_SWITCH:{timestamp}".encode()
        sig = key.sign(message).signature
        ks.submit_activation_signature(holder.key_id, sig, message)

        with pytest.raises(SystemShutdownError):
            ks.check_operational()

    def test_shutdown_callbacks_called(self):
        """Test that shutdown callbacks are called on activation."""
        ks = EnhancedKillSwitch(required_signatures=1)
        callback_called = []

        def callback():
            callback_called.append(True)

        ks.register_shutdown_callback(callback)

        key = SigningKey.generate()
        holder = ks.register_key_holder("Alice", bytes(key.verify_key))

        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"ACTIVATE_KILL_SWITCH:{timestamp}".encode()
        sig = key.sign(message).signature
        ks.submit_activation_signature(holder.key_id, sig, message)

        assert len(callback_called) == 1

    def test_multiple_callbacks(self):
        """Test that multiple callbacks are called."""
        ks = EnhancedKillSwitch(required_signatures=1)
        results = []

        ks.register_shutdown_callback(lambda: results.append("cb1"))
        ks.register_shutdown_callback(lambda: results.append("cb2"))
        ks.register_shutdown_callback(lambda: results.append("cb3"))

        key = SigningKey.generate()
        holder = ks.register_key_holder("Alice", bytes(key.verify_key))

        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"ACTIVATE_KILL_SWITCH:{timestamp}".encode()
        sig = key.sign(message).signature
        ks.submit_activation_signature(holder.key_id, sig, message)

        assert results == ["cb1", "cb2", "cb3"]


class TestDeadManSwitch:
    """Tests for dead man's switch functionality."""

    def test_heartbeat_resets_missed_count(self):
        """Test that heartbeat resets missed heartbeat count."""
        config = DeadManConfig(
            enabled=True,
            heartbeat_interval=timedelta(seconds=1),
            max_missed_heartbeats=3,
        )
        ks = EnhancedKillSwitch(deadman_config=config)

        # Simulate missed heartbeat
        ks._missed_heartbeats = 2

        success, msg = ks.heartbeat()
        assert success
        assert ks._missed_heartbeats == 0

    def test_heartbeat_updates_last_time(self):
        """Test that heartbeat updates last heartbeat time."""
        config = DeadManConfig(enabled=True)
        ks = EnhancedKillSwitch(deadman_config=config)

        before = ks._last_heartbeat
        time.sleep(0.01)
        ks.heartbeat()
        after = ks._last_heartbeat

        assert after > before

    def test_heartbeat_fails_when_activated(self):
        """Test that heartbeat fails when kill switch is activated."""
        config = DeadManConfig(enabled=True)
        ks = EnhancedKillSwitch(deadman_config=config)
        ks._state = KillSwitchState.ACTIVATED

        success, msg = ks.heartbeat()
        assert not success

    def test_deadman_activation(self):
        """Test dead man's switch activation after missed heartbeats."""
        config = DeadManConfig(
            enabled=True,
            heartbeat_interval=timedelta(milliseconds=50),
            max_missed_heartbeats=2,
        )
        ks = EnhancedKillSwitch(deadman_config=config)

        # Wait for deadman to trigger
        time.sleep(0.25)

        assert ks.is_activated()
        assert ks._activation_channel == ActivationChannel.DEADMAN

    def test_warning_callbacks(self):
        """Test warning callbacks before deadman activation."""
        config = DeadManConfig(
            enabled=True,
            heartbeat_interval=timedelta(milliseconds=50),
            max_missed_heartbeats=5,
            warning_threshold=2,
        )
        warnings = []
        ks = EnhancedKillSwitch(deadman_config=config)
        ks.register_warning_callback(lambda msg: warnings.append(msg))

        # Wait for warnings
        time.sleep(0.2)

        # Should have received warnings before full activation
        assert len(warnings) > 0 or ks.is_activated()

    def test_regular_heartbeats_prevent_activation(self):
        """Test that regular heartbeats prevent activation."""
        config = DeadManConfig(
            enabled=True,
            heartbeat_interval=timedelta(milliseconds=50),
            max_missed_heartbeats=3,
        )
        ks = EnhancedKillSwitch(deadman_config=config)

        # Send heartbeats regularly
        for _ in range(5):
            ks.heartbeat()
            time.sleep(0.03)

        assert not ks.is_activated()

        # Cleanup
        ks.shutdown()


class TestActivationChannels:
    """Tests for different activation channels."""

    def test_file_channel_activation(self):
        """Test file-based activation."""
        ks = EnhancedKillSwitch()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("ACTIVATE")
            temp_path = Path(f.name)

        try:
            ks.check_watchdog_file(temp_path)
            assert ks.is_activated()
            assert ks._activation_channel == ActivationChannel.FILE
        finally:
            temp_path.unlink()

    def test_file_channel_no_activation(self):
        """Test that normal file content doesn't activate."""
        ks = EnhancedKillSwitch()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("normal content")
            temp_path = Path(f.name)

        try:
            ks.check_watchdog_file(temp_path)
            assert not ks.is_activated()
        finally:
            temp_path.unlink()

    def test_missing_watchdog_file_ignored(self):
        """Test that missing watchdog file is ignored."""
        ks = EnhancedKillSwitch()
        ks.check_watchdog_file(Path("/nonexistent/path.txt"))
        assert not ks.is_activated()

    def test_environment_channel_activation(self):
        """Test environment variable activation."""
        ks = EnhancedKillSwitch()

        os.environ["TEST_KILL_SWITCH"] = "ACTIVATE"
        try:
            ks.check_environment("TEST_KILL_SWITCH")
            assert ks.is_activated()
            assert ks._activation_channel == ActivationChannel.ENVIRONMENT
        finally:
            del os.environ["TEST_KILL_SWITCH"]

    def test_environment_channel_no_activation(self):
        """Test that normal env value doesn't activate."""
        ks = EnhancedKillSwitch()

        os.environ["TEST_KILL_SWITCH"] = "normal"
        try:
            ks.check_environment("TEST_KILL_SWITCH")
            assert not ks.is_activated()
        finally:
            del os.environ["TEST_KILL_SWITCH"]

    def test_manual_activation(self):
        """Test manual activation via activate method."""
        ks = EnhancedKillSwitch()

        ks.activate(
            channel=ActivationChannel.MANUAL,
            reason="Test activation",
        )

        assert ks.is_activated()
        assert ks._activation_channel == ActivationChannel.MANUAL
        assert ks._activation_reason == "Test activation"


class TestFailsafe:
    """Tests for failsafe mechanism."""

    def test_failsafe_activation_on_errors(self):
        """Test failsafe activation after too many errors."""
        config = FailsafeConfig(
            enabled=True,
            max_consecutive_errors=3,
            error_window=timedelta(minutes=10),
        )
        ks = EnhancedKillSwitch(failsafe_config=config)

        # Report errors
        for i in range(3):
            ks.report_component_error("test_component", RuntimeError(f"Error {i}"))

        assert ks.is_activated()
        assert ks._activation_channel == ActivationChannel.FAILSAFE

    def test_failsafe_not_activated_below_threshold(self):
        """Test failsafe not activated below error threshold."""
        config = FailsafeConfig(
            enabled=True,
            max_consecutive_errors=5,
            error_window=timedelta(minutes=10),
        )
        ks = EnhancedKillSwitch(failsafe_config=config)

        # Report fewer errors than threshold
        for i in range(3):
            ks.report_component_error("test_component", RuntimeError(f"Error {i}"))

        assert not ks.is_activated()

    def test_failsafe_component_health_critical(self):
        """Test failsafe activation on critical component failure."""
        config = FailsafeConfig(
            enabled=True,
            auto_activate_on_critical=True,
            monitored_components={"policy_engine", "audit_log"},
        )
        ks = EnhancedKillSwitch(failsafe_config=config)

        # Report critical component unhealthy
        ks.report_component_status("policy_engine", is_healthy=False)

        assert ks.is_activated()

    def test_failsafe_component_health_non_critical(self):
        """Test that non-critical component failure doesn't activate."""
        config = FailsafeConfig(
            enabled=True,
            auto_activate_on_critical=True,
            monitored_components={"policy_engine"},
        )
        ks = EnhancedKillSwitch(failsafe_config=config)

        # Report non-monitored component unhealthy
        ks.report_component_status("other_component", is_healthy=False)

        assert not ks.is_activated()

    def test_failsafe_disabled(self):
        """Test that disabled failsafe doesn't activate."""
        config = FailsafeConfig(enabled=False)
        ks = EnhancedKillSwitch(failsafe_config=config)

        # Report many errors
        for i in range(10):
            ks.report_component_error("test", RuntimeError(f"Error {i}"))

        assert not ks.is_activated()


class TestStatePersistence:
    """Tests for state persistence."""

    def test_state_saved_on_activation(self):
        """Test that state is saved when activated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "kill_switch_state.json"
            ks = EnhancedKillSwitch(state_file=state_file)

            ks.activate(
                channel=ActivationChannel.MANUAL,
                reason="Test",
            )

            assert state_file.exists()

            import json
            with open(state_file) as f:
                data = json.load(f)

            assert data["state"] == "activated"

    def test_state_restored_on_init(self):
        """Test that activated state is restored on init."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "kill_switch_state.json"

            # Create first instance and activate
            ks1 = EnhancedKillSwitch(state_file=state_file)
            ks1.activate(channel=ActivationChannel.MANUAL, reason="Test")
            ks1.shutdown()

            # Create second instance - should restore state
            ks2 = EnhancedKillSwitch(state_file=state_file)
            assert ks2.is_activated()
            ks2.shutdown()


class TestReset:
    """Tests for kill switch reset functionality."""

    def test_reset_requires_master_signature(self):
        """Test that reset requires valid master signature."""
        ks = EnhancedKillSwitch()
        ks.activate(channel=ActivationChannel.MANUAL, reason="Test")

        # Try reset with invalid signature
        wrong_key = SigningKey.generate()
        message = b"RESET_KILL_SWITCH:test"
        bad_sig = wrong_key.sign(message).signature

        success, msg = ks.reset(bad_sig, message)
        assert not success
        assert ks.is_activated()

    def test_reset_with_valid_signature(self):
        """Test reset with valid master signature."""
        signing_key = SigningKey.generate()
        ks = EnhancedKillSwitch(signing_key=signing_key)
        ks.activate(channel=ActivationChannel.MANUAL, reason="Test")

        message = b"RESET_KILL_SWITCH:test"
        sig = signing_key.sign(message).signature

        success, msg = ks.reset(sig, message)
        assert success
        assert not ks.is_activated()
        assert ks._state == KillSwitchState.ARMED

    def test_reset_clears_pending_signatures(self):
        """Test that reset clears pending signatures."""
        signing_key = SigningKey.generate()
        ks = EnhancedKillSwitch(required_signatures=2, signing_key=signing_key)

        # Register and submit one signature
        key1 = SigningKey.generate()
        holder1 = ks.register_key_holder("Alice", bytes(key1.verify_key))
        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"ACTIVATE_KILL_SWITCH:{timestamp}".encode()
        sig1 = key1.sign(message).signature
        ks.submit_activation_signature(holder1.key_id, sig1, message)

        assert len(ks._pending_signatures) == 1

        # Activate and reset
        ks.activate(channel=ActivationChannel.MANUAL, reason="Test")
        reset_msg = b"RESET_KILL_SWITCH:test"
        reset_sig = signing_key.sign(reset_msg).signature
        ks.reset(reset_sig, reset_msg)

        assert len(ks._pending_signatures) == 0


class TestStatus:
    """Tests for status reporting."""

    def test_get_status_armed(self):
        """Test status when armed."""
        ks = EnhancedKillSwitch(required_signatures=2)
        status = ks.get_status()

        assert status["state"] == "armed"
        assert status["required_signatures"] == 2
        assert status["activation_time"] is None

    def test_get_status_activated(self):
        """Test status when activated."""
        ks = EnhancedKillSwitch()
        ks.activate(channel=ActivationChannel.MANUAL, reason="Test reason")

        status = ks.get_status()
        assert status["state"] == "activated"
        assert status["activation_channel"] == "manual"
        assert status["activation_reason"] == "Test reason"
        assert status["activation_time"] is not None

    def test_get_status_includes_key_holders(self):
        """Test that status includes key holder info."""
        ks = EnhancedKillSwitch()
        key = SigningKey.generate()
        ks.register_key_holder("Alice", bytes(key.verify_key))

        status = ks.get_status()
        assert len(status["key_holders"]) == 1
        assert status["key_holders"][0]["name"] == "Alice"

    def test_get_status_includes_deadman_info(self):
        """Test that status includes dead man's switch info."""
        config = DeadManConfig(enabled=True, max_missed_heartbeats=5)
        ks = EnhancedKillSwitch(deadman_config=config)

        status = ks.get_status()
        assert status["deadman"]["enabled"] is True
        assert status["deadman"]["max_missed"] == 5

    def test_activation_records(self):
        """Test that activation attempts are recorded."""
        ks = EnhancedKillSwitch()
        key = SigningKey.generate()
        holder = ks.register_key_holder("Alice", bytes(key.verify_key))

        # Failed attempt with invalid signature
        wrong_key = SigningKey.generate()
        message = b"ACTIVATE_KILL_SWITCH:2024-01-01T00:00:00+00:00"
        bad_sig = wrong_key.sign(message).signature
        ks.submit_activation_signature(holder.key_id, bad_sig, message)

        records = ks.get_activation_records()
        assert len(records) == 1
        assert not records[0].successful


class TestDistributedKillSwitch:
    """Tests for distributed kill switch functionality."""

    def test_node_registration(self):
        """Test registering nodes in cluster."""
        local_ks = EnhancedKillSwitch()
        dist_ks = DistributedKillSwitch(
            local_kill_switch=local_ks,
            node_id="node-1",
            node_name="Node 1",
        )

        dist_ks.register_node("node-2", "Node 2", "http://node2:8080")
        dist_ks.register_node("node-3", "Node 3", "http://node3:8080")

        status = dist_ks.get_cluster_status()
        assert len(status["cluster_nodes"]) == 2

    def test_receive_shutdown_signal(self):
        """Test receiving shutdown signal from another node."""
        local_ks = EnhancedKillSwitch()
        dist_ks = DistributedKillSwitch(
            local_kill_switch=local_ks,
            node_id="node-1",
            node_name="Node 1",
        )

        dist_ks.receive_shutdown_signal("node-2", "Emergency shutdown")

        assert local_ks.is_activated()
        assert local_ks._activation_channel == ActivationChannel.NETWORK

    def test_local_status_in_cluster_status(self):
        """Test that cluster status includes local node status."""
        local_ks = EnhancedKillSwitch()
        dist_ks = DistributedKillSwitch(
            local_kill_switch=local_ks,
            node_id="node-1",
            node_name="Node 1",
        )

        status = dist_ks.get_cluster_status()
        assert status["local_node"]["node_id"] == "node-1"
        assert status["local_node"]["status"]["state"] == "armed"


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_heartbeats(self):
        """Test concurrent heartbeat calls."""
        config = DeadManConfig(
            enabled=True,
            heartbeat_interval=timedelta(seconds=10),
        )
        ks = EnhancedKillSwitch(deadman_config=config)
        results = []

        def heartbeat():
            for _ in range(100):
                success, _ = ks.heartbeat()
                results.append(success)

        threads = [threading.Thread(target=heartbeat) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results)
        assert not ks.is_activated()
        ks.shutdown()

    def test_concurrent_signature_submission(self):
        """Test concurrent signature submissions."""
        ks = EnhancedKillSwitch(required_signatures=5)
        keys = [SigningKey.generate() for _ in range(5)]
        holders = [
            ks.register_key_holder(f"Holder {i}", bytes(k.verify_key))
            for i, k in enumerate(keys)
        ]

        results = []
        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"ACTIVATE_KILL_SWITCH:{timestamp}".encode()

        def submit_sig(idx):
            sig = keys[idx].sign(message).signature
            success, _ = ks.submit_activation_signature(holders[idx].key_id, sig, message)
            results.append(success)

        threads = [threading.Thread(target=submit_sig, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results)
        assert ks.is_activated()

    def test_activation_during_heartbeat(self):
        """Test that activation works during heartbeat monitoring."""
        config = DeadManConfig(
            enabled=True,
            heartbeat_interval=timedelta(milliseconds=10),
        )
        ks = EnhancedKillSwitch(deadman_config=config)

        # Start heartbeating
        stop = threading.Event()

        def heartbeat_loop():
            while not stop.is_set():
                ks.heartbeat()
                time.sleep(0.005)

        t = threading.Thread(target=heartbeat_loop)
        t.start()

        time.sleep(0.05)

        # Activate manually
        ks.activate(channel=ActivationChannel.MANUAL, reason="Test")

        stop.set()
        t.join()
        ks.shutdown()

        assert ks.is_activated()


class TestEdgeCases:
    """Tests for edge cases."""

    def test_double_activation(self):
        """Test that double activation is idempotent."""
        ks = EnhancedKillSwitch()

        ks.activate(channel=ActivationChannel.MANUAL, reason="First")
        first_time = ks._activation_time

        ks.activate(channel=ActivationChannel.MANUAL, reason="Second")
        second_time = ks._activation_time

        assert first_time == second_time
        assert ks._activation_reason == "First"  # First reason preserved

    def test_registration_after_activation_fails(self):
        """Test that key holder registration fails after activation."""
        ks = EnhancedKillSwitch()
        ks.activate(channel=ActivationChannel.MANUAL, reason="Test")

        key = SigningKey.generate()
        with pytest.raises(RuntimeError):
            ks.register_key_holder("Alice", bytes(key.verify_key))

    def test_already_activated_returns_true(self):
        """Test that submitting signature when activated returns true."""
        ks = EnhancedKillSwitch()
        key = SigningKey.generate()
        holder = ks.register_key_holder("Alice", bytes(key.verify_key))

        ks.activate(channel=ActivationChannel.MANUAL, reason="Test")

        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"ACTIVATE_KILL_SWITCH:{timestamp}".encode()
        sig = key.sign(message).signature

        success, msg = ks.submit_activation_signature(holder.key_id, sig, message)
        assert success
        assert "already activated" in msg

    def test_unknown_key_holder(self):
        """Test submission with unknown key holder."""
        ks = EnhancedKillSwitch()

        success, msg = ks.submit_activation_signature(
            "unknown_key_id",
            b"signature",
            b"message",
        )
        assert not success
        assert "Unknown key holder" in msg

    def test_callback_exception_doesnt_prevent_activation(self):
        """Test that callback exceptions don't prevent activation."""
        ks = EnhancedKillSwitch()

        def failing_callback():
            raise RuntimeError("Callback failed")

        def success_callback():
            pass

        ks.register_shutdown_callback(failing_callback)
        ks.register_shutdown_callback(success_callback)

        # Should not raise
        ks.activate(channel=ActivationChannel.MANUAL, reason="Test")
        assert ks.is_activated()
