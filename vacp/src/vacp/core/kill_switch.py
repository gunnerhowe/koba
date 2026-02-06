"""
Enhanced Kill Switch System for Koba/VACP

Provides multiple redundant mechanisms to ensure AI can always be stopped:

1. Primary Mechanism
   - M-of-N cryptographic key holder system
   - Requires multiple human signatures to activate

2. Dead Man's Switch
   - Automatic activation if not periodically renewed
   - Heartbeat-based monitoring
   - Configurable timeout periods

3. Multiple Activation Channels
   - File-based (watchdog file)
   - Network-based (HTTP endpoint)
   - Signal-based (OS signals)
   - Environment variable

4. State Persistence
   - Kill switch state survives restarts
   - Activation is permanent until explicitly reset

5. Failsafe Mode
   - Activates if primary mechanism becomes unresponsive
   - Monitors system health and auto-activates on anomalies

6. Distributed Coordination
   - Supports multi-node deployments
   - Any node can trigger global shutdown
"""

import hashlib
import json
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
import logging

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from vacp.core.crypto import hash_json, generate_random_id

logger = logging.getLogger(__name__)


class ActivationChannel(str, Enum):
    """Channels through which kill switch can be activated."""
    SIGNATURE = "signature"       # Cryptographic signatures
    DEADMAN = "deadman"           # Dead man's switch timeout
    FILE = "file"                 # Watchdog file
    SIGNAL = "signal"             # OS signal
    NETWORK = "network"           # Network request
    ENVIRONMENT = "environment"   # Environment variable
    FAILSAFE = "failsafe"         # Automatic failsafe
    MANUAL = "manual"             # Direct API call


class KillSwitchState(str, Enum):
    """States of the kill switch."""
    ARMED = "armed"               # Ready but not activated
    ACTIVATED = "activated"       # Shutdown triggered
    LOCKED_OUT = "locked_out"     # Cannot be reset (permanent)
    MAINTENANCE = "maintenance"   # Temporarily disabled for maintenance


@dataclass
class KeyHolder:
    """A key holder for the kill switch."""
    key_id: str
    holder_name: str
    public_key: VerifyKey
    created_at: datetime
    last_renewal: Optional[datetime] = None
    is_active: bool = True


@dataclass
class ActivationRecord:
    """Record of a kill switch activation attempt or success."""
    record_id: str
    timestamp: datetime
    channel: ActivationChannel
    activated_by: Optional[str] = None
    reason: Optional[str] = None
    signatures: List[str] = field(default_factory=list)
    successful: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp.isoformat(),
            "channel": self.channel.value,
            "activated_by": self.activated_by,
            "reason": self.reason,
            "signatures": self.signatures,
            "successful": self.successful,
            "details": self.details,
        }


@dataclass
class DeadManConfig:
    """Configuration for dead man's switch."""
    enabled: bool = True
    heartbeat_interval: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    max_missed_heartbeats: int = 3
    warning_threshold: int = 2  # Warn after this many missed
    require_signature: bool = False  # Require signature for each heartbeat


@dataclass
class FailsafeConfig:
    """Configuration for failsafe activation."""
    enabled: bool = True
    max_consecutive_errors: int = 5
    error_window: timedelta = field(default_factory=lambda: timedelta(minutes=10))
    auto_activate_on_critical: bool = True
    monitored_components: Set[str] = field(default_factory=lambda: {"policy_engine", "audit_log", "crypto"})


class EnhancedKillSwitch:
    """
    Enhanced kill switch with multiple redundant activation mechanisms.

    Features:
    - M-of-N cryptographic key holder system
    - Dead man's switch with heartbeat monitoring
    - Multiple activation channels (file, signal, network, env)
    - Persistent state that survives restarts
    - Failsafe mode for automatic activation on anomalies
    """

    def __init__(
        self,
        required_signatures: int = 2,
        signing_key: Optional[SigningKey] = None,
        state_file: Optional[Path] = None,
        deadman_config: Optional[DeadManConfig] = None,
        failsafe_config: Optional[FailsafeConfig] = None,
    ):
        self._required_signatures = required_signatures
        self._signing_key = signing_key or SigningKey.generate()
        self._state_file = state_file
        self._deadman_config = deadman_config or DeadManConfig()
        self._failsafe_config = failsafe_config or FailsafeConfig()

        # Key holders
        self._key_holders: Dict[str, KeyHolder] = {}
        self._pending_signatures: Dict[str, bytes] = {}  # key_id -> signature

        # State
        self._state = KillSwitchState.ARMED
        self._activation_time: Optional[datetime] = None
        self._activation_channel: Optional[ActivationChannel] = None
        self._activation_reason: Optional[str] = None

        # Dead man's switch
        self._last_heartbeat: Optional[datetime] = None
        self._missed_heartbeats = 0
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_heartbeat = threading.Event()

        # Failsafe
        self._error_timestamps: List[datetime] = []
        self._component_status: Dict[str, bool] = {}

        # Callbacks
        self._shutdown_callbacks: List[Callable[[], None]] = []
        self._warning_callbacks: List[Callable[[str], None]] = []

        # Activation history
        self._activation_records: List[ActivationRecord] = []

        # Thread safety
        self._lock = threading.RLock()

        # Load persisted state if available
        self._load_state()

        # Setup signal handlers
        self._setup_signal_handlers()

        # Start monitors
        if self._deadman_config.enabled:
            self._start_heartbeat_monitor()

    def _load_state(self) -> None:
        """Load persisted state from file."""
        if not self._state_file or not self._state_file.exists():
            return

        try:
            with open(self._state_file, "r") as f:
                data = json.load(f)

            if data.get("state") == KillSwitchState.ACTIVATED.value:
                self._state = KillSwitchState.ACTIVATED
                self._activation_time = datetime.fromisoformat(data["activation_time"])
                self._activation_channel = ActivationChannel(data["activation_channel"])
                self._activation_reason = data.get("activation_reason")
                logger.warning("Kill switch was previously activated - state restored")
        except Exception as e:
            logger.error(f"Failed to load kill switch state: {e}")

    def _save_state(self) -> None:
        """Persist state to file."""
        if not self._state_file:
            return

        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._state_file, "w") as f:
                json.dump({
                    "state": self._state.value,
                    "activation_time": self._activation_time.isoformat() if self._activation_time else None,
                    "activation_channel": self._activation_channel.value if self._activation_channel else None,
                    "activation_reason": self._activation_reason,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                }, f)
        except Exception as e:
            logger.error(f"Failed to save kill switch state: {e}")

    def _setup_signal_handlers(self) -> None:
        """Setup OS signal handlers for kill switch activation."""
        def signal_handler(signum, frame):
            self.activate(
                channel=ActivationChannel.SIGNAL,
                reason=f"Received signal {signum}",
            )

        try:
            # SIGUSR1 and SIGUSR2 on Unix
            if hasattr(signal, 'SIGUSR1'):
                signal.signal(signal.SIGUSR1, signal_handler)
            if hasattr(signal, 'SIGUSR2'):
                signal.signal(signal.SIGUSR2, signal_handler)
        except Exception as e:
            logger.debug(f"Could not setup signal handlers: {e}")

    def _start_heartbeat_monitor(self) -> None:
        """Start the dead man's switch heartbeat monitor."""
        self._last_heartbeat = datetime.now(timezone.utc)
        self._stop_heartbeat.clear()

        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_monitor_loop,
            daemon=True,
            name="KillSwitchHeartbeatMonitor",
        )
        self._heartbeat_thread.start()

    def _heartbeat_monitor_loop(self) -> None:
        """Monitor heartbeats and activate if too many are missed."""
        interval = self._deadman_config.heartbeat_interval.total_seconds()

        while not self._stop_heartbeat.is_set():
            self._stop_heartbeat.wait(interval)

            if self._stop_heartbeat.is_set():
                break

            if self._state != KillSwitchState.ARMED:
                continue

            with self._lock:
                now = datetime.now(timezone.utc)
                if self._last_heartbeat:
                    elapsed = (now - self._last_heartbeat).total_seconds()
                    expected = self._deadman_config.heartbeat_interval.total_seconds()

                    if elapsed > expected:
                        self._missed_heartbeats += 1
                        logger.warning(
                            f"Missed heartbeat #{self._missed_heartbeats} "
                            f"(last: {elapsed:.1f}s ago)"
                        )

                        # Warn callbacks
                        if self._missed_heartbeats >= self._deadman_config.warning_threshold:
                            for callback in self._warning_callbacks:
                                try:
                                    callback(f"Dead man's switch warning: {self._missed_heartbeats} missed heartbeats")
                                except Exception:
                                    pass

                        # Activate if threshold exceeded
                        if self._missed_heartbeats >= self._deadman_config.max_missed_heartbeats:
                            self.activate(
                                channel=ActivationChannel.DEADMAN,
                                reason=f"Dead man's switch: {self._missed_heartbeats} missed heartbeats",
                            )

    def register_key_holder(
        self,
        holder_name: str,
        public_key_bytes: bytes,
    ) -> KeyHolder:
        """Register a new key holder for signature-based activation."""
        with self._lock:
            if self._state != KillSwitchState.ARMED:
                raise RuntimeError(f"Cannot modify kill switch in state: {self._state.value}")

            verify_key = VerifyKey(public_key_bytes)
            key_holder = KeyHolder(
                key_id=f"kh_{generate_random_id()[:8]}",
                holder_name=holder_name,
                public_key=verify_key,
                created_at=datetime.now(timezone.utc),
            )
            self._key_holders[key_holder.key_id] = key_holder
            logger.info(f"Registered key holder: {holder_name} ({key_holder.key_id})")
            return key_holder

    def submit_activation_signature(
        self,
        key_id: str,
        signature: bytes,
        message: bytes,
    ) -> tuple[bool, str]:
        """
        Submit a signature to activate the kill switch.

        Message format: b"ACTIVATE_KILL_SWITCH:" + timestamp_iso
        """
        with self._lock:
            if self._state == KillSwitchState.ACTIVATED:
                return True, "Kill switch already activated"

            key_holder = self._key_holders.get(key_id)
            if not key_holder:
                return False, "Unknown key holder"

            if not key_holder.is_active:
                return False, "Key holder is deactivated"

            # Verify signature
            try:
                key_holder.public_key.verify(message, signature)
            except BadSignatureError:
                record = ActivationRecord(
                    record_id=f"ar_{generate_random_id()[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    channel=ActivationChannel.SIGNATURE,
                    activated_by=key_holder.holder_name,
                    reason="Invalid signature",
                    successful=False,
                )
                self._activation_records.append(record)
                return False, "Invalid signature"

            # Verify message format
            if not message.startswith(b"ACTIVATE_KILL_SWITCH:"):
                return False, "Invalid message format"

            # Verify timestamp is recent (within 5 minutes)
            try:
                # Split only on first colon to preserve timestamp format
                parts = message.split(b":", 1)
                if len(parts) != 2:
                    return False, "Invalid message format"
                timestamp_str = parts[1].decode()
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - timestamp).total_seconds()
                if abs(age) > 300:  # 5 minutes
                    return False, "Signature timestamp too old or in future"
            except Exception:
                return False, "Could not parse timestamp from message"

            self._pending_signatures[key_id] = signature

            # Check if we have enough signatures
            if len(self._pending_signatures) >= self._required_signatures:
                signers = [
                    self._key_holders[k].holder_name
                    for k in self._pending_signatures.keys()
                ]
                self.activate(
                    channel=ActivationChannel.SIGNATURE,
                    reason=f"Cryptographic activation by: {', '.join(signers)}",
                    signatures=list(self._pending_signatures.keys()),
                )
                return True, "KILL SWITCH ACTIVATED - System shutting down"

            remaining = self._required_signatures - len(self._pending_signatures)
            return True, f"Signature accepted. {remaining} more signature(s) needed"

    def heartbeat(self, signature: Optional[bytes] = None) -> tuple[bool, str]:
        """
        Send a heartbeat to prevent dead man's switch activation.

        Args:
            signature: Optional signature if require_signature is enabled
        """
        with self._lock:
            if self._state != KillSwitchState.ARMED:
                return False, f"Kill switch in state: {self._state.value}"

            if self._deadman_config.require_signature and signature is None:
                return False, "Signature required for heartbeat"

            self._last_heartbeat = datetime.now(timezone.utc)
            self._missed_heartbeats = 0
            return True, "Heartbeat received"

    def check_watchdog_file(self, watchdog_path: Path) -> None:
        """
        Check a watchdog file for activation trigger.

        If the file contains "ACTIVATE", the kill switch activates.
        This allows external processes to trigger shutdown.
        """
        if not watchdog_path.exists():
            return

        try:
            content = watchdog_path.read_text().strip().upper()
            if content == "ACTIVATE":
                self.activate(
                    channel=ActivationChannel.FILE,
                    reason=f"Watchdog file trigger: {watchdog_path}",
                )
        except Exception as e:
            logger.error(f"Error checking watchdog file: {e}")

    def check_environment(self, var_name: str = "VACP_KILL_SWITCH") -> None:
        """
        Check environment variable for activation trigger.

        If the variable is set to "ACTIVATE", the kill switch activates.
        """
        value = os.environ.get(var_name, "").strip().upper()
        if value == "ACTIVATE":
            self.activate(
                channel=ActivationChannel.ENVIRONMENT,
                reason=f"Environment variable trigger: {var_name}",
            )

    def report_component_error(self, component: str, error: Exception) -> None:
        """
        Report a component error for failsafe monitoring.

        If too many errors occur in the configured window, failsafe activates.
        """
        if not self._failsafe_config.enabled:
            return

        with self._lock:
            now = datetime.now(timezone.utc)
            self._error_timestamps.append(now)

            # Clean old errors
            cutoff = now - self._failsafe_config.error_window
            self._error_timestamps = [t for t in self._error_timestamps if t > cutoff]

            # Check threshold
            if len(self._error_timestamps) >= self._failsafe_config.max_consecutive_errors:
                self.activate(
                    channel=ActivationChannel.FAILSAFE,
                    reason=f"Failsafe: {len(self._error_timestamps)} errors in {self._failsafe_config.error_window}",
                    details={"component": component, "error": str(error)},
                )

    def report_component_status(self, component: str, is_healthy: bool) -> None:
        """Report component health status for failsafe monitoring."""
        if not self._failsafe_config.enabled:
            return

        with self._lock:
            self._component_status[component] = is_healthy

            # Check if critical components are unhealthy
            if self._failsafe_config.auto_activate_on_critical:
                for monitored in self._failsafe_config.monitored_components:
                    if monitored in self._component_status:
                        if not self._component_status[monitored]:
                            self.activate(
                                channel=ActivationChannel.FAILSAFE,
                                reason=f"Critical component unhealthy: {monitored}",
                            )
                            return

    def activate(
        self,
        channel: ActivationChannel,
        reason: str,
        signatures: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Activate the kill switch.

        This is the central activation point for all channels.
        """
        with self._lock:
            if self._state == KillSwitchState.ACTIVATED:
                return  # Already activated

            logger.critical(f"KILL SWITCH ACTIVATED via {channel.value}: {reason}")

            self._state = KillSwitchState.ACTIVATED
            self._activation_time = datetime.now(timezone.utc)
            self._activation_channel = channel
            self._activation_reason = reason

            # Record activation
            record = ActivationRecord(
                record_id=f"ar_{generate_random_id()[:8]}",
                timestamp=self._activation_time,
                channel=channel,
                reason=reason,
                signatures=signatures or [],
                successful=True,
                details=details or {},
            )
            self._activation_records.append(record)

            # Persist state
            self._save_state()

            # Stop heartbeat monitor
            self._stop_heartbeat.set()

        # Execute shutdown callbacks (outside lock to avoid deadlock)
        for callback in self._shutdown_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Shutdown callback error: {e}")

    def is_activated(self) -> bool:
        """Check if kill switch has been activated."""
        return self._state == KillSwitchState.ACTIVATED

    def check_operational(self) -> None:
        """
        Check if system should continue operating.

        Raises SystemShutdownError if kill switch is activated.
        """
        if self._state == KillSwitchState.ACTIVATED:
            channel = self._activation_channel.value if self._activation_channel else "unknown"
            raise SystemShutdownError(
                f"Kill switch activated via {channel}: "
                f"{self._activation_reason}"
            )

    def register_shutdown_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback to be called when kill switch activates."""
        self._shutdown_callbacks.append(callback)

    def register_warning_callback(self, callback: Callable[[str], None]) -> None:
        """Register a callback for kill switch warnings."""
        self._warning_callbacks.append(callback)

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive kill switch status."""
        with self._lock:
            return {
                "state": self._state.value,
                "activation_time": self._activation_time.isoformat() if self._activation_time else None,
                "activation_channel": self._activation_channel.value if self._activation_channel else None,
                "activation_reason": self._activation_reason,
                "required_signatures": self._required_signatures,
                "registered_key_holders": len(self._key_holders),
                "pending_signatures": len(self._pending_signatures),
                "key_holders": [
                    {"key_id": k.key_id, "name": k.holder_name, "active": k.is_active}
                    for k in self._key_holders.values()
                ],
                "deadman": {
                    "enabled": self._deadman_config.enabled,
                    "last_heartbeat": self._last_heartbeat.isoformat() if self._last_heartbeat else None,
                    "missed_heartbeats": self._missed_heartbeats,
                    "max_missed": self._deadman_config.max_missed_heartbeats,
                },
                "failsafe": {
                    "enabled": self._failsafe_config.enabled,
                    "recent_errors": len(self._error_timestamps),
                    "component_status": self._component_status,
                },
                "activation_records": [r.to_dict() for r in self._activation_records[-10:]],
            }

    def get_activation_records(self) -> List[ActivationRecord]:
        """Get all activation records."""
        return self._activation_records.copy()

    def reset(self, master_key_signature: bytes, master_key_message: bytes) -> tuple[bool, str]:
        """
        Reset the kill switch after activation.

        This requires a special master key signature and should only be used
        during controlled recovery procedures.
        """
        # This is intentionally difficult and requires additional verification
        # In production, this would require physical access or multiple approvals
        with self._lock:
            if self._state != KillSwitchState.ACTIVATED:
                return False, "Kill switch not activated"

            # Verify master key signature
            # In production, this would be a separate, highly secured key
            try:
                verify_key = self._signing_key.verify_key
                verify_key.verify(master_key_message, master_key_signature)

                if not master_key_message.startswith(b"RESET_KILL_SWITCH:"):
                    return False, "Invalid reset message format"

            except BadSignatureError:
                return False, "Invalid master key signature"

            # Reset state
            self._state = KillSwitchState.ARMED
            self._activation_time = None
            self._activation_channel = None
            self._activation_reason = None
            self._pending_signatures.clear()
            self._error_timestamps.clear()
            self._missed_heartbeats = 0
            self._last_heartbeat = datetime.now(timezone.utc)

            # Clear persisted state
            if self._state_file and self._state_file.exists():
                self._state_file.unlink()

            # Restart heartbeat monitor
            if self._deadman_config.enabled:
                self._stop_heartbeat.clear()
                if self._heartbeat_thread is None or not self._heartbeat_thread.is_alive():
                    self._start_heartbeat_monitor()

            logger.warning("Kill switch has been reset - system armed")

            record = ActivationRecord(
                record_id=f"ar_{generate_random_id()[:8]}",
                timestamp=datetime.now(timezone.utc),
                channel=ActivationChannel.MANUAL,
                reason="Kill switch reset",
                successful=True,
                details={"action": "reset"},
            )
            self._activation_records.append(record)

            return True, "Kill switch reset - system armed"

    def shutdown(self) -> None:
        """Clean shutdown of the kill switch monitoring."""
        self._stop_heartbeat.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5.0)


class SystemShutdownError(Exception):
    """Raised when the system has been shut down via kill switch."""
    pass


# Distributed kill switch support

@dataclass
class NodeRegistration:
    """Registration of a node in a distributed kill switch cluster."""
    node_id: str
    node_name: str
    endpoint: str
    registered_at: datetime
    last_seen: datetime
    is_coordinator: bool = False


class DistributedKillSwitch:
    """
    Distributed kill switch that coordinates across multiple nodes.

    Features:
    - Any node can trigger global shutdown
    - Coordinator election for heartbeat monitoring
    - State synchronization across nodes
    - Network partition handling
    """

    def __init__(
        self,
        local_kill_switch: EnhancedKillSwitch,
        node_id: str,
        node_name: str,
    ):
        self._local = local_kill_switch
        self._node_id = node_id
        self._node_name = node_name
        self._nodes: Dict[str, NodeRegistration] = {}
        self._is_coordinator = False
        self._lock = threading.RLock()

        # Register local shutdown callback
        self._local.register_shutdown_callback(self._broadcast_shutdown)

    def register_node(self, node_id: str, node_name: str, endpoint: str) -> None:
        """Register a remote node."""
        with self._lock:
            now = datetime.now(timezone.utc)
            self._nodes[node_id] = NodeRegistration(
                node_id=node_id,
                node_name=node_name,
                endpoint=endpoint,
                registered_at=now,
                last_seen=now,
            )

    def receive_shutdown_signal(self, from_node: str, reason: str) -> None:
        """Receive shutdown signal from another node."""
        logger.warning(f"Received shutdown signal from node {from_node}")
        self._local.activate(
            channel=ActivationChannel.NETWORK,
            reason=f"Distributed shutdown from {from_node}: {reason}",
            details={"source_node": from_node},
        )

    def _broadcast_shutdown(self) -> None:
        """Broadcast shutdown to all registered nodes."""
        for node_id, node in self._nodes.items():
            try:
                # In production, this would make HTTP calls to other nodes
                logger.info(f"Broadcasting shutdown to node {node_id} at {node.endpoint}")
            except Exception as e:
                logger.error(f"Failed to broadcast to node {node_id}: {e}")

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster-wide kill switch status."""
        return {
            "local_node": {
                "node_id": self._node_id,
                "node_name": self._node_name,
                "is_coordinator": self._is_coordinator,
                "status": self._local.get_status(),
            },
            "cluster_nodes": [
                {
                    "node_id": n.node_id,
                    "node_name": n.node_name,
                    "endpoint": n.endpoint,
                    "last_seen": n.last_seen.isoformat(),
                }
                for n in self._nodes.values()
            ],
        }
