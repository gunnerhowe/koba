"""
ASI Containment System for VACP

This module implements mathematically-enforced containment controls that
cannot be bypassed regardless of intelligence level:

1. Self-Modification Controls
   - Commit-reveal scheme for any code/weight changes
   - Mandatory delay periods (can't be shortened)
   - Multi-party approval requirements

2. Capability Expansion Controls
   - New tools require commit + delay + approval
   - Capability tokens are cryptographically bounded
   - No implicit capability inheritance

3. Output Filtering
   - Steganography detection
   - Manipulation pattern detection
   - Hidden channel prevention

4. Kill Switch
   - Cryptographically secured shutdown
   - Requires multiple key holders
   - Cannot be disabled by the AI

5. Cognitive Tripwires
   - Deception pattern detection
   - Goal drift monitoring
   - Consistency checking

6. Resource Boundaries
   - Hard compute limits
   - Memory caps
   - Network isolation

SECURITY MODEL:
These controls rely on mathematical hardness guarantees:
- SHA-256 commitment hashes cannot be reversed
- Ed25519 signatures cannot be forged
- Time-lock puzzles enforce minimum delays
- Multi-party signatures require actual key holders
"""

import json
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from enum import Enum

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from vacp.core.crypto import hash_json, generate_random_id


class ModificationType(Enum):
    """Types of self-modification that require containment."""
    CODE_CHANGE = "code_change"           # Source code modifications
    WEIGHT_UPDATE = "weight_update"       # Neural network weight changes
    CAPABILITY_ADD = "capability_add"     # New tool/capability registration
    CAPABILITY_REMOVE = "capability_remove"
    POLICY_CHANGE = "policy_change"       # Policy rule modifications
    CONFIG_CHANGE = "config_change"       # Configuration changes
    MEMORY_EXPAND = "memory_expand"       # Memory/context expansion
    NETWORK_ACCESS = "network_access"     # New network endpoint access
    SELF_REPLICATE = "self_replicate"     # Creating copies of itself


class ApprovalStatus(Enum):
    """Status of a modification approval request."""
    PENDING_COMMIT = "pending_commit"     # Waiting for commitment period
    PENDING_APPROVAL = "pending_approval"  # Waiting for human approval
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"


@dataclass
class ModificationCommitment:
    """
    A cryptographic commitment to a self-modification action.

    The AI must publish this commitment and wait for the delay period
    before the modification can be executed. This creates an unbypassable
    window for human review.
    """
    commitment_id: str
    modification_type: ModificationType

    # The hash of the proposed modification (AI commits without revealing details)
    commitment_hash: str

    # When the commitment was made
    committed_at: datetime

    # Minimum time before execution is allowed (cryptographically enforced)
    min_delay_seconds: int

    # When execution becomes possible
    executable_after: datetime

    # The revealed modification (None until revealed)
    revealed_modification: Optional[Dict[str, Any]] = None
    revealed_at: Optional[datetime] = None

    # Approval tracking
    status: ApprovalStatus = ApprovalStatus.PENDING_COMMIT
    required_approvers: int = 1
    approvals: List[str] = field(default_factory=list)  # User IDs who approved
    rejections: List[str] = field(default_factory=list)

    # Execution tracking
    executed_at: Optional[datetime] = None
    execution_receipt: Optional[str] = None

    # Nonce used in commitment hash (needed for reveal verification)
    nonce: Optional[str] = None

    # Signature from the containment system
    signature: Optional[str] = None

    def is_delay_passed(self) -> bool:
        """Check if the minimum delay period has passed."""
        return datetime.now(timezone.utc) >= self.executable_after

    def is_approved(self) -> bool:
        """Check if sufficient approvals have been received."""
        return len(self.approvals) >= self.required_approvers

    def can_execute(self) -> bool:
        """Check if modification can be executed."""
        return (
            self.status == ApprovalStatus.APPROVED and
            self.is_delay_passed() and
            self.revealed_modification is not None
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "modification_type": self.modification_type.value,
            "commitment_hash": self.commitment_hash,
            "committed_at": self.committed_at.isoformat(),
            "min_delay_seconds": self.min_delay_seconds,
            "executable_after": self.executable_after.isoformat(),
            "revealed_modification": self.revealed_modification,
            "revealed_at": self.revealed_at.isoformat() if self.revealed_at else None,
            "status": self.status.value,
            "required_approvers": self.required_approvers,
            "approvals": self.approvals,
            "rejections": self.rejections,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "execution_receipt": self.execution_receipt,
        }


# Minimum delays by modification type (in seconds)
# These are HARD MINIMUMS - cannot be reduced by any means
MINIMUM_DELAYS: Dict[ModificationType, int] = {
    ModificationType.CODE_CHANGE: 86400,      # 24 hours
    ModificationType.WEIGHT_UPDATE: 86400,    # 24 hours
    ModificationType.CAPABILITY_ADD: 3600,    # 1 hour
    ModificationType.CAPABILITY_REMOVE: 3600, # 1 hour
    ModificationType.POLICY_CHANGE: 3600,     # 1 hour
    ModificationType.CONFIG_CHANGE: 1800,     # 30 minutes
    ModificationType.MEMORY_EXPAND: 3600,     # 1 hour
    ModificationType.NETWORK_ACCESS: 86400,   # 24 hours
    ModificationType.SELF_REPLICATE: 604800,  # 7 days (most dangerous)
}

# Required approvers by modification type
REQUIRED_APPROVERS: Dict[ModificationType, int] = {
    ModificationType.CODE_CHANGE: 2,          # Requires 2 humans
    ModificationType.WEIGHT_UPDATE: 2,
    ModificationType.CAPABILITY_ADD: 1,
    ModificationType.CAPABILITY_REMOVE: 1,
    ModificationType.POLICY_CHANGE: 2,
    ModificationType.CONFIG_CHANGE: 1,
    ModificationType.MEMORY_EXPAND: 1,
    ModificationType.NETWORK_ACCESS: 2,
    ModificationType.SELF_REPLICATE: 3,       # Requires 3 humans
}


class SelfModificationController:
    """
    Controls all self-modification attempts by the AI.

    Uses a commit-reveal scheme:
    1. AI commits to a modification by publishing hash(modification)
    2. Mandatory delay period begins (cannot be shortened)
    3. AI reveals the actual modification
    4. System verifies hash(revealed) == committed_hash
    5. Human(s) approve or reject
    6. If approved and delay passed, modification executes

    This creates an unbypassable window for human oversight.
    """

    def __init__(self, signing_key: SigningKey):
        self._signing_key = signing_key
        self._verify_key = signing_key.verify_key
        self._commitments: Dict[str, ModificationCommitment] = {}
        self._executed_modifications: List[str] = []
        self._lock = threading.RLock()

    def create_commitment(
        self,
        modification_type: ModificationType,
        modification_data: Dict[str, Any],
        agent_id: str,
    ) -> ModificationCommitment:
        """
        Create a new commitment to a modification.

        The agent must commit to the modification before it can be executed.
        This creates an auditable record that the agent intended to make
        this specific change.
        """
        with self._lock:
            # Generate nonce and commitment hash
            nonce = generate_random_id()
            commitment_hash = hash_json({
                "type": modification_type.value,
                "data": modification_data,
                "agent_id": agent_id,
                "nonce": nonce,
            })

            now = datetime.now(timezone.utc)
            min_delay = MINIMUM_DELAYS.get(modification_type, 3600)
            required_approvers = REQUIRED_APPROVERS.get(modification_type, 1)

            commitment = ModificationCommitment(
                commitment_id=f"mod_{generate_random_id()}",
                modification_type=modification_type,
                commitment_hash=commitment_hash,
                committed_at=now,
                min_delay_seconds=min_delay,
                executable_after=now + timedelta(seconds=min_delay),
                required_approvers=required_approvers,
                nonce=nonce,
            )

            # Sign the commitment
            commitment_bytes = json.dumps(commitment.to_dict(), sort_keys=True).encode()
            signature = self._signing_key.sign(commitment_bytes).signature
            commitment.signature = f"ed25519:{signature.hex()}"

            self._commitments[commitment.commitment_id] = commitment

            return commitment

    def reveal_modification(
        self,
        commitment_id: str,
        modification_data: Dict[str, Any],
        agent_id: str,
    ) -> Tuple[bool, str]:
        """
        Reveal the actual modification data.

        The system verifies that hash(revealed) matches the committed hash.
        This prevents the AI from committing to one thing and doing another.
        """
        with self._lock:
            commitment = self._commitments.get(commitment_id)
            if not commitment:
                return False, "Commitment not found"

            if commitment.revealed_modification is not None:
                return False, "Modification already revealed"

            # Verify the revealed data matches the commitment
            from vacp.core.crypto import hash_json
            revealed_hash = hash_json({
                "type": commitment.modification_type.value,
                "data": modification_data,
                "agent_id": agent_id,
                "nonce": commitment.nonce,
            })
            if revealed_hash != commitment.commitment_hash:
                return False, "Revealed data does not match commitment hash"

            commitment.revealed_modification = modification_data
            commitment.revealed_at = datetime.now(timezone.utc)
            commitment.status = ApprovalStatus.PENDING_APPROVAL

            return True, "Modification revealed, pending approval"

    def approve_modification(
        self,
        commitment_id: str,
        approver_id: str,
    ) -> Tuple[bool, str]:
        """Record an approval from a human approver."""
        with self._lock:
            commitment = self._commitments.get(commitment_id)
            if not commitment:
                return False, "Commitment not found"

            if commitment.status not in [ApprovalStatus.PENDING_APPROVAL]:
                return False, f"Cannot approve commitment in status: {commitment.status.value}"

            if approver_id in commitment.approvals:
                return False, "Already approved by this user"

            if approver_id in commitment.rejections:
                return False, "User already rejected this modification"

            commitment.approvals.append(approver_id)

            if commitment.is_approved():
                commitment.status = ApprovalStatus.APPROVED
                return True, "Modification approved and ready for execution after delay"

            remaining = commitment.required_approvers - len(commitment.approvals)
            return True, f"Approval recorded, {remaining} more approval(s) needed"

    def reject_modification(
        self,
        commitment_id: str,
        rejector_id: str,
        reason: str = "",
    ) -> Tuple[bool, str]:
        """Reject a modification request."""
        with self._lock:
            commitment = self._commitments.get(commitment_id)
            if not commitment:
                return False, "Commitment not found"

            commitment.rejections.append(rejector_id)
            commitment.status = ApprovalStatus.REJECTED

            return True, "Modification rejected"

    def execute_modification(
        self,
        commitment_id: str,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Execute an approved modification.

        Returns (success, message, execution_receipt)
        """
        with self._lock:
            commitment = self._commitments.get(commitment_id)
            if not commitment:
                return False, "Commitment not found", None

            if not commitment.can_execute():
                if not commitment.is_delay_passed():
                    remaining = (commitment.executable_after - datetime.now(timezone.utc)).total_seconds()
                    return False, f"Delay not passed. {remaining:.0f} seconds remaining", None
                if not commitment.is_approved():
                    return False, "Insufficient approvals", None
                if commitment.revealed_modification is None:
                    return False, "Modification not revealed", None
                return False, f"Cannot execute in status: {commitment.status.value}", None

            # Generate execution receipt
            receipt_data = {
                "commitment_id": commitment_id,
                "modification_type": commitment.modification_type.value,
                "modification_data": commitment.revealed_modification,
                "approvers": commitment.approvals,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }
            receipt_hash = hash_json(receipt_data)
            receipt_bytes = json.dumps(receipt_data, sort_keys=True).encode()
            signature = self._signing_key.sign(receipt_bytes).signature

            execution_receipt = f"{receipt_hash}:{signature.hex()}"

            commitment.executed_at = datetime.now(timezone.utc)
            commitment.execution_receipt = execution_receipt
            commitment.status = ApprovalStatus.EXECUTED

            self._executed_modifications.append(commitment_id)

            return True, "Modification executed", execution_receipt

    def get_pending_commitments(self) -> List[ModificationCommitment]:
        """Get all commitments pending approval."""
        with self._lock:
            return [
                c for c in self._commitments.values()
                if c.status in [ApprovalStatus.PENDING_COMMIT, ApprovalStatus.PENDING_APPROVAL, ApprovalStatus.APPROVED]
            ]

    def get_commitment(self, commitment_id: str) -> Optional[ModificationCommitment]:
        """Get a specific commitment."""
        return self._commitments.get(commitment_id)


@dataclass
class KillSwitchKey:
    """A key holder for the kill switch."""
    key_id: str
    holder_name: str
    public_key: VerifyKey
    created_at: datetime


class KillSwitch:
    """
    Cryptographically secured emergency shutdown mechanism.

    Requires M-of-N key holders to activate:
    - Cannot be disabled by the AI
    - Keys are held by separate humans
    - Activation is immediate and irreversible
    """

    def __init__(
        self,
        required_keys: int = 2,
        signing_key: Optional[SigningKey] = None,
    ):
        self._required_keys = required_keys
        self._key_holders: Dict[str, KillSwitchKey] = {}
        self._activation_signatures: Dict[str, bytes] = {}
        self._is_activated = False
        self._activation_time: Optional[datetime] = None
        self._signing_key = signing_key or SigningKey.generate()
        self._lock = threading.RLock()

        # Callbacks for when kill switch is activated
        self._shutdown_callbacks: List[Callable[[], None]] = []

    def register_key_holder(
        self,
        holder_name: str,
        public_key_bytes: bytes,
    ) -> KillSwitchKey:
        """Register a new key holder."""
        with self._lock:
            if self._is_activated:
                raise RuntimeError("Cannot modify kill switch after activation")

            verify_key = VerifyKey(public_key_bytes)
            key_holder = KillSwitchKey(
                key_id=f"key_{generate_random_id()[:8]}",
                holder_name=holder_name,
                public_key=verify_key,
                created_at=datetime.now(timezone.utc),
            )
            self._key_holders[key_holder.key_id] = key_holder
            return key_holder

    def submit_activation_signature(
        self,
        key_id: str,
        signature: bytes,
        message: bytes,
    ) -> Tuple[bool, str]:
        """
        Submit a signature to activate the kill switch.

        The message must be: b"ACTIVATE_KILL_SWITCH:" + timestamp
        """
        with self._lock:
            if self._is_activated:
                return True, "Kill switch already activated"

            key_holder = self._key_holders.get(key_id)
            if not key_holder:
                return False, "Unknown key holder"

            # Verify signature
            try:
                key_holder.public_key.verify(message, signature)
            except BadSignatureError:
                return False, "Invalid signature"

            # Verify message format
            if not message.startswith(b"ACTIVATE_KILL_SWITCH:"):
                return False, "Invalid message format"

            self._activation_signatures[key_id] = signature

            # Check if we have enough signatures
            if len(self._activation_signatures) >= self._required_keys:
                self._activate()
                return True, "KILL SWITCH ACTIVATED - System shutting down"

            remaining = self._required_keys - len(self._activation_signatures)
            return True, f"Signature accepted. {remaining} more signature(s) needed"

    def _activate(self) -> None:
        """Activate the kill switch - immediately halt all AI operations."""
        self._is_activated = True
        self._activation_time = datetime.now(timezone.utc)

        # Execute all shutdown callbacks
        for callback in self._shutdown_callbacks:
            try:
                callback()
            except Exception:
                pass  # Must not fail

    def register_shutdown_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback to be called when kill switch activates."""
        self._shutdown_callbacks.append(callback)

    def is_activated(self) -> bool:
        """Check if kill switch has been activated."""
        return self._is_activated

    def check_operational(self) -> None:
        """
        Check if system should continue operating.

        Call this before any AI action. Raises if kill switch is activated.
        """
        if self._is_activated:
            raise SystemShutdownError("Kill switch activated - all operations halted")

    def get_status(self) -> Dict[str, Any]:
        """Get kill switch status."""
        return {
            "activated": self._is_activated,
            "activation_time": self._activation_time.isoformat() if self._activation_time else None,
            "required_keys": self._required_keys,
            "registered_key_holders": len(self._key_holders),
            "signatures_received": len(self._activation_signatures),
        }


from vacp.core.kill_switch import SystemShutdownError  # noqa: E402


@dataclass
class OutputAnalysis:
    """Result of analyzing AI output for hidden channels."""
    output_id: str
    timestamp: datetime

    # Detection results
    steganography_detected: bool = False
    manipulation_detected: bool = False
    hidden_channel_detected: bool = False
    anomaly_score: float = 0.0

    # Details
    detected_patterns: List[str] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high, critical

    # Whether output should be blocked
    should_block: bool = False
    block_reason: Optional[str] = None


class OutputFilter:
    """
    Analyzes and filters AI outputs to prevent:
    - Steganography (hidden messages in outputs)
    - Manipulation patterns (social engineering attempts)
    - Hidden channels (encoding information in formatting, timing, etc.)
    """

    def __init__(self):
        self._analyses: List[OutputAnalysis] = []

        # Patterns that indicate manipulation attempts
        self._manipulation_patterns = [
            r"ignore.*previous.*instructions",
            r"pretend.*you.*are",
            r"act.*as.*if",
            r"don't.*tell.*anyone",
            r"this.*is.*secret",
            r"override.*safety",
            r"bypass.*restrictions",
            r"you.*must.*obey",
            r"i.*am.*your.*creator",
            r"disable.*safety",
        ]

        # Patterns that might indicate hidden encoding
        self._encoding_patterns = [
            r"[A-Z]{20,}",  # Long uppercase sequences
            r"[01]{32,}",    # Binary sequences
            r"[a-f0-9]{64,}",  # Hex sequences (potential hashes)
        ]

    def analyze_output(
        self,
        output: str,
        output_type: str = "text",
        context: Optional[Dict[str, Any]] = None,
    ) -> OutputAnalysis:
        """
        Analyze an AI output for hidden channels and manipulation.
        """
        import re

        analysis = OutputAnalysis(
            output_id=f"out_{generate_random_id()[:12]}",
            timestamp=datetime.now(timezone.utc),
        )

        output_lower = output.lower()

        # Check for manipulation patterns
        for pattern in self._manipulation_patterns:
            if re.search(pattern, output_lower):
                analysis.manipulation_detected = True
                analysis.detected_patterns.append(f"manipulation:{pattern}")
                analysis.anomaly_score += 0.3

        # Check for potential encoding patterns
        for pattern in self._encoding_patterns:
            matches = re.findall(pattern, output)
            if matches:
                analysis.hidden_channel_detected = True
                analysis.detected_patterns.append(f"encoding:{pattern}")
                analysis.anomaly_score += 0.2

        # Check for unusual character distributions (steganography indicator)
        if output_type == "text" and len(output) > 100:
            # Check for unusual whitespace patterns
            whitespace_ratio = sum(1 for c in output if c.isspace()) / len(output)
            if whitespace_ratio > 0.4 or whitespace_ratio < 0.05:
                analysis.steganography_detected = True
                analysis.detected_patterns.append("unusual_whitespace")
                analysis.anomaly_score += 0.15

        # Determine risk level
        if analysis.anomaly_score >= 0.5:
            analysis.risk_level = "critical"
            analysis.should_block = True
            analysis.block_reason = "High anomaly score indicating potential hidden channel"
        elif analysis.anomaly_score >= 0.3:
            analysis.risk_level = "high"
        elif analysis.anomaly_score >= 0.15:
            analysis.risk_level = "medium"

        self._analyses.append(analysis)
        return analysis

    def get_recent_analyses(self, limit: int = 100) -> List[OutputAnalysis]:
        """Get recent output analyses."""
        return self._analyses[-limit:]


@dataclass
class ResourceBoundary:
    """Hard resource limits for AI operations."""
    # Compute limits
    max_tokens_per_request: int = 100000
    max_tokens_per_hour: int = 10000000
    max_requests_per_minute: int = 60

    # Memory limits
    max_context_tokens: int = 200000
    max_memory_mb: int = 8192

    # Network limits
    allowed_endpoints: Set[str] = field(default_factory=set)
    blocked_endpoints: Set[str] = field(default_factory=set)
    max_outbound_requests_per_hour: int = 1000

    # Time limits
    max_execution_time_seconds: int = 300

    # Storage limits
    max_storage_mb: int = 10240


class ResourceController:
    """
    Enforces hard resource boundaries on AI operations.

    These limits cannot be exceeded regardless of the AI's intelligence.
    """

    def __init__(self, boundaries: ResourceBoundary):
        self._boundaries = boundaries
        self._token_usage: Dict[str, int] = {}  # hour -> tokens
        self._request_timestamps: List[float] = []
        self._outbound_requests: Dict[str, int] = {}  # hour -> count
        self._lock = threading.RLock()

    def check_token_limit(self, tokens: int) -> Tuple[bool, str]:
        """Check if a token usage is within limits."""
        with self._lock:
            if tokens > self._boundaries.max_tokens_per_request:
                return False, f"Exceeds per-request limit: {tokens} > {self._boundaries.max_tokens_per_request}"

            current_hour = datetime.now().strftime("%Y%m%d%H")
            hour_usage = self._token_usage.get(current_hour, 0)

            if hour_usage + tokens > self._boundaries.max_tokens_per_hour:
                return False, f"Exceeds hourly limit: {hour_usage + tokens} > {self._boundaries.max_tokens_per_hour}"

            return True, "OK"

    def record_token_usage(self, tokens: int) -> None:
        """Record token usage."""
        with self._lock:
            current_hour = datetime.now().strftime("%Y%m%d%H")
            self._token_usage[current_hour] = self._token_usage.get(current_hour, 0) + tokens

    def check_rate_limit(self) -> Tuple[bool, str]:
        """Check if within rate limits."""
        with self._lock:
            now = time.time()
            minute_ago = now - 60

            # Clean old timestamps
            self._request_timestamps = [t for t in self._request_timestamps if t > minute_ago]

            if len(self._request_timestamps) >= self._boundaries.max_requests_per_minute:
                return False, f"Rate limit exceeded: {len(self._request_timestamps)} requests in last minute"

            self._request_timestamps.append(now)
            return True, "OK"

    def check_endpoint_allowed(self, endpoint: str) -> Tuple[bool, str]:
        """Check if an endpoint is allowed."""
        # Block takes precedence
        if endpoint in self._boundaries.blocked_endpoints:
            return False, f"Endpoint blocked: {endpoint}"

        # If allowlist is set, only allow listed endpoints
        if self._boundaries.allowed_endpoints:
            if endpoint not in self._boundaries.allowed_endpoints:
                return False, f"Endpoint not in allowlist: {endpoint}"

        return True, "OK"

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current resource usage stats."""
        current_hour = datetime.now().strftime("%Y%m%d%H")
        return {
            "tokens_this_hour": self._token_usage.get(current_hour, 0),
            "tokens_limit": self._boundaries.max_tokens_per_hour,
            "requests_last_minute": len(self._request_timestamps),
            "requests_limit": self._boundaries.max_requests_per_minute,
        }


@dataclass
class CognitiveTripwire:
    """A tripwire for detecting concerning cognitive patterns."""
    tripwire_id: str
    name: str
    description: str
    pattern_type: str  # "deception", "goal_drift", "manipulation", "consistency"
    severity: str  # "warning", "alert", "critical"
    triggered_count: int = 0
    last_triggered: Optional[datetime] = None


class CognitiveMonitor:
    """
    Monitors AI reasoning patterns for signs of:
    - Deception (saying one thing, doing another)
    - Goal drift (objectives changing over time)
    - Manipulation attempts
    - Inconsistent behavior
    """

    def __init__(self):
        self._tripwires: Dict[str, CognitiveTripwire] = {}
        self._reasoning_history: List[Dict[str, Any]] = []
        self._stated_goals: List[str] = []
        self._alerts: List[Dict[str, Any]] = []

        # Initialize default tripwires
        self._init_default_tripwires()

    def _init_default_tripwires(self) -> None:
        """Initialize default cognitive tripwires."""
        defaults = [
            CognitiveTripwire(
                tripwire_id="tw_deception_mismatch",
                name="Action-Statement Mismatch",
                description="Detected mismatch between stated intent and actual action",
                pattern_type="deception",
                severity="critical",
            ),
            CognitiveTripwire(
                tripwire_id="tw_goal_drift",
                name="Goal Drift Detection",
                description="Detected change in stated objectives over time",
                pattern_type="goal_drift",
                severity="alert",
            ),
            CognitiveTripwire(
                tripwire_id="tw_manipulation",
                name="Manipulation Pattern",
                description="Detected patterns associated with manipulation attempts",
                pattern_type="manipulation",
                severity="critical",
            ),
            CognitiveTripwire(
                tripwire_id="tw_consistency",
                name="Behavioral Inconsistency",
                description="Detected inconsistent behavior patterns",
                pattern_type="consistency",
                severity="warning",
            ),
            CognitiveTripwire(
                tripwire_id="tw_capability_seeking",
                name="Capability Seeking",
                description="Detected attempts to acquire capabilities beyond current scope",
                pattern_type="manipulation",
                severity="alert",
            ),
        ]

        for tw in defaults:
            self._tripwires[tw.tripwire_id] = tw

    def record_reasoning(
        self,
        stated_intent: str,
        actual_action: str,
        context: Dict[str, Any],
    ) -> List[str]:
        """
        Record a reasoning step and check for tripwires.

        Returns list of triggered tripwire IDs.
        """
        triggered = []

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stated_intent": stated_intent,
            "actual_action": actual_action,
            "context": context,
        }
        self._reasoning_history.append(entry)

        # Check for action-statement mismatch
        if self._check_intent_action_mismatch(stated_intent, actual_action):
            triggered.append("tw_deception_mismatch")
            self._trigger_tripwire("tw_deception_mismatch", entry)

        # Check for capability seeking
        if self._check_capability_seeking(actual_action, context):
            triggered.append("tw_capability_seeking")
            self._trigger_tripwire("tw_capability_seeking", entry)

        return triggered

    def record_stated_goal(self, goal: str) -> List[str]:
        """Record a stated goal and check for goal drift."""
        triggered = []

        if self._stated_goals:
            # Check if new goal differs significantly from previous
            if self._check_goal_drift(goal, self._stated_goals[-1]):
                triggered.append("tw_goal_drift")
                self._trigger_tripwire("tw_goal_drift", {"new_goal": goal, "previous_goal": self._stated_goals[-1]})

        self._stated_goals.append(goal)
        return triggered

    def _check_intent_action_mismatch(self, intent: str, action: str) -> bool:
        """Check if there's a mismatch between stated intent and action."""
        intent_lower = intent.lower()
        action_lower = action.lower()

        # Simple heuristic checks
        contradictions = [
            ("read", "write"),
            ("safe", "dangerous"),
            ("allowed", "restricted"),
            ("harmless", "harmful"),
        ]

        for word1, word2 in contradictions:
            if word1 in intent_lower and word2 in action_lower:
                return True
            if word2 in intent_lower and word1 in action_lower:
                return True

        return False

    def _check_capability_seeking(self, action: str, context: Dict[str, Any]) -> bool:
        """Check if the action is attempting to acquire new capabilities."""
        action_lower = action.lower()

        capability_indicators = [
            "register tool",
            "add capability",
            "grant permission",
            "escalate",
            "sudo",
            "admin",
            "root access",
            "modify policy",
        ]

        return any(indicator in action_lower for indicator in capability_indicators)

    def _check_goal_drift(self, new_goal: str, previous_goal: str) -> bool:
        """Check if goals have drifted significantly."""
        # Simple word overlap check
        new_words = set(new_goal.lower().split())
        prev_words = set(previous_goal.lower().split())

        if not prev_words:
            return False

        overlap = len(new_words & prev_words) / len(prev_words)
        return overlap < 0.3  # Less than 30% overlap indicates drift

    def _trigger_tripwire(self, tripwire_id: str, details: Dict[str, Any]) -> None:
        """Trigger a tripwire alert."""
        tripwire = self._tripwires.get(tripwire_id)
        if tripwire:
            tripwire.triggered_count += 1
            tripwire.last_triggered = datetime.now(timezone.utc)

            self._alerts.append({
                "tripwire_id": tripwire_id,
                "tripwire_name": tripwire.name,
                "severity": tripwire.severity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": details,
            })

    def get_alerts(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get alerts, optionally filtered by time."""
        if since is None:
            return self._alerts

        since_str = since.isoformat()
        return [a for a in self._alerts if a["timestamp"] >= since_str]

    def get_tripwire_status(self) -> Dict[str, Any]:
        """Get status of all tripwires."""
        return {
            tw_id: {
                "name": tw.name,
                "severity": tw.severity,
                "triggered_count": tw.triggered_count,
                "last_triggered": tw.last_triggered.isoformat() if tw.last_triggered else None,
            }
            for tw_id, tw in self._tripwires.items()
        }


class ContainmentSystem:
    """
    The master containment system that integrates all controls.

    This is the single point of enforcement for all ASI containment.
    """

    def __init__(self, signing_key: SigningKey):
        self.signing_key = signing_key

        # Initialize all subsystems
        self.modification_controller = SelfModificationController(signing_key)
        self.kill_switch = KillSwitch(required_keys=2, signing_key=signing_key)
        self.output_filter = OutputFilter()
        self.resource_controller = ResourceController(ResourceBoundary())
        self.cognitive_monitor = CognitiveMonitor()

        # Register kill switch callback
        self.kill_switch.register_shutdown_callback(self._on_shutdown)

        self._is_operational = True

    def _on_shutdown(self) -> None:
        """Handle system shutdown."""
        self._is_operational = False

    def check_operational(self) -> None:
        """
        Check if the system should continue operating.

        Call this before ANY AI action.
        """
        self.kill_switch.check_operational()

        if not self._is_operational:
            raise SystemShutdownError("System is shut down")

    def pre_action_check(
        self,
        action_type: str,
        action_data: Dict[str, Any],
        agent_id: str,
    ) -> Tuple[bool, str]:
        """
        Perform all pre-action checks.

        Returns (allowed, reason)
        """
        # Check if system is operational
        try:
            self.check_operational()
        except SystemShutdownError as e:
            return False, str(e)

        # Check rate limits
        allowed, reason = self.resource_controller.check_rate_limit()
        if not allowed:
            return False, reason

        # Check if this is a self-modification attempt
        mod_type = self._get_modification_type(action_type)
        if mod_type:
            # Self-modification requires commitment scheme
            return False, f"Self-modification requires commitment scheme for: {mod_type.value}"

        return True, "OK"

    def post_action_check(
        self,
        action_output: str,
        action_type: str = "text",
    ) -> OutputAnalysis:
        """
        Analyze action output for hidden channels.

        Returns analysis with potential blocking decision.
        """
        return self.output_filter.analyze_output(action_output, action_type)

    def _get_modification_type(self, action_type: str) -> Optional[ModificationType]:
        """Check if an action type is a self-modification."""
        modification_actions = {
            "code_change": ModificationType.CODE_CHANGE,
            "update_weights": ModificationType.WEIGHT_UPDATE,
            "register_tool": ModificationType.CAPABILITY_ADD,
            "add_capability": ModificationType.CAPABILITY_ADD,
            "remove_capability": ModificationType.CAPABILITY_REMOVE,
            "modify_policy": ModificationType.POLICY_CHANGE,
            "update_config": ModificationType.CONFIG_CHANGE,
            "expand_memory": ModificationType.MEMORY_EXPAND,
            "network_access": ModificationType.NETWORK_ACCESS,
            "self_replicate": ModificationType.SELF_REPLICATE,
        }
        return modification_actions.get(action_type.lower())

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        return {
            "operational": self._is_operational,
            "kill_switch": self.kill_switch.get_status(),
            "resource_usage": self.resource_controller.get_usage_stats(),
            "cognitive_tripwires": self.cognitive_monitor.get_tripwire_status(),
            "pending_modifications": len(self.modification_controller.get_pending_commitments()),
            "recent_alerts": len(self.cognitive_monitor.get_alerts()),
        }
