"""
Anomaly Tripwire for VACP

This module implements sequence anomaly detection for agent action patterns.
It does NOT try to judge semantic truth or intent - it detects PATTERNS
that deviate from learned baselines.

Detection methods:
1. Echo State Network (ESN) for temporal sequence modeling
2. Statistical anomaly detection on action graphs
3. Rate/tempo anomaly detection
4. Entropy-based detection

When anomalies are detected, the tripwire can trigger:
- Stricter policy tiers
- Read-only mode
- Human approval requirements
- Session quarantine
"""

import math
import random
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import hashlib

from vacp.core.crypto import generate_random_id


class TripwireAction(Enum):
    """Actions that can be triggered by the tripwire."""
    LOG_ONLY = "log_only"                  # Just log, no enforcement
    INCREASE_SCRUTINY = "increase_scrutiny"  # More detailed logging
    REQUIRE_APPROVAL = "require_approval"    # Require human approval
    READ_ONLY_MODE = "read_only_mode"        # Block all writes
    THROTTLE = "throttle"                    # Rate limit actions
    QUARANTINE = "quarantine"                # Block all actions


class AnomalyType(Enum):
    """Types of anomalies detected."""
    SEQUENCE = "sequence"          # Unusual action sequence
    RATE = "rate"                  # Unusual action rate
    ENTROPY = "entropy"            # Unusual entropy in actions
    ESCALATION = "escalation"      # Privilege escalation pattern
    EXFILTRATION = "exfiltration"  # Data exfiltration pattern
    INJECTION = "injection"        # Possible injection pattern


@dataclass
class AnomalyEvent:
    """A detected anomaly event."""
    event_id: str
    anomaly_type: AnomalyType
    session_id: str
    agent_id: str
    timestamp: datetime
    score: float  # 0-1, higher = more anomalous
    confidence: float  # 0-1, confidence in detection
    description: str
    triggered_action: TripwireAction
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "anomaly_type": self.anomaly_type.value,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.isoformat(),
            "score": self.score,
            "confidence": self.confidence,
            "description": self.description,
            "triggered_action": self.triggered_action.value,
            "context": self.context,
        }


@dataclass
class ActionEvent:
    """An action event for sequence analysis."""
    action_id: str
    tool_name: str
    session_id: str
    agent_id: str
    timestamp: datetime
    success: bool
    parameters_hash: str
    response_size: int = 0
    execution_time_ms: float = 0

    def to_vector(self, tool_vocab: Dict[str, int]) -> List[float]:
        """Convert action to feature vector."""
        tool_idx = tool_vocab.get(self.tool_name, 0)
        tool_one_hot = [0.0] * len(tool_vocab)
        if tool_idx < len(tool_one_hot):
            tool_one_hot[tool_idx] = 1.0

        return tool_one_hot + [
            1.0 if self.success else 0.0,
            min(1.0, self.response_size / 10000),  # Normalize
            min(1.0, self.execution_time_ms / 10000),
        ]


class EchoStateNetwork:
    """
    Echo State Network for sequence anomaly detection.

    The ESN learns typical action patterns and flags deviations.
    It does NOT try to predict semantic content - only patterns.
    """

    def __init__(
        self,
        input_size: int,
        reservoir_size: int = 100,
        spectral_radius: float = 0.9,
        input_scaling: float = 0.5,
        leak_rate: float = 0.3,
        seed: Optional[int] = None,
    ):
        """
        Initialize the Echo State Network.

        Args:
            input_size: Dimension of input vectors
            reservoir_size: Size of the reservoir
            spectral_radius: Spectral radius of reservoir weights
            input_scaling: Scaling for input weights
            leak_rate: Leak rate for state updates
            seed: Random seed for reproducibility
        """
        self.input_size = input_size
        self.reservoir_size = reservoir_size
        self.spectral_radius = spectral_radius
        self.input_scaling = input_scaling
        self.leak_rate = leak_rate

        if seed is not None:
            random.seed(seed)

        # Initialize weights
        self.W_in = self._init_input_weights()
        self.W_res = self._init_reservoir_weights()

        # Reservoir state
        self.state = [0.0] * reservoir_size

        # Output weights (learned)
        self.W_out: Optional[List[List[float]]] = None

        # Training data
        self._training_states: List[List[float]] = []
        self._training_targets: List[List[float]] = []

    def _init_input_weights(self) -> List[List[float]]:
        """Initialize input-to-reservoir weights."""
        return [
            [random.uniform(-1, 1) * self.input_scaling for _ in range(self.input_size)]
            for _ in range(self.reservoir_size)
        ]

    def _init_reservoir_weights(self) -> List[List[float]]:
        """Initialize reservoir weights with desired spectral radius."""
        # Sparse random matrix
        density = 0.1
        W = [[0.0] * self.reservoir_size for _ in range(self.reservoir_size)]

        for i in range(self.reservoir_size):
            for j in range(self.reservoir_size):
                if random.random() < density:
                    W[i][j] = random.uniform(-1, 1)

        # Scale to desired spectral radius (simplified)
        max_val = max(max(abs(w) for w in row) for row in W) or 1.0
        scale = self.spectral_radius / max_val

        return [[w * scale for w in row] for row in W]

    def update(self, input_vec: List[float]) -> List[float]:
        """
        Update reservoir state with new input.

        Args:
            input_vec: Input vector

        Returns:
            New reservoir state
        """
        # Compute input contribution
        u = [0.0] * self.reservoir_size
        for i in range(self.reservoir_size):
            for j in range(min(len(input_vec), self.input_size)):
                u[i] += self.W_in[i][j] * input_vec[j]

        # Compute reservoir contribution
        r = [0.0] * self.reservoir_size
        for i in range(self.reservoir_size):
            for j in range(self.reservoir_size):
                r[i] += self.W_res[i][j] * self.state[j]

        # Update state with leak
        new_state = []
        for i in range(self.reservoir_size):
            pre_activation = u[i] + r[i]
            activated = math.tanh(pre_activation)
            new_val = (1 - self.leak_rate) * self.state[i] + self.leak_rate * activated
            new_state.append(new_val)

        self.state = new_state
        return new_state

    def collect_state(self, input_vec: List[float], target: List[float]) -> None:
        """Collect state for training."""
        state = self.update(input_vec)
        self._training_states.append(state.copy())
        self._training_targets.append(target)

    def train(self, regularization: float = 1e-6) -> None:
        """
        Train output weights using collected states.

        Uses ridge regression for regularization.
        """
        if not self._training_states:
            return

        # Simple ridge regression
        n = len(self._training_states)
        d = self.reservoir_size
        out_dim = len(self._training_targets[0])

        # X^T X + lambda*I
        XtX = [[0.0] * d for _ in range(d)]
        for state in self._training_states:
            for i in range(d):
                for j in range(d):
                    XtX[i][j] += state[i] * state[j]
        for i in range(d):
            XtX[i][i] += regularization

        # X^T Y
        XtY = [[0.0] * out_dim for _ in range(d)]
        for k, state in enumerate(self._training_states):
            target = self._training_targets[k]
            for i in range(d):
                for j in range(out_dim):
                    XtY[i][j] += state[i] * target[j]

        # Solve (simplified - in production use numpy)
        # For now, just use the pseudo-inverse approximation
        self.W_out = XtY  # Simplified

        # Clear training data
        self._training_states = []
        self._training_targets = []

    def predict(self, input_vec: List[float]) -> Tuple[List[float], float]:
        """
        Make prediction and return anomaly score.

        Returns:
            Tuple of (predicted next state, anomaly score)
        """
        state = self.update(input_vec)

        if self.W_out is None:
            return input_vec, 0.0

        # Compute prediction
        out_dim = len(self.W_out[0])
        prediction = [0.0] * out_dim
        for i in range(self.reservoir_size):
            for j in range(out_dim):
                prediction[j] += state[i] * self.W_out[i][j]

        # Compute anomaly score (prediction error)
        error = 0.0
        for i in range(min(len(prediction), len(input_vec))):
            error += (prediction[i] - input_vec[i]) ** 2
        anomaly_score = min(1.0, math.sqrt(error / len(input_vec)))

        return prediction, anomaly_score

    def reset_state(self) -> None:
        """Reset reservoir state."""
        self.state = [0.0] * self.reservoir_size


class SequenceAnalyzer:
    """
    Analyzes action sequences for anomalies.

    Uses multiple detection methods:
    - ESN for temporal patterns
    - N-gram analysis for common patterns
    - Entropy analysis
    """

    def __init__(
        self,
        window_size: int = 50,
        ngram_sizes: Optional[List[int]] = None,
    ):
        """
        Initialize the sequence analyzer.

        Args:
            window_size: Size of analysis window
            ngram_sizes: N-gram sizes to track
        """
        self.window_size = window_size
        self.ngram_sizes = ngram_sizes or [2, 3, 4]

        # Per-session state
        self._session_windows: Dict[str, deque] = {}
        self._session_esns: Dict[str, EchoStateNetwork] = {}

        # Global patterns (learned from all sessions)
        self._ngram_counts: Dict[int, Dict[str, int]] = {n: {} for n in self.ngram_sizes}
        self._total_actions = 0

        # Tool vocabulary
        self._tool_vocab: Dict[str, int] = {}
        self._tool_count = 0

    def add_action(self, action: ActionEvent) -> List[AnomalyEvent]:
        """
        Add an action and check for anomalies.

        Args:
            action: The action event

        Returns:
            List of detected anomalies
        """
        anomalies = []
        session_id = action.session_id

        # Update tool vocabulary
        if action.tool_name not in self._tool_vocab:
            self._tool_vocab[action.tool_name] = self._tool_count
            self._tool_count += 1

        # Get or create session window
        if session_id not in self._session_windows:
            self._session_windows[session_id] = deque(maxlen=self.window_size)
            # Create ESN with appropriate input size
            input_size = self._tool_count + 3  # tools + success + size + time
            self._session_esns[session_id] = EchoStateNetwork(
                input_size=max(10, input_size),
                reservoir_size=50,
            )

        window = self._session_windows[session_id]
        window.append(action)

        self._total_actions += 1

        # Update n-gram counts
        self._update_ngrams(list(window))

        # Run detection methods
        esn_anomaly = self._check_esn_anomaly(action, session_id)
        if esn_anomaly:
            anomalies.append(esn_anomaly)

        rate_anomaly = self._check_rate_anomaly(session_id)
        if rate_anomaly:
            anomalies.append(rate_anomaly)

        entropy_anomaly = self._check_entropy_anomaly(list(window), action)
        if entropy_anomaly:
            anomalies.append(entropy_anomaly)

        pattern_anomaly = self._check_pattern_anomaly(list(window), action)
        if pattern_anomaly:
            anomalies.append(pattern_anomaly)

        return anomalies

    def _check_esn_anomaly(
        self,
        action: ActionEvent,
        session_id: str,
    ) -> Optional[AnomalyEvent]:
        """Check for ESN-based sequence anomaly."""
        esn = self._session_esns.get(session_id)
        if not esn:
            return None

        input_vec = action.to_vector(self._tool_vocab)
        # Pad input vector to match ESN input size
        while len(input_vec) < esn.input_size:
            input_vec.append(0.0)
        input_vec = input_vec[:esn.input_size]

        _, anomaly_score = esn.predict(input_vec)

        # Collect for training
        esn.collect_state(input_vec, input_vec)

        # Periodically retrain
        if len(esn._training_states) >= 100:
            esn.train()

        if anomaly_score > 0.7:  # Threshold
            return AnomalyEvent(
                event_id=generate_random_id("anom"),
                anomaly_type=AnomalyType.SEQUENCE,
                session_id=session_id,
                agent_id=action.agent_id,
                timestamp=datetime.now(timezone.utc),
                score=anomaly_score,
                confidence=0.6,  # ESN confidence
                description=f"Unusual action sequence detected: {action.tool_name}",
                triggered_action=self._score_to_action(anomaly_score),
                context={"tool": action.tool_name, "score": anomaly_score},
            )

        return None

    def _check_rate_anomaly(self, session_id: str) -> Optional[AnomalyEvent]:
        """Check for unusual action rate."""
        window = self._session_windows.get(session_id)
        if not window or len(window) < 10:
            return None

        # Calculate actions per second over last 10 actions
        recent = list(window)[-10:]
        time_span = (recent[-1].timestamp - recent[0].timestamp).total_seconds()

        if time_span <= 0:
            return None

        rate = len(recent) / time_span

        # Anomaly if rate is very high (more than 10 actions/second)
        if rate > 10:
            score = min(1.0, rate / 20)
            return AnomalyEvent(
                event_id=generate_random_id("anom"),
                anomaly_type=AnomalyType.RATE,
                session_id=session_id,
                agent_id=recent[-1].agent_id,
                timestamp=datetime.now(timezone.utc),
                score=score,
                confidence=0.8,
                description=f"Unusually high action rate: {rate:.1f}/s",
                triggered_action=TripwireAction.THROTTLE,
                context={"rate": rate, "window_seconds": time_span},
            )

        return None

    def _check_entropy_anomaly(
        self,
        window: List[ActionEvent],
        current: ActionEvent,
    ) -> Optional[AnomalyEvent]:
        """Check for entropy anomalies in action patterns."""
        if len(window) < 5:
            return None

        # Calculate tool entropy
        tool_counts: Dict[str, int] = {}
        for action in window:
            tool_counts[action.tool_name] = tool_counts.get(action.tool_name, 0) + 1

        total = sum(tool_counts.values())
        entropy = 0.0
        for count in tool_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Very low entropy = repetitive (possibly automated attack)
        if len(tool_counts) > 1 and entropy < 0.5:
            return AnomalyEvent(
                event_id=generate_random_id("anom"),
                anomaly_type=AnomalyType.ENTROPY,
                session_id=current.session_id,
                agent_id=current.agent_id,
                timestamp=datetime.now(timezone.utc),
                score=1.0 - entropy,
                confidence=0.5,
                description=f"Low action entropy detected ({entropy:.2f} bits)",
                triggered_action=TripwireAction.INCREASE_SCRUTINY,
                context={"entropy": entropy, "unique_tools": len(tool_counts)},
            )

        return None

    def _check_pattern_anomaly(
        self,
        window: List[ActionEvent],
        current: ActionEvent,
    ) -> Optional[AnomalyEvent]:
        """Check for known dangerous patterns."""
        if len(window) < 3:
            return None

        recent_tools = [a.tool_name for a in window[-5:]]

        # Check for escalation pattern (read -> write -> admin)
        risk_levels = {
            "read": 0, "get": 0, "list": 0, "query": 0,
            "write": 1, "create": 1, "update": 1,
            "delete": 2, "admin": 3, "exec": 3,
        }

        escalation_score = 0
        prev_risk = 0
        for tool in recent_tools:
            tool_lower = tool.lower()
            risk = 0
            for pattern, level in risk_levels.items():
                if pattern in tool_lower:
                    risk = max(risk, level)
            if risk > prev_risk:
                escalation_score += risk - prev_risk
            prev_risk = risk

        if escalation_score >= 3:
            return AnomalyEvent(
                event_id=generate_random_id("anom"),
                anomaly_type=AnomalyType.ESCALATION,
                session_id=current.session_id,
                agent_id=current.agent_id,
                timestamp=datetime.now(timezone.utc),
                score=min(1.0, escalation_score / 5),
                confidence=0.7,
                description="Privilege escalation pattern detected",
                triggered_action=TripwireAction.REQUIRE_APPROVAL,
                context={"tools": recent_tools, "escalation_score": escalation_score},
            )

        # Check for exfiltration pattern (multiple reads followed by network)
        read_count = sum(1 for t in recent_tools if any(p in t.lower() for p in ["read", "get", "query"]))
        has_network = any("network" in t.lower() or "api" in t.lower() or "send" in t.lower() for t in recent_tools)

        if read_count >= 3 and has_network:
            return AnomalyEvent(
                event_id=generate_random_id("anom"),
                anomaly_type=AnomalyType.EXFILTRATION,
                session_id=current.session_id,
                agent_id=current.agent_id,
                timestamp=datetime.now(timezone.utc),
                score=0.8,
                confidence=0.6,
                description="Possible data exfiltration pattern",
                triggered_action=TripwireAction.READ_ONLY_MODE,
                context={"read_count": read_count, "tools": recent_tools},
            )

        return None

    def _update_ngrams(self, window: List[ActionEvent]) -> None:
        """Update n-gram counts."""
        for n in self.ngram_sizes:
            if len(window) >= n:
                ngram = tuple(a.tool_name for a in window[-n:])
                key = str(ngram)
                self._ngram_counts[n][key] = self._ngram_counts[n].get(key, 0) + 1

    def _score_to_action(self, score: float) -> TripwireAction:
        """Convert anomaly score to action."""
        if score >= 0.9:
            return TripwireAction.QUARANTINE
        elif score >= 0.8:
            return TripwireAction.REQUIRE_APPROVAL
        elif score >= 0.7:
            return TripwireAction.THROTTLE
        elif score >= 0.5:
            return TripwireAction.INCREASE_SCRUTINY
        return TripwireAction.LOG_ONLY

    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """Get statistics for a session."""
        window = self._session_windows.get(session_id)
        if not window:
            return {}

        actions = list(window)
        tool_counts: Dict[str, int] = {}
        for action in actions:
            tool_counts[action.tool_name] = tool_counts.get(action.tool_name, 0) + 1

        return {
            "total_actions": len(actions),
            "unique_tools": len(tool_counts),
            "tool_distribution": tool_counts,
            "success_rate": sum(1 for a in actions if a.success) / len(actions) if actions else 0,
        }


class TripwireEngine:
    """
    Main tripwire engine that coordinates anomaly detection.

    Integrates with the gateway to provide real-time anomaly detection
    and trigger protective actions.
    """

    def __init__(
        self,
        analyzer: Optional[SequenceAnalyzer] = None,
        thresholds: Optional[Dict[AnomalyType, float]] = None,
    ):
        """
        Initialize the tripwire engine.

        Args:
            analyzer: Sequence analyzer to use
            thresholds: Custom thresholds per anomaly type
        """
        self.analyzer = analyzer or SequenceAnalyzer()
        self.thresholds = thresholds or {
            AnomalyType.SEQUENCE: 0.7,
            AnomalyType.RATE: 0.6,
            AnomalyType.ENTROPY: 0.5,
            AnomalyType.ESCALATION: 0.6,
            AnomalyType.EXFILTRATION: 0.5,
            AnomalyType.INJECTION: 0.4,
        }

        # Event history
        self._events: List[AnomalyEvent] = []

        # Current session states
        self._session_states: Dict[str, TripwireAction] = {}

        # Callbacks
        self._callbacks: List[Callable[[AnomalyEvent], None]] = []

        # Statistics
        self._stats = {
            "actions_analyzed": 0,
            "anomalies_detected": 0,
            "sessions_quarantined": 0,
        }

    def register_callback(
        self,
        callback: Callable[[AnomalyEvent], None],
    ) -> None:
        """Register a callback for anomaly events."""
        self._callbacks.append(callback)

    def analyze_action(
        self,
        tool_name: str,
        session_id: str,
        agent_id: str,
        success: bool,
        parameters: Dict[str, Any],
        response_size: int = 0,
        execution_time_ms: float = 0,
    ) -> Tuple[bool, List[AnomalyEvent], TripwireAction]:
        """
        Analyze an action for anomalies.

        Args:
            tool_name: Name of the tool called
            session_id: Session identifier
            agent_id: Agent identifier
            success: Whether the action succeeded
            parameters: Action parameters (hashed, not stored)
            response_size: Size of response
            execution_time_ms: Execution time

        Returns:
            Tuple of (should_allow, anomaly_events, current_action_level)
        """
        self._stats["actions_analyzed"] += 1

        # Create action event
        params_hash = hashlib.sha256(
            str(sorted(parameters.items())).encode()
        ).hexdigest()[:16]

        action = ActionEvent(
            action_id=generate_random_id("act"),
            tool_name=tool_name,
            session_id=session_id,
            agent_id=agent_id,
            timestamp=datetime.now(timezone.utc),
            success=success,
            parameters_hash=params_hash,
            response_size=response_size,
            execution_time_ms=execution_time_ms,
        )

        # Analyze
        anomalies = self.analyzer.add_action(action)

        # Update state
        current_action = self._session_states.get(session_id, TripwireAction.LOG_ONLY)

        for anomaly in anomalies:
            self._events.append(anomaly)
            self._stats["anomalies_detected"] += 1

            # Escalate session state if needed
            if self._action_severity(anomaly.triggered_action) > self._action_severity(current_action):
                current_action = anomaly.triggered_action
                self._session_states[session_id] = current_action

            # Trigger callbacks
            for callback in self._callbacks:
                try:
                    callback(anomaly)
                except Exception:
                    pass

        # Track quarantines
        if current_action == TripwireAction.QUARANTINE:
            self._stats["sessions_quarantined"] += 1

        # Determine if action should be allowed
        should_allow = current_action not in [TripwireAction.QUARANTINE]

        return should_allow, anomalies, current_action

    def get_session_state(self, session_id: str) -> TripwireAction:
        """Get current state for a session."""
        return self._session_states.get(session_id, TripwireAction.LOG_ONLY)

    def reset_session_state(self, session_id: str) -> None:
        """Reset session state to normal."""
        if session_id in self._session_states:
            del self._session_states[session_id]

    def get_recent_events(
        self,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AnomalyEvent]:
        """Get recent anomaly events."""
        events = self._events
        if session_id:
            events = [e for e in events if e.session_id == session_id]
        return events[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get tripwire statistics."""
        return {
            **self._stats,
            "active_sessions": len(self._session_states),
            "session_states": dict(self._session_states),
        }

    def _action_severity(self, action: TripwireAction) -> int:
        """Get severity level of an action."""
        severity = {
            TripwireAction.LOG_ONLY: 0,
            TripwireAction.INCREASE_SCRUTINY: 1,
            TripwireAction.THROTTLE: 2,
            TripwireAction.REQUIRE_APPROVAL: 3,
            TripwireAction.READ_ONLY_MODE: 4,
            TripwireAction.QUARANTINE: 5,
        }
        return severity.get(action, 0)
