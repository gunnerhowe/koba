"""
Alerting System for Koba/VACP

Provides:
- Alert rule definitions
- Alert evaluation and triggering
- Notification channels (webhook, email, etc.)
- Alert state management
"""

import json
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertState(str, Enum):
    """Alert state."""
    PENDING = "pending"
    FIRING = "firing"
    RESOLVED = "resolved"


class AlertCondition(str, Enum):
    """Types of alert conditions."""
    THRESHOLD = "threshold"
    RATE = "rate"
    ABSENCE = "absence"
    PATTERN = "pattern"


@dataclass
class Alert:
    """Represents an active alert."""
    id: str
    rule_id: str
    severity: AlertSeverity
    state: AlertState
    title: str
    description: str
    labels: Dict[str, str]
    started_at: datetime
    resolved_at: Optional[datetime] = None
    value: Optional[float] = None
    annotations: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "state": self.state.value,
            "title": self.title,
            "description": self.description,
            "labels": self.labels,
            "started_at": self.started_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "value": self.value,
            "annotations": self.annotations,
        }


@dataclass
class AlertRule:
    """Definition of an alert rule."""
    id: str
    name: str
    description: str
    severity: AlertSeverity
    condition: AlertCondition
    metric_name: str
    threshold: Optional[float] = None
    comparison: str = ">"  # ">", "<", ">=", "<=", "==", "!="
    for_duration: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True

    def evaluate(self, value: float) -> bool:
        """Evaluate if the alert condition is met."""
        if self.threshold is None:
            return False

        comparisons = {
            ">": lambda v, t: v > t,
            "<": lambda v, t: v < t,
            ">=": lambda v, t: v >= t,
            "<=": lambda v, t: v <= t,
            "==": lambda v, t: v == t,
            "!=": lambda v, t: v != t,
        }

        compare_func = comparisons.get(self.comparison)
        if compare_func is None:
            return False

        return compare_func(value, self.threshold)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "condition": self.condition.value,
            "metric_name": self.metric_name,
            "threshold": self.threshold,
            "comparison": self.comparison,
            "for_duration": self.for_duration.total_seconds(),
            "labels": self.labels,
            "enabled": self.enabled,
        }


@dataclass
class NotificationChannel:
    """Configuration for a notification channel."""
    id: str
    name: str
    channel_type: str  # "webhook", "email", "slack"
    config: Dict[str, Any]
    enabled: bool = True


class WebhookNotifier:
    """Sends alerts via webhook."""

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = headers or {}

    def send(self, alert: Alert) -> bool:
        """Send an alert to the webhook."""
        try:
            data = json.dumps(alert.to_dict()).encode("utf-8")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    **self.headers,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
                return response.status == 200
        except urllib.error.URLError as e:
            logger.error(f"Failed to send webhook: {e}")
            return False


class AlertManager:
    """
    Manages alert rules and active alerts.

    Features:
    - Rule-based alerting
    - Alert state management (pending -> firing -> resolved)
    - Multiple notification channels
    - Alert grouping and deduplication
    """

    def __init__(self):
        self._rules: Dict[str, AlertRule] = {}
        self._alerts: Dict[str, Alert] = {}
        self._pending: Dict[str, datetime] = {}  # rule_id -> first_trigger_time
        self._channels: Dict[str, NotificationChannel] = {}
        self._notifiers: Dict[str, Callable[[Alert], bool]] = {}
        self._lock = threading.Lock()

        self._register_default_rules()

    def _register_default_rules(self) -> None:
        """Register default VACP alert rules."""
        self.add_rule(AlertRule(
            id="high_injection_rate",
            name="High Injection Attempt Rate",
            description="Unusually high rate of injection attempts detected",
            severity=AlertSeverity.CRITICAL,
            condition=AlertCondition.RATE,
            metric_name="vacp_injection_attempts_total",
            threshold=10.0,
            comparison=">=",
            for_duration=timedelta(minutes=5),
        ))

        self.add_rule(AlertRule(
            id="high_block_rate",
            name="High Tool Call Block Rate",
            description="Unusually high rate of blocked tool calls",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.RATE,
            metric_name="vacp_tool_calls_blocked_total",
            threshold=50.0,
            comparison=">=",
            for_duration=timedelta(minutes=10),
        ))

        self.add_rule(AlertRule(
            id="policy_eval_latency",
            name="High Policy Evaluation Latency",
            description="Policy evaluation taking too long",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="vacp_policy_evaluation_duration_seconds",
            threshold=0.5,
            comparison=">=",
            for_duration=timedelta(minutes=5),
        ))

    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        with self._lock:
            self._rules[rule.id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove an alert rule."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                return True
            return False

    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get a rule by ID."""
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self) -> List[AlertRule]:
        """List all rules."""
        with self._lock:
            return list(self._rules.values())

    def add_channel(self, channel: NotificationChannel) -> None:
        """Add a notification channel."""
        with self._lock:
            self._channels[channel.id] = channel

            if channel.channel_type == "webhook":
                url = channel.config.get("url")
                headers = channel.config.get("headers", {})
                if url:
                    notifier = WebhookNotifier(url, headers)
                    self._notifiers[channel.id] = notifier.send

    def remove_channel(self, channel_id: str) -> bool:
        """Remove a notification channel."""
        with self._lock:
            if channel_id in self._channels:
                del self._channels[channel_id]
                if channel_id in self._notifiers:
                    del self._notifiers[channel_id]
                return True
            return False

    def evaluate(self, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None) -> List[Alert]:
        """
        Evaluate alert rules against a metric value.

        Returns list of newly fired alerts.
        """
        now = datetime.now(timezone.utc)
        new_alerts = []
        labels = labels or {}

        with self._lock:
            for rule in self._rules.values():
                if not rule.enabled:
                    continue
                if rule.metric_name != metric_name:
                    continue

                condition_met = rule.evaluate(value)
                rule_key = f"{rule.id}:{json.dumps(labels, sort_keys=True)}"

                if condition_met:
                    if rule_key not in self._pending:
                        self._pending[rule_key] = now

                    pending_time = now - self._pending[rule_key]

                    if pending_time >= rule.for_duration:
                        if rule_key not in self._alerts:
                            alert = self._create_alert(rule, value, labels, now)
                            self._alerts[rule_key] = alert
                            new_alerts.append(alert)
                else:
                    if rule_key in self._pending:
                        del self._pending[rule_key]

                    if rule_key in self._alerts:
                        alert = self._alerts[rule_key]
                        if alert.state == AlertState.FIRING:
                            alert.state = AlertState.RESOLVED
                            alert.resolved_at = now

        for alert in new_alerts:
            self._notify(alert)

        return new_alerts

    def _create_alert(
        self,
        rule: AlertRule,
        value: float,
        labels: Dict[str, str],
        timestamp: datetime,
    ) -> Alert:
        """Create a new alert from a rule."""
        import secrets
        alert_id = secrets.token_hex(8)

        return Alert(
            id=alert_id,
            rule_id=rule.id,
            severity=rule.severity,
            state=AlertState.FIRING,
            title=rule.name,
            description=rule.description,
            labels={**rule.labels, **labels},
            started_at=timestamp,
            value=value,
            annotations=rule.annotations,
        )

    def _notify(self, alert: Alert) -> None:
        """Send alert to all enabled notification channels."""
        with self._lock:
            for channel_id, notifier in self._notifiers.items():
                channel = self._channels.get(channel_id)
                if channel and channel.enabled:
                    try:
                        notifier(alert)
                    except Exception as e:
                        logger.error(f"Failed to notify channel {channel_id}: {e}")

    def get_alerts(
        self,
        state: Optional[AlertState] = None,
        severity: Optional[AlertSeverity] = None,
    ) -> List[Alert]:
        """Get alerts, optionally filtered by state and severity."""
        with self._lock:
            alerts = list(self._alerts.values())

        if state:
            alerts = [a for a in alerts if a.state == state]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        return alerts

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID."""
        with self._lock:
            for alert in self._alerts.values():
                if alert.id == alert_id:
                    return alert
        return None

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert (mark as resolved)."""
        with self._lock:
            for alert in self._alerts.values():
                if alert.id == alert_id:
                    if alert.state == AlertState.FIRING:
                        alert.state = AlertState.RESOLVED
                        alert.resolved_at = datetime.now(timezone.utc)
                        return True
        return False

    def clear_resolved_alerts(self, older_than: timedelta = timedelta(hours=24)) -> int:
        """Clear resolved alerts older than the specified duration."""
        cutoff = datetime.now(timezone.utc) - older_than
        count = 0

        with self._lock:
            to_remove = []
            for key, alert in self._alerts.items():
                if alert.state == AlertState.RESOLVED and alert.resolved_at:
                    if alert.resolved_at < cutoff:
                        to_remove.append(key)

            for key in to_remove:
                del self._alerts[key]
                count += 1

        return count

    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        with self._lock:
            alerts = list(self._alerts.values())

        return {
            "total_rules": len(self._rules),
            "total_alerts": len(alerts),
            "firing": len([a for a in alerts if a.state == AlertState.FIRING]),
            "resolved": len([a for a in alerts if a.state == AlertState.RESOLVED]),
            "by_severity": {
                sev.value: len([a for a in alerts if a.severity == sev])
                for sev in AlertSeverity
            },
        }
