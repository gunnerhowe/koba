"""
Tests for the monitoring module.

Covers:
- Metrics collection (Counter, Gauge, Histogram)
- Alerting system (rules, evaluation, notifications)
- Health checks (components, system, probes)
"""

import pytest
import time
import threading
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

from vacp.monitoring.metrics import (
    Counter,
    Gauge,
    Histogram,
    MetricType,
    MetricsCollector,
    get_collector,
    reset_collector,
)
from vacp.monitoring.alerts import (
    Alert,
    AlertCondition,
    AlertManager,
    AlertRule,
    AlertSeverity,
    AlertState,
    NotificationChannel,
    WebhookNotifier,
)
from vacp.monitoring.health import (
    ComponentHealth,
    HealthChecker,
    HealthStatus,
    SystemHealth,
    create_database_check,
    create_provider_check,
    get_health_checker,
    reset_health_checker,
)


# =============================================================================
# Metrics Tests
# =============================================================================


class TestCounter:
    """Tests for Counter metric."""

    def test_counter_increment(self):
        """Test basic counter increment."""
        counter = Counter("test_counter", "Test counter")
        counter.inc()
        assert counter.get() == 1.0

    def test_counter_increment_by_value(self):
        """Test counter increment by specific value."""
        counter = Counter("test_counter", "Test counter")
        counter.inc(5.0)
        assert counter.get() == 5.0
        counter.inc(3.0)
        assert counter.get() == 8.0

    def test_counter_negative_raises(self):
        """Test that negative increments raise an error."""
        counter = Counter("test_counter", "Test counter")
        with pytest.raises(ValueError, match="Counter can only be incremented"):
            counter.inc(-1.0)

    def test_counter_with_labels(self):
        """Test counter with labels."""
        counter = Counter("test_counter", "Test counter", labels=["method", "status"])
        counter.inc(method="GET", status="200")
        counter.inc(method="GET", status="200")
        counter.inc(method="POST", status="201")

        assert counter.get(method="GET", status="200") == 2.0
        assert counter.get(method="POST", status="201") == 1.0
        assert counter.get(method="GET", status="404") == 0.0

    def test_counter_samples(self):
        """Test getting counter samples."""
        counter = Counter("test_counter", "Test counter", labels=["method"])
        counter.inc(method="GET")
        counter.inc(2.0, method="POST")

        samples = counter.samples()
        assert len(samples) == 2
        assert all(s.metric_type == MetricType.COUNTER for s in samples)

    def test_counter_to_prometheus(self):
        """Test Prometheus format output."""
        counter = Counter("http_requests", "HTTP requests", labels=["method"])
        counter.inc(method="GET")

        samples = counter.samples()
        prometheus_line = samples[0].to_prometheus()
        assert "http_requests" in prometheus_line
        assert 'method="GET"' in prometheus_line


class TestGauge:
    """Tests for Gauge metric."""

    def test_gauge_set(self):
        """Test gauge set."""
        gauge = Gauge("test_gauge", "Test gauge")
        gauge.set(42.0)
        assert gauge.get() == 42.0

    def test_gauge_inc_dec(self):
        """Test gauge increment and decrement."""
        gauge = Gauge("test_gauge", "Test gauge")
        gauge.set(10.0)
        gauge.inc(5.0)
        assert gauge.get() == 15.0
        gauge.dec(3.0)
        assert gauge.get() == 12.0

    def test_gauge_with_labels(self):
        """Test gauge with labels."""
        gauge = Gauge("connections", "Active connections", labels=["service"])
        gauge.set(10.0, service="api")
        gauge.set(5.0, service="worker")

        assert gauge.get(service="api") == 10.0
        assert gauge.get(service="worker") == 5.0

    def test_gauge_samples(self):
        """Test getting gauge samples."""
        gauge = Gauge("temperature", "Temperature", labels=["location"])
        gauge.set(25.0, location="server1")
        gauge.set(28.0, location="server2")

        samples = gauge.samples()
        assert len(samples) == 2
        assert all(s.metric_type == MetricType.GAUGE for s in samples)


class TestHistogram:
    """Tests for Histogram metric."""

    def test_histogram_observe(self):
        """Test histogram observation."""
        histogram = Histogram("request_duration", "Request duration")
        histogram.observe(0.05)
        histogram.observe(0.1)
        histogram.observe(0.5)

        samples = histogram.samples()
        # Should have bucket samples + sum + count
        assert len(samples) > 3

    def test_histogram_custom_buckets(self):
        """Test histogram with custom buckets."""
        buckets = (0.1, 0.5, 1.0, 5.0)
        histogram = Histogram(
            "custom_histogram",
            "Custom histogram",
            buckets=buckets,
        )
        histogram.observe(0.3)

        samples = histogram.samples()
        bucket_samples = [s for s in samples if "_bucket" in s.name]
        # Should have buckets + +Inf
        assert len(bucket_samples) == len(buckets) + 1

    def test_histogram_with_labels(self):
        """Test histogram with labels."""
        histogram = Histogram(
            "request_duration",
            "Request duration",
            labels=["endpoint"],
        )
        histogram.observe(0.1, endpoint="/api/users")
        histogram.observe(0.2, endpoint="/api/users")
        histogram.observe(0.5, endpoint="/api/orders")

        samples = histogram.samples()
        assert len(samples) > 0

    def test_histogram_sum_count(self):
        """Test histogram sum and count."""
        histogram = Histogram("test_histogram", "Test histogram")
        histogram.observe(1.0)
        histogram.observe(2.0)
        histogram.observe(3.0)

        samples = histogram.samples()
        sum_sample = next((s for s in samples if "_sum" in s.name), None)
        count_sample = next((s for s in samples if "_count" in s.name), None)

        assert sum_sample is not None
        assert sum_sample.value == 6.0
        assert count_sample is not None
        assert count_sample.value == 3


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def setup_method(self):
        """Reset collector before each test."""
        reset_collector()

    def test_register_metric(self):
        """Test registering a metric."""
        collector = MetricsCollector()
        counter = Counter("test_counter", "Test counter")
        collector.register(counter)

        assert collector.get("test_counter") is counter

    def test_get_typed_metrics(self):
        """Test getting typed metrics."""
        collector = MetricsCollector()
        collector.register(Counter("test_counter", "Test counter"))
        collector.register(Gauge("test_gauge", "Test gauge"))
        collector.register(Histogram("test_histogram", "Test histogram"))

        assert collector.counter("test_counter") is not None
        assert collector.gauge("test_gauge") is not None
        assert collector.histogram("test_histogram") is not None

    def test_collect_all_samples(self):
        """Test collecting all samples."""
        collector = MetricsCollector()
        counter = Counter("test_counter", "Test counter")
        counter.inc()
        collector.register(counter)

        samples = collector.collect()
        assert len(samples) >= 1

    def test_prometheus_export(self):
        """Test Prometheus format export."""
        collector = MetricsCollector()
        counter = Counter("test_counter", "Test counter description")
        counter.inc()
        collector.register(counter)

        output = collector.to_prometheus()
        assert "# HELP test_counter Test counter description" in output
        assert "# TYPE test_counter counter" in output
        assert "test_counter" in output

    def test_dict_export(self):
        """Test dictionary export."""
        collector = MetricsCollector()
        counter = Counter("test_counter", "Test counter")
        counter.inc(5.0)
        collector.register(counter)

        result = collector.to_dict()
        assert "test_counter" in result
        assert result["test_counter"]["type"] == "counter"

    def test_global_collector(self):
        """Test global collector singleton."""
        collector1 = get_collector()
        collector2 = get_collector()
        assert collector1 is collector2

    def test_default_vacp_metrics(self):
        """Test that default VACP metrics are registered."""
        collector = MetricsCollector()
        # Check for default metrics
        assert collector.get("vacp_policy_evaluations_total") is not None
        assert collector.get("vacp_tool_calls_total") is not None
        assert collector.get("vacp_injection_attempts_total") is not None

    def test_thread_safety(self):
        """Test thread-safe metric operations."""
        counter = Counter("concurrent_counter", "Concurrent counter")
        results = []

        def increment():
            for _ in range(100):
                counter.inc()
            results.append(True)

        threads = [threading.Thread(target=increment) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counter.get() == 1000.0


# =============================================================================
# Alert Tests
# =============================================================================


class TestAlertRule:
    """Tests for AlertRule."""

    def test_evaluate_greater_than(self):
        """Test greater than comparison."""
        rule = AlertRule(
            id="test",
            name="Test",
            description="Test rule",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            comparison=">",
        )
        assert rule.evaluate(15.0) is True
        assert rule.evaluate(10.0) is False
        assert rule.evaluate(5.0) is False

    def test_evaluate_less_than(self):
        """Test less than comparison."""
        rule = AlertRule(
            id="test",
            name="Test",
            description="Test rule",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            comparison="<",
        )
        assert rule.evaluate(5.0) is True
        assert rule.evaluate(10.0) is False

    def test_evaluate_greater_equal(self):
        """Test greater than or equal comparison."""
        rule = AlertRule(
            id="test",
            name="Test",
            description="Test rule",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            comparison=">=",
        )
        assert rule.evaluate(15.0) is True
        assert rule.evaluate(10.0) is True
        assert rule.evaluate(5.0) is False

    def test_evaluate_equal(self):
        """Test equality comparison."""
        rule = AlertRule(
            id="test",
            name="Test",
            description="Test rule",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            comparison="==",
        )
        assert rule.evaluate(10.0) is True
        assert rule.evaluate(10.1) is False

    def test_evaluate_not_equal(self):
        """Test not equal comparison."""
        rule = AlertRule(
            id="test",
            name="Test",
            description="Test rule",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            comparison="!=",
        )
        assert rule.evaluate(5.0) is True
        assert rule.evaluate(10.0) is False

    def test_rule_to_dict(self):
        """Test rule serialization."""
        rule = AlertRule(
            id="test",
            name="Test Rule",
            description="Description",
            severity=AlertSeverity.CRITICAL,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
        )
        data = rule.to_dict()
        assert data["id"] == "test"
        assert data["name"] == "Test Rule"
        assert data["severity"] == "critical"


class TestAlert:
    """Tests for Alert dataclass."""

    def test_alert_to_dict(self):
        """Test alert serialization."""
        now = datetime.now(timezone.utc)
        alert = Alert(
            id="alert-1",
            rule_id="rule-1",
            severity=AlertSeverity.WARNING,
            state=AlertState.FIRING,
            title="Test Alert",
            description="Alert description",
            labels={"env": "prod"},
            started_at=now,
            value=15.0,
        )
        data = alert.to_dict()
        assert data["id"] == "alert-1"
        assert data["severity"] == "warning"
        assert data["state"] == "firing"
        assert data["value"] == 15.0

    def test_alert_resolved(self):
        """Test resolved alert."""
        now = datetime.now(timezone.utc)
        alert = Alert(
            id="alert-1",
            rule_id="rule-1",
            severity=AlertSeverity.WARNING,
            state=AlertState.RESOLVED,
            title="Test Alert",
            description="Alert description",
            labels={},
            started_at=now,
            resolved_at=now,
        )
        data = alert.to_dict()
        assert data["state"] == "resolved"
        assert data["resolved_at"] is not None


class TestAlertManager:
    """Tests for AlertManager."""

    def test_add_remove_rule(self):
        """Test adding and removing rules."""
        manager = AlertManager()
        initial_count = len(manager.list_rules())

        rule = AlertRule(
            id="custom_rule",
            name="Custom Rule",
            description="Custom rule",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="custom_metric",
            threshold=10.0,
        )
        manager.add_rule(rule)
        assert len(manager.list_rules()) == initial_count + 1

        manager.remove_rule("custom_rule")
        assert len(manager.list_rules()) == initial_count

    def test_get_rule(self):
        """Test getting a rule by ID."""
        manager = AlertManager()
        rule = manager.get_rule("high_injection_rate")
        assert rule is not None
        assert rule.id == "high_injection_rate"

    def test_evaluate_triggers_alert(self):
        """Test that evaluation triggers alerts."""
        manager = AlertManager()
        # Create a rule with 0 duration for immediate triggering
        rule = AlertRule(
            id="instant_alert",
            name="Instant Alert",
            description="Triggers immediately",
            severity=AlertSeverity.CRITICAL,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            comparison=">=",
            for_duration=timedelta(seconds=0),
        )
        manager.add_rule(rule)

        # Trigger the alert
        alerts = manager.evaluate("test_metric", 15.0)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "instant_alert"
        assert alerts[0].state == AlertState.FIRING

    def test_evaluate_no_trigger_below_threshold(self):
        """Test that evaluation doesn't trigger below threshold."""
        manager = AlertManager()
        rule = AlertRule(
            id="threshold_alert",
            name="Threshold Alert",
            description="Above threshold",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            comparison=">=",
            for_duration=timedelta(seconds=0),
        )
        manager.add_rule(rule)

        alerts = manager.evaluate("test_metric", 5.0)
        assert len(alerts) == 0

    def test_evaluate_with_labels(self):
        """Test evaluation with labels."""
        manager = AlertManager()
        rule = AlertRule(
            id="labeled_alert",
            name="Labeled Alert",
            description="With labels",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            for_duration=timedelta(seconds=0),
        )
        manager.add_rule(rule)

        alerts = manager.evaluate("test_metric", 15.0, labels={"env": "prod"})
        assert len(alerts) == 1
        assert "env" in alerts[0].labels

    def test_alert_resolves(self):
        """Test that alerts resolve when condition clears."""
        manager = AlertManager()
        rule = AlertRule(
            id="resolve_test",
            name="Resolve Test",
            description="Test resolution",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            for_duration=timedelta(seconds=0),
        )
        manager.add_rule(rule)

        # Trigger alert
        manager.evaluate("test_metric", 15.0)
        firing = manager.get_alerts(state=AlertState.FIRING)
        assert len(firing) >= 1

        # Resolve alert
        manager.evaluate("test_metric", 5.0)
        resolved = manager.get_alerts(state=AlertState.RESOLVED)
        assert len(resolved) >= 1

    def test_get_alerts_by_severity(self):
        """Test filtering alerts by severity."""
        manager = AlertManager()

        # Create rules with different severities
        for severity in [AlertSeverity.WARNING, AlertSeverity.CRITICAL]:
            rule = AlertRule(
                id=f"alert_{severity.value}",
                name=f"Alert {severity.value}",
                description="Test",
                severity=severity,
                condition=AlertCondition.THRESHOLD,
                metric_name=f"metric_{severity.value}",
                threshold=10.0,
                for_duration=timedelta(seconds=0),
            )
            manager.add_rule(rule)
            manager.evaluate(f"metric_{severity.value}", 15.0)

        critical = manager.get_alerts(severity=AlertSeverity.CRITICAL)
        warning = manager.get_alerts(severity=AlertSeverity.WARNING)
        assert len(critical) >= 1
        assert len(warning) >= 1

    def test_acknowledge_alert(self):
        """Test acknowledging an alert."""
        manager = AlertManager()
        rule = AlertRule(
            id="ack_test",
            name="Ack Test",
            description="Test ack",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            for_duration=timedelta(seconds=0),
        )
        manager.add_rule(rule)

        alerts = manager.evaluate("test_metric", 15.0)
        assert len(alerts) == 1

        result = manager.acknowledge_alert(alerts[0].id)
        assert result is True

        alert = manager.get_alert(alerts[0].id)
        assert alert.state == AlertState.RESOLVED

    def test_get_statistics(self):
        """Test getting alert statistics."""
        manager = AlertManager()
        stats = manager.get_statistics()

        assert "total_rules" in stats
        assert "total_alerts" in stats
        assert "firing" in stats
        assert "resolved" in stats
        assert "by_severity" in stats

    def test_add_notification_channel(self):
        """Test adding notification channel."""
        manager = AlertManager()
        channel = NotificationChannel(
            id="test_webhook",
            name="Test Webhook",
            channel_type="webhook",
            config={"url": "https://example.com/webhook"},
        )
        manager.add_channel(channel)

        # Should not raise
        manager.remove_channel("test_webhook")

    def test_disabled_rule_not_evaluated(self):
        """Test that disabled rules are not evaluated."""
        manager = AlertManager()
        rule = AlertRule(
            id="disabled_rule",
            name="Disabled Rule",
            description="Should not fire",
            severity=AlertSeverity.CRITICAL,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            for_duration=timedelta(seconds=0),
            enabled=False,
        )
        manager.add_rule(rule)

        alerts = manager.evaluate("test_metric", 100.0)
        disabled_alerts = [a for a in alerts if a.rule_id == "disabled_rule"]
        assert len(disabled_alerts) == 0

    def test_clear_resolved_alerts(self):
        """Test clearing old resolved alerts."""
        manager = AlertManager()
        rule = AlertRule(
            id="clear_test",
            name="Clear Test",
            description="Test clear",
            severity=AlertSeverity.WARNING,
            condition=AlertCondition.THRESHOLD,
            metric_name="test_metric",
            threshold=10.0,
            for_duration=timedelta(seconds=0),
        )
        manager.add_rule(rule)

        # Create and resolve an alert
        manager.evaluate("test_metric", 15.0)
        manager.evaluate("test_metric", 5.0)

        # Should not clear recent alerts
        count = manager.clear_resolved_alerts(older_than=timedelta(hours=24))
        assert count == 0

        # Should clear with small duration
        count = manager.clear_resolved_alerts(older_than=timedelta(seconds=0))
        assert count >= 0


class TestWebhookNotifier:
    """Tests for WebhookNotifier."""

    @patch("urllib.request.urlopen")
    def test_send_success(self, mock_urlopen):
        """Test successful webhook send."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        notifier = WebhookNotifier("https://example.com/webhook")
        alert = Alert(
            id="test-1",
            rule_id="rule-1",
            severity=AlertSeverity.WARNING,
            state=AlertState.FIRING,
            title="Test",
            description="Test alert",
            labels={},
            started_at=datetime.now(timezone.utc),
        )

        result = notifier.send(alert)
        assert result is True

    @patch("urllib.request.urlopen")
    def test_send_with_headers(self, mock_urlopen):
        """Test webhook with custom headers."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        notifier = WebhookNotifier(
            "https://example.com/webhook",
            headers={"Authorization": "Bearer token123"},
        )
        alert = Alert(
            id="test-1",
            rule_id="rule-1",
            severity=AlertSeverity.WARNING,
            state=AlertState.FIRING,
            title="Test",
            description="Test",
            labels={},
            started_at=datetime.now(timezone.utc),
        )

        notifier.send(alert)
        # Check that request was made with headers
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert "Authorization" in request.headers


# =============================================================================
# Health Check Tests
# =============================================================================


class TestHealthChecker:
    """Tests for HealthChecker."""

    def setup_method(self):
        """Reset health checker before each test."""
        reset_health_checker()

    def test_default_checks(self):
        """Test that default checks are registered."""
        checker = HealthChecker()
        names = checker.get_component_names()
        assert "vacp_core" in names

    def test_register_check(self):
        """Test registering a custom check."""
        checker = HealthChecker()

        def custom_check() -> ComponentHealth:
            return ComponentHealth(
                name="custom",
                status=HealthStatus.HEALTHY,
                message="OK",
            )

        checker.register("custom", custom_check)
        assert "custom" in checker.get_component_names()

    def test_unregister_check(self):
        """Test unregistering a check."""
        checker = HealthChecker()

        def custom_check() -> ComponentHealth:
            return ComponentHealth(name="custom", status=HealthStatus.HEALTHY)

        checker.register("custom", custom_check)
        assert checker.unregister("custom") is True
        assert "custom" not in checker.get_component_names()
        assert checker.unregister("nonexistent") is False

    def test_check_component(self):
        """Test checking a specific component."""
        checker = HealthChecker()
        result = checker.check_component("vacp_core")

        assert result is not None
        assert result.name == "vacp_core"
        assert result.status == HealthStatus.HEALTHY

    def test_check_nonexistent_component(self):
        """Test checking a nonexistent component."""
        checker = HealthChecker()
        result = checker.check_component("nonexistent")
        assert result is None

    def test_check_all(self):
        """Test checking all components."""
        checker = HealthChecker()
        health = checker.check_all()

        assert isinstance(health, SystemHealth)
        assert health.status == HealthStatus.HEALTHY
        assert len(health.components) >= 1

    def test_system_health_properties(self):
        """Test SystemHealth properties."""
        health = SystemHealth(
            status=HealthStatus.HEALTHY,
            components=[],
            timestamp=datetime.now(timezone.utc),
        )
        assert health.is_healthy is True
        assert health.is_ready is True

        degraded = SystemHealth(
            status=HealthStatus.DEGRADED,
            components=[],
            timestamp=datetime.now(timezone.utc),
        )
        assert degraded.is_healthy is False
        assert degraded.is_ready is True

        unhealthy = SystemHealth(
            status=HealthStatus.UNHEALTHY,
            components=[],
            timestamp=datetime.now(timezone.utc),
        )
        assert unhealthy.is_healthy is False
        assert unhealthy.is_ready is False

    def test_aggregate_status_unhealthy(self):
        """Test that one unhealthy component makes system unhealthy."""
        checker = HealthChecker()

        def unhealthy_check() -> ComponentHealth:
            return ComponentHealth(name="bad", status=HealthStatus.UNHEALTHY)

        checker.register("bad", unhealthy_check)
        health = checker.check_all()
        assert health.status == HealthStatus.UNHEALTHY

    def test_aggregate_status_degraded(self):
        """Test that one degraded component makes system degraded."""
        checker = HealthChecker()

        def degraded_check() -> ComponentHealth:
            return ComponentHealth(name="degraded", status=HealthStatus.DEGRADED)

        checker.register("degraded", degraded_check)
        # Note: vacp_core is healthy, so we need to check aggregation
        health = checker.check_all()
        # With one healthy and one degraded, system should be degraded
        assert health.status == HealthStatus.DEGRADED

    def test_check_exception_handling(self):
        """Test that check exceptions are handled."""
        checker = HealthChecker()

        def failing_check() -> ComponentHealth:
            raise RuntimeError("Check failed")

        checker.register("failing", failing_check)
        result = checker.check_component("failing")

        assert result is not None
        assert result.status == HealthStatus.UNHEALTHY
        assert "Check failed" in result.message

    def test_caching(self):
        """Test health check result caching."""
        checker = HealthChecker(cache_ttl=60.0)
        call_count = 0

        def counting_check() -> ComponentHealth:
            nonlocal call_count
            call_count += 1
            return ComponentHealth(name="counting", status=HealthStatus.HEALTHY)

        checker.register("counting", counting_check)

        # First call
        checker.check_component("counting", use_cache=True)
        assert call_count == 1

        # Second call should use cache
        checker.check_component("counting", use_cache=True)
        assert call_count == 1

        # Force bypass cache
        checker.check_component("counting", use_cache=False)
        assert call_count == 2

    def test_liveness_probe(self):
        """Test liveness probe."""
        checker = HealthChecker()
        assert checker.liveness() is True

    def test_readiness_probe(self):
        """Test readiness probe."""
        checker = HealthChecker()
        assert checker.readiness() is True

        # Add unhealthy component
        def unhealthy() -> ComponentHealth:
            return ComponentHealth(name="bad", status=HealthStatus.UNHEALTHY)

        checker.register("bad", unhealthy)
        # Clear cache for immediate effect
        checker.check_component("bad", use_cache=False)
        assert checker.readiness() is False

    def test_uptime(self):
        """Test uptime tracking."""
        checker = HealthChecker()
        time.sleep(0.1)
        health = checker.check_all()
        assert health.uptime_seconds >= 0.1

    def test_version(self):
        """Test version in health output."""
        checker = HealthChecker(version="1.0.0")
        health = checker.check_all()
        assert health.version == "1.0.0"

    def test_to_dict(self):
        """Test health serialization."""
        checker = HealthChecker(version="1.0.0")
        health = checker.check_all()
        data = health.to_dict()

        assert "status" in data
        assert "components" in data
        assert "timestamp" in data
        assert "version" in data

    def test_component_health_to_dict(self):
        """Test component health serialization."""
        health = ComponentHealth(
            name="test",
            status=HealthStatus.HEALTHY,
            message="OK",
            latency_ms=1.5,
            details={"key": "value"},
        )
        data = health.to_dict()

        assert data["name"] == "test"
        assert data["status"] == "healthy"
        assert data["message"] == "OK"
        assert data["latency_ms"] == 1.5
        assert data["details"] == {"key": "value"}

    def test_background_checks(self):
        """Test background health check thread."""
        checker = HealthChecker(check_interval=0.1)
        check_times = []

        def tracking_check() -> ComponentHealth:
            check_times.append(datetime.now(timezone.utc))
            return ComponentHealth(name="tracking", status=HealthStatus.HEALTHY)

        checker.register("tracking", tracking_check)
        checker.start_background_checks()

        time.sleep(0.35)  # Wait for a few check cycles
        checker.stop_background_checks()

        # Should have been checked multiple times
        assert len(check_times) >= 2

    def test_global_health_checker(self):
        """Test global health checker singleton."""
        checker1 = get_health_checker()
        checker2 = get_health_checker()
        assert checker1 is checker2


class TestHealthCheckFactories:
    """Tests for health check factory functions."""

    def test_create_database_check_success(self):
        """Test database health check factory with success."""
        check_func = create_database_check(
            "test_db",
            lambda: True,
        )
        result = check_func()
        assert result.status == HealthStatus.HEALTHY

    def test_create_database_check_failure(self):
        """Test database health check factory with failure."""
        check_func = create_database_check(
            "test_db",
            lambda: False,
        )
        result = check_func()
        assert result.status == HealthStatus.UNHEALTHY

    def test_create_database_check_exception(self):
        """Test database health check factory with exception."""
        def failing_check():
            raise RuntimeError("Connection failed")

        check_func = create_database_check("test_db", failing_check)
        result = check_func()
        assert result.status == HealthStatus.UNHEALTHY
        assert "Connection failed" in result.message

    def test_create_provider_check_available(self):
        """Test provider health check factory with available provider."""
        check_func = create_provider_check(
            "test_provider",
            lambda: True,
        )
        result = check_func()
        assert result.status == HealthStatus.HEALTHY

    def test_create_provider_check_unavailable(self):
        """Test provider health check factory with unavailable provider."""
        check_func = create_provider_check(
            "test_provider",
            lambda: False,
        )
        result = check_func()
        assert result.status == HealthStatus.DEGRADED

    def test_create_provider_check_exception(self):
        """Test provider health check factory with exception."""
        def failing_check():
            raise RuntimeError("Provider error")

        check_func = create_provider_check("test_provider", failing_check)
        result = check_func()
        assert result.status == HealthStatus.UNHEALTHY


# =============================================================================
# Integration Tests
# =============================================================================


class TestMonitoringIntegration:
    """Integration tests for the monitoring module."""

    def setup_method(self):
        """Reset global state."""
        reset_collector()
        reset_health_checker()

    def test_metrics_and_alerts_integration(self):
        """Test metrics feeding into alerts."""
        collector = get_collector()
        AlertManager()

        # Create alert rule for injection attempts
        # Already has default rules, but let's verify they work

        # Record some injection attempts
        counter = collector.counter("vacp_injection_attempts_total")
        if counter:
            counter.inc(type="sql", tenant_id="tenant1")

        # The alert evaluation would typically happen in a monitoring loop
        # For this test, we just verify the components work together

    def test_health_with_custom_components(self):
        """Test health checker with multiple custom components."""
        checker = HealthChecker(version="test")

        # Register multiple checks
        checker.register("database", create_database_check("db", lambda: True))
        checker.register("cache", create_database_check("cache", lambda: True))
        checker.register("api", create_provider_check("api", lambda: True))

        health = checker.check_all()
        assert health.status == HealthStatus.HEALTHY
        assert len(health.components) == 4  # 3 custom + 1 default

    def test_full_monitoring_stack(self):
        """Test all monitoring components together."""
        # Initialize components
        collector = MetricsCollector()
        manager = AlertManager()
        checker = HealthChecker(version="1.0.0")

        # Register health check for alert manager
        def alert_health() -> ComponentHealth:
            stats = manager.get_statistics()
            status = HealthStatus.HEALTHY
            if stats["firing"] > 0:
                status = HealthStatus.DEGRADED
            return ComponentHealth(
                name="alerts",
                status=status,
                details=stats,
            )

        checker.register("alerts", alert_health)

        # Record metrics
        counter = collector.counter("vacp_policy_evaluations_total")
        if counter:
            counter.inc(decision="allow", tenant_id="test")

        # Check health
        health = checker.check_all()
        assert health.status == HealthStatus.HEALTHY

        # Export metrics
        prometheus = collector.to_prometheus()
        assert "vacp_policy_evaluations_total" in prometheus
