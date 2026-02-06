"""
Monitoring and Alerting for Koba/VACP

Provides:
- Metrics collection (Prometheus format)
- Alerting rules and notifications
- Health check endpoints
- Dashboard data endpoints
"""

from vacp.monitoring.metrics import (
    MetricsCollector,
    Counter,
    Gauge,
    Histogram,
    MetricType,
)
from vacp.monitoring.alerts import (
    AlertManager,
    Alert,
    AlertSeverity,
    AlertRule,
    AlertCondition,
)
from vacp.monitoring.health import (
    HealthChecker,
    HealthStatus,
    ComponentHealth,
    SystemHealth,
)

__all__ = [
    "MetricsCollector",
    "Counter",
    "Gauge",
    "Histogram",
    "MetricType",
    "AlertManager",
    "Alert",
    "AlertSeverity",
    "AlertRule",
    "AlertCondition",
    "HealthChecker",
    "HealthStatus",
    "ComponentHealth",
    "SystemHealth",
]
