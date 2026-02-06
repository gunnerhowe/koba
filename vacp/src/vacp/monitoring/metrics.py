"""
Metrics Collection for Koba/VACP

Provides Prometheus-compatible metrics collection with:
- Counters (monotonically increasing values)
- Gauges (values that can go up or down)
- Histograms (distribution of values)
- Labels for multi-dimensional metrics
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class MetricType(str, Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass
class MetricSample:
    """A single metric sample."""
    name: str
    value: float
    labels: Dict[str, str]
    timestamp: datetime
    metric_type: MetricType

    def to_prometheus(self) -> str:
        """Convert to Prometheus text format."""
        labels_str = ""
        if self.labels:
            label_parts = [f'{k}="{v}"' for k, v in sorted(self.labels.items())]
            labels_str = "{" + ",".join(label_parts) + "}"

        return f"{self.name}{labels_str} {self.value}"


class Counter:
    """A counter metric that only increases."""

    def __init__(self, name: str, description: str, labels: Optional[List[str]] = None):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self._values: Dict[Tuple[str, ...], float] = {}
        self._lock = threading.Lock()

    def inc(self, value: float = 1.0, **labels) -> None:
        """Increment the counter."""
        if value < 0:
            raise ValueError("Counter can only be incremented")

        label_values = self._get_label_values(labels)
        with self._lock:
            if label_values not in self._values:
                self._values[label_values] = 0.0
            self._values[label_values] += value

    def get(self, **labels) -> float:
        """Get the current value."""
        label_values = self._get_label_values(labels)
        with self._lock:
            return self._values.get(label_values, 0.0)

    def samples(self) -> List[MetricSample]:
        """Get all samples."""
        with self._lock:
            samples = []
            for label_values, value in self._values.items():
                labels = dict(zip(self.label_names, label_values))
                samples.append(MetricSample(
                    name=self.name,
                    value=value,
                    labels=labels,
                    timestamp=datetime.now(timezone.utc),
                    metric_type=MetricType.COUNTER,
                ))
            return samples

    def _get_label_values(self, labels: Dict[str, str]) -> Tuple[str, ...]:
        """Get label values as a tuple for indexing."""
        return tuple(labels.get(name, "") for name in self.label_names)


class Gauge:
    """A gauge metric that can go up or down."""

    def __init__(self, name: str, description: str, labels: Optional[List[str]] = None):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self._values: Dict[Tuple[str, ...], float] = {}
        self._lock = threading.Lock()

    def set(self, value: float, **labels) -> None:
        """Set the gauge value."""
        label_values = self._get_label_values(labels)
        with self._lock:
            self._values[label_values] = value

    def inc(self, value: float = 1.0, **labels) -> None:
        """Increment the gauge."""
        label_values = self._get_label_values(labels)
        with self._lock:
            if label_values not in self._values:
                self._values[label_values] = 0.0
            self._values[label_values] += value

    def dec(self, value: float = 1.0, **labels) -> None:
        """Decrement the gauge."""
        label_values = self._get_label_values(labels)
        with self._lock:
            if label_values not in self._values:
                self._values[label_values] = 0.0
            self._values[label_values] -= value

    def get(self, **labels) -> float:
        """Get the current value."""
        label_values = self._get_label_values(labels)
        with self._lock:
            return self._values.get(label_values, 0.0)

    def samples(self) -> List[MetricSample]:
        """Get all samples."""
        with self._lock:
            samples = []
            for label_values, value in self._values.items():
                labels = dict(zip(self.label_names, label_values))
                samples.append(MetricSample(
                    name=self.name,
                    value=value,
                    labels=labels,
                    timestamp=datetime.now(timezone.utc),
                    metric_type=MetricType.GAUGE,
                ))
            return samples

    def _get_label_values(self, labels: Dict[str, str]) -> Tuple[str, ...]:
        """Get label values as a tuple for indexing."""
        return tuple(labels.get(name, "") for name in self.label_names)


class Histogram:
    """A histogram metric for measuring distributions."""

    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(
        self,
        name: str,
        description: str,
        labels: Optional[List[str]] = None,
        buckets: Optional[Tuple[float, ...]] = None,
    ):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self.buckets = buckets or self.DEFAULT_BUCKETS
        self._counts: Dict[Tuple[str, ...], List[int]] = {}
        self._sums: Dict[Tuple[str, ...], float] = {}
        self._totals: Dict[Tuple[str, ...], int] = {}
        self._lock = threading.Lock()

    def observe(self, value: float, **labels) -> None:
        """Record a value in the histogram."""
        label_values = self._get_label_values(labels)

        with self._lock:
            if label_values not in self._counts:
                self._counts[label_values] = [0] * len(self.buckets)
                self._sums[label_values] = 0.0
                self._totals[label_values] = 0

            for i, bucket in enumerate(self.buckets):
                if value <= bucket:
                    self._counts[label_values][i] += 1

            self._sums[label_values] += value
            self._totals[label_values] += 1

    def samples(self) -> List[MetricSample]:
        """Get all samples."""
        samples = []
        now = datetime.now(timezone.utc)

        with self._lock:
            for label_values, bucket_counts in self._counts.items():
                base_labels = dict(zip(self.label_names, label_values))

                cumulative = 0
                for i, bucket in enumerate(self.buckets):
                    cumulative += bucket_counts[i]
                    labels = {**base_labels, "le": str(bucket)}
                    samples.append(MetricSample(
                        name=f"{self.name}_bucket",
                        value=cumulative,
                        labels=labels,
                        timestamp=now,
                        metric_type=MetricType.HISTOGRAM,
                    ))

                labels = {**base_labels, "le": "+Inf"}
                samples.append(MetricSample(
                    name=f"{self.name}_bucket",
                    value=self._totals[label_values],
                    labels=labels,
                    timestamp=now,
                    metric_type=MetricType.HISTOGRAM,
                ))

                samples.append(MetricSample(
                    name=f"{self.name}_sum",
                    value=self._sums[label_values],
                    labels=base_labels,
                    timestamp=now,
                    metric_type=MetricType.HISTOGRAM,
                ))

                samples.append(MetricSample(
                    name=f"{self.name}_count",
                    value=self._totals[label_values],
                    labels=base_labels,
                    timestamp=now,
                    metric_type=MetricType.HISTOGRAM,
                ))

        return samples

    def _get_label_values(self, labels: Dict[str, str]) -> Tuple[str, ...]:
        """Get label values as a tuple for indexing."""
        return tuple(labels.get(name, "") for name in self.label_names)


class MetricsCollector:
    """Central metrics collector and registry."""

    def __init__(self):
        self._metrics: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._register_default_metrics()

    def _register_default_metrics(self) -> None:
        """Register default VACP metrics."""
        self.register(Counter(
            "vacp_policy_evaluations_total",
            "Total number of policy evaluations",
            labels=["tenant_id", "decision"],
        ))
        self.register(Histogram(
            "vacp_policy_evaluation_duration_seconds",
            "Policy evaluation duration",
            labels=["tenant_id"],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        ))
        self.register(Counter(
            "vacp_tool_calls_total",
            "Total number of tool calls",
            labels=["tenant_id", "agent_id", "tool_name", "result"],
        ))
        self.register(Counter(
            "vacp_tool_calls_blocked_total",
            "Total number of blocked tool calls",
            labels=["tenant_id", "reason"],
        ))
        self.register(Counter(
            "vacp_injection_attempts_total",
            "Total injection attempts detected",
            labels=["tenant_id", "type"],
        ))
        self.register(Gauge(
            "vacp_active_sessions",
            "Number of active sessions",
            labels=["tenant_id"],
        ))
        self.register(Gauge(
            "vacp_active_agents",
            "Number of active agents",
            labels=["tenant_id"],
        ))

    def register(self, metric: Any) -> None:
        """Register a metric."""
        with self._lock:
            self._metrics[metric.name] = metric

    def get(self, name: str) -> Optional[Any]:
        """Get a metric by name."""
        with self._lock:
            return self._metrics.get(name)

    def counter(self, name: str) -> Optional[Counter]:
        """Get a counter metric."""
        metric = self.get(name)
        return metric if isinstance(metric, Counter) else None

    def gauge(self, name: str) -> Optional[Gauge]:
        """Get a gauge metric."""
        metric = self.get(name)
        return metric if isinstance(metric, Gauge) else None

    def histogram(self, name: str) -> Optional[Histogram]:
        """Get a histogram metric."""
        metric = self.get(name)
        return metric if isinstance(metric, Histogram) else None

    def collect(self) -> List[MetricSample]:
        """Collect all metric samples."""
        samples = []
        with self._lock:
            for metric in self._metrics.values():
                samples.extend(metric.samples())
        return samples

    def to_prometheus(self) -> str:
        """Export all metrics in Prometheus text format."""
        lines = []
        with self._lock:
            for name, metric in sorted(self._metrics.items()):
                lines.append(f"# HELP {name} {metric.description}")
                if isinstance(metric, Counter):
                    lines.append(f"# TYPE {name} counter")
                elif isinstance(metric, Gauge):
                    lines.append(f"# TYPE {name} gauge")
                elif isinstance(metric, Histogram):
                    lines.append(f"# TYPE {name} histogram")
                for sample in metric.samples():
                    lines.append(sample.to_prometheus())
        return "\n".join(lines) + "\n"

    def to_dict(self) -> Dict[str, Any]:
        """Export metrics as a dictionary."""
        result = {}
        with self._lock:
            for name, metric in self._metrics.items():
                samples = metric.samples()
                if not samples:
                    continue
                result[name] = {
                    "description": metric.description,
                    "type": samples[0].metric_type.value,
                    "samples": [{"labels": s.labels, "value": s.value} for s in samples],
                }
        return result


_global_collector: Optional[MetricsCollector] = None


def get_collector() -> MetricsCollector:
    """Get the global metrics collector."""
    global _global_collector
    if _global_collector is None:
        _global_collector = MetricsCollector()
    return _global_collector


def reset_collector() -> None:
    """Reset the global metrics collector."""
    global _global_collector
    _global_collector = None
