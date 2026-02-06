"""
Health Check System for Koba/VACP

Provides:
- Component health monitoring
- System-wide health aggregation
- Dependency checks (database, AI providers, etc.)
- Readiness and liveness probes for Kubernetes
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a single component."""
    name: str
    status: HealthStatus
    message: Optional[str] = None
    last_check: Optional[datetime] = None
    latency_ms: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "latency_ms": self.latency_ms,
            "details": self.details,
        }


@dataclass
class SystemHealth:
    """Aggregated health status of the entire system."""
    status: HealthStatus
    components: List[ComponentHealth]
    timestamp: datetime
    version: Optional[str] = None
    uptime_seconds: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "components": [c.to_dict() for c in self.components],
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "uptime_seconds": self.uptime_seconds,
        }

    @property
    def is_healthy(self) -> bool:
        return self.status == HealthStatus.HEALTHY

    @property
    def is_ready(self) -> bool:
        """Check if the system is ready to serve traffic."""
        return self.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)


# Type alias for health check functions
HealthCheckFunc = Callable[[], ComponentHealth]


class HealthChecker:
    """
    Manages health checks for all system components.

    Features:
    - Register custom health checks
    - Periodic background checks
    - Caching of health results
    - Kubernetes-compatible probes
    """

    def __init__(
        self,
        version: Optional[str] = None,
        check_interval: float = 30.0,
        cache_ttl: float = 10.0,
    ):
        self._version = version
        self._check_interval = check_interval
        self._cache_ttl = cache_ttl
        self._start_time = datetime.now(timezone.utc)

        self._checks: Dict[str, HealthCheckFunc] = {}
        self._cached_results: Dict[str, ComponentHealth] = {}
        self._cache_times: Dict[str, datetime] = {}
        self._lock = threading.Lock()

        self._background_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Register default checks
        self._register_default_checks()

    def _register_default_checks(self) -> None:
        """Register default health checks."""
        # Self check - always healthy if we can run
        self.register("vacp_core", self._check_core)

    def _check_core(self) -> ComponentHealth:
        """Basic core health check."""
        return ComponentHealth(
            name="vacp_core",
            status=HealthStatus.HEALTHY,
            message="VACP core is running",
            last_check=datetime.now(timezone.utc),
            latency_ms=0.0,
        )

    def register(self, name: str, check_func: HealthCheckFunc) -> None:
        """Register a health check function."""
        with self._lock:
            self._checks[name] = check_func

    def unregister(self, name: str) -> bool:
        """Unregister a health check."""
        with self._lock:
            if name in self._checks:
                del self._checks[name]
                if name in self._cached_results:
                    del self._cached_results[name]
                    del self._cache_times[name]
                return True
            return False

    def check_component(self, name: str, use_cache: bool = True) -> Optional[ComponentHealth]:
        """
        Check a specific component's health.

        Args:
            name: Component name
            use_cache: Whether to use cached results

        Returns:
            Component health or None if not found
        """
        with self._lock:
            check_func = self._checks.get(name)
            if check_func is None:
                return None

            # Check cache
            if use_cache and name in self._cached_results:
                cache_time = self._cache_times.get(name)
                if cache_time:
                    age = (datetime.now(timezone.utc) - cache_time).total_seconds()
                    if age < self._cache_ttl:
                        return self._cached_results[name]

        # Run the check (outside lock to avoid blocking)
        start_time = time.perf_counter()
        try:
            result = check_func()
            result.latency_ms = (time.perf_counter() - start_time) * 1000
            result.last_check = datetime.now(timezone.utc)
        except Exception as e:
            logger.error(f"Health check failed for {name}: {e}")
            result = ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check failed: {str(e)}",
                last_check=datetime.now(timezone.utc),
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

        # Update cache
        with self._lock:
            self._cached_results[name] = result
            self._cache_times[name] = datetime.now(timezone.utc)

        return result

    def check_all(self, use_cache: bool = True) -> SystemHealth:
        """
        Check all registered components and return system health.

        Args:
            use_cache: Whether to use cached results

        Returns:
            Aggregated system health
        """
        with self._lock:
            check_names = list(self._checks.keys())

        components = []
        for name in check_names:
            result = self.check_component(name, use_cache=use_cache)
            if result:
                components.append(result)

        # Determine overall status
        system_status = self._aggregate_status(components)

        uptime = (datetime.now(timezone.utc) - self._start_time).total_seconds()

        return SystemHealth(
            status=system_status,
            components=components,
            timestamp=datetime.now(timezone.utc),
            version=self._version,
            uptime_seconds=uptime,
        )

    def _aggregate_status(self, components: List[ComponentHealth]) -> HealthStatus:
        """Determine overall system status from component statuses."""
        if not components:
            return HealthStatus.UNKNOWN

        statuses = [c.status for c in components]

        # Any unhealthy component makes system unhealthy
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY

        # Any degraded component makes system degraded
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED

        # Any unknown makes system degraded
        if HealthStatus.UNKNOWN in statuses:
            return HealthStatus.DEGRADED

        return HealthStatus.HEALTHY

    def liveness(self) -> bool:
        """
        Kubernetes liveness probe.

        Returns True if the application is running (not deadlocked).
        """
        # Basic liveness - can we run code?
        return True

    def readiness(self) -> bool:
        """
        Kubernetes readiness probe.

        Returns True if the application is ready to serve traffic.
        """
        health = self.check_all(use_cache=True)
        return health.is_ready

    def start_background_checks(self) -> None:
        """Start periodic background health checks."""
        if self._background_thread is not None:
            return

        self._stop_event.clear()
        self._background_thread = threading.Thread(
            target=self._background_check_loop,
            daemon=True,
        )
        self._background_thread.start()

    def stop_background_checks(self) -> None:
        """Stop background health checks."""
        self._stop_event.set()
        if self._background_thread:
            self._background_thread.join(timeout=5.0)
            self._background_thread = None

    def _background_check_loop(self) -> None:
        """Background loop for periodic health checks."""
        while not self._stop_event.is_set():
            try:
                self.check_all(use_cache=False)
            except Exception as e:
                logger.error(f"Background health check failed: {e}")

            self._stop_event.wait(self._check_interval)

    def get_component_names(self) -> List[str]:
        """Get list of registered component names."""
        with self._lock:
            return list(self._checks.keys())


def create_database_check(
    name: str,
    check_connection: Callable[[], bool],
    timeout: float = 5.0,
) -> HealthCheckFunc:
    """
    Create a health check function for a database connection.

    Args:
        name: Component name
        check_connection: Function that returns True if DB is connected
        timeout: Timeout in seconds

    Returns:
        Health check function
    """
    def check() -> ComponentHealth:
        try:
            is_connected = check_connection()
            if is_connected:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.HEALTHY,
                    message="Database connection is healthy",
                )
            else:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message="Database connection failed",
                )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Database error: {str(e)}",
            )

    return check


def create_provider_check(
    name: str,
    check_func: Callable[[], bool],
) -> HealthCheckFunc:
    """
    Create a health check function for an AI provider.

    Args:
        name: Component name
        check_func: Function that returns True if provider is available

    Returns:
        Health check function
    """
    def check() -> ComponentHealth:
        try:
            is_available = check_func()
            if is_available:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.HEALTHY,
                    message="Provider is available",
                )
            else:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.DEGRADED,
                    message="Provider is temporarily unavailable",
                )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Provider error: {str(e)}",
            )

    return check


def create_dependency_check(
    name: str,
    url: str,
    timeout: float = 5.0,
) -> HealthCheckFunc:
    """
    Create a health check function for an HTTP dependency.

    Args:
        name: Component name
        url: URL to check
        timeout: Request timeout

    Returns:
        Health check function
    """
    import urllib.request
    import urllib.error

    def check() -> ComponentHealth:
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status < 400:
                    return ComponentHealth(
                        name=name,
                        status=HealthStatus.HEALTHY,
                        message=f"Dependency {name} is reachable",
                        details={"url": url, "status_code": response.status},
                    )
                else:
                    return ComponentHealth(
                        name=name,
                        status=HealthStatus.DEGRADED,
                        message=f"Dependency returned status {response.status}",
                        details={"url": url, "status_code": response.status},
                    )
        except urllib.error.URLError as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Cannot reach dependency: {str(e)}",
                details={"url": url},
            )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Dependency check failed: {str(e)}",
                details={"url": url},
            )

    return check


_global_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """Get the global health checker instance."""
    global _global_checker
    if _global_checker is None:
        _global_checker = HealthChecker()
    return _global_checker


def reset_health_checker() -> None:
    """Reset the global health checker."""
    global _global_checker
    if _global_checker:
        _global_checker.stop_background_checks()
    _global_checker = None
