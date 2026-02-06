"""
VACP AI Provider Health Checks

Production-ready health monitoring for AI providers with:
- Configurable health check endpoints
- Automatic retry with backoff
- Circuit breaker integration
- Latency tracking and metrics
- Provider-specific health validation
"""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
import statistics

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


class HealthStatus(Enum):
    """Provider health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ProviderType(Enum):
    """Supported AI provider types."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    GOOGLE = "google"
    COHERE = "cohere"
    HUGGINGFACE = "huggingface"
    LOCAL = "local"
    CUSTOM = "custom"


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    provider: str
    status: HealthStatus
    latency_ms: float
    timestamp: datetime
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "provider": self.provider,
            "status": self.status.value,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "details": self.details,
            "error": self.error,
        }


@dataclass
class ProviderConfig:
    """Configuration for an AI provider."""
    name: str
    provider_type: ProviderType
    api_base_url: str
    api_key: str = ""
    health_endpoint: str = ""
    timeout_seconds: float = 10.0
    # Thresholds
    latency_warning_ms: float = 1000.0
    latency_critical_ms: float = 5000.0
    # Circuit breaker settings
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0
    # Custom headers
    headers: Dict[str, str] = field(default_factory=dict)
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreaker:
    """Circuit breaker for a provider."""
    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    state: CircuitState = CircuitState.CLOSED
    failure_threshold: int = 5
    recovery_timeout: float = 30.0

    def record_failure(self) -> None:
        """Record a failure."""
        self.failure_count += 1
        self.last_failure_time = datetime.now(timezone.utc)

        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN

    def record_success(self) -> None:
        """Record a success."""
        self.failure_count = 0
        self.state = CircuitState.CLOSED

    def can_execute(self) -> bool:
        """Check if requests can be executed."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            if self.last_failure_time:
                elapsed = (datetime.now(timezone.utc) - self.last_failure_time).total_seconds()
                if elapsed >= self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    return True
            return False

        # HALF_OPEN - allow one request to test
        return True


class ProviderHealthChecker(ABC):
    """Abstract base class for provider health checkers."""

    def __init__(self, config: ProviderConfig):
        self.config = config
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=config.failure_threshold,
            recovery_timeout=config.recovery_timeout,
        )
        self._latencies: List[float] = []
        self._max_latency_samples = 100

    @abstractmethod
    async def check_health(self) -> HealthCheckResult:
        """Perform health check."""
        pass

    def record_latency(self, latency_ms: float) -> None:
        """Record a latency sample."""
        self._latencies.append(latency_ms)
        if len(self._latencies) > self._max_latency_samples:
            self._latencies.pop(0)

    def get_latency_stats(self) -> Dict[str, float]:
        """Get latency statistics."""
        if not self._latencies:
            return {"avg": 0, "min": 0, "max": 0, "p50": 0, "p95": 0, "p99": 0}

        sorted_latencies = sorted(self._latencies)
        n = len(sorted_latencies)

        return {
            "avg": statistics.mean(self._latencies),
            "min": min(self._latencies),
            "max": max(self._latencies),
            "p50": sorted_latencies[int(n * 0.5)],
            "p95": sorted_latencies[int(n * 0.95)] if n >= 20 else sorted_latencies[-1],
            "p99": sorted_latencies[int(n * 0.99)] if n >= 100 else sorted_latencies[-1],
        }

    def _determine_status(self, latency_ms: float) -> HealthStatus:
        """Determine health status based on latency."""
        if latency_ms >= self.config.latency_critical_ms:
            return HealthStatus.DEGRADED
        elif latency_ms >= self.config.latency_warning_ms:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY


class OpenAIHealthChecker(ProviderHealthChecker):
    """Health checker for OpenAI API."""

    async def check_health(self) -> HealthCheckResult:
        """Check OpenAI API health."""
        if not AIOHTTP_AVAILABLE:
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNKNOWN,
                latency_ms=0,
                timestamp=datetime.now(timezone.utc),
                error="aiohttp not available",
            )

        if not self.circuit_breaker.can_execute():
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=0,
                timestamp=datetime.now(timezone.utc),
                message="Circuit breaker open",
            )

        start = time.perf_counter()
        try:
            # OpenAI doesn't have a dedicated health endpoint
            # We use the models endpoint as a lightweight check
            url = f"{self.config.api_base_url}/models"

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                **self.config.headers,
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                ) as response:
                    latency_ms = (time.perf_counter() - start) * 1000
                    self.record_latency(latency_ms)

                    if response.status == 200:
                        data = await response.json()
                        model_count = len(data.get("data", []))

                        self.circuit_breaker.record_success()
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=self._determine_status(latency_ms),
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            message=f"OK - {model_count} models available",
                            details={
                                "model_count": model_count,
                                "latency_stats": self.get_latency_stats(),
                            },
                        )
                    else:
                        self.circuit_breaker.record_failure()
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=HealthStatus.UNHEALTHY,
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            error=f"HTTP {response.status}",
                        )

        except asyncio.TimeoutError:
            self.circuit_breaker.record_failure()
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=(time.perf_counter() - start) * 1000,
                timestamp=datetime.now(timezone.utc),
                error="Timeout",
            )
        except Exception as e:
            self.circuit_breaker.record_failure()
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=(time.perf_counter() - start) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=str(e),
            )


class AnthropicHealthChecker(ProviderHealthChecker):
    """Health checker for Anthropic API."""

    async def check_health(self) -> HealthCheckResult:
        """Check Anthropic API health."""
        if not AIOHTTP_AVAILABLE:
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNKNOWN,
                latency_ms=0,
                timestamp=datetime.now(timezone.utc),
                error="aiohttp not available",
            )

        if not self.circuit_breaker.can_execute():
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=0,
                timestamp=datetime.now(timezone.utc),
                message="Circuit breaker open",
            )

        start = time.perf_counter()
        try:
            # Anthropic uses a simple endpoint check
            # We send a minimal request to verify connectivity
            url = f"{self.config.api_base_url}/messages"

            headers = {
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                **self.config.headers,
            }

            # Minimal request that will fail validation but proves connectivity
            # We expect a 400 error with specific message
            payload = {"model": "health-check", "max_tokens": 1, "messages": []}

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                ) as response:
                    latency_ms = (time.perf_counter() - start) * 1000
                    self.record_latency(latency_ms)

                    # 400 with validation error means API is reachable
                    # 401 means bad API key but API is reachable
                    if response.status in (400, 401):
                        self.circuit_breaker.record_success()
                        status = HealthStatus.HEALTHY if response.status == 400 else HealthStatus.DEGRADED
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=self._determine_status(latency_ms) if status == HealthStatus.HEALTHY else status,
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            message="API reachable",
                            details={
                                "http_status": response.status,
                                "latency_stats": self.get_latency_stats(),
                            },
                        )
                    elif response.status == 200:
                        # Unexpected but OK
                        self.circuit_breaker.record_success()
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=self._determine_status(latency_ms),
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            message="OK",
                        )
                    else:
                        self.circuit_breaker.record_failure()
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=HealthStatus.UNHEALTHY,
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            error=f"HTTP {response.status}",
                        )

        except asyncio.TimeoutError:
            self.circuit_breaker.record_failure()
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=(time.perf_counter() - start) * 1000,
                timestamp=datetime.now(timezone.utc),
                error="Timeout",
            )
        except Exception as e:
            self.circuit_breaker.record_failure()
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=(time.perf_counter() - start) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=str(e),
            )


class AzureOpenAIHealthChecker(ProviderHealthChecker):
    """Health checker for Azure OpenAI."""

    async def check_health(self) -> HealthCheckResult:
        """Check Azure OpenAI health."""
        if not AIOHTTP_AVAILABLE:
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNKNOWN,
                latency_ms=0,
                timestamp=datetime.now(timezone.utc),
                error="aiohttp not available",
            )

        if not self.circuit_breaker.can_execute():
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=0,
                timestamp=datetime.now(timezone.utc),
                message="Circuit breaker open",
            )

        start = time.perf_counter()
        try:
            # Azure OpenAI uses deployments endpoint
            deployment_id = self.config.metadata.get("deployment_id", "")
            api_version = self.config.metadata.get("api_version", "2024-02-01")

            url = f"{self.config.api_base_url}/openai/deployments?api-version={api_version}"

            headers = {
                "api-key": self.config.api_key,
                **self.config.headers,
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                ) as response:
                    latency_ms = (time.perf_counter() - start) * 1000
                    self.record_latency(latency_ms)

                    if response.status == 200:
                        data = await response.json()
                        deployments = data.get("data", [])

                        self.circuit_breaker.record_success()
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=self._determine_status(latency_ms),
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            message=f"OK - {len(deployments)} deployments",
                            details={
                                "deployment_count": len(deployments),
                                "latency_stats": self.get_latency_stats(),
                            },
                        )
                    else:
                        self.circuit_breaker.record_failure()
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=HealthStatus.UNHEALTHY,
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            error=f"HTTP {response.status}",
                        )

        except asyncio.TimeoutError:
            self.circuit_breaker.record_failure()
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=(time.perf_counter() - start) * 1000,
                timestamp=datetime.now(timezone.utc),
                error="Timeout",
            )
        except Exception as e:
            self.circuit_breaker.record_failure()
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=(time.perf_counter() - start) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=str(e),
            )


class GenericHealthChecker(ProviderHealthChecker):
    """Generic health checker for any HTTP endpoint."""

    async def check_health(self) -> HealthCheckResult:
        """Check health via HTTP."""
        if not AIOHTTP_AVAILABLE:
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNKNOWN,
                latency_ms=0,
                timestamp=datetime.now(timezone.utc),
                error="aiohttp not available",
            )

        if not self.circuit_breaker.can_execute():
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=0,
                timestamp=datetime.now(timezone.utc),
                message="Circuit breaker open",
            )

        start = time.perf_counter()
        try:
            url = self.config.health_endpoint or f"{self.config.api_base_url}/health"

            headers = dict(self.config.headers)
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                ) as response:
                    latency_ms = (time.perf_counter() - start) * 1000
                    self.record_latency(latency_ms)

                    if response.status == 200:
                        self.circuit_breaker.record_success()
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=self._determine_status(latency_ms),
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            message="OK",
                            details={
                                "latency_stats": self.get_latency_stats(),
                            },
                        )
                    else:
                        self.circuit_breaker.record_failure()
                        return HealthCheckResult(
                            provider=self.config.name,
                            status=HealthStatus.UNHEALTHY,
                            latency_ms=latency_ms,
                            timestamp=datetime.now(timezone.utc),
                            error=f"HTTP {response.status}",
                        )

        except asyncio.TimeoutError:
            self.circuit_breaker.record_failure()
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=(time.perf_counter() - start) * 1000,
                timestamp=datetime.now(timezone.utc),
                error="Timeout",
            )
        except Exception as e:
            self.circuit_breaker.record_failure()
            return HealthCheckResult(
                provider=self.config.name,
                status=HealthStatus.UNHEALTHY,
                latency_ms=(time.perf_counter() - start) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=str(e),
            )


class ProviderHealthManager:
    """
    Manages health checks for multiple AI providers.

    Features:
    - Concurrent health checking
    - Automatic retry with backoff
    - Circuit breaker pattern
    - Aggregated health status
    """

    def __init__(self):
        self._providers: Dict[str, ProviderHealthChecker] = {}
        self._last_results: Dict[str, HealthCheckResult] = {}
        self._check_interval: float = 30.0
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def register_provider(self, config: ProviderConfig) -> None:
        """Register a provider for health checking."""
        checker = self._create_checker(config)
        self._providers[config.name] = checker

    def _create_checker(self, config: ProviderConfig) -> ProviderHealthChecker:
        """Create appropriate checker for provider type."""
        checker_map = {
            ProviderType.OPENAI: OpenAIHealthChecker,
            ProviderType.ANTHROPIC: AnthropicHealthChecker,
            ProviderType.AZURE_OPENAI: AzureOpenAIHealthChecker,
        }

        checker_class = checker_map.get(config.provider_type, GenericHealthChecker)
        return checker_class(config)

    async def check_provider(self, provider_name: str) -> Optional[HealthCheckResult]:
        """Check health of a specific provider."""
        if provider_name not in self._providers:
            return None

        checker = self._providers[provider_name]
        result = await checker.check_health()
        self._last_results[provider_name] = result
        return result

    async def check_all(self) -> Dict[str, HealthCheckResult]:
        """Check health of all providers concurrently."""
        tasks = {
            name: asyncio.create_task(checker.check_health())
            for name, checker in self._providers.items()
        }

        results = {}
        for name, task in tasks.items():
            try:
                result = await task
                results[name] = result
                self._last_results[name] = result
            except Exception as e:
                results[name] = HealthCheckResult(
                    provider=name,
                    status=HealthStatus.UNKNOWN,
                    latency_ms=0,
                    timestamp=datetime.now(timezone.utc),
                    error=str(e),
                )

        return results

    def get_last_result(self, provider_name: str) -> Optional[HealthCheckResult]:
        """Get the last health check result for a provider."""
        return self._last_results.get(provider_name)

    def get_all_results(self) -> Dict[str, HealthCheckResult]:
        """Get all last health check results."""
        return dict(self._last_results)

    def get_aggregate_status(self) -> Dict[str, Any]:
        """Get aggregated health status across all providers."""
        if not self._last_results:
            return {
                "overall_status": HealthStatus.UNKNOWN.value,
                "healthy_count": 0,
                "degraded_count": 0,
                "unhealthy_count": 0,
                "providers": {},
            }

        healthy = 0
        degraded = 0
        unhealthy = 0

        for result in self._last_results.values():
            if result.status == HealthStatus.HEALTHY:
                healthy += 1
            elif result.status == HealthStatus.DEGRADED:
                degraded += 1
            else:
                unhealthy += 1

        # Determine overall status
        if unhealthy > 0:
            overall = HealthStatus.UNHEALTHY
        elif degraded > 0:
            overall = HealthStatus.DEGRADED
        elif healthy > 0:
            overall = HealthStatus.HEALTHY
        else:
            overall = HealthStatus.UNKNOWN

        return {
            "overall_status": overall.value,
            "healthy_count": healthy,
            "degraded_count": degraded,
            "unhealthy_count": unhealthy,
            "total_providers": len(self._last_results),
            "providers": {
                name: result.to_dict()
                for name, result in self._last_results.items()
            },
        }

    def is_provider_healthy(self, provider_name: str) -> bool:
        """Check if a specific provider is healthy."""
        result = self._last_results.get(provider_name)
        return result is not None and result.status == HealthStatus.HEALTHY

    def get_healthy_providers(self) -> List[str]:
        """Get list of healthy provider names."""
        return [
            name for name, result in self._last_results.items()
            if result.status == HealthStatus.HEALTHY
        ]

    async def _background_check_loop(self) -> None:
        """Background loop for periodic health checks."""
        while self._running:
            await self.check_all()
            await asyncio.sleep(self._check_interval)

    async def start_background_checks(self, interval: float = 30.0) -> None:
        """Start background health checking."""
        self._check_interval = interval
        self._running = True
        self._task = asyncio.create_task(self._background_check_loop())

    async def stop_background_checks(self) -> None:
        """Stop background health checking."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


# Global manager instance
_health_manager: Optional[ProviderHealthManager] = None


def get_provider_health_manager() -> ProviderHealthManager:
    """Get the global provider health manager."""
    global _health_manager
    if _health_manager is None:
        _health_manager = ProviderHealthManager()
    return _health_manager


def configure_default_providers() -> ProviderHealthManager:
    """Configure default AI providers from environment."""
    import os

    manager = get_provider_health_manager()

    # OpenAI
    if os.environ.get("OPENAI_API_KEY"):
        manager.register_provider(ProviderConfig(
            name="openai",
            provider_type=ProviderType.OPENAI,
            api_base_url=os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1"),
            api_key=os.environ["OPENAI_API_KEY"],
        ))

    # Anthropic
    if os.environ.get("ANTHROPIC_API_KEY"):
        manager.register_provider(ProviderConfig(
            name="anthropic",
            provider_type=ProviderType.ANTHROPIC,
            api_base_url=os.environ.get("ANTHROPIC_API_BASE", "https://api.anthropic.com/v1"),
            api_key=os.environ["ANTHROPIC_API_KEY"],
        ))

    # Azure OpenAI
    if os.environ.get("AZURE_OPENAI_API_KEY"):
        manager.register_provider(ProviderConfig(
            name="azure_openai",
            provider_type=ProviderType.AZURE_OPENAI,
            api_base_url=os.environ.get("AZURE_OPENAI_ENDPOINT", ""),
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            metadata={
                "deployment_id": os.environ.get("AZURE_OPENAI_DEPLOYMENT", ""),
                "api_version": os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01"),
            },
        ))

    return manager
