"""
Tests for VACP AI Provider Health Checks.

Tests covering:
- Individual provider health checkers
- Circuit breaker functionality
- Health status aggregation
- Latency tracking
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vacp.core.provider_health import (
    CircuitBreaker,
    CircuitState,
    GenericHealthChecker,
    HealthCheckResult,
    HealthStatus,
    ProviderConfig,
    ProviderHealthManager,
    ProviderType,
    get_provider_health_manager,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def openai_config():
    """Create OpenAI provider config."""
    return ProviderConfig(
        name="openai-test",
        provider_type=ProviderType.OPENAI,
        api_base_url="https://api.openai.com/v1",
        api_key="test-key",
        timeout_seconds=5.0,
        latency_warning_ms=500.0,
        latency_critical_ms=2000.0,
    )


@pytest.fixture
def anthropic_config():
    """Create Anthropic provider config."""
    return ProviderConfig(
        name="anthropic-test",
        provider_type=ProviderType.ANTHROPIC,
        api_base_url="https://api.anthropic.com/v1",
        api_key="test-key",
        timeout_seconds=5.0,
    )


@pytest.fixture
def generic_config():
    """Create generic provider config."""
    return ProviderConfig(
        name="generic-test",
        provider_type=ProviderType.CUSTOM,
        api_base_url="https://api.example.com",
        health_endpoint="https://api.example.com/health",
        timeout_seconds=5.0,
    )


@pytest.fixture
def health_manager():
    """Create a fresh health manager."""
    return ProviderHealthManager()


# =============================================================================
# Test HealthCheckResult
# =============================================================================


class TestHealthCheckResult:
    """Tests for HealthCheckResult dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        now = datetime.now(timezone.utc)
        result = HealthCheckResult(
            provider="test-provider",
            status=HealthStatus.HEALTHY,
            latency_ms=150.5,
            timestamp=now,
            message="OK",
            details={"model_count": 10},
        )

        data = result.to_dict()

        assert data["provider"] == "test-provider"
        assert data["status"] == "healthy"
        assert data["latency_ms"] == 150.5
        assert data["message"] == "OK"
        assert data["details"]["model_count"] == 10
        assert data["error"] is None

    def test_to_dict_with_error(self):
        """Test conversion with error."""
        result = HealthCheckResult(
            provider="test",
            status=HealthStatus.UNHEALTHY,
            latency_ms=0,
            timestamp=datetime.now(timezone.utc),
            error="Connection refused",
        )

        data = result.to_dict()

        assert data["status"] == "unhealthy"
        assert data["error"] == "Connection refused"


# =============================================================================
# Test CircuitBreaker
# =============================================================================


class TestCircuitBreaker:
    """Tests for CircuitBreaker."""

    def test_initial_state_closed(self):
        """Test circuit breaker starts closed."""
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute() is True

    def test_opens_after_threshold(self):
        """Test circuit opens after failure threshold."""
        cb = CircuitBreaker(failure_threshold=3)

        for _ in range(3):
            cb.record_failure()

        assert cb.state == CircuitState.OPEN
        assert cb.can_execute() is False

    def test_success_resets_count(self):
        """Test success resets failure count."""
        cb = CircuitBreaker(failure_threshold=3)

        cb.record_failure()
        cb.record_failure()
        assert cb.failure_count == 2

        cb.record_success()
        assert cb.failure_count == 0
        assert cb.state == CircuitState.CLOSED

    def test_half_open_after_timeout(self):
        """Test circuit becomes half-open after timeout."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)

        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.can_execute() is False

        # Wait for recovery timeout
        import time
        time.sleep(0.15)

        assert cb.can_execute() is True
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_success_closes(self):
        """Test successful request in half-open state closes circuit."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0)

        cb.record_failure()
        cb.state = CircuitState.HALF_OPEN

        cb.record_success()
        assert cb.state == CircuitState.CLOSED


# =============================================================================
# Test GenericHealthChecker
# =============================================================================


class TestGenericHealthChecker:
    """Tests for GenericHealthChecker."""

    @pytest.mark.asyncio
    async def test_healthy_response(self, generic_config):
        """Test healthy response handling."""
        checker = GenericHealthChecker(generic_config)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = MagicMock()
            session_instance.get.return_value = mock_response
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock(return_value=None)
            mock_session.return_value = session_instance

            result = await checker.check_health()

            assert result.status == HealthStatus.HEALTHY
            assert result.latency_ms > 0

    @pytest.mark.asyncio
    async def test_unhealthy_response(self, generic_config):
        """Test unhealthy response handling."""
        checker = GenericHealthChecker(generic_config)

        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = MagicMock()
            session_instance.get.return_value = mock_response
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock(return_value=None)
            mock_session.return_value = session_instance

            result = await checker.check_health()

            assert result.status == HealthStatus.UNHEALTHY
            assert "500" in result.error

    @pytest.mark.asyncio
    async def test_timeout_handling(self, generic_config):
        """Test timeout handling."""
        checker = GenericHealthChecker(generic_config)

        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = MagicMock()
            session_instance.get.side_effect = asyncio.TimeoutError()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock(return_value=None)
            mock_session.return_value = session_instance

            result = await checker.check_health()

            assert result.status == HealthStatus.UNHEALTHY
            assert "Timeout" in result.error

    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks(self, generic_config):
        """Test circuit breaker prevents requests when open."""
        checker = GenericHealthChecker(generic_config)

        # Force circuit open
        checker.circuit_breaker.state = CircuitState.OPEN
        checker.circuit_breaker.last_failure_time = datetime.now(timezone.utc)

        result = await checker.check_health()

        assert result.status == HealthStatus.UNHEALTHY
        assert "Circuit breaker" in result.message

    def test_latency_recording(self, generic_config):
        """Test latency statistics tracking."""
        checker = GenericHealthChecker(generic_config)

        # Record some latencies
        for latency in [100, 150, 200, 250, 300]:
            checker.record_latency(latency)

        stats = checker.get_latency_stats()

        assert stats["avg"] == 200.0
        assert stats["min"] == 100
        assert stats["max"] == 300

    def test_latency_max_samples(self, generic_config):
        """Test latency sample limit."""
        checker = GenericHealthChecker(generic_config)
        checker._max_latency_samples = 5

        for i in range(10):
            checker.record_latency(float(i * 100))

        assert len(checker._latencies) == 5
        # Should have the last 5 samples
        assert checker._latencies[0] == 500.0

    def test_status_determination(self, generic_config):
        """Test status determination based on latency."""
        # Set specific thresholds for testing
        generic_config.latency_warning_ms = 500.0
        generic_config.latency_critical_ms = 2000.0
        checker = GenericHealthChecker(generic_config)

        assert checker._determine_status(100) == HealthStatus.HEALTHY
        assert checker._determine_status(600) == HealthStatus.DEGRADED  # > warning
        assert checker._determine_status(3000) == HealthStatus.DEGRADED  # > critical


# =============================================================================
# Test ProviderHealthManager
# =============================================================================


class TestProviderHealthManager:
    """Tests for ProviderHealthManager."""

    def test_register_provider(self, health_manager, openai_config):
        """Test provider registration."""
        health_manager.register_provider(openai_config)

        assert "openai-test" in health_manager._providers

    @pytest.mark.asyncio
    async def test_check_provider(self, health_manager, generic_config):
        """Test checking a single provider."""
        health_manager.register_provider(generic_config)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = MagicMock()
            session_instance.get.return_value = mock_response
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock(return_value=None)
            mock_session.return_value = session_instance

            result = await health_manager.check_provider("generic-test")

            assert result is not None
            assert result.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_check_unknown_provider(self, health_manager):
        """Test checking unknown provider returns None."""
        result = await health_manager.check_provider("unknown")
        assert result is None

    @pytest.mark.asyncio
    async def test_check_all(self, health_manager, generic_config):
        """Test checking all providers."""
        # Register multiple providers
        config1 = ProviderConfig(
            name="provider1",
            provider_type=ProviderType.CUSTOM,
            api_base_url="https://api1.example.com",
            health_endpoint="https://api1.example.com/health",
        )
        config2 = ProviderConfig(
            name="provider2",
            provider_type=ProviderType.CUSTOM,
            api_base_url="https://api2.example.com",
            health_endpoint="https://api2.example.com/health",
        )

        health_manager.register_provider(config1)
        health_manager.register_provider(config2)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = MagicMock()
            session_instance.get.return_value = mock_response
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock(return_value=None)
            mock_session.return_value = session_instance

            results = await health_manager.check_all()

            assert len(results) == 2
            assert "provider1" in results
            assert "provider2" in results

    def test_get_last_result(self, health_manager):
        """Test getting last result."""
        result = HealthCheckResult(
            provider="test",
            status=HealthStatus.HEALTHY,
            latency_ms=100,
            timestamp=datetime.now(timezone.utc),
        )
        health_manager._last_results["test"] = result

        retrieved = health_manager.get_last_result("test")
        assert retrieved == result

    def test_get_last_result_unknown(self, health_manager):
        """Test getting result for unknown provider."""
        assert health_manager.get_last_result("unknown") is None

    def test_get_aggregate_status_empty(self, health_manager):
        """Test aggregate status with no providers."""
        status = health_manager.get_aggregate_status()

        assert status["overall_status"] == "unknown"
        assert status["healthy_count"] == 0

    def test_get_aggregate_status_all_healthy(self, health_manager):
        """Test aggregate status when all healthy."""
        for i in range(3):
            health_manager._last_results[f"provider{i}"] = HealthCheckResult(
                provider=f"provider{i}",
                status=HealthStatus.HEALTHY,
                latency_ms=100,
                timestamp=datetime.now(timezone.utc),
            )

        status = health_manager.get_aggregate_status()

        assert status["overall_status"] == "healthy"
        assert status["healthy_count"] == 3
        assert status["unhealthy_count"] == 0

    def test_get_aggregate_status_mixed(self, health_manager):
        """Test aggregate status with mixed health."""
        health_manager._last_results["healthy1"] = HealthCheckResult(
            provider="healthy1",
            status=HealthStatus.HEALTHY,
            latency_ms=100,
            timestamp=datetime.now(timezone.utc),
        )
        health_manager._last_results["degraded1"] = HealthCheckResult(
            provider="degraded1",
            status=HealthStatus.DEGRADED,
            latency_ms=500,
            timestamp=datetime.now(timezone.utc),
        )
        health_manager._last_results["unhealthy1"] = HealthCheckResult(
            provider="unhealthy1",
            status=HealthStatus.UNHEALTHY,
            latency_ms=0,
            timestamp=datetime.now(timezone.utc),
        )

        status = health_manager.get_aggregate_status()

        assert status["overall_status"] == "unhealthy"
        assert status["healthy_count"] == 1
        assert status["degraded_count"] == 1
        assert status["unhealthy_count"] == 1

    def test_is_provider_healthy(self, health_manager):
        """Test checking if provider is healthy."""
        health_manager._last_results["healthy"] = HealthCheckResult(
            provider="healthy",
            status=HealthStatus.HEALTHY,
            latency_ms=100,
            timestamp=datetime.now(timezone.utc),
        )
        health_manager._last_results["unhealthy"] = HealthCheckResult(
            provider="unhealthy",
            status=HealthStatus.UNHEALTHY,
            latency_ms=0,
            timestamp=datetime.now(timezone.utc),
        )

        assert health_manager.is_provider_healthy("healthy") is True
        assert health_manager.is_provider_healthy("unhealthy") is False
        assert health_manager.is_provider_healthy("unknown") is False

    def test_get_healthy_providers(self, health_manager):
        """Test getting list of healthy providers."""
        health_manager._last_results["healthy1"] = HealthCheckResult(
            provider="healthy1",
            status=HealthStatus.HEALTHY,
            latency_ms=100,
            timestamp=datetime.now(timezone.utc),
        )
        health_manager._last_results["healthy2"] = HealthCheckResult(
            provider="healthy2",
            status=HealthStatus.HEALTHY,
            latency_ms=150,
            timestamp=datetime.now(timezone.utc),
        )
        health_manager._last_results["unhealthy"] = HealthCheckResult(
            provider="unhealthy",
            status=HealthStatus.UNHEALTHY,
            latency_ms=0,
            timestamp=datetime.now(timezone.utc),
        )

        healthy = health_manager.get_healthy_providers()

        assert len(healthy) == 2
        assert "healthy1" in healthy
        assert "healthy2" in healthy
        assert "unhealthy" not in healthy


# =============================================================================
# Test Global Functions
# =============================================================================


class TestGlobalFunctions:
    """Tests for global helper functions."""

    def test_get_provider_health_manager_singleton(self):
        """Test singleton pattern."""
        import vacp.core.provider_health as module
        module._health_manager = None

        manager1 = get_provider_health_manager()
        manager2 = get_provider_health_manager()

        assert manager1 is manager2


# =============================================================================
# Test Background Checks
# =============================================================================


class TestBackgroundChecks:
    """Tests for background health checking."""

    @pytest.mark.asyncio
    async def test_start_and_stop_background_checks(self, health_manager):
        """Test starting and stopping background checks."""
        await health_manager.start_background_checks(interval=0.1)

        assert health_manager._running is True
        assert health_manager._task is not None

        await health_manager.stop_background_checks()

        assert health_manager._running is False

    @pytest.mark.asyncio
    async def test_background_checks_run(self, health_manager, generic_config):
        """Test that background checks actually run."""
        health_manager.register_provider(generic_config)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = MagicMock()
            session_instance.get.return_value = mock_response
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock(return_value=None)
            mock_session.return_value = session_instance

            await health_manager.start_background_checks(interval=0.1)

            # Wait for at least one check
            await asyncio.sleep(0.2)

            await health_manager.stop_background_checks()

            # Should have results now
            result = health_manager.get_last_result("generic-test")
            assert result is not None


# =============================================================================
# Test ProviderConfig
# =============================================================================


class TestProviderConfig:
    """Tests for ProviderConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ProviderConfig(
            name="test",
            provider_type=ProviderType.CUSTOM,
            api_base_url="https://api.example.com",
        )

        assert config.timeout_seconds == 10.0
        assert config.latency_warning_ms == 1000.0
        assert config.latency_critical_ms == 5000.0
        assert config.failure_threshold == 5
        assert config.max_retries == 3

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ProviderConfig(
            name="custom",
            provider_type=ProviderType.OPENAI,
            api_base_url="https://custom.api.com",
            api_key="secret-key",
            timeout_seconds=30.0,
            latency_warning_ms=500.0,
            headers={"X-Custom": "value"},
            metadata={"region": "us-east"},
        )

        assert config.timeout_seconds == 30.0
        assert config.latency_warning_ms == 500.0
        assert config.headers["X-Custom"] == "value"
        assert config.metadata["region"] == "us-east"
