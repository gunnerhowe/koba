"""
API Middleware for VACP

Production-ready middleware components:
- Rate limiting with sliding window
- Request tracing
- Security headers
- Metrics collection
"""

import asyncio
import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
import threading
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_size: int = 10
    enabled: bool = True
    # Exempt paths from rate limiting
    exempt_paths: List[str] = field(default_factory=lambda: ["/health", "/metrics"])
    # Different limits per endpoint pattern
    endpoint_limits: Dict[str, int] = field(default_factory=dict)


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter with sub-second precision.

    Uses a combination of fixed window and sliding log for efficiency
    while maintaining accuracy.
    """

    def __init__(self):
        self._windows: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._cleanup_interval = 60  # Cleanup every 60 seconds
        self._last_cleanup = time.time()

    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int, float]:
        """
        Check if request is allowed under rate limit.

        Returns:
            Tuple of (allowed, remaining, retry_after_seconds)
        """
        now = time.time()
        window_start = now - window_seconds

        with self._lock:
            # Cleanup old entries periodically
            if now - self._last_cleanup > self._cleanup_interval:
                self._cleanup_old_entries(window_start)
                self._last_cleanup = now

            # Get timestamps for this key
            timestamps = self._windows[key]

            # Remove expired entries
            timestamps = [ts for ts in timestamps if ts > window_start]
            self._windows[key] = timestamps

            # Check if allowed
            current_count = len(timestamps)

            if current_count >= max_requests:
                # Calculate retry-after based on oldest timestamp
                oldest = min(timestamps) if timestamps else now
                retry_after = oldest + window_seconds - now
                return False, 0, max(0, retry_after)

            # Add current request
            timestamps.append(now)
            self._windows[key] = timestamps

            remaining = max_requests - len(timestamps)
            return True, remaining, 0

    def _cleanup_old_entries(self, cutoff: float) -> None:
        """Remove entries older than cutoff."""
        keys_to_delete = []
        for key, timestamps in self._windows.items():
            self._windows[key] = [ts for ts in timestamps if ts > cutoff]
            if not self._windows[key]:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self._windows[key]

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        with self._lock:
            return {
                "active_keys": len(self._windows),
                "total_entries": sum(len(ts) for ts in self._windows.values()),
            }


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using sliding window algorithm.

    Features:
    - Per-IP and per-API-key rate limiting
    - Configurable limits per endpoint
    - Proper rate limit headers (RateLimit-*)
    - Graceful degradation
    """

    def __init__(self, app, config: Optional[RateLimitConfig] = None):
        super().__init__(app)
        self.config = config or RateLimitConfig()
        self.limiter = SlidingWindowRateLimiter()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.config.enabled:
            return await call_next(request)

        # Skip exempt paths
        path = request.url.path
        if any(path.startswith(exempt) for exempt in self.config.exempt_paths):
            return await call_next(request)

        # Get rate limit key (prefer API key, fall back to IP)
        key = self._get_rate_limit_key(request)

        # Get limit for this endpoint
        limit = self._get_limit_for_path(path)

        # Check rate limit (per minute)
        allowed, remaining, retry_after = self.limiter.is_allowed(
            key=f"{key}:minute",
            max_requests=limit,
            window_seconds=60,
        )

        if not allowed:
            return self._rate_limit_response(remaining, retry_after)

        # Also check hourly limit
        hourly_allowed, hourly_remaining, hourly_retry = self.limiter.is_allowed(
            key=f"{key}:hour",
            max_requests=self.config.requests_per_hour,
            window_seconds=3600,
        )

        if not hourly_allowed:
            return self._rate_limit_response(hourly_remaining, hourly_retry)

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + 60))

        return response

    def _get_rate_limit_key(self, request: Request) -> str:
        """Get the key to use for rate limiting."""
        # Prefer API key if present
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"apikey:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"

        # Use client IP
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"

        return f"ip:{ip}"

    def _get_limit_for_path(self, path: str) -> int:
        """Get the rate limit for a specific path."""
        # Check endpoint-specific limits
        for pattern, limit in self.config.endpoint_limits.items():
            if path.startswith(pattern):
                return limit

        # Default limit
        return self.config.requests_per_minute

    def _rate_limit_response(self, remaining: int, retry_after: float) -> Response:
        """Generate rate limit exceeded response."""
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "code": "RATE_LIMIT_EXCEEDED",
                "retry_after_seconds": int(retry_after) + 1,
            },
            headers={
                "X-RateLimit-Remaining": "0",
                "Retry-After": str(int(retry_after) + 1),
            },
        )


@dataclass
class RequestTrace:
    """A single request trace."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> Optional[float]:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return None


class RequestTracingMiddleware(BaseHTTPMiddleware):
    """
    Request tracing middleware for observability.

    Implements W3C Trace Context propagation.
    """

    def __init__(self, app, service_name: str = "vacp"):
        super().__init__(app)
        self.service_name = service_name
        self._traces: List[RequestTrace] = []
        self._lock = threading.Lock()
        self._max_traces = 10000

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Extract or generate trace context
        traceparent = request.headers.get("traceparent")
        trace_id, parent_span_id = self._parse_traceparent(traceparent)

        if not trace_id:
            trace_id = uuid.uuid4().hex

        span_id = uuid.uuid4().hex[:16]

        # Create trace
        trace = RequestTrace(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation=f"{request.method} {request.url.path}",
            start_time=datetime.now(timezone.utc),
            attributes={
                "http.method": request.method,
                "http.url": str(request.url),
                "http.host": request.headers.get("host"),
                "http.user_agent": request.headers.get("user-agent"),
                "service.name": self.service_name,
            },
        )

        # Store trace ID in request state for use in handlers
        request.state.trace_id = trace_id
        request.state.span_id = span_id

        try:
            response = await call_next(request)
            trace.status_code = response.status_code
            trace.end_time = datetime.now(timezone.utc)

            # Add trace headers to response
            response.headers["X-Trace-ID"] = trace_id
            response.headers["X-Span-ID"] = span_id

            # Store trace
            self._store_trace(trace)

            return response

        except Exception as e:
            trace.error = str(e)
            trace.end_time = datetime.now(timezone.utc)
            self._store_trace(trace)
            raise

    def _parse_traceparent(self, traceparent: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        """Parse W3C traceparent header."""
        if not traceparent:
            return None, None

        try:
            parts = traceparent.split("-")
            if len(parts) >= 3:
                return parts[1], parts[2]
        except Exception:
            pass

        return None, None

    def _store_trace(self, trace: RequestTrace) -> None:
        """Store trace for later export."""
        with self._lock:
            self._traces.append(trace)
            # Trim old traces
            if len(self._traces) > self._max_traces:
                self._traces = self._traces[-self._max_traces:]

    def get_recent_traces(self, limit: int = 100) -> List[RequestTrace]:
        """Get recent traces."""
        with self._lock:
            return list(self._traces[-limit:])

    def get_trace_by_id(self, trace_id: str) -> List[RequestTrace]:
        """Get all spans for a trace ID."""
        with self._lock:
            return [t for t in self._traces if t.trace_id == trace_id]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to responses.

    Implements OWASP security header recommendations.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Remove server identification (if present)
        if "Server" in response.headers:
            del response.headers["Server"]

        return response


class MetricsCollector:
    """
    Collects API metrics for Prometheus export.
    """

    def __init__(self):
        self._request_count: Dict[Tuple[str, str, int], int] = defaultdict(int)
        self._request_latency: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self._active_requests: int = 0
        self._lock = threading.Lock()

    def record_request(
        self,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
    ) -> None:
        """Record a request."""
        with self._lock:
            # Normalize path to avoid cardinality explosion
            normalized_path = self._normalize_path(path)

            self._request_count[(method, normalized_path, status_code)] += 1

            latency_key = (method, normalized_path)
            self._request_latency[latency_key].append(latency_ms)

            # Keep only recent latencies
            if len(self._request_latency[latency_key]) > 1000:
                self._request_latency[latency_key] = self._request_latency[latency_key][-1000:]

    def _normalize_path(self, path: str) -> str:
        """Normalize path to reduce cardinality."""
        # Replace UUIDs and IDs with placeholders
        import re

        # UUID pattern
        path = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{id}',
            path,
            flags=re.IGNORECASE
        )

        # Numeric IDs
        path = re.sub(r'/\d+(?=/|$)', '/{id}', path)

        return path

    def increment_active(self) -> None:
        with self._lock:
            self._active_requests += 1

    def decrement_active(self) -> None:
        with self._lock:
            self._active_requests = max(0, self._active_requests - 1)

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []

        with self._lock:
            # Request count
            lines.append("# HELP vacp_http_requests_total Total HTTP requests")
            lines.append("# TYPE vacp_http_requests_total counter")
            for (method, path, status), count in self._request_count.items():
                lines.append(
                    f'vacp_http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}'
                )

            # Active requests
            lines.append("# HELP vacp_http_requests_active Active HTTP requests")
            lines.append("# TYPE vacp_http_requests_active gauge")
            lines.append(f"vacp_http_requests_active {self._active_requests}")

            # Request latency histogram
            lines.append("# HELP vacp_http_request_duration_ms HTTP request duration in milliseconds")
            lines.append("# TYPE vacp_http_request_duration_ms histogram")

            buckets = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]

            for (method, path), latencies in self._request_latency.items():
                if not latencies:
                    continue

                # Calculate bucket counts
                for bucket in buckets:
                    count = sum(1 for l in latencies if l <= bucket)
                    lines.append(
                        f'vacp_http_request_duration_ms_bucket{{method="{method}",path="{path}",le="{bucket}"}} {count}'
                    )

                # +Inf bucket
                lines.append(
                    f'vacp_http_request_duration_ms_bucket{{method="{method}",path="{path}",le="+Inf"}} {len(latencies)}'
                )

                # Sum and count
                lines.append(
                    f'vacp_http_request_duration_ms_sum{{method="{method}",path="{path}"}} {sum(latencies)}'
                )
                lines.append(
                    f'vacp_http_request_duration_ms_count{{method="{method}",path="{path}"}} {len(latencies)}'
                )

        return "\n".join(lines)


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Middleware to collect request metrics.
    """

    def __init__(self, app, collector: MetricsCollector):
        super().__init__(app)
        self.collector = collector

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        self.collector.increment_active()
        start_time = time.time()

        try:
            response = await call_next(request)

            latency_ms = (time.time() - start_time) * 1000
            self.collector.record_request(
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                latency_ms=latency_ms,
            )

            return response

        finally:
            self.collector.decrement_active()


# Circuit breaker implementation
@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5
    success_threshold: int = 3
    timeout_seconds: float = 30.0
    half_open_max_calls: int = 3


class CircuitBreakerState:
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """
    Circuit breaker for external service calls.

    Prevents cascading failures by failing fast when a service is down.
    """

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            self._check_state_transition()
            return self._state

    def _check_state_transition(self) -> None:
        """Check if state should transition."""
        if self._state == CircuitBreakerState.OPEN:
            if self._last_failure_time:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.config.timeout_seconds:
                    self._state = CircuitBreakerState.HALF_OPEN
                    self._half_open_calls = 0
                    self._success_count = 0

    def allow_request(self) -> bool:
        """Check if request should be allowed."""
        with self._lock:
            self._check_state_transition()

            if self._state == CircuitBreakerState.CLOSED:
                return True

            if self._state == CircuitBreakerState.OPEN:
                return False

            # Half-open: allow limited requests
            if self._half_open_calls < self.config.half_open_max_calls:
                self._half_open_calls += 1
                return True

            return False

    def record_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._state = CircuitBreakerState.CLOSED
                    self._failure_count = 0
            else:
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitBreakerState.HALF_OPEN:
                self._state = CircuitBreakerState.OPEN
            elif self._failure_count >= self.config.failure_threshold:
                self._state = CircuitBreakerState.OPEN

    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker stats."""
        with self._lock:
            return {
                "name": self.name,
                "state": self._state,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "last_failure_time": self._last_failure_time,
            }


class CircuitBreakerRegistry:
    """Registry for circuit breakers."""

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def get_or_create(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ) -> CircuitBreaker:
        """Get or create a circuit breaker."""
        with self._lock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(name, config)
            return self._breakers[name]

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get stats for all circuit breakers."""
        with self._lock:
            return {name: cb.get_stats() for name, cb in self._breakers.items()}


# Global registry
circuit_breaker_registry = CircuitBreakerRegistry()
