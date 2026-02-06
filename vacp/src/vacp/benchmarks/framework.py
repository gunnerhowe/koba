"""
Benchmark Framework for Koba/VACP

Provides infrastructure for running, measuring, and reporting performance benchmarks.
"""

import gc
import statistics
import threading
import time
import tracemalloc
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    name: str
    iterations: int
    total_time_seconds: float
    min_time_seconds: float
    max_time_seconds: float
    mean_time_seconds: float
    median_time_seconds: float
    std_dev_seconds: float
    operations_per_second: float
    memory_peak_mb: float
    memory_allocated_mb: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: int = 0
    error_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "iterations": self.iterations,
            "total_time_seconds": round(self.total_time_seconds, 6),
            "min_time_seconds": round(self.min_time_seconds, 6),
            "max_time_seconds": round(self.max_time_seconds, 6),
            "mean_time_seconds": round(self.mean_time_seconds, 6),
            "median_time_seconds": round(self.median_time_seconds, 6),
            "std_dev_seconds": round(self.std_dev_seconds, 6),
            "operations_per_second": round(self.operations_per_second, 2),
            "memory_peak_mb": round(self.memory_peak_mb, 2),
            "memory_allocated_mb": round(self.memory_allocated_mb, 2),
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "errors": self.errors,
            "error_rate": round(self.error_rate, 4),
        }

    def summary(self) -> str:
        """Return a human-readable summary."""
        return (
            f"{self.name}:\n"
            f"  Iterations: {self.iterations:,}\n"
            f"  Total time: {self.total_time_seconds:.3f}s\n"
            f"  Mean: {self.mean_time_seconds * 1000:.3f}ms\n"
            f"  Min: {self.min_time_seconds * 1000:.3f}ms\n"
            f"  Max: {self.max_time_seconds * 1000:.3f}ms\n"
            f"  Std Dev: {self.std_dev_seconds * 1000:.3f}ms\n"
            f"  Ops/sec: {self.operations_per_second:,.2f}\n"
            f"  Memory Peak: {self.memory_peak_mb:.2f}MB\n"
            f"  Errors: {self.errors} ({self.error_rate:.2%})"
        )


@dataclass
class LoadTestResult:
    """Result of a load test."""
    name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    duration_seconds: float
    requests_per_second: float
    mean_latency_seconds: float
    p50_latency_seconds: float
    p95_latency_seconds: float
    p99_latency_seconds: float
    max_latency_seconds: float
    concurrent_users: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    errors_by_type: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "duration_seconds": round(self.duration_seconds, 3),
            "requests_per_second": round(self.requests_per_second, 2),
            "mean_latency_seconds": round(self.mean_latency_seconds, 6),
            "p50_latency_seconds": round(self.p50_latency_seconds, 6),
            "p95_latency_seconds": round(self.p95_latency_seconds, 6),
            "p99_latency_seconds": round(self.p99_latency_seconds, 6),
            "max_latency_seconds": round(self.max_latency_seconds, 6),
            "concurrent_users": self.concurrent_users,
            "timestamp": self.timestamp.isoformat(),
            "errors_by_type": self.errors_by_type,
        }

    def summary(self) -> str:
        """Return a human-readable summary."""
        return (
            f"{self.name}:\n"
            f"  Total Requests: {self.total_requests:,}\n"
            f"  Successful: {self.successful_requests:,}\n"
            f"  Failed: {self.failed_requests:,}\n"
            f"  Duration: {self.duration_seconds:.2f}s\n"
            f"  RPS: {self.requests_per_second:,.2f}\n"
            f"  Mean Latency: {self.mean_latency_seconds * 1000:.3f}ms\n"
            f"  P50: {self.p50_latency_seconds * 1000:.3f}ms\n"
            f"  P95: {self.p95_latency_seconds * 1000:.3f}ms\n"
            f"  P99: {self.p99_latency_seconds * 1000:.3f}ms\n"
            f"  Max: {self.max_latency_seconds * 1000:.3f}ms\n"
            f"  Concurrent Users: {self.concurrent_users}"
        )


class Benchmark(ABC):
    """Base class for benchmarks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Benchmark name."""
        pass

    @abstractmethod
    def setup(self) -> None:
        """Setup before running benchmark."""
        pass

    @abstractmethod
    def teardown(self) -> None:
        """Cleanup after benchmark."""
        pass

    @abstractmethod
    def run_iteration(self) -> None:
        """Run a single benchmark iteration."""
        pass

    def warmup(self, iterations: int = 10) -> None:
        """Warmup iterations (not measured)."""
        for _ in range(iterations):
            try:
                self.run_iteration()
            except Exception:
                pass


def run_benchmark(
    benchmark: Benchmark,
    iterations: int = 1000,
    warmup_iterations: int = 100,
    track_memory: bool = True,
) -> BenchmarkResult:
    """
    Run a benchmark and collect statistics.

    Args:
        benchmark: The benchmark to run
        iterations: Number of iterations
        warmup_iterations: Warmup iterations (not measured)
        track_memory: Whether to track memory usage

    Returns:
        BenchmarkResult with statistics
    """
    # Setup
    benchmark.setup()

    # Warmup
    benchmark.warmup(warmup_iterations)

    # Force garbage collection before timing
    gc.collect()

    # Start memory tracking
    if track_memory:
        tracemalloc.start()
        tracemalloc.reset_peak()

    # Run benchmark
    times: List[float] = []
    errors = 0

    start_total = time.perf_counter()

    for _ in range(iterations):
        start = time.perf_counter()
        try:
            benchmark.run_iteration()
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        except Exception as e:
            errors += 1
            logger.debug(f"Benchmark iteration error: {e}")

    end_total = time.perf_counter()
    total_time = end_total - start_total

    # Get memory stats
    memory_peak = 0.0
    memory_allocated = 0.0
    if track_memory:
        current, peak = tracemalloc.get_traced_memory()
        memory_peak = peak / (1024 * 1024)  # Convert to MB
        memory_allocated = current / (1024 * 1024)
        tracemalloc.stop()

    # Teardown
    benchmark.teardown()

    # Calculate statistics
    if times:
        result = BenchmarkResult(
            name=benchmark.name,
            iterations=iterations,
            total_time_seconds=total_time,
            min_time_seconds=min(times),
            max_time_seconds=max(times),
            mean_time_seconds=statistics.mean(times),
            median_time_seconds=statistics.median(times),
            std_dev_seconds=statistics.stdev(times) if len(times) > 1 else 0.0,
            operations_per_second=len(times) / total_time if total_time > 0 else 0,
            memory_peak_mb=memory_peak,
            memory_allocated_mb=memory_allocated,
            errors=errors,
            error_rate=errors / iterations if iterations > 0 else 0,
        )
    else:
        result = BenchmarkResult(
            name=benchmark.name,
            iterations=iterations,
            total_time_seconds=total_time,
            min_time_seconds=0,
            max_time_seconds=0,
            mean_time_seconds=0,
            median_time_seconds=0,
            std_dev_seconds=0,
            operations_per_second=0,
            memory_peak_mb=memory_peak,
            memory_allocated_mb=memory_allocated,
            errors=errors,
            error_rate=1.0,
        )

    return result


def run_load_test(
    operation: Callable[[], None],
    name: str = "LoadTest",
    total_requests: int = 1000,
    concurrent_users: int = 10,
    duration_seconds: Optional[float] = None,
) -> LoadTestResult:
    """
    Run a load test with concurrent users.

    Args:
        operation: Function to call for each request
        name: Test name
        total_requests: Total number of requests
        concurrent_users: Number of concurrent threads
        duration_seconds: Optional duration limit

    Returns:
        LoadTestResult with statistics
    """
    latencies: List[float] = []
    errors_by_type: Dict[str, int] = {}
    successful = 0
    failed = 0
    lock = threading.Lock()
    stop_event = threading.Event()

    def worker(request_num: int) -> Tuple[bool, float, Optional[str]]:
        if stop_event.is_set():
            return False, 0.0, "stopped"

        start = time.perf_counter()
        try:
            operation()
            elapsed = time.perf_counter() - start
            return True, elapsed, None
        except Exception as e:
            elapsed = time.perf_counter() - start
            return False, elapsed, type(e).__name__

    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
        futures = []

        for i in range(total_requests):
            if duration_seconds and (time.perf_counter() - start_time) >= duration_seconds:
                stop_event.set()
                break
            futures.append(executor.submit(worker, i))

        for future in as_completed(futures):
            success, latency, error_type = future.result()
            with lock:
                latencies.append(latency)
                if success:
                    successful += 1
                else:
                    failed += 1
                    if error_type:
                        errors_by_type[error_type] = errors_by_type.get(error_type, 0) + 1

    end_time = time.perf_counter()
    duration = end_time - start_time

    # Calculate percentiles
    sorted_latencies = sorted(latencies)
    n = len(sorted_latencies)

    def percentile(p: float) -> float:
        if not sorted_latencies:
            return 0.0
        k = int(n * p / 100)
        return sorted_latencies[min(k, n - 1)]

    return LoadTestResult(
        name=name,
        total_requests=len(latencies),
        successful_requests=successful,
        failed_requests=failed,
        duration_seconds=duration,
        requests_per_second=len(latencies) / duration if duration > 0 else 0,
        mean_latency_seconds=statistics.mean(latencies) if latencies else 0,
        p50_latency_seconds=percentile(50),
        p95_latency_seconds=percentile(95),
        p99_latency_seconds=percentile(99),
        max_latency_seconds=max(latencies) if latencies else 0,
        concurrent_users=concurrent_users,
        errors_by_type=errors_by_type,
    )


class BenchmarkSuite:
    """Collection of benchmarks to run together."""

    def __init__(self, name: str = "BenchmarkSuite"):
        self.name = name
        self._benchmarks: List[Benchmark] = []
        self._results: List[BenchmarkResult] = []

    def add(self, benchmark: Benchmark) -> None:
        """Add a benchmark to the suite."""
        self._benchmarks.append(benchmark)

    def run_all(
        self,
        iterations: int = 1000,
        warmup_iterations: int = 100,
    ) -> List[BenchmarkResult]:
        """
        Run all benchmarks in the suite.

        Returns list of results.
        """
        self._results = []

        for benchmark in self._benchmarks:
            logger.info(f"Running benchmark: {benchmark.name}")
            result = run_benchmark(
                benchmark,
                iterations=iterations,
                warmup_iterations=warmup_iterations,
            )
            self._results.append(result)
            logger.info(f"Completed: {result.operations_per_second:.2f} ops/sec")

        return self._results

    def get_results(self) -> List[BenchmarkResult]:
        """Get all benchmark results."""
        return self._results

    def format_report(self) -> str:
        """Format results as a report."""
        if not self._results:
            return "No benchmark results available."

        lines = [
            f"Benchmark Suite: {self.name}",
            "=" * 60,
            "",
        ]

        for result in self._results:
            lines.append(result.summary())
            lines.append("")

        return "\n".join(lines)


def format_results(results: List[BenchmarkResult]) -> str:
    """Format benchmark results as a table."""
    if not results:
        return "No results"

    headers = ["Name", "Iterations", "Mean (ms)", "Min (ms)", "Max (ms)", "Ops/sec", "Errors"]
    rows = []

    for r in results:
        rows.append([
            r.name,
            f"{r.iterations:,}",
            f"{r.mean_time_seconds * 1000:.3f}",
            f"{r.min_time_seconds * 1000:.3f}",
            f"{r.max_time_seconds * 1000:.3f}",
            f"{r.operations_per_second:,.2f}",
            str(r.errors),
        ])

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    # Format table
    separator = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    header_line = "|" + "|".join(f" {h:^{w}} " for h, w in zip(headers, widths)) + "|"

    lines = [separator, header_line, separator]
    for row in rows:
        row_line = "|" + "|".join(f" {c:>{w}} " for c, w in zip(row, widths)) + "|"
        lines.append(row_line)
    lines.append(separator)

    return "\n".join(lines)


def compare_results(
    baseline: BenchmarkResult,
    current: BenchmarkResult,
) -> Dict[str, Any]:
    """
    Compare two benchmark results.

    Returns comparison with improvement percentages.
    """
    def calc_diff(old: float, new: float) -> Tuple[float, str]:
        if old == 0:
            return 0.0, "N/A"
        diff = ((new - old) / old) * 100
        direction = "faster" if diff < 0 else "slower"
        return abs(diff), direction

    mean_diff, mean_dir = calc_diff(baseline.mean_time_seconds, current.mean_time_seconds)
    ops_diff = ((current.operations_per_second - baseline.operations_per_second) /
                baseline.operations_per_second * 100) if baseline.operations_per_second > 0 else 0

    return {
        "baseline_name": baseline.name,
        "current_name": current.name,
        "mean_time_change_percent": mean_diff,
        "mean_time_direction": mean_dir,
        "ops_per_second_change_percent": ops_diff,
        "baseline_ops_per_second": baseline.operations_per_second,
        "current_ops_per_second": current.operations_per_second,
        "memory_peak_change_mb": current.memory_peak_mb - baseline.memory_peak_mb,
    }
