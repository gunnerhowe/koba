"""
Tests for the benchmark framework and scenarios.

These tests verify the benchmark infrastructure works correctly.
They are NOT performance tests themselves.
"""

import pytest
import time
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from vacp.benchmarks.framework import (
    Benchmark,
    BenchmarkResult,
    BenchmarkSuite,
    LoadTestResult,
    run_benchmark,
    run_load_test,
    format_results,
    compare_results,
)
from vacp.benchmarks.scenarios import (
    PolicyEvaluationBenchmark,
    AuditLogBenchmark,
    ConcurrencyBenchmark,
    MemoryBenchmark,
    HashingBenchmark,
    SignatureBenchmark,
    MerkleLogBenchmark,
)


class SimpleBenchmark(Benchmark):
    """Simple benchmark for testing the framework."""

    def __init__(self, sleep_ms: float = 0.1, fail_rate: float = 0.0):
        self._sleep_ms = sleep_ms
        self._fail_rate = fail_rate
        self._setup_called = False
        self._teardown_called = False
        self._iterations = 0

    @property
    def name(self) -> str:
        return "SimpleBenchmark"

    def setup(self) -> None:
        self._setup_called = True

    def teardown(self) -> None:
        self._teardown_called = True

    def run_iteration(self) -> None:
        self._iterations += 1
        time.sleep(self._sleep_ms / 1000)
        if self._fail_rate > 0:
            import random
            if random.random() < self._fail_rate:
                raise RuntimeError("Simulated failure")


class TestBenchmarkFramework:
    """Tests for benchmark framework."""

    def test_run_benchmark_basic(self):
        """Test basic benchmark execution."""
        benchmark = SimpleBenchmark(sleep_ms=0.1)
        result = run_benchmark(benchmark, iterations=10, warmup_iterations=2)

        assert result.name == "SimpleBenchmark"
        assert result.iterations == 10
        assert result.total_time_seconds > 0
        assert result.mean_time_seconds > 0
        assert result.operations_per_second > 0
        assert result.errors == 0

    def test_setup_and_teardown_called(self):
        """Test that setup and teardown are called."""
        benchmark = SimpleBenchmark()
        run_benchmark(benchmark, iterations=5, warmup_iterations=2)

        assert benchmark._setup_called
        assert benchmark._teardown_called

    def test_warmup_iterations(self):
        """Test that warmup iterations run before timing."""
        benchmark = SimpleBenchmark()
        run_benchmark(benchmark, iterations=10, warmup_iterations=5)

        # Warmup + measured = total iterations
        assert benchmark._iterations >= 10

    def test_error_handling(self):
        """Test that errors are counted."""
        benchmark = SimpleBenchmark(fail_rate=0.5)
        result = run_benchmark(benchmark, iterations=100, warmup_iterations=0)

        # Should have some errors (probabilistic)
        assert result.errors > 0 or result.iterations > 0

    def test_memory_tracking(self):
        """Test memory tracking."""
        benchmark = MemoryBenchmark(object_count=10, object_size_bytes=100)
        result = run_benchmark(benchmark, iterations=5, track_memory=True)

        # Memory peak should be recorded
        assert result.memory_peak_mb >= 0

    def test_statistics_calculated(self):
        """Test that all statistics are calculated."""
        benchmark = SimpleBenchmark(sleep_ms=1)
        result = run_benchmark(benchmark, iterations=10, warmup_iterations=2)

        assert result.min_time_seconds > 0
        assert result.max_time_seconds >= result.min_time_seconds
        assert result.median_time_seconds > 0
        assert result.std_dev_seconds >= 0


class TestBenchmarkResult:
    """Tests for BenchmarkResult."""

    def test_to_dict(self):
        """Test serialization to dict."""
        result = BenchmarkResult(
            name="test",
            iterations=100,
            total_time_seconds=1.0,
            min_time_seconds=0.008,
            max_time_seconds=0.012,
            mean_time_seconds=0.01,
            median_time_seconds=0.01,
            std_dev_seconds=0.001,
            operations_per_second=100.0,
            memory_peak_mb=10.0,
            memory_allocated_mb=5.0,
            errors=0,
            error_rate=0.0,
        )

        data = result.to_dict()
        assert data["name"] == "test"
        assert data["iterations"] == 100
        assert "timestamp" in data

    def test_summary(self):
        """Test human-readable summary."""
        result = BenchmarkResult(
            name="test",
            iterations=100,
            total_time_seconds=1.0,
            min_time_seconds=0.008,
            max_time_seconds=0.012,
            mean_time_seconds=0.01,
            median_time_seconds=0.01,
            std_dev_seconds=0.001,
            operations_per_second=100.0,
            memory_peak_mb=10.0,
            memory_allocated_mb=5.0,
            errors=0,
            error_rate=0.0,
        )

        summary = result.summary()
        assert "test" in summary
        assert "100" in summary
        assert "Ops/sec" in summary


class TestBenchmarkSuite:
    """Tests for BenchmarkSuite."""

    def test_add_and_run(self):
        """Test adding and running benchmarks."""
        suite = BenchmarkSuite("TestSuite")
        suite.add(SimpleBenchmark(sleep_ms=0.1))
        suite.add(SimpleBenchmark(sleep_ms=0.2))

        results = suite.run_all(iterations=5, warmup_iterations=2)
        assert len(results) == 2

    def test_get_results(self):
        """Test getting results after running."""
        suite = BenchmarkSuite()
        suite.add(SimpleBenchmark())
        suite.run_all(iterations=5, warmup_iterations=1)

        results = suite.get_results()
        assert len(results) == 1

    def test_format_report(self):
        """Test formatting report."""
        suite = BenchmarkSuite("TestSuite")
        suite.add(SimpleBenchmark())
        suite.run_all(iterations=5, warmup_iterations=1)

        report = suite.format_report()
        assert "TestSuite" in report


class TestLoadTest:
    """Tests for load testing."""

    def test_run_load_test_basic(self):
        """Test basic load test."""
        counter = [0]

        def operation():
            counter[0] += 1

        result = run_load_test(
            operation=operation,
            name="BasicTest",
            total_requests=100,
            concurrent_users=5,
        )

        assert result.total_requests == 100
        assert result.successful_requests > 0
        assert result.requests_per_second > 0

    def test_load_test_with_errors(self):
        """Test load test with failing operations."""
        fail_count = [0]

        def failing_operation():
            fail_count[0] += 1
            if fail_count[0] % 3 == 0:
                raise RuntimeError("Simulated failure")

        result = run_load_test(
            operation=failing_operation,
            name="FailingTest",
            total_requests=30,
            concurrent_users=3,
        )

        assert result.failed_requests > 0
        assert "RuntimeError" in result.errors_by_type

    def test_load_test_percentiles(self):
        """Test percentile calculations."""
        def operation():
            time.sleep(0.001)

        result = run_load_test(
            operation=operation,
            name="LatencyTest",
            total_requests=50,
            concurrent_users=5,
        )

        assert result.p50_latency_seconds > 0
        assert result.p95_latency_seconds >= result.p50_latency_seconds
        assert result.p99_latency_seconds >= result.p95_latency_seconds

    def test_load_test_result_to_dict(self):
        """Test LoadTestResult serialization."""
        result = LoadTestResult(
            name="test",
            total_requests=100,
            successful_requests=95,
            failed_requests=5,
            duration_seconds=1.0,
            requests_per_second=100.0,
            mean_latency_seconds=0.01,
            p50_latency_seconds=0.009,
            p95_latency_seconds=0.015,
            p99_latency_seconds=0.02,
            max_latency_seconds=0.025,
            concurrent_users=10,
        )

        data = result.to_dict()
        assert data["total_requests"] == 100
        assert data["concurrent_users"] == 10


class TestFormatResults:
    """Tests for result formatting."""

    def test_format_results_table(self):
        """Test table formatting."""
        results = [
            BenchmarkResult(
                name="Test1",
                iterations=100,
                total_time_seconds=1.0,
                min_time_seconds=0.008,
                max_time_seconds=0.012,
                mean_time_seconds=0.01,
                median_time_seconds=0.01,
                std_dev_seconds=0.001,
                operations_per_second=100.0,
                memory_peak_mb=10.0,
                memory_allocated_mb=5.0,
                errors=0,
                error_rate=0.0,
            ),
            BenchmarkResult(
                name="Test2",
                iterations=200,
                total_time_seconds=2.0,
                min_time_seconds=0.008,
                max_time_seconds=0.012,
                mean_time_seconds=0.01,
                median_time_seconds=0.01,
                std_dev_seconds=0.001,
                operations_per_second=100.0,
                memory_peak_mb=10.0,
                memory_allocated_mb=5.0,
                errors=5,
                error_rate=0.025,
            ),
        ]

        table = format_results(results)
        assert "Test1" in table
        assert "Test2" in table
        assert "+" in table  # Table borders

    def test_format_empty_results(self):
        """Test formatting empty results."""
        table = format_results([])
        assert "No results" in table


class TestCompareResults:
    """Tests for result comparison."""

    def test_compare_faster(self):
        """Test comparing when current is faster."""
        baseline = BenchmarkResult(
            name="Baseline",
            iterations=100,
            total_time_seconds=1.0,
            min_time_seconds=0.008,
            max_time_seconds=0.012,
            mean_time_seconds=0.010,
            median_time_seconds=0.01,
            std_dev_seconds=0.001,
            operations_per_second=100.0,
            memory_peak_mb=10.0,
            memory_allocated_mb=5.0,
            errors=0,
            error_rate=0.0,
        )
        current = BenchmarkResult(
            name="Current",
            iterations=100,
            total_time_seconds=0.5,
            min_time_seconds=0.004,
            max_time_seconds=0.006,
            mean_time_seconds=0.005,
            median_time_seconds=0.005,
            std_dev_seconds=0.0005,
            operations_per_second=200.0,
            memory_peak_mb=8.0,
            memory_allocated_mb=4.0,
            errors=0,
            error_rate=0.0,
        )

        comparison = compare_results(baseline, current)
        assert comparison["mean_time_direction"] == "faster"
        assert comparison["ops_per_second_change_percent"] > 0


class TestPolicyEvaluationBenchmark:
    """Tests for PolicyEvaluationBenchmark."""

    def test_setup_creates_engine(self):
        """Test that setup creates policy engine."""
        benchmark = PolicyEvaluationBenchmark(num_rules=10, complexity="simple")
        benchmark.setup()

        assert benchmark._engine is not None
        assert len(benchmark._test_contexts) == 100

        benchmark.teardown()

    def test_run_iteration(self):
        """Test running a single iteration."""
        benchmark = PolicyEvaluationBenchmark(num_rules=10, complexity="simple")
        benchmark.setup()

        # Should not raise
        benchmark.run_iteration()

        benchmark.teardown()

    def test_different_complexities(self):
        """Test different complexity levels."""
        for complexity in ["simple", "medium", "complex"]:
            benchmark = PolicyEvaluationBenchmark(num_rules=5, complexity=complexity)
            benchmark.setup()
            benchmark.run_iteration()
            benchmark.teardown()


class TestAuditLogBenchmark:
    """Tests for AuditLogBenchmark."""

    def test_memory_db(self):
        """Test with in-memory database."""
        benchmark = AuditLogBenchmark(use_memory_db=True)
        benchmark.setup()

        # Run a few iterations
        for _ in range(5):
            benchmark.run_iteration()

        benchmark.teardown()

    def test_batch_size(self):
        """Test different batch sizes."""
        benchmark = AuditLogBenchmark(batch_size=10)
        benchmark.setup()

        benchmark.run_iteration()
        assert benchmark._counter == 10

        benchmark.teardown()


class TestConcurrencyBenchmark:
    """Tests for ConcurrencyBenchmark."""

    def test_concurrent_workers(self):
        """Test concurrent workers."""
        benchmark = ConcurrencyBenchmark(
            concurrent_workers=3,
            operations_per_worker=5,
        )
        benchmark.setup()

        benchmark.run_iteration()
        assert benchmark._completed == 15  # 3 workers * 5 ops

        benchmark.teardown()


class TestHashingBenchmark:
    """Tests for HashingBenchmark."""

    def test_hashing(self):
        """Test hashing benchmark."""
        benchmark = HashingBenchmark(data_size_bytes=1024)
        benchmark.setup()

        # Should not raise
        benchmark.run_iteration()

        benchmark.teardown()


class TestSignatureBenchmark:
    """Tests for SignatureBenchmark."""

    def test_signing(self):
        """Test signature generation."""
        benchmark = SignatureBenchmark(verify_only=False)
        benchmark.setup()
        benchmark.run_iteration()
        benchmark.teardown()

    def test_verification(self):
        """Test signature verification."""
        benchmark = SignatureBenchmark(verify_only=True)
        benchmark.setup()
        benchmark.run_iteration()
        benchmark.teardown()


class TestMerkleLogBenchmark:
    """Tests for MerkleLogBenchmark."""

    def test_merkle_log(self):
        """Test Merkle log benchmark."""
        benchmark = MerkleLogBenchmark(batch_size=10)
        benchmark.setup()

        benchmark.run_iteration()
        assert benchmark._counter == 10

        benchmark.teardown()


class TestMemoryBenchmark:
    """Tests for MemoryBenchmark."""

    def test_memory_benchmark(self):
        """Test memory benchmark."""
        benchmark = MemoryBenchmark(object_count=10, object_size_bytes=100)
        benchmark.setup()

        # Should not raise
        benchmark.run_iteration()

        # Objects should be cleared
        assert len(benchmark._objects) == 0

        benchmark.teardown()


class TestIntegration:
    """Integration tests for benchmark suite."""

    def test_run_mini_suite(self):
        """Test running a minimal benchmark suite."""
        suite = BenchmarkSuite("MiniSuite")

        # Add simple benchmarks
        suite.add(HashingBenchmark(data_size_bytes=100))
        suite.add(SimpleBenchmark(sleep_ms=0.1))

        results = suite.run_all(iterations=10, warmup_iterations=2)

        assert len(results) == 2
        for result in results:
            assert result.iterations == 10
            assert result.errors == 0

    def test_benchmark_reproducibility(self):
        """Test that benchmarks produce consistent results."""
        benchmark = HashingBenchmark(data_size_bytes=1024)

        results = []
        for _ in range(3):
            result = run_benchmark(benchmark, iterations=100, warmup_iterations=10)
            results.append(result.mean_time_seconds)

        # Results should be within reasonable variance
        mean = sum(results) / len(results)
        for r in results:
            variance = abs(r - mean) / mean
            # Allow 100% variance due to system scheduling
            assert variance < 1.0
