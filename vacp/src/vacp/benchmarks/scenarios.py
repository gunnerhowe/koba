"""
Benchmark Scenarios for Koba/VACP

Specific benchmark implementations for VACP components:
- Policy evaluation
- Audit log operations
- Concurrent request handling
- Memory usage
"""

import gc
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vacp.benchmarks.framework import (
    Benchmark,
    BenchmarkResult,
    LoadTestResult,
    run_benchmark,
    run_load_test,
)
from vacp.core.policy import PolicyEngine, PolicyBundle, PolicyRule, PolicyDecision
from vacp.core.crypto import generate_random_id
from vacp.storage.sqlite import SQLiteBackend


class PolicyEvaluationBenchmark(Benchmark):
    """Benchmark for policy evaluation performance."""

    def __init__(
        self,
        num_rules: int = 100,
        num_patterns: int = 10,
        complexity: str = "medium",
    ):
        self._num_rules = num_rules
        self._num_patterns = num_patterns
        self._complexity = complexity
        self._engine: Optional[PolicyEngine] = None
        self._test_contexts: List[Dict[str, Any]] = []

    @property
    def name(self) -> str:
        return f"PolicyEvaluation_{self._num_rules}rules_{self._complexity}"

    def setup(self) -> None:
        """Create policy engine with rules."""
        self._engine = PolicyEngine()

        # Create rules based on complexity
        rules = []
        for i in range(self._num_rules):
            rule = PolicyRule(
                id=f"rule_{i}",
                name=f"Test Rule {i}",
                description=f"Test rule {i}",
                priority=i,
                tool_patterns=[f"tool_{i % 10}"] if self._complexity != "complex" else [f"tool_{i % 10}_*"],
                decision=PolicyDecision.DENY if i % 3 == 0 else PolicyDecision.ALLOW,
            )
            rules.append(rule)

        bundle = PolicyBundle(
            id="test_bundle",
            version="1.0.0",
            name="Benchmark Policy Bundle",
            rules=rules,
            created_at=datetime.now(timezone.utc),
        )
        self._engine.load_bundle(bundle)

        # Generate test contexts
        self._test_contexts = [
            self._generate_context(i) for i in range(100)
        ]

    def _generate_context(self, index: int) -> Dict[str, Any]:
        """Generate evaluation context."""
        return {
            "tenant_id": "benchmark_tenant",
            "agent_id": f"agent_{index % 5}",
            "tool_name": f"tool_{index % 10}",
            "session_id": f"session_{index}",
            "request_data": {
                "action": ["read", "write", "execute", "delete"][index % 4],
                "level": index % 10,
                "resource": f"resource_{index}",
            },
        }

    def teardown(self) -> None:
        """Cleanup."""
        self._engine = None
        self._test_contexts = []

    def run_iteration(self) -> None:
        """Evaluate policy with a random context."""
        context = self._test_contexts[secrets.randbelow(len(self._test_contexts))]
        from vacp.core.policy import PolicyEvaluationContext
        eval_ctx = PolicyEvaluationContext(
            tenant_id=context["tenant_id"],
            agent_id=context["agent_id"],
            tool_name=context["tool_name"],
            session_id=context["session_id"],
            request_data=context["request_data"],
        )
        self._engine.evaluate(eval_ctx)


class AuditLogBenchmark(Benchmark):
    """Benchmark for audit log write performance."""

    def __init__(
        self,
        use_memory_db: bool = True,
        batch_size: int = 1,
    ):
        self._use_memory_db = use_memory_db
        self._batch_size = batch_size
        self._storage: Optional[SQLiteBackend] = None
        self._counter = 0

    @property
    def name(self) -> str:
        db_type = "memory" if self._use_memory_db else "file"
        return f"AuditLogWrite_{db_type}_batch{self._batch_size}"

    def setup(self) -> None:
        """Setup storage backend."""
        if self._use_memory_db:
            self._storage = SQLiteBackend(":memory:")
        else:
            import tempfile
            self._temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
            self._storage = SQLiteBackend(self._temp_file.name)
        self._storage.initialize()
        self._counter = 0

    def teardown(self) -> None:
        """Cleanup."""
        if self._storage:
            self._storage.close()
        self._storage = None
        if hasattr(self, '_temp_file'):
            import os
            os.unlink(self._temp_file.name)

    def run_iteration(self) -> None:
        """Write audit log entries."""
        for _ in range(self._batch_size):
            self._storage.append_entry(
                entry_type="tool_call",
                agent_id="benchmark_agent",
                tenant_id="benchmark_tenant",
                action="execute",
                data={
                    "tool_name": "benchmark_tool",
                    "arguments": {"arg1": "value1", "arg2": self._counter},
                    "result": "success",
                },
            )
            self._counter += 1


class ConcurrencyBenchmark(Benchmark):
    """Benchmark for concurrent request handling."""

    def __init__(
        self,
        concurrent_workers: int = 10,
        operations_per_worker: int = 10,
    ):
        self._concurrent_workers = concurrent_workers
        self._operations_per_worker = operations_per_worker
        self._engine: Optional[PolicyEngine] = None
        self._lock = threading.Lock()
        self._completed = 0

    @property
    def name(self) -> str:
        return f"Concurrency_{self._concurrent_workers}workers_{self._operations_per_worker}ops"

    def setup(self) -> None:
        """Setup policy engine."""
        self._engine = PolicyEngine()

        # Create simple rules
        rules = [
            PolicyRule(
                id=f"rule_{i}",
                name=f"Rule {i}",
                description="Test",
                priority=i,
                tool_patterns=[f"tool_{i % 5}"],
                decision=PolicyDecision.ALLOW,
            )
            for i in range(10)
        ]

        bundle = PolicyBundle(
            id="concurrent_test",
            version="1.0.0",
            name="Concurrent Benchmark Bundle",
            rules=rules,
            created_at=datetime.now(timezone.utc),
        )
        self._engine.load_bundle(bundle)
        self._completed = 0

    def teardown(self) -> None:
        """Cleanup."""
        self._engine = None

    def run_iteration(self) -> None:
        """Run concurrent policy evaluations."""
        from vacp.core.policy import PolicyEvaluationContext

        def worker(worker_id: int) -> int:
            completed = 0
            for i in range(self._operations_per_worker):
                ctx = PolicyEvaluationContext(
                    tenant_id="benchmark",
                    agent_id=f"agent_{worker_id}",
                    tool_name=f"tool_{i % 5}",
                    session_id=f"session_{worker_id}",
                    request_data={"op": i},
                )
                self._engine.evaluate(ctx)
                completed += 1
            return completed

        with ThreadPoolExecutor(max_workers=self._concurrent_workers) as executor:
            futures = [executor.submit(worker, i) for i in range(self._concurrent_workers)]
            for f in futures:
                with self._lock:
                    self._completed += f.result()


class MemoryBenchmark(Benchmark):
    """Benchmark for memory usage patterns."""

    def __init__(
        self,
        object_count: int = 1000,
        object_size_bytes: int = 1024,
    ):
        self._object_count = object_count
        self._object_size_bytes = object_size_bytes
        self._objects: List[Any] = []

    @property
    def name(self) -> str:
        return f"Memory_{self._object_count}objects_{self._object_size_bytes}bytes"

    def setup(self) -> None:
        """Setup - clear objects."""
        self._objects = []
        gc.collect()

    def teardown(self) -> None:
        """Cleanup."""
        self._objects = []
        gc.collect()

    def run_iteration(self) -> None:
        """Create and discard objects."""
        # Create objects
        new_objects = []
        for _ in range(self._object_count):
            obj = {
                "id": generate_random_id(),
                "data": "x" * self._object_size_bytes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {"key": "value"},
            }
            new_objects.append(obj)

        # Keep reference briefly
        self._objects = new_objects

        # Clear and collect
        self._objects = []
        gc.collect()


class HashingBenchmark(Benchmark):
    """Benchmark for cryptographic hashing performance."""

    def __init__(self, data_size_bytes: int = 1024):
        self._data_size_bytes = data_size_bytes
        self._test_data: bytes = b""

    @property
    def name(self) -> str:
        return f"Hashing_{self._data_size_bytes}bytes"

    def setup(self) -> None:
        """Generate test data."""
        self._test_data = secrets.token_bytes(self._data_size_bytes)

    def teardown(self) -> None:
        """Cleanup."""
        self._test_data = b""

    def run_iteration(self) -> None:
        """Hash data."""
        import hashlib
        hashlib.sha256(self._test_data).hexdigest()


class SignatureBenchmark(Benchmark):
    """Benchmark for Ed25519 signature operations."""

    def __init__(self, verify_only: bool = False):
        self._verify_only = verify_only
        self._signing_key = None
        self._message: bytes = b""
        self._signature: bytes = b""

    @property
    def name(self) -> str:
        op = "Verify" if self._verify_only else "Sign"
        return f"Signature_{op}"

    def setup(self) -> None:
        """Generate keys and message."""
        from nacl.signing import SigningKey
        self._signing_key = SigningKey.generate()
        self._message = b"Test message for signature benchmark"
        self._signature = self._signing_key.sign(self._message).signature

    def teardown(self) -> None:
        """Cleanup."""
        self._signing_key = None

    def run_iteration(self) -> None:
        """Sign or verify."""
        if self._verify_only:
            self._signing_key.verify_key.verify(self._message, self._signature)
        else:
            self._signing_key.sign(self._message)


class MerkleLogBenchmark(Benchmark):
    """Benchmark for Merkle log operations."""

    def __init__(self, batch_size: int = 100):
        self._batch_size = batch_size
        self._log = None
        self._counter = 0

    @property
    def name(self) -> str:
        return f"MerkleLog_batch{self._batch_size}"

    def setup(self) -> None:
        """Create Merkle log."""
        from vacp.core.merkle import MerkleLog
        self._log = MerkleLog()
        self._counter = 0

    def teardown(self) -> None:
        """Cleanup."""
        self._log = None

    def run_iteration(self) -> None:
        """Append entries to Merkle log."""
        for _ in range(self._batch_size):
            entry_data = f"entry_{self._counter}_{datetime.now(timezone.utc).isoformat()}"
            self._log.append(entry_data.encode("utf-8"))
            self._counter += 1


def run_standard_benchmark_suite(
    iterations: int = 1000,
    warmup: int = 100,
) -> List[BenchmarkResult]:
    """
    Run the standard benchmark suite.

    Returns list of results for all benchmarks.
    """
    benchmarks = [
        # Policy evaluation - various complexities
        PolicyEvaluationBenchmark(num_rules=10, complexity="simple"),
        PolicyEvaluationBenchmark(num_rules=100, complexity="medium"),
        PolicyEvaluationBenchmark(num_rules=100, complexity="complex"),

        # Audit logging
        AuditLogBenchmark(use_memory_db=True, batch_size=1),
        AuditLogBenchmark(use_memory_db=True, batch_size=10),

        # Cryptographic operations
        HashingBenchmark(data_size_bytes=1024),
        HashingBenchmark(data_size_bytes=10240),
        SignatureBenchmark(verify_only=False),
        SignatureBenchmark(verify_only=True),

        # Merkle log
        MerkleLogBenchmark(batch_size=10),
        MerkleLogBenchmark(batch_size=100),

        # Concurrency
        ConcurrencyBenchmark(concurrent_workers=5, operations_per_worker=10),
        ConcurrencyBenchmark(concurrent_workers=10, operations_per_worker=10),

        # Memory
        MemoryBenchmark(object_count=100, object_size_bytes=1024),
    ]

    results = []
    for benchmark in benchmarks:
        result = run_benchmark(
            benchmark,
            iterations=iterations,
            warmup_iterations=warmup,
        )
        results.append(result)

    return results


def run_load_test_suite(
    requests_per_test: int = 1000,
    concurrent_users_list: List[int] = None,
) -> List[LoadTestResult]:
    """
    Run load tests with different concurrency levels.

    Returns list of load test results.
    """
    if concurrent_users_list is None:
        concurrent_users_list = [1, 5, 10, 25, 50]

    # Setup shared resources
    from vacp.core.policy import PolicyEngine, PolicyBundle, PolicyRule, PolicyEvaluationContext

    engine = PolicyEngine()
    rules = [
        PolicyRule(
            id=f"rule_{i}",
            name=f"Rule {i}",
            description="Test",
            priority=i,
            tool_patterns=[f"tool_{i % 5}"],
            decision=PolicyDecision.ALLOW,
        )
        for i in range(50)
    ]
    bundle = PolicyBundle(
        id="load_test",
        version="1.0.0",
        name="Load Test Bundle",
        rules=rules,
        created_at=datetime.now(timezone.utc),
    )
    engine.load_bundle(bundle)

    counter = [0]
    lock = threading.Lock()

    def operation():
        with lock:
            counter[0] += 1
            i = counter[0]

        ctx = PolicyEvaluationContext(
            tenant_id="load_test",
            agent_id=f"agent_{i % 10}",
            tool_name=f"tool_{i % 5}",
            session_id=f"session_{i}",
            request_data={"op": i},
        )
        engine.evaluate(ctx)

    results = []
    for users in concurrent_users_list:
        counter[0] = 0
        result = run_load_test(
            operation=operation,
            name=f"PolicyEval_{users}users",
            total_requests=requests_per_test,
            concurrent_users=users,
        )
        results.append(result)

    return results
