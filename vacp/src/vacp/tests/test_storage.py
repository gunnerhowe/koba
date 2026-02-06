"""
Tests for the storage layer.

Tests cover:
- SQLiteBackend initialization and schema migrations
- AuditLogStorage operations
- PolicyStorage operations
- ReceiptStorage operations
- SessionStorage operations
- BehaviorProfileStorage operations
- Merkle tree integrity verification
- Connection pooling and thread safety
"""

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor

import pytest

from vacp.storage import (
    SQLiteBackend,
    StorageConfig,
    StorageError,
    NotFoundError,
    DuplicateError,
    create_storage_backend,
)


@pytest.fixture
def storage():
    """Create an in-memory SQLite backend for testing."""
    backend = SQLiteBackend(":memory:")
    backend.initialize()
    yield backend
    backend.close()


@pytest.fixture
def file_storage():
    """Create a file-based SQLite backend for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    backend = SQLiteBackend(db_path)
    backend.initialize()
    yield backend
    backend.close()

    # Clean up
    if os.path.exists(db_path):
        os.unlink(db_path)
    # WAL files
    for ext in ["-wal", "-shm"]:
        wal_path = db_path + ext
        if os.path.exists(wal_path):
            os.unlink(wal_path)


class TestStorageBackend:
    """Test StorageBackend interface."""

    def test_initialize_creates_schema(self, storage):
        """Test that initialize creates all required tables."""
        is_healthy, message = storage.health_check()
        assert is_healthy, f"Storage not healthy: {message}"

    def test_health_check_detects_issues(self):
        """Test that health check detects missing tables."""
        backend = SQLiteBackend(":memory:")
        # Don't initialize - tables won't exist
        backend.pool.initialize()

        is_healthy, message = backend.health_check()
        assert not is_healthy
        assert "Missing tables" in message

        backend.close()

    def test_close_releases_connections(self, storage):
        """Test that close releases all connections."""
        storage.close()
        # Pool should be empty and uninitialized
        assert not storage.pool._initialized


class TestAuditLogStorage:
    """Test AuditLogStorage operations."""

    def test_append_entry_returns_id(self, storage):
        """Test that append_entry returns a valid ID."""
        entry_id = storage.append_entry(
            entry_type="tool_call",
            agent_id="agent-123",
            tenant_id="tenant-456",
            action="file.read",
            data={"path": "/etc/passwd"},
        )

        assert entry_id is not None
        assert len(entry_id) > 0

    def test_append_entry_stores_data(self, storage):
        """Test that append_entry stores all data correctly."""
        entry_id = storage.append_entry(
            entry_type="policy_decision",
            agent_id="agent-abc",
            tenant_id="tenant-xyz",
            action="database.query",
            data={"query": "SELECT * FROM users", "result": "allowed"},
        )

        entry = storage.get_entry(entry_id)
        assert entry is not None
        assert entry["entry_type"] == "policy_decision"
        assert entry["agent_id"] == "agent-abc"
        assert entry["tenant_id"] == "tenant-xyz"
        assert entry["action"] == "database.query"
        assert entry["data"]["query"] == "SELECT * FROM users"

    def test_append_entry_with_timestamp(self, storage):
        """Test that custom timestamp is stored."""
        ts = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        entry_id = storage.append_entry(
            entry_type="test",
            agent_id="agent",
            tenant_id="tenant",
            action="test",
            data={},
            timestamp=ts,
        )

        entry = storage.get_entry(entry_id)
        assert ts.isoformat() in entry["timestamp"]

    def test_append_entry_creates_hash_chain(self, storage):
        """Test that entries are chained by hash."""
        id1 = storage.append_entry(
            entry_type="test", agent_id="a", tenant_id="t",
            action="first", data={}
        )
        id2 = storage.append_entry(
            entry_type="test", agent_id="a", tenant_id="t",
            action="second", data={}
        )

        entry1 = storage.get_entry(id1)
        entry2 = storage.get_entry(id2)

        assert entry1["previous_hash"] is None
        assert entry2["previous_hash"] == entry1["hash"]

    def test_get_entry_returns_none_for_missing(self, storage):
        """Test that get_entry returns None for non-existent ID."""
        entry = storage.get_entry("non-existent-id")
        assert entry is None

    def test_query_entries_filters_by_tenant(self, storage):
        """Test querying entries by tenant_id."""
        storage.append_entry("test", "a1", "tenant-1", "act1", {})
        storage.append_entry("test", "a2", "tenant-2", "act2", {})
        storage.append_entry("test", "a3", "tenant-1", "act3", {})

        entries = storage.query_entries(tenant_id="tenant-1")
        assert len(entries) == 2
        assert all(e["tenant_id"] == "tenant-1" for e in entries)

    def test_query_entries_filters_by_agent(self, storage):
        """Test querying entries by agent_id."""
        storage.append_entry("test", "agent-A", "t", "act1", {})
        storage.append_entry("test", "agent-B", "t", "act2", {})
        storage.append_entry("test", "agent-A", "t", "act3", {})

        entries = storage.query_entries(agent_id="agent-A")
        assert len(entries) == 2
        assert all(e["agent_id"] == "agent-A" for e in entries)

    def test_query_entries_filters_by_type(self, storage):
        """Test querying entries by entry_type."""
        storage.append_entry("tool_call", "a", "t", "act1", {})
        storage.append_entry("policy_decision", "a", "t", "act2", {})
        storage.append_entry("tool_call", "a", "t", "act3", {})

        entries = storage.query_entries(entry_type="tool_call")
        assert len(entries) == 2
        assert all(e["entry_type"] == "tool_call" for e in entries)

    def test_query_entries_filters_by_time_range(self, storage):
        """Test querying entries by time range."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=2)
        future = now + timedelta(hours=2)

        storage.append_entry("test", "a", "t", "past", {}, timestamp=past)
        storage.append_entry("test", "a", "t", "now", {}, timestamp=now)
        storage.append_entry("test", "a", "t", "future", {}, timestamp=future)

        entries = storage.query_entries(
            start_time=past - timedelta(minutes=1),
            end_time=now + timedelta(minutes=1),
        )
        assert len(entries) == 2

    def test_query_entries_respects_limit_and_offset(self, storage):
        """Test pagination with limit and offset."""
        for i in range(10):
            storage.append_entry("test", "a", "t", f"action-{i}", {})

        # Get first page
        page1 = storage.query_entries(limit=3, offset=0)
        assert len(page1) == 3

        # Get second page
        page2 = storage.query_entries(limit=3, offset=3)
        assert len(page2) == 3

        # Pages should be different
        page1_ids = {e["id"] for e in page1}
        page2_ids = {e["id"] for e in page2}
        assert page1_ids.isdisjoint(page2_ids)

    def test_get_entry_count(self, storage):
        """Test counting entries with filters."""
        storage.append_entry("test", "a1", "t1", "act", {})
        storage.append_entry("test", "a2", "t1", "act", {})
        storage.append_entry("test", "a1", "t2", "act", {})

        assert storage.get_entry_count() == 3
        assert storage.get_entry_count(tenant_id="t1") == 2
        assert storage.get_entry_count(agent_id="a1") == 2
        assert storage.get_entry_count(tenant_id="t1", agent_id="a1") == 1

    def test_get_merkle_root(self, storage):
        """Test Merkle root computation."""
        # Empty log has no root
        assert storage.get_merkle_root() is None

        # Add entries
        storage.append_entry("test", "a", "t", "act1", {})
        root1 = storage.get_merkle_root()
        assert root1 is not None

        storage.append_entry("test", "a", "t", "act2", {})
        root2 = storage.get_merkle_root()
        assert root2 is not None
        assert root2 != root1  # Root should change

    def test_get_inclusion_proof(self, storage):
        """Test Merkle inclusion proof generation."""
        ids = []
        for i in range(4):
            entry_id = storage.append_entry("test", "a", "t", f"act{i}", {})
            ids.append(entry_id)

        # Get proof for each entry
        for entry_id in ids:
            proof = storage.get_inclusion_proof(entry_id)
            assert proof is not None
            assert proof["entry_id"] == entry_id
            assert "proof" in proof
            assert "root" in proof

    def test_get_inclusion_proof_missing_entry(self, storage):
        """Test that missing entries return None proof."""
        proof = storage.get_inclusion_proof("non-existent")
        assert proof is None


class TestPolicyStorage:
    """Test PolicyStorage operations."""

    def test_save_and_get_bundle(self, storage):
        """Test saving and retrieving a policy bundle."""
        bundle = {
            "id": "bundle-123",
            "tenant_id": "tenant-abc",
            "version": "1.0.0",
            "policies": [{"name": "default-deny", "effect": "deny"}],
        }

        storage.save_bundle(bundle)
        retrieved = storage.get_bundle("bundle-123")

        assert retrieved is not None
        assert retrieved["id"] == "bundle-123"
        assert retrieved["policies"][0]["effect"] == "deny"

    def test_get_bundle_returns_none_for_missing(self, storage):
        """Test that missing bundles return None."""
        bundle = storage.get_bundle("non-existent")
        assert bundle is None

    def test_save_bundle_updates_existing(self, storage):
        """Test that saving existing bundle updates it."""
        bundle_v1 = {
            "id": "bundle-1",
            "tenant_id": "t",
            "version": "1.0.0",
            "data": "version 1",
        }
        bundle_v2 = {
            "id": "bundle-1",
            "tenant_id": "t",
            "version": "2.0.0",
            "data": "version 2",
        }

        storage.save_bundle(bundle_v1)
        storage.save_bundle(bundle_v2)

        retrieved = storage.get_bundle("bundle-1")
        assert retrieved["data"] == "version 2"

    def test_get_bundle_version(self, storage):
        """Test retrieving specific bundle version."""
        bundle_v1 = {"id": "bundle-1", "tenant_id": "t", "version": "1.0.0", "data": "v1"}
        bundle_v2 = {"id": "bundle-1", "tenant_id": "t", "version": "2.0.0", "data": "v2"}

        storage.save_bundle(bundle_v1)
        storage.save_bundle(bundle_v2)

        v1 = storage.get_bundle_version("bundle-1", "1.0.0")
        v2 = storage.get_bundle_version("bundle-1", "2.0.0")

        assert v1["data"] == "v1"
        assert v2["data"] == "v2"

    def test_list_bundles(self, storage):
        """Test listing policy bundles."""
        storage.save_bundle({"id": "b1", "tenant_id": "t1", "version": "1.0"})
        storage.save_bundle({"id": "b2", "tenant_id": "t2", "version": "1.0"})
        storage.save_bundle({"id": "b3", "tenant_id": "t1", "version": "2.0"})  # Different version

        all_bundles = storage.list_bundles()
        assert len(all_bundles) == 3

        t1_bundles = storage.list_bundles(tenant_id="t1")
        assert len(t1_bundles) == 2

    def test_get_and_set_active_bundle(self, storage):
        """Test setting and getting active bundle for tenant."""
        storage.save_bundle({"id": "b1", "tenant_id": "tenant-1", "version": "1.0"})
        storage.save_bundle({"id": "b2", "tenant_id": "tenant-1", "version": "2.0"})

        # No active bundle initially
        active = storage.get_active_bundle("tenant-1")
        assert active is None

        # Set active bundle
        storage.set_active_bundle("tenant-1", "b1")
        active = storage.get_active_bundle("tenant-1")
        assert active is not None
        assert active["id"] == "b1"

        # Change active bundle
        storage.set_active_bundle("tenant-1", "b2")
        active = storage.get_active_bundle("tenant-1")
        assert active["id"] == "b2"

    def test_get_bundle_history(self, storage):
        """Test getting bundle version history."""
        storage.save_bundle({"id": "bundle", "tenant_id": "t", "version": "1.0"})
        storage.save_bundle({"id": "bundle", "tenant_id": "t", "version": "2.0"})
        storage.save_bundle({"id": "bundle", "tenant_id": "t", "version": "3.0"})

        history = storage.get_bundle_history("bundle")
        assert len(history) == 3
        # Verify all versions exist (order may vary with rapid inserts)
        versions = {h["version"] for h in history}
        assert versions == {"1.0", "2.0", "3.0"}


class TestReceiptStorage:
    """Test ReceiptStorage operations."""

    def test_save_and_get_receipt(self, storage):
        """Test saving and retrieving a receipt."""
        receipt = {
            "id": "receipt-123",
            "tenant_id": "tenant-1",
            "agent_id": "agent-1",
            "tool_id": "tool-1",
            "action": "file.read",
            "parameters": {"path": "/etc/passwd"},
            "result": {"status": "success"},
            "signature": "sig123",
        }

        storage.save_receipt(receipt)
        retrieved = storage.get_receipt("receipt-123")

        assert retrieved is not None
        assert retrieved["tool_id"] == "tool-1"
        assert retrieved["parameters"]["path"] == "/etc/passwd"

    def test_save_duplicate_receipt_raises_error(self, storage):
        """Test that duplicate receipts raise error."""
        receipt = {
            "id": "receipt-dup",
            "tenant_id": "t",
            "agent_id": "a",
            "tool_id": "tool",
            "action": "act",
            "parameters": {},
            "signature": "sig",
        }

        storage.save_receipt(receipt)
        with pytest.raises(DuplicateError):
            storage.save_receipt(receipt)

    def test_query_receipts(self, storage):
        """Test querying receipts with filters."""
        storage.save_receipt({
            "id": "r1", "tenant_id": "t1", "agent_id": "a1",
            "tool_id": "tool1", "action": "act", "parameters": {},
            "signature": "sig",
        })
        storage.save_receipt({
            "id": "r2", "tenant_id": "t2", "agent_id": "a1",
            "tool_id": "tool2", "action": "act", "parameters": {},
            "signature": "sig",
        })
        storage.save_receipt({
            "id": "r3", "tenant_id": "t1", "agent_id": "a2",
            "tool_id": "tool1", "action": "act", "parameters": {},
            "signature": "sig",
        })

        assert len(storage.query_receipts(tenant_id="t1")) == 2
        assert len(storage.query_receipts(agent_id="a1")) == 2
        assert len(storage.query_receipts(tool_id="tool1")) == 2

    def test_verify_receipt_chain_valid(self, storage):
        """Test verifying a valid receipt chain."""
        storage.save_receipt({
            "id": "r1", "tenant_id": "t", "agent_id": "a",
            "tool_id": "tool", "action": "act", "parameters": {},
            "signature": "sig", "previous_receipt_id": None,
        })
        storage.save_receipt({
            "id": "r2", "tenant_id": "t", "agent_id": "a",
            "tool_id": "tool", "action": "act", "parameters": {},
            "signature": "sig", "previous_receipt_id": "r1",
        })

        is_valid, invalid_ids = storage.verify_receipt_chain(["r1", "r2"])
        assert is_valid
        assert len(invalid_ids) == 0

    def test_verify_receipt_chain_invalid(self, storage):
        """Test verifying an invalid receipt chain."""
        storage.save_receipt({
            "id": "r1", "tenant_id": "t", "agent_id": "a",
            "tool_id": "tool", "action": "act", "parameters": {},
            "signature": "sig", "previous_receipt_id": "non-existent",
        })

        is_valid, invalid_ids = storage.verify_receipt_chain(["r1"])
        assert not is_valid
        assert "r1" in invalid_ids


class TestSessionStorage:
    """Test SessionStorage operations."""

    def test_create_and_get_session(self, storage):
        """Test creating and retrieving a session."""
        storage.create_session(
            session_id="session-123",
            tenant_id="tenant-1",
            agent_id="agent-1",
            metadata={"user": "alice"},
        )

        session = storage.get_session("session-123")
        assert session is not None
        assert session["tenant_id"] == "tenant-1"
        assert session["metadata"]["user"] == "alice"
        assert session["status"] == "active"

    def test_create_duplicate_session_raises_error(self, storage):
        """Test that duplicate session raises error."""
        storage.create_session("session-dup", "t", "a")
        with pytest.raises(DuplicateError):
            storage.create_session("session-dup", "t", "a")

    def test_update_session(self, storage):
        """Test updating session data."""
        storage.create_session("session-1", "t", "a", metadata={"key1": "value1"})

        storage.update_session("session-1", {"key2": "value2"})

        session = storage.get_session("session-1")
        assert session["metadata"]["key1"] == "value1"
        assert session["metadata"]["key2"] == "value2"

    def test_update_missing_session_raises_error(self, storage):
        """Test that updating missing session raises error."""
        with pytest.raises(NotFoundError):
            storage.update_session("non-existent", {"data": "value"})

    def test_end_session(self, storage):
        """Test ending a session."""
        storage.create_session("session-1", "t", "a")

        storage.end_session("session-1")

        session = storage.get_session("session-1")
        assert session["status"] == "ended"
        assert session["ended_at"] is not None

    def test_append_and_get_session_history(self, storage):
        """Test appending and retrieving session actions."""
        storage.create_session("session-1", "t", "a")

        storage.append_session_action("session-1", {"action": "file.read", "path": "/etc/passwd"})
        storage.append_session_action("session-1", {"action": "file.write", "path": "/tmp/out"})

        history = storage.get_session_history("session-1")
        assert len(history) == 2


class TestBehaviorProfileStorage:
    """Test BehaviorProfileStorage operations."""

    def test_get_profile_returns_none_for_new_agent(self, storage):
        """Test that new agents have no profile."""
        profile = storage.get_profile("new-agent")
        assert profile is None

    def test_update_and_get_profile(self, storage):
        """Test updating and retrieving behavior profile."""
        storage.update_profile("agent-1", {
            "baseline_actions": ["file.read", "database.query"],
            "risk_level": "low",
        })

        profile = storage.get_profile("agent-1")
        assert profile is not None
        assert profile["profile_data"]["risk_level"] == "low"

    def test_record_and_get_action_history(self, storage):
        """Test recording and retrieving action history."""
        storage.record_action("agent-1", "tool_call", {"tool": "file.read"})
        storage.record_action("agent-1", "policy_check", {"result": "allowed"})
        storage.record_action("agent-1", "tool_call", {"tool": "database.query"})

        all_actions = storage.get_action_history("agent-1")
        assert len(all_actions) == 3

        tool_actions = storage.get_action_history("agent-1", action_type="tool_call")
        assert len(tool_actions) == 2

    def test_get_and_update_anomaly_score(self, storage):
        """Test anomaly score operations."""
        # New agent has 0 score
        assert storage.get_anomaly_score("agent-1") == 0.0

        # Create profile and update score
        storage.record_action("agent-1", "test", {})
        storage.update_anomaly_score("agent-1", 0.75)

        assert storage.get_anomaly_score("agent-1") == 0.75


class TestConnectionPooling:
    """Test connection pooling and thread safety."""

    def test_concurrent_writes(self, storage):
        """Test that concurrent writes are handled correctly."""
        results = []
        errors = []

        def write_entry(i):
            try:
                entry_id = storage.append_entry(
                    entry_type="test",
                    agent_id=f"agent-{i}",
                    tenant_id="tenant",
                    action=f"action-{i}",
                    data={"index": i},
                )
                results.append(entry_id)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(write_entry, i) for i in range(50)]
            for f in futures:
                f.result()

        assert len(errors) == 0
        assert len(results) == 50
        assert storage.get_entry_count() == 50

    def test_concurrent_reads_and_writes(self, file_storage):
        """Test concurrent reads and writes using file-based storage."""
        storage = file_storage

        # Pre-populate some data
        for i in range(10):
            storage.append_entry("test", f"a{i}", "t", "act", {})

        read_results = []
        write_results = []
        errors = []

        def read_entries():
            try:
                entries = storage.query_entries(limit=100)
                read_results.append(len(entries))
            except Exception as e:
                errors.append(e)

        def write_entry(i):
            try:
                entry_id = storage.append_entry("test", f"a{i}", "t", "act", {})
                write_results.append(entry_id)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for i in range(20):
                if i % 2 == 0:
                    futures.append(executor.submit(read_entries))
                else:
                    futures.append(executor.submit(write_entry, i + 100))
            for f in futures:
                f.result()

        assert len(errors) == 0


class TestStorageFactory:
    """Test storage factory function."""

    def test_create_sqlite_backend(self):
        """Test creating SQLite backend via factory."""
        config = StorageConfig(backend_type="sqlite", connection_string=":memory:")
        backend = create_storage_backend(config)

        assert isinstance(backend, SQLiteBackend)
        backend.initialize()
        is_healthy, _ = backend.health_check()
        assert is_healthy
        backend.close()

    def test_create_memory_backend(self):
        """Test creating in-memory backend via factory."""
        config = StorageConfig(backend_type="memory")
        backend = create_storage_backend(config)

        assert isinstance(backend, SQLiteBackend)
        backend.initialize()
        is_healthy, _ = backend.health_check()
        assert is_healthy
        backend.close()

    def test_create_unknown_backend_raises_error(self):
        """Test that unknown backend type raises error."""
        config = StorageConfig(backend_type="unknown")
        with pytest.raises(ValueError, match="Unknown backend type"):
            create_storage_backend(config)


class TestFilePersistence:
    """Test file-based storage persistence."""

    def test_data_persists_across_connections(self, file_storage):
        """Test that data persists when closing and reopening."""
        db_path = file_storage.database

        # Write some data
        entry_id = file_storage.append_entry("test", "agent", "tenant", "action", {"key": "value"})
        file_storage.close()

        # Reopen and verify data
        new_storage = SQLiteBackend(db_path)
        new_storage.initialize()

        entry = new_storage.get_entry(entry_id)
        assert entry is not None
        assert entry["data"]["key"] == "value"

        new_storage.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
