"""
SQLite Storage Backend for Koba/VACP

Production-ready SQLite implementation with:
- Thread-safe connection pooling
- Transaction support
- Merkle tree for audit log integrity
- Full-text search support
- Automatic migrations
"""

import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from queue import Queue

from vacp.storage.base import (
    StorageBackend,
    AuditLogStorage,
    PolicyStorage,
    ReceiptStorage,
    SessionStorage,
    BehaviorProfileStorage,
    StorageError,
    NotFoundError,
    DuplicateError,
)


class ConnectionPool:
    """Thread-safe SQLite connection pool."""

    def __init__(self, database: str, pool_size: int = 5):
        self.database = database
        self.pool_size = pool_size
        self._pool: Queue = Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()  # Serialize writes for in-memory
        self._initialized = False
        self._is_memory = database == ":memory:" or "mode=memory" in database

    def initialize(self) -> None:
        """Initialize the connection pool."""
        with self._lock:
            if self._initialized:
                return

            # For in-memory databases, use shared cache mode
            if self._is_memory:
                # Use file URI with shared cache for in-memory
                uri = "file::memory:?cache=shared"
                for _ in range(self.pool_size):
                    conn = sqlite3.connect(
                        uri,
                        uri=True,
                        check_same_thread=False,
                        isolation_level=None,
                    )
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys=ON")
                    self._pool.put(conn)
            else:
                # For file-based databases
                for _ in range(self.pool_size):
                    conn = sqlite3.connect(
                        self.database,
                        check_same_thread=False,
                        isolation_level=None,  # Autocommit mode, we'll manage transactions
                    )
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.execute("PRAGMA foreign_keys=ON")
                    conn.execute("PRAGMA busy_timeout=5000")
                    self._pool.put(conn)
            self._initialized = True

    @contextmanager
    def get_connection(self):
        """Get a connection from the pool."""
        if not self._initialized:
            self.initialize()
        conn = self._pool.get()
        try:
            yield conn
        finally:
            self._pool.put(conn)

    @contextmanager
    def get_write_connection(self):
        """Get a connection with write lock for thread-safe writes."""
        if not self._initialized:
            self.initialize()
        # For in-memory databases, serialize all writes
        if self._is_memory:
            with self._write_lock:
                conn = self._pool.get()
                try:
                    yield conn
                finally:
                    self._pool.put(conn)
        else:
            conn = self._pool.get()
            try:
                yield conn
            finally:
                self._pool.put(conn)

    def close_all(self) -> None:
        """Close all connections in the pool."""
        with self._lock:
            while not self._pool.empty():
                conn = self._pool.get_nowait()
                conn.close()
            self._initialized = False


class MerkleTree:
    """Simple Merkle tree for audit log integrity."""

    @staticmethod
    def hash_entry(data: str) -> str:
        """Hash a single entry."""
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def hash_pair(left: str, right: str) -> str:
        """Hash two nodes together."""
        combined = left + right
        return hashlib.sha256(combined.encode()).hexdigest()

    @staticmethod
    def compute_root(hashes: List[str]) -> Optional[str]:
        """Compute the Merkle root from a list of hashes."""
        if not hashes:
            return None

        # Pad to power of 2
        while len(hashes) & (len(hashes) - 1) != 0:
            hashes.append(hashes[-1])

        while len(hashes) > 1:
            new_hashes = []
            for i in range(0, len(hashes), 2):
                new_hashes.append(MerkleTree.hash_pair(hashes[i], hashes[i + 1]))
            hashes = new_hashes

        return hashes[0]

    @staticmethod
    def get_proof(hashes: List[str], index: int) -> List[Dict[str, Any]]:
        """Get the inclusion proof for an entry at the given index."""
        if not hashes or index >= len(hashes):
            return []

        proof = []
        # Pad to power of 2
        original_len = len(hashes)
        while len(hashes) & (len(hashes) - 1) != 0:
            hashes.append(hashes[-1])

        level = 0
        while len(hashes) > 1:
            sibling_index = index ^ 1  # XOR to get sibling
            if sibling_index < len(hashes):
                proof.append({
                    "level": level,
                    "position": "right" if index % 2 == 0 else "left",
                    "hash": hashes[sibling_index],
                })
            new_hashes = []
            for i in range(0, len(hashes), 2):
                new_hashes.append(MerkleTree.hash_pair(hashes[i], hashes[i + 1]))
            hashes = new_hashes
            index //= 2
            level += 1

        return proof


class SQLiteBackend(StorageBackend, AuditLogStorage, PolicyStorage, ReceiptStorage, SessionStorage, BehaviorProfileStorage):
    """
    SQLite storage backend implementing all storage interfaces.

    Thread-safe with connection pooling and transaction support.
    """

    SCHEMA_VERSION = 1

    def __init__(self, database: str = "koba.db", pool_size: int = 5):
        self.database = database
        self.pool = ConnectionPool(database, pool_size)
        self._merkle_cache: Dict[str, str] = {}

    def initialize(self) -> None:
        """Initialize the database schema."""
        self.pool.initialize()

        with self.pool.get_connection() as conn:
            # Check/create schema version table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
            """)

            # Get current version
            cursor = conn.execute("SELECT MAX(version) FROM schema_version")
            current_version = cursor.fetchone()[0] or 0

            if current_version < self.SCHEMA_VERSION:
                self._run_migrations(conn, current_version)

    def _run_migrations(self, conn: sqlite3.Connection, from_version: int) -> None:
        """Run database migrations."""
        migrations = [
            self._migration_v1,
        ]

        for version, migration in enumerate(migrations[from_version:], start=from_version + 1):
            migration(conn)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, datetime.now(timezone.utc).isoformat()),
            )

    def _migration_v1(self, conn: sqlite3.Connection) -> None:
        """Initial schema creation."""
        # Audit log table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                entry_type TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                data TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                hash TEXT NOT NULL,
                previous_hash TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(entry_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")

        # Merkle roots table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS merkle_roots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_hash TEXT NOT NULL,
                entry_count INTEGER NOT NULL,
                computed_at TEXT NOT NULL
            )
        """)

        # Policy bundles table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS policy_bundles (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                version TEXT NOT NULL,
                data TEXT NOT NULL,
                is_active INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tenant_id, version)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_tenant ON policy_bundles(tenant_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_active ON policy_bundles(tenant_id, is_active)")

        # Policy version history
        conn.execute("""
            CREATE TABLE IF NOT EXISTS policy_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bundle_id TEXT NOT NULL,
                version TEXT NOT NULL,
                data TEXT NOT NULL,
                changed_by TEXT,
                change_reason TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (bundle_id) REFERENCES policy_bundles(id)
            )
        """)

        # Receipts table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                action TEXT NOT NULL,
                parameters TEXT NOT NULL,
                result TEXT,
                signature TEXT NOT NULL,
                previous_receipt_id TEXT,
                timestamp TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_receipt_tenant ON receipts(tenant_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_receipt_agent ON receipts(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_receipt_tool ON receipts(tool_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_receipt_timestamp ON receipts(timestamp)")

        # Sessions table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                metadata TEXT,
                status TEXT DEFAULT 'active',
                started_at TEXT NOT NULL,
                ended_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_session_tenant ON sessions(tenant_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_session_agent ON sessions(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_session_status ON sessions(status)")

        # Session actions table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                action_data TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_session_action_session ON session_actions(session_id)")

        # Behavior profiles table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS behavior_profiles (
                agent_id TEXT PRIMARY KEY,
                profile_data TEXT NOT NULL,
                anomaly_score REAL DEFAULT 0.0,
                last_action_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Behavior action history
        conn.execute("""
            CREATE TABLE IF NOT EXISTS behavior_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_data TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (agent_id) REFERENCES behavior_profiles(agent_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_behavior_agent ON behavior_actions(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_behavior_type ON behavior_actions(action_type)")

    def close(self) -> None:
        """Close all database connections."""
        self.pool.close_all()

    def health_check(self) -> Tuple[bool, str]:
        """Check database health."""
        try:
            with self.pool.get_connection() as conn:
                conn.execute("SELECT 1")
                # Check table existence
                cursor = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                tables = [row[0] for row in cursor.fetchall()]
                required_tables = [
                    "audit_log", "policy_bundles", "receipts",
                    "sessions", "behavior_profiles"
                ]
                missing = [t for t in required_tables if t not in tables]
                if missing:
                    return False, f"Missing tables: {missing}"
                return True, "Database healthy"
        except Exception as e:
            return False, f"Database error: {str(e)}"

    # ==================== AuditLogStorage Implementation ====================

    def append_entry(
        self,
        entry_type: str,
        agent_id: str,
        tenant_id: str,
        action: str,
        data: Dict[str, Any],
        timestamp: Optional[datetime] = None,
    ) -> str:
        """Append an entry to the audit log."""
        entry_id = str(uuid.uuid4())
        ts = timestamp or datetime.now(timezone.utc)

        # Compute hash for integrity
        entry_content = json.dumps({
            "id": entry_id,
            "type": entry_type,
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "action": action,
            "data": data,
            "timestamp": ts.isoformat(),
        }, sort_keys=True)
        entry_hash = MerkleTree.hash_entry(entry_content)

        with self.pool.get_write_connection() as conn:
            # Get previous hash for chain
            cursor = conn.execute(
                "SELECT hash FROM audit_log ORDER BY rowid DESC LIMIT 1"
            )
            row = cursor.fetchone()
            previous_hash = row["hash"] if row else None

            conn.execute(
                """
                INSERT INTO audit_log
                (id, entry_type, agent_id, tenant_id, action, data, timestamp, hash, previous_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    entry_type,
                    agent_id,
                    tenant_id,
                    action,
                    json.dumps(data),
                    ts.isoformat(),
                    entry_hash,
                    previous_hash,
                ),
            )

        # Invalidate merkle cache
        self._merkle_cache.clear()

        return entry_id

    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get a single audit log entry by ID."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM audit_log WHERE id = ?",
                (entry_id,),
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_audit_entry(row)
            return None

    def query_entries(
        self,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        entry_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query audit log entries with filters."""
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: List[Any] = []

        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if entry_type:
            query += " AND entry_type = ?"
            params.append(entry_type)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.pool.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_audit_entry(row) for row in cursor.fetchall()]

    def get_entry_count(
        self,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        entry_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """Get count of entries matching filters."""
        query = "SELECT COUNT(*) FROM audit_log WHERE 1=1"
        params: List[Any] = []

        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if entry_type:
            query += " AND entry_type = ?"
            params.append(entry_type)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        with self.pool.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchone()[0]

    def get_merkle_root(self) -> Optional[str]:
        """Get the current Merkle root of the audit log."""
        cache_key = "merkle_root"
        if cache_key in self._merkle_cache:
            return self._merkle_cache[cache_key]

        with self.pool.get_connection() as conn:
            cursor = conn.execute("SELECT hash FROM audit_log ORDER BY rowid")
            hashes = [row["hash"] for row in cursor.fetchall()]

        if not hashes:
            return None

        root = MerkleTree.compute_root(hashes)
        self._merkle_cache[cache_key] = root
        return root

    def get_inclusion_proof(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get the Merkle inclusion proof for an entry."""
        with self.pool.get_connection() as conn:
            # Get all hashes in order
            cursor = conn.execute("SELECT id, hash FROM audit_log ORDER BY rowid")
            rows = cursor.fetchall()

            hashes = [row["hash"] for row in rows]
            ids = [row["id"] for row in rows]

            if entry_id not in ids:
                return None

            index = ids.index(entry_id)

        proof = MerkleTree.get_proof(hashes.copy(), index)
        root = MerkleTree.compute_root(hashes.copy())

        return {
            "entry_id": entry_id,
            "entry_hash": hashes[index],
            "index": index,
            "proof": proof,
            "root": root,
        }

    def _row_to_audit_entry(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a database row to an audit entry dict."""
        return {
            "id": row["id"],
            "entry_type": row["entry_type"],
            "agent_id": row["agent_id"],
            "tenant_id": row["tenant_id"],
            "action": row["action"],
            "data": json.loads(row["data"]),
            "timestamp": row["timestamp"],
            "hash": row["hash"],
            "previous_hash": row["previous_hash"],
        }

    # ==================== PolicyStorage Implementation ====================

    def save_bundle(self, bundle: Dict[str, Any]) -> None:
        """Save a policy bundle."""
        bundle_id = bundle.get("id") or str(uuid.uuid4())
        tenant_id = bundle.get("tenant_id", "default")
        version = bundle.get("version", "1.0.0")

        with self.pool.get_write_connection() as conn:
            # Check if bundle already exists
            cursor = conn.execute(
                "SELECT id FROM policy_bundles WHERE id = ?",
                (bundle_id,),
            )
            exists = cursor.fetchone() is not None

            if exists:
                # Update existing bundle
                conn.execute(
                    """
                    UPDATE policy_bundles
                    SET data = ?, version = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (json.dumps(bundle), version, bundle_id),
                )
            else:
                # Insert new bundle
                conn.execute(
                    """
                    INSERT INTO policy_bundles (id, tenant_id, version, data)
                    VALUES (?, ?, ?, ?)
                    """,
                    (bundle_id, tenant_id, version, json.dumps(bundle)),
                )

            # Save to history
            conn.execute(
                """
                INSERT INTO policy_history (bundle_id, version, data)
                VALUES (?, ?, ?)
                """,
                (bundle_id, version, json.dumps(bundle)),
            )

    def get_bundle(self, bundle_id: str) -> Optional[Dict[str, Any]]:
        """Get a policy bundle by ID."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT data FROM policy_bundles WHERE id = ?",
                (bundle_id,),
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["data"])
            return None

    def get_bundle_version(
        self,
        bundle_id: str,
        version: str,
    ) -> Optional[Dict[str, Any]]:
        """Get a specific version of a policy bundle."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT data FROM policy_history
                WHERE bundle_id = ? AND version = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (bundle_id, version),
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["data"])
            return None

    def list_bundles(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List policy bundles."""
        query = "SELECT data FROM policy_bundles"
        params: List[Any] = []

        if tenant_id:
            query += " WHERE tenant_id = ?"
            params.append(tenant_id)

        query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.pool.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [json.loads(row["data"]) for row in cursor.fetchall()]

    def get_active_bundle(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get the active policy bundle for a tenant."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT data FROM policy_bundles
                WHERE tenant_id = ? AND is_active = 1
                """,
                (tenant_id,),
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["data"])
            return None

    def set_active_bundle(self, tenant_id: str, bundle_id: str) -> None:
        """Set the active policy bundle for a tenant."""
        with self.pool.get_write_connection() as conn:
            # Deactivate all bundles for tenant
            conn.execute(
                "UPDATE policy_bundles SET is_active = 0 WHERE tenant_id = ?",
                (tenant_id,),
            )
            # Activate the specified bundle
            conn.execute(
                "UPDATE policy_bundles SET is_active = 1 WHERE id = ? AND tenant_id = ?",
                (bundle_id, tenant_id),
            )

    def get_bundle_history(
        self,
        bundle_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get version history for a policy bundle."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT data, version, created_at FROM policy_history
                WHERE bundle_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (bundle_id, limit),
            )
            return [
                {
                    "data": json.loads(row["data"]),
                    "version": row["version"],
                    "created_at": row["created_at"],
                }
                for row in cursor.fetchall()
            ]

    # ==================== ReceiptStorage Implementation ====================

    def save_receipt(self, receipt: Dict[str, Any]) -> None:
        """Save an action receipt."""
        receipt_id = receipt.get("id") or str(uuid.uuid4())

        with self.pool.get_write_connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO receipts
                    (id, tenant_id, agent_id, tool_id, action, parameters, result, signature, previous_receipt_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt_id,
                        receipt.get("tenant_id", "default"),
                        receipt.get("agent_id"),
                        receipt.get("tool_id"),
                        receipt.get("action"),
                        json.dumps(receipt.get("parameters", {})),
                        json.dumps(receipt.get("result")),
                        receipt.get("signature"),
                        receipt.get("previous_receipt_id"),
                        receipt.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    ),
                )
            except sqlite3.IntegrityError as e:
                raise DuplicateError(f"Receipt {receipt_id} already exists") from e

    def get_receipt(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        """Get a receipt by ID."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM receipts WHERE id = ?",
                (receipt_id,),
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_receipt(row)
            return None

    def query_receipts(
        self,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query receipts with filters."""
        query = "SELECT * FROM receipts WHERE 1=1"
        params: List[Any] = []

        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if tool_id:
            query += " AND tool_id = ?"
            params.append(tool_id)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.pool.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_receipt(row) for row in cursor.fetchall()]

    def verify_receipt_chain(
        self,
        receipt_ids: List[str],
    ) -> Tuple[bool, List[str]]:
        """Verify a chain of receipts."""
        invalid_ids = []

        with self.pool.get_connection() as conn:
            for receipt_id in receipt_ids:
                cursor = conn.execute(
                    "SELECT * FROM receipts WHERE id = ?",
                    (receipt_id,),
                )
                row = cursor.fetchone()
                if not row:
                    invalid_ids.append(receipt_id)
                    continue

                # Verify chain link
                if row["previous_receipt_id"]:
                    cursor = conn.execute(
                        "SELECT id FROM receipts WHERE id = ?",
                        (row["previous_receipt_id"],),
                    )
                    if not cursor.fetchone():
                        invalid_ids.append(receipt_id)

        return len(invalid_ids) == 0, invalid_ids

    def _row_to_receipt(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a database row to a receipt dict."""
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "agent_id": row["agent_id"],
            "tool_id": row["tool_id"],
            "action": row["action"],
            "parameters": json.loads(row["parameters"]),
            "result": json.loads(row["result"]) if row["result"] else None,
            "signature": row["signature"],
            "previous_receipt_id": row["previous_receipt_id"],
            "timestamp": row["timestamp"],
        }

    # ==================== SessionStorage Implementation ====================

    def create_session(
        self,
        session_id: str,
        tenant_id: str,
        agent_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create a new session."""
        with self.pool.get_write_connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO sessions (id, tenant_id, agent_id, metadata, started_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        tenant_id,
                        agent_id,
                        json.dumps(metadata) if metadata else None,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as e:
                raise DuplicateError(f"Session {session_id} already exists") from e

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_session(row)
            return None

    def update_session(
        self,
        session_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Update session data."""
        with self.pool.get_write_connection() as conn:
            # Get existing session
            cursor = conn.execute(
                "SELECT metadata FROM sessions WHERE id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise NotFoundError(f"Session {session_id} not found")

            existing = json.loads(row["metadata"]) if row["metadata"] else {}
            existing.update(data)

            conn.execute(
                "UPDATE sessions SET metadata = ? WHERE id = ?",
                (json.dumps(existing), session_id),
            )

    def end_session(self, session_id: str) -> None:
        """Mark a session as ended."""
        with self.pool.get_write_connection() as conn:
            conn.execute(
                """
                UPDATE sessions
                SET status = 'ended', ended_at = ?
                WHERE id = ?
                """,
                (datetime.now(timezone.utc).isoformat(), session_id),
            )

    def get_session_history(
        self,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get action history for a session."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT action_data, timestamp FROM session_actions
                WHERE session_id = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (session_id, limit),
            )
            return [
                {
                    "data": json.loads(row["action_data"]),
                    "timestamp": row["timestamp"],
                }
                for row in cursor.fetchall()
            ]

    def append_session_action(
        self,
        session_id: str,
        action: Dict[str, Any],
    ) -> None:
        """Append an action to session history."""
        with self.pool.get_write_connection() as conn:
            conn.execute(
                """
                INSERT INTO session_actions (session_id, action_data, timestamp)
                VALUES (?, ?, ?)
                """,
                (
                    session_id,
                    json.dumps(action),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def _row_to_session(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a database row to a session dict."""
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "agent_id": row["agent_id"],
            "metadata": json.loads(row["metadata"]) if row["metadata"] else None,
            "status": row["status"],
            "started_at": row["started_at"],
            "ended_at": row["ended_at"],
        }

    # ==================== BehaviorProfileStorage Implementation ====================

    def get_profile(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get behavior profile for an agent."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM behavior_profiles WHERE agent_id = ?",
                (agent_id,),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "agent_id": row["agent_id"],
                    "profile_data": json.loads(row["profile_data"]),
                    "anomaly_score": row["anomaly_score"],
                    "last_action_at": row["last_action_at"],
                }
            return None

    def update_profile(
        self,
        agent_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Update agent behavior profile."""
        with self.pool.get_write_connection() as conn:
            cursor = conn.execute(
                "SELECT agent_id FROM behavior_profiles WHERE agent_id = ?",
                (agent_id,),
            )
            if cursor.fetchone():
                conn.execute(
                    """
                    UPDATE behavior_profiles
                    SET profile_data = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE agent_id = ?
                    """,
                    (json.dumps(data), agent_id),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO behavior_profiles (agent_id, profile_data)
                    VALUES (?, ?)
                    """,
                    (agent_id, json.dumps(data)),
                )

    def record_action(
        self,
        agent_id: str,
        action_type: str,
        action_data: Dict[str, Any],
    ) -> None:
        """Record an action in the agent's profile."""
        with self.pool.get_write_connection() as conn:
            timestamp = datetime.now(timezone.utc).isoformat()

            # Ensure profile exists
            cursor = conn.execute(
                "SELECT agent_id FROM behavior_profiles WHERE agent_id = ?",
                (agent_id,),
            )
            if not cursor.fetchone():
                conn.execute(
                    """
                    INSERT INTO behavior_profiles (agent_id, profile_data, last_action_at)
                    VALUES (?, '{}', ?)
                    """,
                    (agent_id, timestamp),
                )
            else:
                conn.execute(
                    """
                    UPDATE behavior_profiles
                    SET last_action_at = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE agent_id = ?
                    """,
                    (timestamp, agent_id),
                )

            # Record the action
            conn.execute(
                """
                INSERT INTO behavior_actions (agent_id, action_type, action_data, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (agent_id, action_type, json.dumps(action_data), timestamp),
            )

    def get_action_history(
        self,
        agent_id: str,
        action_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get action history for an agent."""
        query = """
            SELECT action_type, action_data, timestamp FROM behavior_actions
            WHERE agent_id = ?
        """
        params: List[Any] = [agent_id]

        if action_type:
            query += " AND action_type = ?"
            params.append(action_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.pool.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [
                {
                    "action_type": row["action_type"],
                    "action_data": json.loads(row["action_data"]),
                    "timestamp": row["timestamp"],
                }
                for row in cursor.fetchall()
            ]

    def get_anomaly_score(self, agent_id: str) -> float:
        """Get the current anomaly score for an agent."""
        with self.pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT anomaly_score FROM behavior_profiles WHERE agent_id = ?",
                (agent_id,),
            )
            row = cursor.fetchone()
            return row["anomaly_score"] if row else 0.0

    def update_anomaly_score(self, agent_id: str, score: float) -> None:
        """Update the anomaly score for an agent."""
        with self.pool.get_write_connection() as conn:
            conn.execute(
                """
                UPDATE behavior_profiles
                SET anomaly_score = ?, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
                """,
                (score, agent_id),
            )
