"""
Base Storage Interfaces for Koba

Defines abstract interfaces for storage backends.
Implementations must be:
- Thread-safe
- Transactional where possible
- Support for batched operations
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


class StorageError(Exception):
    """Base exception for storage errors."""
    pass


class NotFoundError(StorageError):
    """Raised when a requested item is not found."""
    pass


class DuplicateError(StorageError):
    """Raised when trying to create a duplicate item."""
    pass


class StorageBackend(ABC):
    """
    Abstract base class for storage backends.

    All storage operations should be:
    - Atomic (complete or fail entirely)
    - Durable (survive restarts)
    - Consistent (no partial writes)
    """

    @abstractmethod
    def initialize(self) -> None:
        """Initialize the storage backend (create tables, etc.)."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close connections and clean up resources."""
        pass

    @abstractmethod
    def health_check(self) -> Tuple[bool, str]:
        """
        Check if the storage backend is healthy.

        Returns (is_healthy, message).
        """
        pass


class AuditLogStorage(ABC):
    """Interface for storing audit log entries."""

    @abstractmethod
    def append_entry(
        self,
        entry_type: str,
        agent_id: str,
        tenant_id: str,
        action: str,
        data: Dict[str, Any],
        timestamp: Optional[datetime] = None,
    ) -> str:
        """
        Append an entry to the audit log.

        Returns the entry ID.
        """
        pass

    @abstractmethod
    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get a single audit log entry by ID."""
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def get_entry_count(
        self,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        entry_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """Get count of entries matching filters."""
        pass

    @abstractmethod
    def get_merkle_root(self) -> Optional[str]:
        """Get the current Merkle root of the audit log."""
        pass

    @abstractmethod
    def get_inclusion_proof(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get the Merkle inclusion proof for an entry."""
        pass


class PolicyStorage(ABC):
    """Interface for storing policy bundles."""

    @abstractmethod
    def save_bundle(self, bundle: Dict[str, Any]) -> None:
        """Save a policy bundle."""
        pass

    @abstractmethod
    def get_bundle(self, bundle_id: str) -> Optional[Dict[str, Any]]:
        """Get a policy bundle by ID."""
        pass

    @abstractmethod
    def get_bundle_version(
        self,
        bundle_id: str,
        version: str,
    ) -> Optional[Dict[str, Any]]:
        """Get a specific version of a policy bundle."""
        pass

    @abstractmethod
    def list_bundles(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List policy bundles."""
        pass

    @abstractmethod
    def get_active_bundle(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get the active policy bundle for a tenant."""
        pass

    @abstractmethod
    def set_active_bundle(self, tenant_id: str, bundle_id: str) -> None:
        """Set the active policy bundle for a tenant."""
        pass

    @abstractmethod
    def get_bundle_history(
        self,
        bundle_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get version history for a policy bundle."""
        pass


class ReceiptStorage(ABC):
    """Interface for storing action receipts."""

    @abstractmethod
    def save_receipt(self, receipt: Dict[str, Any]) -> None:
        """Save an action receipt."""
        pass

    @abstractmethod
    def get_receipt(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        """Get a receipt by ID."""
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def verify_receipt_chain(
        self,
        receipt_ids: List[str],
    ) -> Tuple[bool, List[str]]:
        """
        Verify a chain of receipts.

        Returns (is_valid, list_of_invalid_ids).
        """
        pass


class SessionStorage(ABC):
    """Interface for storing session state."""

    @abstractmethod
    def create_session(
        self,
        session_id: str,
        tenant_id: str,
        agent_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create a new session."""
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID."""
        pass

    @abstractmethod
    def update_session(
        self,
        session_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Update session data."""
        pass

    @abstractmethod
    def end_session(self, session_id: str) -> None:
        """Mark a session as ended."""
        pass

    @abstractmethod
    def get_session_history(
        self,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get action history for a session."""
        pass

    @abstractmethod
    def append_session_action(
        self,
        session_id: str,
        action: Dict[str, Any],
    ) -> None:
        """Append an action to session history."""
        pass


class BehaviorProfileStorage(ABC):
    """Interface for storing agent behavior profiles."""

    @abstractmethod
    def get_profile(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get behavior profile for an agent."""
        pass

    @abstractmethod
    def update_profile(
        self,
        agent_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Update agent behavior profile."""
        pass

    @abstractmethod
    def record_action(
        self,
        agent_id: str,
        action_type: str,
        action_data: Dict[str, Any],
    ) -> None:
        """Record an action in the agent's profile."""
        pass

    @abstractmethod
    def get_action_history(
        self,
        agent_id: str,
        action_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get action history for an agent."""
        pass

    @abstractmethod
    def get_anomaly_score(self, agent_id: str) -> float:
        """Get the current anomaly score for an agent."""
        pass


@dataclass
class StorageConfig:
    """Configuration for storage backend."""
    backend_type: str = "sqlite"  # "sqlite", "postgres", "memory"
    connection_string: str = "koba.db"
    pool_size: int = 5
    max_overflow: int = 10
    echo: bool = False  # Log SQL queries
    auto_migrate: bool = True


def create_storage_backend(config: StorageConfig) -> StorageBackend:
    """
    Factory function to create a storage backend.

    Args:
        config: Storage configuration

    Returns:
        Configured storage backend
    """
    if config.backend_type == "sqlite":
        from vacp.storage.sqlite import SQLiteBackend
        return SQLiteBackend(config.connection_string)
    elif config.backend_type == "memory":
        from vacp.storage.sqlite import SQLiteBackend
        return SQLiteBackend(":memory:")
    else:
        raise ValueError(f"Unknown backend type: {config.backend_type}")
