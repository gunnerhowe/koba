"""
Storage module for Koba

Provides persistent storage backends for:
- Audit logs
- Policy bundles
- Receipts
- Session state
- Agent behavior profiles

Backends:
- SQLite (development/single-node)
- PostgreSQL (production)
"""

from vacp.storage.base import (
    StorageBackend,
    AuditLogStorage,
    PolicyStorage,
    ReceiptStorage,
    SessionStorage,
    BehaviorProfileStorage,
    StorageConfig,
    StorageError,
    NotFoundError,
    DuplicateError,
    create_storage_backend,
)
from vacp.storage.sqlite import SQLiteBackend

__all__ = [
    "StorageBackend",
    "AuditLogStorage",
    "PolicyStorage",
    "ReceiptStorage",
    "SessionStorage",
    "BehaviorProfileStorage",
    "StorageConfig",
    "StorageError",
    "NotFoundError",
    "DuplicateError",
    "SQLiteBackend",
    "create_storage_backend",
]
