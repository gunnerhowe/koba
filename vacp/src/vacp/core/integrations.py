"""
Integration Service for VACP

Provides SQLite-backed persistence for integrations that connect
external AI tools (ClawdBot, Claude Code, LangChain, etc.) to the
Koba governance platform.

Each integration tracks:
- Identity and configuration
- Connection status
- Activity statistics (total calls, allowed, denied)
"""

import json
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vacp.core.database import DatabaseManager

# SQLAlchemy imports - with fallback
try:
    from sqlalchemy import (
        Column, String, Text, DateTime, Integer,
    )
    from vacp.core.database import Base
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False


# ============================================================================
# SQLAlchemy Model
# ============================================================================

if SQLALCHEMY_AVAILABLE:
    class IntegrationModel(Base):  # type: ignore[valid-type,misc]
        """Persistent integration record."""
        __tablename__ = "integrations"

        id = Column(String(64), primary_key=True)
        type = Column(String(100), nullable=False, index=True)
        name = Column(String(255), nullable=False)
        status = Column(String(30), nullable=False, default="connected")
        config = Column(Text, default="{}")  # JSON
        created_at = Column(DateTime(timezone=True), nullable=False)
        last_activity = Column(DateTime(timezone=True), nullable=True)
        total_calls = Column(Integer, nullable=False, default=0)
        allowed = Column(Integer, nullable=False, default=0)
        denied = Column(Integer, nullable=False, default=0)

        def to_dict(self) -> Dict[str, Any]:
            """Serialize to a JSON-compatible dictionary."""
            return {
                "id": self.id,
                "type": self.type,
                "name": self.name,
                "status": self.status,
                "config": json.loads(self.config) if self.config else {},  # type: ignore[arg-type]
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "last_activity": self.last_activity.isoformat() if self.last_activity else None,
                "stats": {
                    "total_calls": self.total_calls or 0,
                    "allowed": self.allowed or 0,
                    "denied": self.denied or 0,
                },
            }


# ============================================================================
# Integration Service
# ============================================================================

class IntegrationService:
    """
    Manages integrations with SQLite-backed persistence.

    Uses the existing DatabaseManager and session pattern from the project.
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        """
        Initialize the integration service.

        Args:
            db_manager: Shared DatabaseManager instance (provides engine + sessions).
        """
        self.db = db_manager

        # Ensure the integrations table exists.  ``create_tables`` on the
        # shared Base is idempotent so this is safe even if called multiple
        # times (it will only CREATE IF NOT EXISTS).
        self.db.create_tables()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def list_all(self) -> List[Dict[str, Any]]:
        """Return every integration as a list of dicts."""
        with self.db.get_session() as session:
            rows = session.query(IntegrationModel).order_by(IntegrationModel.created_at).all()
            return [row.to_dict() for row in rows]

    def get(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Return a single integration by id, or ``None``."""
        with self.db.get_session() as session:
            row = session.query(IntegrationModel).filter_by(id=integration_id).first()
            if row is None:
                return None
            return row.to_dict()

    def create(
        self,
        integration_type: str,
        name: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a new integration and return its dict representation.

        Args:
            integration_type: e.g. "clawdbot", "claude-code", "langchain"
            name: Human-readable display name
            config: Arbitrary JSON configuration blob
        """
        integration_id = secrets.token_hex(8)
        now = datetime.now(timezone.utc)

        model = IntegrationModel(
            id=integration_id,
            type=integration_type,
            name=name,
            status="connected",
            config=json.dumps(config or {}),
            created_at=now,
            last_activity=None,
            total_calls=0,
            allowed=0,
            denied=0,
        )

        with self.db.get_session() as session:
            session.add(model)
            session.flush()
            result = model.to_dict()

        return result

    def update(self, integration_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Partially update an integration.

        Supported keys in *data*: ``name``, ``config``, ``status``.
        Returns the updated dict, or ``None`` if not found.
        """
        with self.db.get_session() as session:
            row = session.query(IntegrationModel).filter_by(id=integration_id).first()
            if row is None:
                return None

            if "name" in data:
                row.name = data["name"]
            if "config" in data:
                existing = json.loads(row.config) if row.config else {}  # type: ignore[arg-type]
                existing.update(data["config"])
                row.config = json.dumps(existing)
            if "status" in data:
                row.status = data["status"]

            session.flush()
            return row.to_dict()

    def delete(self, integration_id: str) -> bool:
        """
        Delete an integration.

        Returns ``True`` if a row was deleted, ``False`` if not found.
        """
        with self.db.get_session() as session:
            row = session.query(IntegrationModel).filter_by(id=integration_id).first()
            if row is None:
                return False
            session.delete(row)
            return True

    # ------------------------------------------------------------------
    # Activity tracking
    # ------------------------------------------------------------------

    def record_activity(self, integration_id: str, decision: str) -> Optional[Dict[str, Any]]:
        """
        Increment stats counters and update ``last_activity``.

        Args:
            integration_id: The integration to update.
            decision: ``"allow"`` or ``"deny"`` (any other value is treated
                      as a generic call that only increments ``total_calls``).

        Returns:
            The updated integration dict, or ``None`` if not found.
        """
        with self.db.get_session() as session:
            row = session.query(IntegrationModel).filter_by(id=integration_id).first()
            if row is None:
                return None

            row.total_calls = (row.total_calls or 0) + 1
            if decision == "allow":
                row.allowed = (row.allowed or 0) + 1
            elif decision == "deny":
                row.denied = (row.denied or 0) + 1
            row.last_activity = datetime.now(timezone.utc)

            session.flush()
            return row.to_dict()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def find_by_type(self, integration_type: str) -> List[Dict[str, Any]]:
        """Return all integrations that match a given type."""
        with self.db.get_session() as session:
            rows = (
                session.query(IntegrationModel)
                .filter_by(type=integration_type)
                .all()
            )
            return [row.to_dict() for row in rows]
