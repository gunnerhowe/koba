"""
Database Models and Connection Management

Provides:
- SQLAlchemy models for all entities
- Connection management for PostgreSQL and SQLite
- Tenant-scoped query helpers
- Migration support via Alembic
"""

import os
import json
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional, TypeVar
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager

# SQLAlchemy imports - with fallback for minimal dependencies
try:
    from sqlalchemy import (
        create_engine, Column, String, Integer, Boolean, Text, DateTime,
        ForeignKey, Index,
    )
    from sqlalchemy.orm import (
        sessionmaker, relationship, declarative_base
    )
    from sqlalchemy.pool import QueuePool, StaticPool
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

# For type hints
T = TypeVar('T')


# ============================================================================
# Enums
# ============================================================================

class TenantStatus(str, Enum):
    """Tenant lifecycle status."""
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class TenantPlan(str, Enum):
    """Tenant subscription plan."""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class UserRole(str, Enum):
    """User roles."""
    VIEWER = "viewer"
    OPERATOR = "operator"
    DEVELOPER = "developer"
    ADMIN = "admin"
    TENANT_ADMIN = "tenant_admin"
    TENANT_OWNER = "tenant_owner"
    SUPER_ADMIN = "super_admin"


class APIKeyStatus(str, Enum):
    """API key status."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


# ============================================================================
# Resource Limits
# ============================================================================

@dataclass
class ResourceLimits:
    """Resource limits based on tenant plan."""
    requests_per_minute: int = 60
    requests_per_day: int = 10000
    max_tools: int = 50
    max_tool_calls_per_minute: int = 30
    max_users: int = 10
    max_api_keys: int = 5
    max_policy_bundles: int = 5
    max_rules_per_bundle: int = 100
    audit_retention_days: int = 30
    max_receipt_storage_mb: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requests_per_minute": self.requests_per_minute,
            "requests_per_day": self.requests_per_day,
            "max_tools": self.max_tools,
            "max_tool_calls_per_minute": self.max_tool_calls_per_minute,
            "max_users": self.max_users,
            "max_api_keys": self.max_api_keys,
            "max_policy_bundles": self.max_policy_bundles,
            "max_rules_per_bundle": self.max_rules_per_bundle,
            "audit_retention_days": self.audit_retention_days,
            "max_receipt_storage_mb": self.max_receipt_storage_mb,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResourceLimits":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


PLAN_LIMITS: Dict[TenantPlan, ResourceLimits] = {
    TenantPlan.FREE: ResourceLimits(
        requests_per_minute=30,
        requests_per_day=1000,
        max_users=3,
        max_api_keys=1,
        max_tools=10,
        audit_retention_days=7,
    ),
    TenantPlan.STARTER: ResourceLimits(
        requests_per_minute=100,
        requests_per_day=50000,
        max_users=10,
        max_api_keys=5,
        max_tools=50,
        audit_retention_days=30,
    ),
    TenantPlan.PROFESSIONAL: ResourceLimits(
        requests_per_minute=500,
        requests_per_day=500000,
        max_users=50,
        max_api_keys=20,
        max_tools=200,
        audit_retention_days=90,
    ),
    TenantPlan.ENTERPRISE: ResourceLimits(
        requests_per_minute=10000,
        requests_per_day=10000000,
        max_users=-1,  # unlimited
        max_api_keys=-1,
        max_tools=-1,
        audit_retention_days=365,
    ),
}


# ============================================================================
# SQLAlchemy Models (if available)
# ============================================================================

if SQLALCHEMY_AVAILABLE:
    Base = declarative_base()

    class TenantModel(Base):  # type: ignore[valid-type,misc]
        """Tenant/Organization."""
        __tablename__ = "tenants"

        id = Column(String(64), primary_key=True)
        name = Column(String(255), nullable=False)
        slug = Column(String(100), unique=True, nullable=False, index=True)
        status = Column(String(20), nullable=False, default=TenantStatus.ACTIVE.value)
        plan = Column(String(20), nullable=False, default=TenantPlan.FREE.value)
        created_at = Column(DateTime(timezone=True), nullable=False)
        updated_at = Column(DateTime(timezone=True), nullable=False)
        settings = Column(Text, default="{}")  # JSON
        resource_limits = Column(Text, default="{}")  # JSON
        metadata_ = Column("metadata", Text, default="{}")  # JSON

        # Relationships
        users = relationship("UserModel", back_populates="tenant", lazy="dynamic")
        api_keys = relationship("APIKeyModel", back_populates="tenant", lazy="dynamic")

        def get_settings(self) -> Dict[str, Any]:
            return json.loads(self.settings) if self.settings else {}  # type: ignore[arg-type]

        def get_resource_limits(self) -> ResourceLimits:
            if self.resource_limits:
                return ResourceLimits.from_dict(json.loads(self.resource_limits))  # type: ignore[arg-type]
            return PLAN_LIMITS.get(TenantPlan(self.plan), ResourceLimits())


    class UserModel(Base):  # type: ignore[valid-type,misc]
        """User account."""
        __tablename__ = "users"

        id = Column(String(64), primary_key=True)
        tenant_id = Column(String(64), ForeignKey("tenants.id"), nullable=True, index=True)
        email = Column(String(255), nullable=False)
        username = Column(String(100), nullable=False)
        password_hash = Column(String(255), nullable=False)
        role = Column(String(30), nullable=False, default=UserRole.VIEWER.value)
        is_system_admin = Column(Boolean, default=False)
        created_at = Column(DateTime(timezone=True), nullable=False)
        updated_at = Column(DateTime(timezone=True), nullable=False)
        last_login = Column(DateTime(timezone=True), nullable=True)
        is_active = Column(Boolean, default=True)
        mfa_enabled = Column(Boolean, default=False)
        mfa_secret = Column(String(255), nullable=True)
        metadata_ = Column("metadata", Text, default="{}")  # JSON

        # Relationships
        tenant = relationship("TenantModel", back_populates="users")
        sessions = relationship("SessionModel", back_populates="user", lazy="dynamic")

        # Composite unique constraint (email unique per tenant)
        __table_args__ = (
            Index('ix_users_tenant_email', 'tenant_id', 'email', unique=True),
            Index('ix_users_tenant_username', 'tenant_id', 'username', unique=True),
        )


    class SessionModel(Base):  # type: ignore[valid-type,misc]
        """User session."""
        __tablename__ = "sessions"

        session_id = Column(String(64), primary_key=True)
        user_id = Column(String(64), ForeignKey("users.id"), nullable=False, index=True)
        tenant_id = Column(String(64), ForeignKey("tenants.id"), nullable=True, index=True)
        created_at = Column(DateTime(timezone=True), nullable=False)
        expires_at = Column(DateTime(timezone=True), nullable=False)
        ip_address = Column(String(45), nullable=True)
        user_agent = Column(String(500), nullable=True)
        is_active = Column(Boolean, default=True)

        # Relationships
        user = relationship("UserModel", back_populates="sessions")


    class APIKeyModel(Base):  # type: ignore[valid-type,misc]
        """Tenant API key."""
        __tablename__ = "api_keys"

        id = Column(String(64), primary_key=True)
        tenant_id = Column(String(64), ForeignKey("tenants.id"), nullable=False, index=True)
        name = Column(String(255), nullable=False)
        key_prefix = Column(String(12), nullable=False)  # First 8 chars for identification
        key_hash = Column(String(255), nullable=False)
        permissions = Column(Text, default="[]")  # JSON array
        rate_limit_rpm = Column(Integer, default=60)
        status = Column(String(20), nullable=False, default=APIKeyStatus.ACTIVE.value)
        created_at = Column(DateTime(timezone=True), nullable=False)
        expires_at = Column(DateTime(timezone=True), nullable=True)
        last_used_at = Column(DateTime(timezone=True), nullable=True)
        created_by = Column(String(64), ForeignKey("users.id"), nullable=True)
        metadata_ = Column("metadata", Text, default="{}")

        # Relationships
        tenant = relationship("TenantModel", back_populates="api_keys")

        __table_args__ = (
            Index('ix_api_keys_prefix', 'key_prefix'),
        )


    class PolicyBundleModel(Base):  # type: ignore[valid-type,misc]
        """Tenant policy bundle."""
        __tablename__ = "policy_bundles"

        id = Column(String(64), primary_key=True)
        tenant_id = Column(String(64), ForeignKey("tenants.id"), nullable=False, index=True)
        version = Column(String(50), nullable=False)
        name = Column(String(255), nullable=False)
        description = Column(Text, default="")
        bundle_data = Column(Text, nullable=False)  # JSON serialized PolicyBundle
        is_active = Column(Boolean, default=False)
        created_at = Column(DateTime(timezone=True), nullable=False)
        updated_at = Column(DateTime(timezone=True), nullable=False)
        created_by = Column(String(64), ForeignKey("users.id"), nullable=True)
        signature = Column(Text, nullable=True)
        signer_public_key = Column(String(255), nullable=True)

        __table_args__ = (
            Index('ix_policy_bundles_tenant_active', 'tenant_id', 'is_active'),
        )


    class ReceiptModel(Base):  # type: ignore[valid-type,misc]
        """Signed Action Receipt."""
        __tablename__ = "receipts"

        id = Column(String(128), primary_key=True)  # SHA-256 hash
        tenant_id = Column(String(64), ForeignKey("tenants.id"), nullable=False, index=True)
        agent_id = Column(String(128), nullable=False, index=True)
        session_id = Column(String(64), nullable=True, index=True)
        tool_id = Column(String(255), nullable=False, index=True)
        decision = Column(String(30), nullable=False)
        receipt_data = Column(Text, nullable=False)  # JSON serialized receipt
        created_at = Column(DateTime(timezone=True), nullable=False, index=True)
        log_index = Column(Integer, nullable=True, index=True)
        merkle_root = Column(String(128), nullable=True)

        __table_args__ = (
            Index('ix_receipts_tenant_created', 'tenant_id', 'created_at'),
            Index('ix_receipts_tenant_agent', 'tenant_id', 'agent_id'),
        )


    class AuditEntryModel(Base):  # type: ignore[valid-type,misc]
        """Audit log entry."""
        __tablename__ = "audit_log"

        id = Column(String(64), primary_key=True)
        tenant_id = Column(String(64), ForeignKey("tenants.id"), nullable=False, index=True)
        event_type = Column(String(100), nullable=False, index=True)
        actor_id = Column(String(64), nullable=True)
        actor_type = Column(String(30), nullable=True)  # user, agent, system
        resource_type = Column(String(50), nullable=True)
        resource_id = Column(String(128), nullable=True)
        action = Column(String(50), nullable=False)
        details = Column(Text, default="{}")  # JSON
        ip_address = Column(String(45), nullable=True)
        created_at = Column(DateTime(timezone=True), nullable=False, index=True)

        __table_args__ = (
            Index('ix_audit_tenant_created', 'tenant_id', 'created_at'),
            Index('ix_audit_tenant_event', 'tenant_id', 'event_type'),
        )


    class BlockchainAnchorModel(Base):  # type: ignore[valid-type,misc]
        """Blockchain anchor record."""
        __tablename__ = "blockchain_anchors"

        id = Column(String(64), primary_key=True)
        tree_size = Column(Integer, nullable=False)
        merkle_root = Column(String(128), nullable=False, index=True)
        tree_head_signature = Column(Text, nullable=False)
        chain = Column(String(30), nullable=False)  # hedera, ethereum
        network = Column(String(30), nullable=False)  # mainnet, testnet
        topic_id = Column(String(50), nullable=True)  # Hedera topic
        sequence_number = Column(Integer, nullable=True)
        transaction_id = Column(String(128), nullable=True, index=True)
        transaction_hash = Column(String(128), nullable=True)
        block_number = Column(Integer, nullable=True)
        timestamp = Column(DateTime(timezone=True), nullable=False)
        anchored_at = Column(DateTime(timezone=True), nullable=False, index=True)
        verified = Column(Boolean, default=False)
        verification_data = Column(Text, nullable=True)  # JSON

        __table_args__ = (
            Index('ix_anchors_merkle', 'merkle_root'),
            Index('ix_anchors_chain_time', 'chain', 'anchored_at'),
        )


    class RefreshTokenModel(Base):  # type: ignore[valid-type,misc]
        """Refresh token storage."""
        __tablename__ = "refresh_tokens"

        token_id = Column(String(64), primary_key=True)
        user_id = Column(String(64), ForeignKey("users.id"), nullable=False, index=True)
        token_hash = Column(String(255), nullable=False)
        created_at = Column(DateTime(timezone=True), nullable=False)
        expires_at = Column(DateTime(timezone=True), nullable=False)
        is_revoked = Column(Boolean, default=False)


# ============================================================================
# Database Connection Management
# ============================================================================

class DatabaseManager:
    """
    Manages database connections and sessions.

    Supports both PostgreSQL (production) and SQLite (development).
    """

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize database manager.

        Args:
            database_url: Database connection URL. If None, uses DATABASE_URL env var
                          or defaults to SQLite.
        """
        if not SQLALCHEMY_AVAILABLE:
            raise ImportError("SQLAlchemy is required for database operations. "
                            "Install with: pip install sqlalchemy")

        self.database_url: str = database_url or os.getenv(
            "DATABASE_URL",
            "sqlite:///./vacp_data/koba.db"
        ) or "sqlite:///./vacp_data/koba.db"  # Fallback to ensure not None

        # Configure engine based on database type
        if self.database_url.startswith("sqlite"):
            # SQLite configuration
            connect_args = {"check_same_thread": False}
            self.engine = create_engine(
                self.database_url,
                connect_args=connect_args,
                poolclass=StaticPool if ":memory:" in self.database_url else QueuePool,
                echo=os.getenv("DB_ECHO", "false").lower() == "true",
            )
        else:
            # PostgreSQL/other configuration
            self.engine = create_engine(
                self.database_url,
                pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
                max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
                pool_pre_ping=True,
                echo=os.getenv("DB_ECHO", "false").lower() == "true",
            )

        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )

    def create_tables(self):
        """Create all tables if they don't exist."""
        Base.metadata.create_all(bind=self.engine)

    def drop_tables(self):
        """Drop all tables (use with caution!)."""
        Base.metadata.drop_all(bind=self.engine)

    @contextmanager
    def get_session(self):
        """
        Get a database session with automatic cleanup.

        Usage:
            with db.get_session() as session:
                session.query(UserModel).all()
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_session_factory(self) -> sessionmaker:
        """Get the session factory for dependency injection."""
        return self.SessionLocal


# ============================================================================
# Dataclass representations (for API compatibility with existing code)
# ============================================================================

@dataclass
class Tenant:
    """Tenant dataclass for API use."""
    id: str
    name: str
    slug: str
    status: TenantStatus
    plan: TenantPlan
    created_at: datetime
    updated_at: datetime
    settings: Dict[str, Any] = field(default_factory=dict)
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status.value,
            "plan": self.plan.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "settings": self.settings,
            "resource_limits": self.resource_limits.to_dict(),
        }

    @classmethod
    def from_model(cls, model: "TenantModel") -> "Tenant":
        """Create from SQLAlchemy model."""
        return cls(  # type: ignore[arg-type]
            id=model.id,
            name=model.name,
            slug=model.slug,
            status=TenantStatus(model.status),
            plan=TenantPlan(model.plan),
            created_at=model.created_at,
            updated_at=model.updated_at,
            settings=json.loads(model.settings) if model.settings else {},  # type: ignore[arg-type]
            resource_limits=model.get_resource_limits(),
            metadata=json.loads(model.metadata_) if model.metadata_ else {},  # type: ignore[arg-type]
        )


@dataclass
class APIKey:
    """API Key dataclass for API use."""
    id: str
    tenant_id: str
    name: str
    key_prefix: str
    permissions: List[str]
    rate_limit_rpm: int
    status: APIKeyStatus
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    created_by: Optional[str]

    def to_dict(self, include_key: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "permissions": self.permissions,
            "rate_limit_rpm": self.rate_limit_rpm,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }
        return data

    @classmethod
    def from_model(cls, model: "APIKeyModel") -> "APIKey":
        """Create from SQLAlchemy model."""
        return cls(  # type: ignore[arg-type]
            id=model.id,
            tenant_id=model.tenant_id,
            name=model.name,
            key_prefix=model.key_prefix,
            permissions=json.loads(model.permissions) if model.permissions else [],  # type: ignore[arg-type]
            rate_limit_rpm=model.rate_limit_rpm,
            status=APIKeyStatus(model.status),
            created_at=model.created_at,
            expires_at=model.expires_at,
            last_used_at=model.last_used_at,
            created_by=model.created_by,
        )


@dataclass
class BlockchainAnchor:
    """Blockchain anchor dataclass."""
    id: str
    tree_size: int
    merkle_root: str
    tree_head_signature: str
    chain: str
    network: str
    topic_id: Optional[str]
    sequence_number: Optional[int]
    transaction_id: Optional[str]
    transaction_hash: Optional[str]
    block_number: Optional[int]
    timestamp: datetime
    anchored_at: datetime
    verified: bool = False
    verification_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tree_size": self.tree_size,
            "merkle_root": self.merkle_root,
            "chain": self.chain,
            "network": self.network,
            "topic_id": self.topic_id,
            "sequence_number": self.sequence_number,
            "transaction_id": self.transaction_id,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "timestamp": self.timestamp.isoformat(),
            "anchored_at": self.anchored_at.isoformat(),
            "verified": self.verified,
        }

    @classmethod
    def from_model(cls, model: "BlockchainAnchorModel") -> "BlockchainAnchor":
        """Create from SQLAlchemy model."""
        return cls(  # type: ignore[arg-type]
            id=model.id,
            tree_size=model.tree_size,
            merkle_root=model.merkle_root,
            tree_head_signature=model.tree_head_signature,
            chain=model.chain,
            network=model.network,
            topic_id=model.topic_id,
            sequence_number=model.sequence_number,
            transaction_id=model.transaction_id,
            transaction_hash=model.transaction_hash,
            block_number=model.block_number,
            timestamp=model.timestamp,
            anchored_at=model.anchored_at,
            verified=model.verified,
            verification_data=json.loads(model.verification_data) if model.verification_data else None,  # type: ignore[arg-type]
        )


# ============================================================================
# Utility Functions
# ============================================================================

def generate_id(prefix: str = "") -> str:
    """Generate a unique ID with optional prefix."""
    random_part = secrets.token_hex(16)
    if prefix:
        return f"{prefix}_{random_part}"
    return random_part


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns:
        Tuple of (full_key, key_prefix, key_hash)
    """
    import hashlib

    # Generate key: koba_<random>
    key = f"koba_{secrets.token_urlsafe(32)}"
    prefix = key[:12]  # First 12 chars for identification
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    return key, prefix, key_hash


def hash_api_key(key: str) -> str:
    """Hash an API key for storage."""
    import hashlib
    return hashlib.sha256(key.encode()).hexdigest()


# ============================================================================
# Global database instance (lazy initialization)
# ============================================================================

_db_manager: Optional[DatabaseManager] = None


def get_db() -> DatabaseManager:
    """Get the global database manager, initializing if needed."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        _db_manager.create_tables()
    return _db_manager


def init_db(database_url: Optional[str] = None) -> DatabaseManager:
    """Initialize the global database manager with custom URL."""
    global _db_manager
    _db_manager = DatabaseManager(database_url)
    _db_manager.create_tables()
    return _db_manager
