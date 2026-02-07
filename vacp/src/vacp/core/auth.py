"""
Authentication and Authorization System

Provides:
- User account management with bcrypt password hashing
- JWT token authentication
- Role-based access control (RBAC)
- Session management
- Multi-tenant support
- API key authentication
- SQLite persistence (with PostgreSQL support via database.py)
"""

import hashlib
import secrets
import sqlite3
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import base64
import hmac

# bcrypt is required for password hashing - no fallback allowed
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    raise RuntimeError(
        "CRITICAL: bcrypt library is required for password hashing. "
        "Install with: pip install bcrypt"
    )


class UserRole(Enum):
    """System roles with hierarchical permissions."""
    VIEWER = "viewer"           # Can view audit logs and tools
    OPERATOR = "operator"       # Can execute tools and approve actions
    ADMIN = "admin"             # Can manage policies, users, and settings
    SUPER_ADMIN = "super_admin" # Full system access including key management


class Permission(Enum):
    """Granular permissions."""
    # Audit
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # Tools
    TOOLS_READ = "tools:read"
    TOOLS_EXECUTE = "tools:execute"
    TOOLS_REGISTER = "tools:register"
    TOOLS_DELETE = "tools:delete"

    # Policy
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    POLICY_DELETE = "policy:delete"

    # Approvals
    APPROVALS_READ = "approvals:read"
    APPROVALS_GRANT = "approvals:grant"
    APPROVALS_DENY = "approvals:deny"

    # Users
    USERS_READ = "users:read"
    USERS_CREATE = "users:create"
    USERS_UPDATE = "users:update"
    USERS_DELETE = "users:delete"

    # Settings
    SETTINGS_READ = "settings:read"
    SETTINGS_WRITE = "settings:write"

    # Capabilities
    CAPABILITIES_ISSUE = "capabilities:issue"
    CAPABILITIES_REVOKE = "capabilities:revoke"

    # System
    SYSTEM_ADMIN = "system:admin"


# Role to permissions mapping
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.VIEWER: {
        Permission.AUDIT_READ,
        Permission.TOOLS_READ,
        Permission.POLICY_READ,
        Permission.APPROVALS_READ,
    },
    UserRole.OPERATOR: {
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.TOOLS_READ,
        Permission.TOOLS_EXECUTE,
        Permission.POLICY_READ,
        Permission.APPROVALS_READ,
        Permission.APPROVALS_GRANT,
        Permission.APPROVALS_DENY,
    },
    UserRole.ADMIN: {
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.TOOLS_READ,
        Permission.TOOLS_EXECUTE,
        Permission.TOOLS_REGISTER,
        Permission.TOOLS_DELETE,
        Permission.POLICY_READ,
        Permission.POLICY_WRITE,
        Permission.POLICY_DELETE,
        Permission.APPROVALS_READ,
        Permission.APPROVALS_GRANT,
        Permission.APPROVALS_DENY,
        Permission.USERS_READ,
        Permission.USERS_CREATE,
        Permission.USERS_UPDATE,
        Permission.SETTINGS_READ,
        Permission.SETTINGS_WRITE,
        Permission.CAPABILITIES_ISSUE,
    },
    UserRole.SUPER_ADMIN: {p for p in Permission},  # All permissions
}


@dataclass
class User:
    """User account."""
    id: str
    email: str
    username: str
    password_hash: str
    role: UserRole
    created_at: datetime
    updated_at: datetime
    tenant_id: Optional[str] = None  # None for system admins
    last_login: Optional[datetime] = None
    is_active: bool = True
    is_system_admin: bool = False  # True for system-wide admins
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        return permission in ROLE_PERMISSIONS.get(self.role, set())

    def get_permissions(self) -> Set[Permission]:
        """Get all permissions for this user."""
        return ROLE_PERMISSIONS.get(self.role, set())

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "role": self.role.value,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_active": self.is_active,
            "is_system_admin": self.is_system_admin,
            "mfa_enabled": self.mfa_enabled,
            "permissions": [p.value for p in self.get_permissions()],
        }
        if include_sensitive:
            data["password_hash"] = self.password_hash
            data["mfa_secret"] = self.mfa_secret
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            email=data["email"],
            username=data["username"],
            password_hash=data["password_hash"],
            role=UserRole(data["role"]),
            created_at=datetime.fromisoformat(data["created_at"]) if isinstance(data["created_at"], str) else data["created_at"],
            updated_at=datetime.fromisoformat(data["updated_at"]) if isinstance(data["updated_at"], str) else data["updated_at"],
            tenant_id=data.get("tenant_id"),
            last_login=datetime.fromisoformat(data["last_login"]) if data.get("last_login") else None,
            is_active=data.get("is_active", True),
            is_system_admin=data.get("is_system_admin", False),
            mfa_enabled=data.get("mfa_enabled", False),
            mfa_secret=data.get("mfa_secret"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Session:
    """User session."""
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    tenant_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool = True

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "is_active": self.is_active,
        }


@dataclass
class APIKey:
    """API Key for programmatic access."""
    id: str
    tenant_id: str
    name: str
    key_hash: str
    key_prefix: str  # First 8 chars for identification
    permissions: List[str]
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    rate_limit: Optional[int] = None  # Requests per minute
    is_active: bool = True
    created_by: Optional[str] = None

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "permissions": self.permissions,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "rate_limit": self.rate_limit,
            "is_active": self.is_active,
            "created_by": self.created_by,
        }
        if include_sensitive:
            data["key_hash"] = self.key_hash
        return data


class PasswordHasher:
    """Password hashing utility."""

    @staticmethod
    def hash(password: str) -> str:
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    @staticmethod
    def verify(password: str, password_hash: str) -> bool:
        """Verify a password against its bcrypt hash."""
        try:
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        except Exception:
            return False


class JWTService:
    """Simple JWT implementation without external dependencies."""

    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        """
        Initialize JWT service.

        Args:
            secret_key: Secret key for signing tokens
            algorithm: Signing algorithm (only HS256 supported)
        """
        self.secret_key = secret_key
        self.algorithm = algorithm

    def _base64url_encode(self, data: bytes) -> str:
        """Base64url encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    def _base64url_decode(self, data: str) -> bytes:
        """Base64url decode with padding restoration."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    def encode(self, payload: Dict[str, Any], expires_in: int = 3600) -> str:
        """
        Encode a JWT token.

        Args:
            payload: Token payload
            expires_in: Expiration time in seconds

        Returns:
            JWT token string
        """
        # Add standard claims
        now = datetime.now(timezone.utc)
        payload = {
            **payload,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        }

        # Header
        header = {"alg": self.algorithm, "typ": "JWT"}
        header_b64 = self._base64url_encode(json.dumps(header).encode())

        # Payload
        payload_b64 = self._base64url_encode(json.dumps(payload).encode())

        # Signature
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = self._base64url_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def decode(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode and verify a JWT token.

        Args:
            token: JWT token string

        Returns:
            Token payload if valid, None otherwise
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            header_b64, payload_b64, signature_b64 = parts

            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_sig = hmac.new(
                self.secret_key.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()

            actual_sig = self._base64url_decode(signature_b64)
            if not hmac.compare_digest(expected_sig, actual_sig):
                return None

            # Decode payload
            payload = json.loads(self._base64url_decode(payload_b64))

            # Check expiration
            if "exp" in payload:
                exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                if datetime.now(timezone.utc) > exp:
                    return None

            return payload
        except Exception:
            return None


class UserDatabase:
    """SQLite-backed user database with multi-tenant support."""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the user database.

        Args:
            db_path: Path to SQLite database. If None, uses in-memory database.
        """
        if db_path:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(db_path)
        else:
            self.db_path = ":memory:"

        self._init_db()

    def _init_db(self):
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    tenant_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT,
                    is_active INTEGER DEFAULT 1,
                    is_system_admin INTEGER DEFAULT 0,
                    mfa_enabled INTEGER DEFAULT 0,
                    mfa_secret TEXT,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    tenant_id TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    tenant_id TEXT,
                    token_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_revoked INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    permissions TEXT DEFAULT '[]',
                    rate_limit INTEGER,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used_at TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_by TEXT,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id)")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_username ON users(tenant_id, username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
            conn.commit()

    def create_user(self, user: User) -> User:
        """Create a new user."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO users (id, email, username, password_hash, role, tenant_id,
                                   created_at, updated_at, is_active, is_system_admin,
                                   mfa_enabled, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user.id, user.email, user.username, user.password_hash,
                user.role.value, user.tenant_id, user.created_at.isoformat(),
                user.updated_at.isoformat(), int(user.is_active),
                int(user.is_system_admin), int(user.mfa_enabled),
                json.dumps(user.metadata)
            ))
            conn.commit()
        return user

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row:
                return self._row_to_user(row)
        return None

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            if row:
                return self._row_to_user(row)
        return None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row:
                return self._row_to_user(row)
        return None

    def update_user(self, user: User) -> User:
        """Update an existing user."""
        user.updated_at = datetime.now(timezone.utc)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE users SET
                    email = ?, username = ?, password_hash = ?, role = ?,
                    tenant_id = ?, updated_at = ?, last_login = ?, is_active = ?,
                    is_system_admin = ?, mfa_enabled = ?, mfa_secret = ?, metadata = ?
                WHERE id = ?
            """, (
                user.email, user.username, user.password_hash, user.role.value,
                user.tenant_id, user.updated_at.isoformat(),
                user.last_login.isoformat() if user.last_login else None,
                int(user.is_active), int(user.is_system_admin),
                int(user.mfa_enabled), user.mfa_secret,
                json.dumps(user.metadata), user.id
            ))
            conn.commit()
        return user

    def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """List all users."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()
            return [self._row_to_user(row) for row in rows]

    def count_users(self) -> int:
        """Count total users."""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def _row_to_user(self, row: sqlite3.Row) -> User:
        """Convert a database row to a User object."""
        return User(
            id=row["id"],
            email=row["email"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=UserRole(row["role"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            tenant_id=row["tenant_id"] if "tenant_id" in row.keys() else None,
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
            is_active=bool(row["is_active"]),
            is_system_admin=bool(row["is_system_admin"]) if "is_system_admin" in row.keys() else False,
            mfa_enabled=bool(row["mfa_enabled"]),
            mfa_secret=row["mfa_secret"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    # Tenant-scoped user queries
    def get_users_by_tenant(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[User]:
        """Get all users for a tenant."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM users WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (tenant_id, limit, offset)
            ).fetchall()
            return [self._row_to_user(row) for row in rows]

    def get_user_by_username_in_tenant(
        self,
        username: str,
        tenant_id: str
    ) -> Optional[User]:
        """Get user by username within a specific tenant."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND tenant_id = ?",
                (username, tenant_id)
            ).fetchone()
            if row:
                return self._row_to_user(row)
        return None

    def get_user_by_email_in_tenant(
        self,
        email: str,
        tenant_id: str
    ) -> Optional[User]:
        """Get user by email within a specific tenant."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM users WHERE email = ? AND tenant_id = ?",
                (email, tenant_id)
            ).fetchone()
            if row:
                return self._row_to_user(row)
        return None

    def count_users_by_tenant(self, tenant_id: str) -> int:
        """Count users in a tenant."""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM users WHERE tenant_id = ?",
                (tenant_id,)
            ).fetchone()[0]

    def get_system_admins(self) -> List[User]:
        """Get all system admin users."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM users WHERE is_system_admin = 1 ORDER BY created_at DESC"
            ).fetchall()
            return [self._row_to_user(row) for row in rows]

    # API Key methods
    def create_api_key(self, api_key: APIKey) -> APIKey:
        """Create a new API key."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix,
                                      permissions, rate_limit, created_at, expires_at,
                                      is_active, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                api_key.id, api_key.tenant_id, api_key.name, api_key.key_hash,
                api_key.key_prefix, json.dumps(api_key.permissions),
                api_key.rate_limit, api_key.created_at.isoformat(),
                api_key.expires_at.isoformat() if api_key.expires_at else None,
                int(api_key.is_active), api_key.created_by
            ))
            conn.commit()
        return api_key

    def get_api_key_by_hash(self, key_hash: str) -> Optional[APIKey]:
        """Get API key by hash."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)
            ).fetchone()
            if row:
                return self._row_to_api_key(row)
        return None

    def get_api_keys_by_tenant(self, tenant_id: str) -> List[APIKey]:
        """Get all API keys for a tenant."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC",
                (tenant_id,)
            ).fetchall()
            return [self._row_to_api_key(row) for row in rows]

    def update_api_key_last_used(self, key_id: str) -> None:
        """Update API key last used timestamp."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), key_id)
            )
            conn.commit()

    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET is_active = 0 WHERE id = ?",
                (key_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_api_key(self, key_id: str) -> bool:
        """Delete an API key."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM api_keys WHERE id = ?", (key_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def _row_to_api_key(self, row: sqlite3.Row) -> APIKey:
        """Convert a database row to an APIKey object."""
        return APIKey(
            id=row["id"],
            tenant_id=row["tenant_id"],
            name=row["name"],
            key_hash=row["key_hash"],
            key_prefix=row["key_prefix"],
            permissions=json.loads(row["permissions"]) if row["permissions"] else [],
            rate_limit=row["rate_limit"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            last_used_at=datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None,
            is_active=bool(row["is_active"]),
            created_by=row["created_by"],
        )

    # Session management
    def create_session(self, session: Session) -> Session:
        """Create a new session."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO sessions (session_id, user_id, tenant_id, created_at, expires_at,
                                      ip_address, user_agent, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.session_id, session.user_id, session.tenant_id,
                session.created_at.isoformat(), session.expires_at.isoformat(),
                session.ip_address, session.user_agent, int(session.is_active)
            ))
            conn.commit()
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if row:
                return Session(
                    session_id=row["session_id"],
                    user_id=row["user_id"],
                    tenant_id=row["tenant_id"] if "tenant_id" in row.keys() else None,
                    created_at=datetime.fromisoformat(row["created_at"]),
                    expires_at=datetime.fromisoformat(row["expires_at"]),
                    ip_address=row["ip_address"],
                    user_agent=row["user_agent"],
                    is_active=bool(row["is_active"]),
                )
        return None

    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE sessions SET is_active = 0 WHERE session_id = ?",
                (session_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def invalidate_user_sessions(self, user_id: str) -> int:
        """Invalidate all sessions for a user."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE sessions SET is_active = 0 WHERE user_id = ?",
                (user_id,)
            )
            conn.commit()
            return cursor.rowcount

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?", (now,)
            )
            conn.commit()
            return cursor.rowcount


class AuthService:
    """Main authentication service."""

    def __init__(
        self,
        db: UserDatabase,
        jwt_secret: Optional[str] = None,
        access_token_ttl: int = 2592000,    # 30 days
        refresh_token_ttl: int = 2592000,   # 30 days
        session_ttl: int = 2592000,         # 30 days
    ):
        """
        Initialize the auth service.

        Args:
            db: User database
            jwt_secret: Secret for JWT signing (generated if not provided)
            access_token_ttl: Access token lifetime in seconds
            refresh_token_ttl: Refresh token lifetime in seconds
            session_ttl: Session lifetime in seconds
        """
        self.db = db
        self.jwt_secret = jwt_secret or secrets.token_hex(32)
        self.jwt_service = JWTService(self.jwt_secret)
        self.access_token_ttl = access_token_ttl
        self.refresh_token_ttl = refresh_token_ttl
        self.session_ttl = session_ttl

    def register(
        self,
        email: str,
        username: str,
        password: str,
        role: UserRole = UserRole.VIEWER,
        tenant_id: Optional[str] = None,
        is_system_admin: bool = False,
    ) -> User:
        """
        Register a new user.

        Args:
            email: User email
            username: Username
            password: Plain text password
            role: User role
            tenant_id: Tenant ID (None for system admins)
            is_system_admin: Whether user is a system admin

        Returns:
            Created user

        Raises:
            ValueError: If email or username already exists
        """
        # Check for existing user (tenant-scoped if tenant_id provided)
        if tenant_id:
            if self.db.get_user_by_email_in_tenant(email, tenant_id):
                raise ValueError("Email already registered in this tenant")
            if self.db.get_user_by_username_in_tenant(username, tenant_id):
                raise ValueError("Username already taken in this tenant")
        else:
            # System admin - check globally
            if self.db.get_user_by_email(email):
                raise ValueError("Email already registered")
            if self.db.get_user_by_username(username):
                raise ValueError("Username already taken")

        now = datetime.now(timezone.utc)
        user = User(
            id=secrets.token_hex(16),
            email=email,
            username=username,
            password_hash=PasswordHasher.hash(password),
            role=role,
            tenant_id=tenant_id,
            created_at=now,
            updated_at=now,
            is_system_admin=is_system_admin,
        )

        return self.db.create_user(user)

    def login(
        self,
        email_or_username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Authenticate a user and create tokens.

        Args:
            email_or_username: Email or username
            password: Plain text password
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Dict with access_token, refresh_token, and user info

        Raises:
            ValueError: If credentials are invalid
        """
        # Find user
        user = self.db.get_user_by_email(email_or_username)
        if not user:
            user = self.db.get_user_by_username(email_or_username)
        if not user:
            raise ValueError("Invalid credentials")

        # Verify password
        if not PasswordHasher.verify(password, user.password_hash):
            raise ValueError("Invalid credentials")

        # Check if active
        if not user.is_active:
            raise ValueError("Account is disabled")

        # Update last login
        user.last_login = datetime.now(timezone.utc)
        self.db.update_user(user)

        # Create session
        session = self._create_session(user, ip_address, user_agent)

        # Create tokens
        access_token = self._create_access_token(user, session.session_id)
        refresh_token = self._create_refresh_token(user, session.session_id)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self.access_token_ttl,
            "user": user.to_dict(),
            "session_id": session.session_id,
        }

    def logout(self, session_id: str) -> bool:
        """
        Logout by invalidating the session.

        Args:
            session_id: Session to invalidate

        Returns:
            True if session was invalidated
        """
        return self.db.invalidate_session(session_id)

    def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Refresh token

        Returns:
            New access_token and refresh_token

        Raises:
            ValueError: If refresh token is invalid
        """
        payload = self.jwt_service.decode(refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise ValueError("Invalid refresh token")

        user = self.db.get_user_by_id(payload["sub"])
        if not user or not user.is_active:
            raise ValueError("Invalid refresh token")

        session_id = payload.get("session_id")
        if session_id:
            session = self.db.get_session(session_id)
            if not session or not session.is_active:
                raise ValueError("Session expired")

        # Create new tokens
        access_token = self._create_access_token(user, session_id)
        new_refresh_token = self._create_refresh_token(user, session_id)

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": self.access_token_ttl,
        }

    def verify_token(self, token: str) -> Optional[User]:
        """
        Verify an access token and return the user.

        Args:
            token: Access token

        Returns:
            User if token is valid, None otherwise
        """
        payload = self.jwt_service.decode(token)
        if not payload or payload.get("type") != "access":
            return None

        user = self.db.get_user_by_id(payload["sub"])
        if not user or not user.is_active:
            return None

        # Verify session is still active
        session_id = payload.get("session_id")
        if session_id:
            session = self.db.get_session(session_id)
            if not session or not session.is_active:
                return None

        return user

    def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
    ) -> bool:
        """
        Change a user's password.

        Args:
            user_id: User ID
            old_password: Current password
            new_password: New password

        Returns:
            True if password was changed

        Raises:
            ValueError: If old password is incorrect
        """
        user = self.db.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        if not PasswordHasher.verify(old_password, user.password_hash):
            raise ValueError("Incorrect current password")

        user.password_hash = PasswordHasher.hash(new_password)
        self.db.update_user(user)

        # Invalidate all sessions
        self.db.invalidate_user_sessions(user_id)

        return True

    def _create_session(
        self,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Session:
        """Create a new session for a user."""
        now = datetime.now(timezone.utc)
        session = Session(
            session_id=secrets.token_hex(16),
            user_id=user.id,
            tenant_id=user.tenant_id,
            created_at=now,
            expires_at=now + timedelta(seconds=self.session_ttl),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return self.db.create_session(session)

    def _create_access_token(self, user: User, session_id: Optional[str] = None) -> str:
        """Create an access token for a user."""
        payload = {
            "sub": user.id,
            "email": user.email,
            "username": user.username,
            "role": user.role.value,
            "tenant_id": user.tenant_id,
            "is_system_admin": user.is_system_admin,
            "permissions": [p.value for p in user.get_permissions()],
            "type": "access",
            "session_id": session_id,
        }
        return self.jwt_service.encode(payload, self.access_token_ttl)

    def _create_refresh_token(self, user: User, session_id: Optional[str] = None) -> str:
        """Create a refresh token for a user."""
        payload = {
            "sub": user.id,
            "tenant_id": user.tenant_id,
            "type": "refresh",
            "session_id": session_id,
        }
        return self.jwt_service.encode(payload, self.refresh_token_ttl)

    # API Key Authentication
    def create_api_key(
        self,
        tenant_id: str,
        name: str,
        permissions: Optional[List[str]] = None,
        rate_limit: Optional[int] = None,
        expires_in_days: Optional[int] = None,
        created_by: Optional[str] = None,
    ) -> tuple[APIKey, str]:
        """
        Create a new API key for a tenant.

        Args:
            tenant_id: Tenant ID
            name: Key name/description
            permissions: List of permission strings
            rate_limit: Requests per minute limit
            expires_in_days: Days until expiration (None = never)
            created_by: User ID of creator

        Returns:
            Tuple of (APIKey object, raw key string)
            The raw key is only returned once - store it securely!
        """
        raw_key = f"kb_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:11]  # "kb_" + first 8 chars

        now = datetime.now(timezone.utc)
        expires_at = None
        if expires_in_days:
            expires_at = now + timedelta(days=expires_in_days)

        api_key = APIKey(
            id=secrets.token_hex(16),
            tenant_id=tenant_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            permissions=permissions or [],
            rate_limit=rate_limit,
            created_at=now,
            expires_at=expires_at,
            created_by=created_by,
        )

        self.db.create_api_key(api_key)
        return api_key, raw_key

    def verify_api_key(self, api_key: str) -> Optional[tuple[APIKey, str]]:
        """
        Verify an API key and return the key object and tenant_id.

        Args:
            api_key: The raw API key string

        Returns:
            Tuple of (APIKey object, tenant_id) if valid, None otherwise
        """
        if not api_key or not api_key.startswith("kb_"):
            return None

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_obj = self.db.get_api_key_by_hash(key_hash)

        if not key_obj:
            return None

        if not key_obj.is_active:
            return None

        if key_obj.is_expired():
            return None

        # Update last used time
        self.db.update_api_key_last_used(key_obj.id)

        return key_obj, key_obj.tenant_id

    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        return self.db.revoke_api_key(key_id)

    def get_tenant_api_keys(self, tenant_id: str) -> List[APIKey]:
        """Get all API keys for a tenant."""
        return self.db.get_api_keys_by_tenant(tenant_id)


def create_auth_service(
    db_path: Optional[Path] = None,
    jwt_secret: Optional[str] = None,
) -> AuthService:
    """Create an auth service with the given configuration."""
    db = UserDatabase(db_path)
    return AuthService(db, jwt_secret=jwt_secret)


def create_default_admin(auth_service: AuthService) -> Optional[User]:
    """Create a default admin user if no users exist.

    Returns the created user. The password is either:
    - Read from VACP_ADMIN_PASSWORD environment variable
    - Generated randomly and printed to console (development only)
    """
    import os
    import secrets

    if auth_service.db.count_users() == 0:
        # Check for password in environment variable (recommended for production)
        admin_password = os.getenv("VACP_ADMIN_PASSWORD")
        password_was_generated = False

        if not admin_password:
            # Generate a secure random password
            admin_password = secrets.token_urlsafe(16)
            password_was_generated = True

        user = auth_service.register(
            email="admin@koba.local",
            username="admin",
            password=admin_password,
            role=UserRole.SUPER_ADMIN,
            tenant_id=None,  # System admin has no tenant
            is_system_admin=True,
        )

        if password_was_generated and user:
            print("\n" + "=" * 60)
            print("  DEFAULT ADMIN ACCOUNT CREATED")
            print("=" * 60)
            print("  Email:    admin@koba.local")
            print(f"  Password: {admin_password}")
            print("=" * 60)
            print("  IMPORTANT: Change this password immediately!")
            print("  For production, set VACP_ADMIN_PASSWORD env variable.")
            print("=" * 60 + "\n")

        return user
    return None


# Tenant Permission - additional permission for tenant management
class TenantPermission(Enum):
    """Permissions for tenant management (system admin only)."""
    TENANTS_READ = "tenants:read"
    TENANTS_CREATE = "tenants:create"
    TENANTS_UPDATE = "tenants:update"
    TENANTS_DELETE = "tenants:delete"
    TENANTS_SUSPEND = "tenants:suspend"
