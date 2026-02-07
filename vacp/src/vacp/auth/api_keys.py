"""
API Key Authentication for Koba/VACP

Provides secure API key management with:
- Key generation and hashing
- Scope-based permissions
- Rate limiting per key
- Expiration support
"""

# DEPRECATED: This API key module uses in-memory storage and is not used by the main API server.
# The canonical auth system is vacp.core.auth which manages API keys via UserDatabase.
# This module is retained for reference but should not be imported for new code.

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Flag, auto
from typing import Any, Dict, List, Optional
import threading


class APIKeyScope(Flag):
    """Scopes that define what an API key can access."""
    NONE = 0
    READ = auto()           # Read operations (query, list)
    WRITE = auto()          # Write operations (create, update)
    DELETE = auto()         # Delete operations
    ADMIN = auto()          # Administrative operations
    POLICY = auto()         # Policy management
    AUDIT = auto()          # Audit log access
    AGENT = auto()          # Agent management
    TENANT = auto()         # Tenant management

    # Convenience combinations
    READ_WRITE = READ | WRITE
    FULL_ACCESS = READ | WRITE | DELETE | ADMIN | POLICY | AUDIT | AGENT | TENANT


@dataclass
class APIKey:
    """Represents an API key."""
    id: str
    name: str
    key_hash: str  # SHA-256 hash of the key
    key_prefix: str  # First 8 chars for identification
    scopes: APIKeyScope
    tenant_id: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime] = None
    is_active: bool = True
    rate_limit: Optional[int] = None  # Requests per minute
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if the key is expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def has_scope(self, scope: APIKeyScope) -> bool:
        """Check if the key has the given scope."""
        return bool(self.scopes & scope)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (without sensitive data)."""
        return {
            "id": self.id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "scopes": self.scopes.value,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "is_active": self.is_active,
            "rate_limit": self.rate_limit,
        }


@dataclass
class APIKeyValidationResult:
    """Result of API key validation."""
    valid: bool
    key: Optional[APIKey] = None
    error: Optional[str] = None
    rate_limited: bool = False
    remaining_requests: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "error": self.error,
            "rate_limited": self.rate_limited,
            "remaining_requests": self.remaining_requests,
        }


class APIKeyManager:
    """
    Manages API keys for operator authentication.

    Features:
    - Secure key generation
    - Hash-based key storage (never stores plaintext keys)
    - Rate limiting per key
    - Expiration support
    """

    KEY_PREFIX = "koba_"
    KEY_LENGTH = 32  # 32 bytes = 256 bits

    def __init__(self):
        self._keys: Dict[str, APIKey] = {}  # key_hash -> APIKey
        self._prefix_index: Dict[str, str] = {}  # key_prefix -> key_hash
        self._rate_limits: Dict[str, List[float]] = {}  # key_hash -> list of timestamps
        self._lock = threading.Lock()

    def create_key(
        self,
        name: str,
        scopes: APIKeyScope = APIKeyScope.READ,
        tenant_id: Optional[str] = None,
        expires_in_days: Optional[int] = None,
        rate_limit: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, APIKey]:
        """
        Create a new API key.

        Returns (raw_key, APIKey object).
        The raw key is only returned once and should be stored securely.
        """
        # Generate secure random key
        raw_bytes = secrets.token_bytes(self.KEY_LENGTH)
        raw_key = self.KEY_PREFIX + raw_bytes.hex()

        # Create hash for storage
        key_hash = self._hash_key(raw_key)
        key_prefix = raw_key[:8 + len(self.KEY_PREFIX)]  # prefix includes "koba_"

        # Generate unique ID
        key_id = secrets.token_hex(8)

        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        api_key = APIKey(
            id=key_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            scopes=scopes,
            tenant_id=tenant_id,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            rate_limit=rate_limit,
            metadata=metadata or {},
        )

        with self._lock:
            self._keys[key_hash] = api_key
            self._prefix_index[key_prefix] = key_hash

        return raw_key, api_key

    def validate_key(
        self,
        raw_key: str,
        required_scope: Optional[APIKeyScope] = None,
    ) -> APIKeyValidationResult:
        """
        Validate an API key.

        Args:
            raw_key: The raw API key string
            required_scope: Optional scope to check

        Returns:
            APIKeyValidationResult with validation status
        """
        if not raw_key or not raw_key.startswith(self.KEY_PREFIX):
            return APIKeyValidationResult(valid=False, error="Invalid key format")

        key_hash = self._hash_key(raw_key)

        with self._lock:
            api_key = self._keys.get(key_hash)

        if api_key is None:
            return APIKeyValidationResult(valid=False, error="Key not found")

        if not api_key.is_active:
            return APIKeyValidationResult(valid=False, error="Key is inactive")

        if api_key.is_expired():
            return APIKeyValidationResult(valid=False, error="Key has expired")

        if required_scope and not api_key.has_scope(required_scope):
            return APIKeyValidationResult(
                valid=False,
                error=f"Key does not have required scope: {required_scope.name}",
            )

        # Check rate limit
        if api_key.rate_limit:
            is_limited, remaining = self._check_rate_limit(key_hash, api_key.rate_limit)
            if is_limited:
                return APIKeyValidationResult(
                    valid=False,
                    key=api_key,
                    error="Rate limit exceeded",
                    rate_limited=True,
                    remaining_requests=0,
                )
            else:
                # Update last used
                with self._lock:
                    api_key.last_used_at = datetime.now(timezone.utc)
                return APIKeyValidationResult(
                    valid=True,
                    key=api_key,
                    remaining_requests=remaining,
                )

        # Update last used
        with self._lock:
            api_key.last_used_at = datetime.now(timezone.utc)

        return APIKeyValidationResult(valid=True, key=api_key)

    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key by ID."""
        with self._lock:
            for key_hash, api_key in self._keys.items():
                if api_key.id == key_id:
                    api_key.is_active = False
                    return True
        return False

    def delete_key(self, key_id: str) -> bool:
        """Delete an API key by ID."""
        with self._lock:
            for key_hash, api_key in list(self._keys.items()):
                if api_key.id == key_id:
                    del self._keys[key_hash]
                    # Also remove from prefix index
                    for prefix, hash_val in list(self._prefix_index.items()):
                        if hash_val == key_hash:
                            del self._prefix_index[prefix]
                            break
                    return True
        return False

    def list_keys(self, tenant_id: Optional[str] = None) -> List[APIKey]:
        """List all API keys, optionally filtered by tenant."""
        with self._lock:
            keys = list(self._keys.values())

        if tenant_id:
            keys = [k for k in keys if k.tenant_id == tenant_id]

        return keys

    def get_key_by_id(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by its ID."""
        with self._lock:
            for api_key in self._keys.values():
                if api_key.id == key_id:
                    return api_key
        return None

    def get_key_by_prefix(self, prefix: str) -> Optional[APIKey]:
        """Get an API key by its prefix (for identification)."""
        with self._lock:
            key_hash = self._prefix_index.get(prefix)
            if key_hash:
                return self._keys.get(key_hash)
        return None

    def update_key(
        self,
        key_id: str,
        name: Optional[str] = None,
        scopes: Optional[APIKeyScope] = None,
        rate_limit: Optional[int] = None,
        is_active: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update an API key's properties."""
        with self._lock:
            for api_key in self._keys.values():
                if api_key.id == key_id:
                    if name is not None:
                        api_key.name = name
                    if scopes is not None:
                        api_key.scopes = scopes
                    if rate_limit is not None:
                        api_key.rate_limit = rate_limit
                    if is_active is not None:
                        api_key.is_active = is_active
                    if metadata is not None:
                        api_key.metadata.update(metadata)
                    return True
        return False

    def _hash_key(self, raw_key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def _check_rate_limit(
        self,
        key_hash: str,
        limit: int,
    ) -> tuple[bool, int]:
        """
        Check and update rate limit for a key.

        Returns (is_limited, remaining_requests).
        """
        current_time = time.time()

        with self._lock:
            if key_hash not in self._rate_limits:
                self._rate_limits[key_hash] = []

            # Remove timestamps older than 1 minute
            self._rate_limits[key_hash] = [
                ts for ts in self._rate_limits[key_hash]
                if current_time - ts < 60
            ]

            if len(self._rate_limits[key_hash]) >= limit:
                return True, 0

            # Add current timestamp
            self._rate_limits[key_hash].append(current_time)
            remaining = limit - len(self._rate_limits[key_hash])

            return False, remaining
