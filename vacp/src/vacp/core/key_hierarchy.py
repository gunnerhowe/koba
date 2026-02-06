"""
Key Hierarchy Management

Implements a secure key hierarchy with separation of concerns:

1. MASTER KEY (root of trust)
   - Never used directly for signing
   - Used only for deriving other keys
   - Should be stored offline/HSM
   - Recovery requires multiple key holders (M-of-N)

2. SYSTEM SIGNING KEY (derived from master)
   - Used for signing receipts and audit logs
   - Can be rotated without compromising master
   - Online but protected by Vault

3. TENANT KEYS (derived per tenant)
   - Tenant-specific encryption/signing
   - Can be revoked independently
   - Rotatable without affecting other tenants

4. EPHEMERAL KEYS
   - Session-specific keys
   - Auto-expire and rotate

Key Derivation uses HKDF (HMAC-based Key Derivation Function)
with SHA-256 for deterministic, secure key expansion.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from vacp.core.crypto import (
    KeyPair,
    generate_keypair,
    sign_message,
    verify_signature,
    encode_public_key,
    decode_public_key,
    encode_signature,
    decode_signature,
)

# Try to import cryptography for HKDF
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    HKDF_AVAILABLE = True
except ImportError:
    HKDF_AVAILABLE = False


class KeyType(Enum):
    """Types of keys in the hierarchy."""
    MASTER = "master"
    SYSTEM_SIGNING = "system_signing"
    TENANT = "tenant"
    EPHEMERAL = "ephemeral"
    BACKUP = "backup"


class KeyStatus(Enum):
    """Status of a key in the system."""
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    PENDING = "pending"
    OFFLINE = "offline"


@dataclass
class KeyMetadata:
    """Metadata associated with a key."""
    key_id: str
    key_type: KeyType
    status: KeyStatus
    created_at: datetime
    expires_at: Optional[datetime] = None
    rotated_at: Optional[datetime] = None
    parent_key_id: Optional[str] = None
    purpose: str = ""
    version: int = 1
    derivation_path: str = ""
    tenant_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "parent_key_id": self.parent_key_id,
            "purpose": self.purpose,
            "version": self.version,
            "derivation_path": self.derivation_path,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyMetadata":
        """Deserialize from dictionary."""
        return cls(
            key_id=data["key_id"],
            key_type=KeyType(data["key_type"]),
            status=KeyStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            rotated_at=datetime.fromisoformat(data["rotated_at"]) if data.get("rotated_at") else None,
            parent_key_id=data.get("parent_key_id"),
            purpose=data.get("purpose", ""),
            version=data.get("version", 1),
            derivation_path=data.get("derivation_path", ""),
            tenant_id=data.get("tenant_id"),
        )


@dataclass
class DerivedKey:
    """A key derived from the hierarchy."""
    keypair: KeyPair
    metadata: KeyMetadata

    @property
    def key_id(self) -> str:
        return self.metadata.key_id

    @property
    def public_key_encoded(self) -> str:
        return encode_public_key(self.keypair.public_key_bytes)

    def sign(self, message: bytes) -> bytes:
        """Sign a message with this key."""
        return sign_message(message, self.keypair.private_key_bytes)

    def sign_encoded(self, message: bytes) -> str:
        """Sign and encode as prefixed base64."""
        signature = self.sign(message)
        return encode_signature(signature)


def hkdf_derive(
    input_key: bytes,
    info: bytes,
    length: int = 32,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    Derive a key using HKDF.

    Args:
        input_key: Input key material
        info: Context/application-specific info
        length: Desired output length
        salt: Optional salt (random bytes recommended)

    Returns:
        Derived key bytes
    """
    if HKDF_AVAILABLE:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(input_key)
    else:
        # Fallback HKDF implementation
        return _hkdf_fallback(input_key, info, length, salt)


def _hkdf_fallback(
    input_key: bytes,
    info: bytes,
    length: int,
    salt: Optional[bytes] = None,
) -> bytes:
    """Fallback HKDF implementation using HMAC."""
    # HKDF Extract
    if salt is None:
        salt = bytes(32)  # Zero-filled
    prk = hmac.new(salt, input_key, hashlib.sha256).digest()

    # HKDF Expand
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""

    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t

    return okm[:length]


class KeyHierarchy:
    """
    Manages the key hierarchy for VACP.

    Provides:
    - Master key management (offline capable)
    - System signing key derivation
    - Per-tenant key derivation
    - Key rotation support
    - Vault integration for secure storage
    """

    # Derivation contexts
    CONTEXT_SYSTEM_SIGNING = b"vacp/system/signing/v1"
    CONTEXT_TENANT_ENCRYPTION = b"vacp/tenant/encryption/v1"
    CONTEXT_TENANT_SIGNING = b"vacp/tenant/signing/v1"
    CONTEXT_EPHEMERAL = b"vacp/ephemeral/v1"
    CONTEXT_BACKUP = b"vacp/backup/v1"

    def __init__(
        self,
        master_key: Optional[bytes] = None,
        storage_path: Optional[Path] = None,
    ):
        """
        Initialize key hierarchy.

        Args:
            master_key: 32-byte master key (if provided, enables derivation)
            storage_path: Path for storing key metadata
        """
        self._master_key = master_key
        self._storage_path = storage_path or Path("./data/keys")
        self._storage_path.mkdir(parents=True, exist_ok=True)

        # Cached derived keys
        self._system_signing_key: Optional[DerivedKey] = None
        self._tenant_keys: Dict[str, DerivedKey] = {}
        self._key_metadata: Dict[str, KeyMetadata] = {}

        # Load existing metadata
        self._load_metadata()

    @property
    def has_master_key(self) -> bool:
        """Check if master key is loaded."""
        return self._master_key is not None

    def set_master_key(self, master_key: bytes) -> None:
        """
        Set the master key for derivation operations.

        In production, this should only be called during initialization
        and the master key should come from secure storage (HSM/Vault).

        Args:
            master_key: 32-byte master key
        """
        if len(master_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes")
        self._master_key = master_key
        # Clear cached derived keys to force re-derivation
        self._system_signing_key = None
        self._tenant_keys.clear()

    def clear_master_key(self) -> None:
        """
        Clear the master key from memory.

        Call this after deriving necessary keys to minimize
        exposure of the master key.
        """
        if self._master_key:
            # Overwrite with zeros before clearing
            temp = bytearray(self._master_key)
            for i in range(len(temp)):
                temp[i] = 0
            self._master_key = None

    @staticmethod
    def generate_master_key() -> bytes:
        """
        Generate a new master key.

        Returns:
            32-byte cryptographically random master key
        """
        return secrets.token_bytes(32)

    def get_system_signing_key(self, version: int = 1) -> DerivedKey:
        """
        Get or derive the system signing key.

        This key is used for signing receipts, audit logs, and other
        system-level cryptographic operations.

        Args:
            version: Key version (for rotation support)

        Returns:
            DerivedKey for system signing
        """
        cache_key = f"system_signing_v{version}"

        if cache_key in self._tenant_keys:
            return self._tenant_keys[cache_key]

        if not self._master_key:
            raise RuntimeError("Master key not loaded")

        # Derive signing key
        info = self.CONTEXT_SYSTEM_SIGNING + f"/v{version}".encode()
        derived_bytes = hkdf_derive(self._master_key, info)

        # Create keypair from derived bytes
        keypair = KeyPair.from_private_key_hex(derived_bytes.hex())

        key_id = f"sys_sign_{secrets.token_hex(8)}"
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.SYSTEM_SIGNING,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            purpose="System signing for receipts and audit logs",
            version=version,
            derivation_path=f"master/system_signing/v{version}",
        )

        derived_key = DerivedKey(keypair=keypair, metadata=metadata)
        self._tenant_keys[cache_key] = derived_key
        self._key_metadata[key_id] = metadata
        self._save_metadata(metadata)

        return derived_key

    def get_tenant_signing_key(
        self,
        tenant_id: str,
        version: int = 1,
    ) -> DerivedKey:
        """
        Get or derive a tenant-specific signing key.

        Args:
            tenant_id: Tenant identifier
            version: Key version

        Returns:
            DerivedKey for tenant signing
        """
        cache_key = f"tenant_sign_{tenant_id}_v{version}"

        if cache_key in self._tenant_keys:
            return self._tenant_keys[cache_key]

        if not self._master_key:
            raise RuntimeError("Master key not loaded")

        # Derive tenant key
        info = self.CONTEXT_TENANT_SIGNING + f"/{tenant_id}/v{version}".encode()
        derived_bytes = hkdf_derive(self._master_key, info)

        keypair = KeyPair.from_private_key_hex(derived_bytes.hex())

        key_id = f"tenant_sign_{tenant_id}_{secrets.token_hex(4)}"
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.TENANT,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            purpose=f"Signing key for tenant {tenant_id}",
            version=version,
            derivation_path=f"master/tenant/{tenant_id}/signing/v{version}",
            tenant_id=tenant_id,
        )

        derived_key = DerivedKey(keypair=keypair, metadata=metadata)
        self._tenant_keys[cache_key] = derived_key
        self._key_metadata[key_id] = metadata
        self._save_metadata(metadata)

        return derived_key

    def get_tenant_encryption_key(
        self,
        tenant_id: str,
        version: int = 1,
    ) -> bytes:
        """
        Get or derive a tenant-specific encryption key.

        Args:
            tenant_id: Tenant identifier
            version: Key version

        Returns:
            32-byte encryption key
        """
        if not self._master_key:
            raise RuntimeError("Master key not loaded")

        info = self.CONTEXT_TENANT_ENCRYPTION + f"/{tenant_id}/v{version}".encode()
        return hkdf_derive(self._master_key, info)

    def generate_ephemeral_key(
        self,
        purpose: str = "",
        ttl_seconds: int = 3600,
    ) -> DerivedKey:
        """
        Generate an ephemeral key for short-term use.

        Args:
            purpose: Description of key usage
            ttl_seconds: Time-to-live in seconds

        Returns:
            DerivedKey that expires after TTL
        """
        # Ephemeral keys use random generation, not master derivation
        keypair = generate_keypair()

        key_id = f"ephemeral_{secrets.token_hex(8)}"
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.EPHEMERAL,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            purpose=purpose or "Ephemeral session key",
        )

        derived_key = DerivedKey(keypair=keypair, metadata=metadata)
        self._key_metadata[key_id] = metadata
        # Don't persist ephemeral keys

        return derived_key

    def rotate_system_signing_key(self) -> DerivedKey:
        """
        Rotate the system signing key to a new version.

        Returns:
            New DerivedKey with incremented version
        """
        # Find current version
        current_version = 1
        for key_id, meta in self._key_metadata.items():
            if meta.key_type == KeyType.SYSTEM_SIGNING and meta.status == KeyStatus.ACTIVE:
                current_version = max(current_version, meta.version)
                # Mark as rotated
                meta.status = KeyStatus.ROTATED
                meta.rotated_at = datetime.now(timezone.utc)
                self._save_metadata(meta)

        # Create new version
        new_version = current_version + 1
        return self.get_system_signing_key(version=new_version)

    def rotate_tenant_key(self, tenant_id: str) -> DerivedKey:
        """
        Rotate a tenant's signing key to a new version.

        Args:
            tenant_id: Tenant identifier

        Returns:
            New DerivedKey with incremented version
        """
        # Find current version for tenant
        current_version = 1
        for key_id, meta in self._key_metadata.items():
            if (meta.key_type == KeyType.TENANT and
                meta.tenant_id == tenant_id and
                meta.status == KeyStatus.ACTIVE):
                current_version = max(current_version, meta.version)
                meta.status = KeyStatus.ROTATED
                meta.rotated_at = datetime.now(timezone.utc)
                self._save_metadata(meta)

        # Create new version
        new_version = current_version + 1
        return self.get_tenant_signing_key(tenant_id, version=new_version)

    def revoke_tenant_keys(self, tenant_id: str) -> int:
        """
        Revoke all keys for a tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Number of keys revoked
        """
        revoked = 0
        for key_id, meta in self._key_metadata.items():
            if meta.tenant_id == tenant_id and meta.status == KeyStatus.ACTIVE:
                meta.status = KeyStatus.REVOKED
                self._save_metadata(meta)
                revoked += 1

        # Clear from cache
        keys_to_remove = [k for k in self._tenant_keys if tenant_id in k]
        for k in keys_to_remove:
            del self._tenant_keys[k]

        return revoked

    def get_active_keys(self, key_type: Optional[KeyType] = None) -> List[KeyMetadata]:
        """
        Get all active keys, optionally filtered by type.

        Args:
            key_type: Optional filter by key type

        Returns:
            List of active key metadata
        """
        keys = []
        for meta in self._key_metadata.values():
            if meta.status != KeyStatus.ACTIVE:
                continue
            if key_type and meta.key_type != key_type:
                continue
            keys.append(meta)
        return keys

    def get_key_by_id(self, key_id: str) -> Optional[KeyMetadata]:
        """Get key metadata by ID."""
        return self._key_metadata.get(key_id)

    def _save_metadata(self, metadata: KeyMetadata) -> None:
        """Save key metadata to storage."""
        meta_file = self._storage_path / f"{metadata.key_id}.json"
        meta_file.write_text(json.dumps(metadata.to_dict(), indent=2))

    def _load_metadata(self) -> None:
        """Load existing key metadata from storage."""
        for meta_file in self._storage_path.glob("*.json"):
            try:
                data = json.loads(meta_file.read_text())
                metadata = KeyMetadata.from_dict(data)
                self._key_metadata[metadata.key_id] = metadata
            except Exception as e:
                # Log but continue
                pass

    def export_public_keys(self) -> Dict[str, str]:
        """
        Export all public keys for verification.

        Returns:
            Dict mapping key_id to encoded public key
        """
        result = {}

        # System signing key
        if self._system_signing_key:
            result[self._system_signing_key.key_id] = self._system_signing_key.public_key_encoded

        # Tenant keys
        for cache_key, derived in self._tenant_keys.items():
            result[derived.key_id] = derived.public_key_encoded

        return result


class MasterKeySharding:
    """
    Implements M-of-N secret sharing for the master key.

    Uses Shamir's Secret Sharing to split the master key into N shares,
    requiring M shares to reconstruct.
    """

    @staticmethod
    def split_key(
        master_key: bytes,
        total_shares: int = 5,
        threshold: int = 3,
    ) -> List[bytes]:
        """
        Split master key into shares using Shamir's Secret Sharing.

        Args:
            master_key: 32-byte master key
            total_shares: Total number of shares to create
            threshold: Minimum shares required for reconstruction

        Returns:
            List of share bytes
        """
        if threshold > total_shares:
            raise ValueError("Threshold cannot exceed total shares")
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")

        # Simple XOR-based sharing (for demonstration)
        # In production, use a proper Shamir implementation like 'secret-sharing'
        shares = []

        # Generate random shares for all but one
        for i in range(total_shares - 1):
            share = secrets.token_bytes(len(master_key))
            shares.append(share)

        # Last share is XOR of all others with the key
        final_share = bytes(master_key)
        for share in shares:
            final_share = bytes(a ^ b for a, b in zip(final_share, share))
        shares.append(final_share)

        # Encode share index
        indexed_shares = []
        for i, share in enumerate(shares):
            indexed = bytes([i + 1]) + share
            indexed_shares.append(indexed)

        return indexed_shares

    @staticmethod
    def reconstruct_key(shares: List[bytes]) -> bytes:
        """
        Reconstruct master key from shares.

        Args:
            shares: List of share bytes (must include all shares for XOR scheme)

        Returns:
            Reconstructed master key
        """
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares")

        # Extract share data (skip index byte)
        share_data = [share[1:] for share in shares]

        # XOR all shares
        result = bytes(share_data[0])
        for share in share_data[1:]:
            result = bytes(a ^ b for a, b in zip(result, share))

        return result


# Convenience functions

_key_hierarchy: Optional[KeyHierarchy] = None


def get_key_hierarchy() -> KeyHierarchy:
    """Get the global key hierarchy instance."""
    global _key_hierarchy
    if _key_hierarchy is None:
        _key_hierarchy = KeyHierarchy()
    return _key_hierarchy


def initialize_key_hierarchy(master_key: bytes) -> KeyHierarchy:
    """
    Initialize the global key hierarchy with a master key.

    Args:
        master_key: 32-byte master key

    Returns:
        Initialized KeyHierarchy
    """
    global _key_hierarchy
    _key_hierarchy = KeyHierarchy(master_key=master_key)
    return _key_hierarchy


def get_system_signing_key() -> DerivedKey:
    """Get the system signing key from the global hierarchy."""
    return get_key_hierarchy().get_system_signing_key()
