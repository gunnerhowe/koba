"""
Cryptographic Primitives for VACP

This module provides the foundational cryptographic operations:
- Ed25519 key generation, signing, and verification
- SHA-256 hashing for data and JSON canonicalization
- Secure random generation

All cryptographic operations use industry-standard libraries and algorithms.
Ed25519 is chosen for its security, performance, and small signature size.
"""

import hashlib
import json
import secrets
import base64
from dataclasses import dataclass
from typing import Union, Any, Optional
from datetime import datetime, timezone

# We use pure Python implementations for portability
# In production, PyNaCl or cryptography library would be preferred

# Ed25519 implementation using Python's cryptography or fallback
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    CRYPTO_BACKEND = "cryptography"
except ImportError:
    CRYPTO_BACKEND = "fallback"
    raise ImportError(
        "CRITICAL: 'cryptography' library is required but not installed. "
        "Ed25519 crypto operations cannot function without it. "
        "Install with: pip install cryptography"
    )


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 keypair for signing and verification."""
    private_key_bytes: bytes
    public_key_bytes: bytes

    @property
    def private_key_hex(self) -> str:
        return self.private_key_bytes.hex()

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    @property
    def public_key_did(self) -> str:
        """Return the public key as a DID (Decentralized Identifier)."""
        return f"did:key:z{base64.urlsafe_b64encode(self.public_key_bytes).decode().rstrip('=')}"

    def to_dict(self) -> dict:
        """Serialize keypair to dictionary (WARNING: includes private key)."""
        return {
            "private_key": self.private_key_hex,
            "public_key": self.public_key_hex,
            "did": self.public_key_did,
        }

    @classmethod
    def from_private_key_hex(cls, private_key_hex: str) -> "KeyPair":
        """Reconstruct keypair from private key hex string."""
        private_bytes = bytes.fromhex(private_key_hex)
        if CRYPTO_BACKEND == "cryptography":
            private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        else:
            # Fallback: use nacl-style derivation
            public_bytes = _derive_public_key_fallback(private_bytes)
        return cls(private_key_bytes=private_bytes, public_key_bytes=public_bytes)


def generate_keypair() -> KeyPair:
    """
    Generate a new Ed25519 keypair.

    Returns:
        KeyPair with private and public key bytes
    """
    if CRYPTO_BACKEND == "cryptography":
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    else:
        # Fallback: generate random 32 bytes for seed
        private_bytes = secrets.token_bytes(32)
        public_bytes = _derive_public_key_fallback(private_bytes)

    return KeyPair(private_key_bytes=private_bytes, public_key_bytes=public_bytes)


def sign_message(message: bytes, private_key: bytes) -> bytes:
    """
    Sign a message using Ed25519.

    Args:
        message: The message bytes to sign
        private_key: 32-byte Ed25519 private key

    Returns:
        64-byte Ed25519 signature
    """
    if CRYPTO_BACKEND == "cryptography":
        key = Ed25519PrivateKey.from_private_bytes(private_key)
        return key.sign(message)
    else:
        return _sign_fallback(message, private_key)


def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        message: The original message bytes
        signature: 64-byte Ed25519 signature
        public_key: 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise
    """
    if CRYPTO_BACKEND == "cryptography":
        try:
            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    else:
        return _verify_fallback(message, signature, public_key)


def hash_data(data: bytes) -> str:
    """
    Compute SHA-256 hash of bytes.

    Args:
        data: Bytes to hash

    Returns:
        Hex-encoded SHA-256 hash with 'sha256:' prefix
    """
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


def hash_json(obj: Any) -> str:
    """
    Compute SHA-256 hash of JSON-serializable object.

    Uses canonical JSON serialization (sorted keys, no whitespace)
    to ensure deterministic hashing.

    Args:
        obj: JSON-serializable Python object

    Returns:
        Hex-encoded SHA-256 hash with 'sha256:' prefix
    """
    canonical = canonicalize_json(obj)
    return hash_data(canonical.encode("utf-8"))


def canonicalize_json(obj: Any) -> str:
    """
    Produce a canonical JSON string for deterministic hashing.

    Rules:
    - Keys are sorted alphabetically at all levels
    - No whitespace between elements
    - Unicode escaped consistently
    - Numbers have no trailing zeros

    Args:
        obj: JSON-serializable Python object

    Returns:
        Canonical JSON string
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_json_serializer,
    )


def generate_random_id(prefix: str = "", length: int = 16) -> str:
    """
    Generate a cryptographically random identifier.

    Args:
        prefix: Optional prefix for the ID
        length: Number of random bytes (default 16 = 128 bits)

    Returns:
        Random hex string, optionally prefixed
    """
    random_hex = secrets.token_hex(length)
    if prefix:
        return f"{prefix}_{random_hex}"
    return random_hex


def generate_nonce() -> str:
    """Generate a random nonce for replay protection."""
    return secrets.token_hex(16)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    import hmac
    return hmac.compare_digest(a, b)


def _json_serializer(obj: Any) -> Any:
    """Custom JSON serializer for special types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


# Fallback implementations - these REFUSE to operate without proper crypto library.
# Install the 'cryptography' package: pip install cryptography

def _derive_public_key_fallback(private_key: bytes) -> bytes:
    """Derive public key from private key - requires cryptography library."""
    raise RuntimeError(
        "Ed25519 operations require the 'cryptography' package. "
        "Install it with: pip install cryptography"
    )


def _sign_fallback(message: bytes, private_key: bytes) -> bytes:
    """Sign message - requires cryptography library."""
    raise RuntimeError(
        "Ed25519 signing requires the 'cryptography' package. "
        "Install it with: pip install cryptography"
    )


def _verify_fallback(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify signature - requires cryptography library."""
    raise RuntimeError(
        "Ed25519 verification requires the 'cryptography' package. "
        "Install it with: pip install cryptography"
    )


# Signature encoding utilities

def encode_signature(signature: bytes) -> str:
    """Encode signature as prefixed base64 string."""
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"ed25519:{encoded}"


def decode_signature(encoded: str) -> bytes:
    """Decode prefixed base64 signature string."""
    if encoded.startswith("ed25519:"):
        encoded = encoded[8:]
    # Add padding back
    padding = 4 - (len(encoded) % 4)
    if padding != 4:
        encoded += "=" * padding
    return base64.urlsafe_b64decode(encoded)


def encode_public_key(public_key: bytes) -> str:
    """Encode public key as prefixed base64 string."""
    encoded = base64.urlsafe_b64encode(public_key).decode("ascii").rstrip("=")
    return f"ed25519-pub:{encoded}"


def decode_public_key(encoded: str) -> bytes:
    """Decode prefixed base64 public key string."""
    if encoded.startswith("ed25519-pub:"):
        encoded = encoded[12:]
    elif encoded.startswith("did:key:z"):
        encoded = encoded[9:]
    # Add padding back
    padding = 4 - (len(encoded) % 4)
    if padding != 4:
        encoded += "=" * padding
    return base64.urlsafe_b64decode(encoded)
