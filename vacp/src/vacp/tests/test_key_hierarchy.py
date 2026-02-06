"""
Tests for key hierarchy management.

Tests cover:
- Master key generation and management
- System signing key derivation
- Tenant key derivation
- Key rotation
- Key revocation
- Ephemeral keys
- Master key sharding
"""

import pytest
import secrets
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from vacp.core.key_hierarchy import (
    KeyType,
    KeyStatus,
    KeyMetadata,
    DerivedKey,
    KeyHierarchy,
    MasterKeySharding,
    hkdf_derive,
    get_key_hierarchy,
    initialize_key_hierarchy,
)
from vacp.core.crypto import verify_signature, decode_signature


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def master_key():
    """Generate a test master key."""
    return secrets.token_bytes(32)


@pytest.fixture
def temp_storage():
    """Create temporary storage directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def key_hierarchy(master_key, temp_storage):
    """Create a key hierarchy with master key."""
    return KeyHierarchy(master_key=master_key, storage_path=temp_storage)


# ============================================================================
# HKDF Tests
# ============================================================================

class TestHKDF:
    """Tests for HKDF key derivation."""

    def test_deterministic_derivation(self, master_key):
        """Test that HKDF produces deterministic output."""
        info = b"test/context"

        derived1 = hkdf_derive(master_key, info)
        derived2 = hkdf_derive(master_key, info)

        assert derived1 == derived2

    def test_different_info_different_output(self, master_key):
        """Test that different info produces different keys."""
        derived1 = hkdf_derive(master_key, b"context1")
        derived2 = hkdf_derive(master_key, b"context2")

        assert derived1 != derived2

    def test_output_length(self, master_key):
        """Test custom output length."""
        derived_16 = hkdf_derive(master_key, b"test", length=16)
        derived_64 = hkdf_derive(master_key, b"test", length=64)

        assert len(derived_16) == 16
        assert len(derived_64) == 64

    def test_with_salt(self, master_key):
        """Test derivation with salt."""
        salt = secrets.token_bytes(32)

        derived_with_salt = hkdf_derive(master_key, b"test", salt=salt)
        derived_without_salt = hkdf_derive(master_key, b"test")

        assert derived_with_salt != derived_without_salt


# ============================================================================
# KeyMetadata Tests
# ============================================================================

class TestKeyMetadata:
    """Tests for KeyMetadata class."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        metadata = KeyMetadata(
            key_id="test_key_123",
            key_type=KeyType.SYSTEM_SIGNING,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            purpose="Test key",
            version=1,
        )

        data = metadata.to_dict()

        assert data["key_id"] == "test_key_123"
        assert data["key_type"] == "system_signing"
        assert data["status"] == "active"

    def test_from_dict(self):
        """Test deserialization from dictionary."""
        data = {
            "key_id": "test_key_456",
            "key_type": "tenant",
            "status": "rotated",
            "created_at": "2024-01-01T00:00:00+00:00",
            "expires_at": None,
            "rotated_at": "2024-02-01T00:00:00+00:00",
            "parent_key_id": None,
            "purpose": "Tenant signing",
            "version": 2,
            "derivation_path": "master/tenant/t1/v2",
            "tenant_id": "t1",
        }

        metadata = KeyMetadata.from_dict(data)

        assert metadata.key_id == "test_key_456"
        assert metadata.key_type == KeyType.TENANT
        assert metadata.status == KeyStatus.ROTATED
        assert metadata.version == 2
        assert metadata.tenant_id == "t1"

    def test_roundtrip(self):
        """Test serialization roundtrip."""
        original = KeyMetadata(
            key_id="roundtrip_key",
            key_type=KeyType.EPHEMERAL,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            purpose="Ephemeral test",
        )

        restored = KeyMetadata.from_dict(original.to_dict())

        assert restored.key_id == original.key_id
        assert restored.key_type == original.key_type
        assert restored.purpose == original.purpose


# ============================================================================
# KeyHierarchy Tests
# ============================================================================

class TestKeyHierarchy:
    """Tests for KeyHierarchy class."""

    def test_has_master_key(self, key_hierarchy):
        """Test master key presence check."""
        assert key_hierarchy.has_master_key

    def test_no_master_key(self, temp_storage):
        """Test hierarchy without master key."""
        hierarchy = KeyHierarchy(storage_path=temp_storage)
        assert not hierarchy.has_master_key

    def test_set_master_key(self, temp_storage):
        """Test setting master key."""
        hierarchy = KeyHierarchy(storage_path=temp_storage)
        master_key = secrets.token_bytes(32)

        hierarchy.set_master_key(master_key)

        assert hierarchy.has_master_key

    def test_set_master_key_wrong_size(self, temp_storage):
        """Test that wrong-sized master key raises error."""
        hierarchy = KeyHierarchy(storage_path=temp_storage)

        with pytest.raises(ValueError):
            hierarchy.set_master_key(b"too_short")

    def test_clear_master_key(self, key_hierarchy):
        """Test clearing master key."""
        key_hierarchy.clear_master_key()
        assert not key_hierarchy.has_master_key

    def test_generate_master_key(self):
        """Test master key generation."""
        key1 = KeyHierarchy.generate_master_key()
        key2 = KeyHierarchy.generate_master_key()

        assert len(key1) == 32
        assert len(key2) == 32
        assert key1 != key2

    def test_get_system_signing_key(self, key_hierarchy):
        """Test getting system signing key."""
        signing_key = key_hierarchy.get_system_signing_key()

        assert signing_key is not None
        assert signing_key.metadata.key_type == KeyType.SYSTEM_SIGNING
        assert signing_key.metadata.status == KeyStatus.ACTIVE

    def test_system_signing_key_cached(self, key_hierarchy):
        """Test that system signing key is cached."""
        key1 = key_hierarchy.get_system_signing_key()
        key2 = key_hierarchy.get_system_signing_key()

        # Should be same instance
        assert key1.key_id == key2.key_id

    def test_system_signing_key_deterministic(self, master_key, temp_storage):
        """Test that same master key produces same signing key."""
        hierarchy1 = KeyHierarchy(master_key=master_key, storage_path=temp_storage / "h1")
        hierarchy2 = KeyHierarchy(master_key=master_key, storage_path=temp_storage / "h2")

        key1 = hierarchy1.get_system_signing_key()
        key2 = hierarchy2.get_system_signing_key()

        # Different instances but same derived key material
        assert key1.keypair.public_key_bytes == key2.keypair.public_key_bytes

    def test_system_signing_key_without_master(self, temp_storage):
        """Test that getting signing key without master raises error."""
        hierarchy = KeyHierarchy(storage_path=temp_storage)

        with pytest.raises(RuntimeError):
            hierarchy.get_system_signing_key()

    def test_get_tenant_signing_key(self, key_hierarchy):
        """Test getting tenant signing key."""
        tenant_key = key_hierarchy.get_tenant_signing_key("tenant_123")

        assert tenant_key is not None
        assert tenant_key.metadata.key_type == KeyType.TENANT
        assert tenant_key.metadata.tenant_id == "tenant_123"

    def test_different_tenants_different_keys(self, key_hierarchy):
        """Test that different tenants get different keys."""
        key1 = key_hierarchy.get_tenant_signing_key("tenant_a")
        key2 = key_hierarchy.get_tenant_signing_key("tenant_b")

        assert key1.keypair.public_key_bytes != key2.keypair.public_key_bytes

    def test_get_tenant_encryption_key(self, key_hierarchy):
        """Test getting tenant encryption key."""
        enc_key = key_hierarchy.get_tenant_encryption_key("tenant_xyz")

        assert len(enc_key) == 32

    def test_tenant_encryption_key_deterministic(self, master_key, temp_storage):
        """Test tenant encryption key is deterministic."""
        hierarchy1 = KeyHierarchy(master_key=master_key, storage_path=temp_storage / "h1")
        hierarchy2 = KeyHierarchy(master_key=master_key, storage_path=temp_storage / "h2")

        key1 = hierarchy1.get_tenant_encryption_key("tenant_abc")
        key2 = hierarchy2.get_tenant_encryption_key("tenant_abc")

        assert key1 == key2

    def test_generate_ephemeral_key(self, key_hierarchy):
        """Test generating ephemeral key."""
        ephemeral = key_hierarchy.generate_ephemeral_key(purpose="Test session")

        assert ephemeral.metadata.key_type == KeyType.EPHEMERAL
        assert ephemeral.metadata.expires_at is not None

    def test_ephemeral_key_expiration(self, key_hierarchy):
        """Test ephemeral key has correct TTL."""
        ttl = 3600
        ephemeral = key_hierarchy.generate_ephemeral_key(ttl_seconds=ttl)

        now = datetime.now(timezone.utc)
        expected_expiry = now + timedelta(seconds=ttl)

        # Allow 5 second tolerance
        diff = abs((ephemeral.metadata.expires_at - expected_expiry).total_seconds())
        assert diff < 5


# ============================================================================
# Key Rotation Tests
# ============================================================================

class TestKeyRotation:
    """Tests for key rotation."""

    def test_rotate_system_signing_key(self, key_hierarchy):
        """Test rotating system signing key."""
        key_v1 = key_hierarchy.get_system_signing_key()
        old_key_id = key_v1.key_id

        key_v2 = key_hierarchy.rotate_system_signing_key()

        # New key should have different ID
        assert key_v2.key_id != old_key_id
        # New version
        assert key_v2.metadata.version > key_v1.metadata.version
        # Old key should be marked rotated
        old_meta = key_hierarchy.get_key_by_id(old_key_id)
        assert old_meta.status == KeyStatus.ROTATED

    def test_rotate_tenant_key(self, key_hierarchy):
        """Test rotating tenant key."""
        tenant_id = "rotate_test_tenant"
        key_v1 = key_hierarchy.get_tenant_signing_key(tenant_id)
        old_key_id = key_v1.key_id

        key_v2 = key_hierarchy.rotate_tenant_key(tenant_id)

        assert key_v2.key_id != old_key_id
        assert key_v2.metadata.version > key_v1.metadata.version

    def test_versioned_keys_different(self, key_hierarchy):
        """Test that different versions produce different keys."""
        key_v1 = key_hierarchy.get_system_signing_key(version=1)
        key_v2 = key_hierarchy.get_system_signing_key(version=2)

        assert key_v1.keypair.public_key_bytes != key_v2.keypair.public_key_bytes


# ============================================================================
# Key Revocation Tests
# ============================================================================

class TestKeyRevocation:
    """Tests for key revocation."""

    def test_revoke_tenant_keys(self, key_hierarchy):
        """Test revoking all tenant keys."""
        tenant_id = "revoke_test"
        key_hierarchy.get_tenant_signing_key(tenant_id, version=1)
        key_hierarchy.get_tenant_signing_key(tenant_id, version=2)

        revoked = key_hierarchy.revoke_tenant_keys(tenant_id)

        assert revoked == 2

    def test_revoked_keys_not_active(self, key_hierarchy):
        """Test that revoked keys are not in active list."""
        tenant_id = "revoke_check"
        key_hierarchy.get_tenant_signing_key(tenant_id)

        key_hierarchy.revoke_tenant_keys(tenant_id)

        active_keys = key_hierarchy.get_active_keys(KeyType.TENANT)
        tenant_keys = [k for k in active_keys if k.tenant_id == tenant_id]
        assert len(tenant_keys) == 0


# ============================================================================
# DerivedKey Tests
# ============================================================================

class TestDerivedKey:
    """Tests for DerivedKey signing operations."""

    def test_sign_message(self, key_hierarchy):
        """Test signing a message."""
        signing_key = key_hierarchy.get_system_signing_key()
        message = b"Test message to sign"

        signature = signing_key.sign(message)

        assert len(signature) == 64

    def test_sign_and_verify(self, key_hierarchy):
        """Test that signed message can be verified."""
        signing_key = key_hierarchy.get_system_signing_key()
        message = b"Important audit entry"

        signature = signing_key.sign(message)

        is_valid = verify_signature(
            message,
            signature,
            signing_key.keypair.public_key_bytes,
        )
        assert is_valid

    def test_sign_encoded(self, key_hierarchy):
        """Test encoded signature format."""
        signing_key = key_hierarchy.get_system_signing_key()
        message = b"Encoded signature test"

        encoded_sig = signing_key.sign_encoded(message)

        assert encoded_sig.startswith("ed25519:")

    def test_public_key_encoded(self, key_hierarchy):
        """Test public key encoding."""
        signing_key = key_hierarchy.get_system_signing_key()

        encoded = signing_key.public_key_encoded

        assert encoded.startswith("ed25519-pub:")


# ============================================================================
# Master Key Sharding Tests
# ============================================================================

class TestMasterKeySharding:
    """Tests for master key sharding."""

    def test_split_key(self, master_key):
        """Test splitting master key into shares."""
        shares = MasterKeySharding.split_key(master_key, total_shares=5, threshold=3)

        assert len(shares) == 5
        # Each share should have index byte + key length
        assert all(len(s) == 33 for s in shares)

    def test_reconstruct_key(self, master_key):
        """Test reconstructing key from all shares."""
        shares = MasterKeySharding.split_key(master_key, total_shares=5, threshold=3)

        reconstructed = MasterKeySharding.reconstruct_key(shares)

        assert reconstructed == master_key

    def test_threshold_validation(self, master_key):
        """Test threshold cannot exceed total shares."""
        with pytest.raises(ValueError):
            MasterKeySharding.split_key(master_key, total_shares=3, threshold=5)

    def test_minimum_threshold(self, master_key):
        """Test minimum threshold of 2."""
        with pytest.raises(ValueError):
            MasterKeySharding.split_key(master_key, total_shares=3, threshold=1)

    def test_minimum_shares_for_reconstruct(self, master_key):
        """Test that reconstruction requires minimum shares."""
        shares = MasterKeySharding.split_key(master_key, total_shares=3, threshold=2)

        with pytest.raises(ValueError):
            MasterKeySharding.reconstruct_key([shares[0]])


# ============================================================================
# Integration Tests
# ============================================================================

class TestKeyHierarchyIntegration:
    """Integration tests for key hierarchy."""

    def test_full_workflow(self, temp_storage):
        """Test complete key hierarchy workflow."""
        # Generate master key
        master_key = KeyHierarchy.generate_master_key()

        # Create hierarchy
        hierarchy = KeyHierarchy(master_key=master_key, storage_path=temp_storage)

        # Get system signing key
        system_key = hierarchy.get_system_signing_key()

        # Create tenant keys
        tenant1_key = hierarchy.get_tenant_signing_key("tenant_1")
        tenant2_key = hierarchy.get_tenant_signing_key("tenant_2")

        # Sign messages
        message = b"Audit log entry"
        system_sig = system_key.sign(message)
        tenant1_sig = tenant1_key.sign(message)

        # Verify signatures
        assert verify_signature(message, system_sig, system_key.keypair.public_key_bytes)
        assert verify_signature(message, tenant1_sig, tenant1_key.keypair.public_key_bytes)

        # Rotate system key
        new_system_key = hierarchy.rotate_system_signing_key()
        assert new_system_key.metadata.version > system_key.metadata.version

        # Revoke tenant
        revoked = hierarchy.revoke_tenant_keys("tenant_1")
        assert revoked > 0

        # Clear master key
        hierarchy.clear_master_key()
        assert not hierarchy.has_master_key

    def test_key_persistence(self, master_key, temp_storage):
        """Test that key metadata persists across instances."""
        # Create hierarchy and generate keys
        hierarchy1 = KeyHierarchy(master_key=master_key, storage_path=temp_storage)
        key1 = hierarchy1.get_system_signing_key()
        key1_id = key1.key_id

        # Create new hierarchy instance with same storage
        hierarchy2 = KeyHierarchy(master_key=master_key, storage_path=temp_storage)

        # Should find the key metadata
        loaded_meta = hierarchy2.get_key_by_id(key1_id)
        assert loaded_meta is not None
        assert loaded_meta.key_type == KeyType.SYSTEM_SIGNING

    def test_export_public_keys(self, key_hierarchy):
        """Test exporting public keys."""
        # Generate some keys
        key_hierarchy.get_system_signing_key()
        key_hierarchy.get_tenant_signing_key("export_test")

        public_keys = key_hierarchy.export_public_keys()

        assert len(public_keys) >= 2
        for key_id, encoded_key in public_keys.items():
            assert encoded_key.startswith("ed25519-pub:")


# ============================================================================
# Global Functions Tests
# ============================================================================

class TestGlobalFunctions:
    """Tests for module-level convenience functions."""

    def test_get_key_hierarchy_singleton(self, temp_storage):
        """Test that get_key_hierarchy returns singleton."""
        import vacp.core.key_hierarchy as kh_module
        kh_module._key_hierarchy = None

        h1 = get_key_hierarchy()
        h2 = get_key_hierarchy()

        assert h1 is h2

    def test_initialize_key_hierarchy(self, temp_storage):
        """Test initializing global hierarchy."""
        import vacp.core.key_hierarchy as kh_module
        kh_module._key_hierarchy = None

        master_key = secrets.token_bytes(32)
        hierarchy = initialize_key_hierarchy(master_key)

        assert hierarchy.has_master_key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
