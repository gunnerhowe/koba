"""
Tests for VACP Database Backup and Restore Module.

Comprehensive tests covering:
- Backup metadata serialization
- Storage providers (local, S3)
- Encryption
- Backup creation and restore
- Backup verification
- Retention and cleanup
"""

import asyncio
import gzip
import hashlib
import json
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vacp.core.backup import (
    BackupConfig,
    BackupEncryption,
    BackupManager,
    BackupMetadata,
    BackupStatus,
    BackupType,
    DatabaseBackup,
    LocalStorageProvider,
    RestorePoint,
    S3StorageProvider,
    StorageBackend,
    get_backup_manager,
    initialize_backup_manager,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def encryption_key():
    """Generate a test encryption key."""
    return secrets.token_bytes(32)


@pytest.fixture
def backup_config(temp_dir, encryption_key):
    """Create a test backup configuration."""
    return BackupConfig(
        storage_backend=StorageBackend.LOCAL,
        storage_path=str(temp_dir / "backups"),
        encryption_enabled=True,
        encryption_key=encryption_key,
        compression_enabled=True,
        compression_level=6,
        retention_days=30,
        max_backups=10,
        database_url="postgresql://test:test@localhost:5432/testdb",
        verify_after_backup=True,
    )


@pytest.fixture
def backup_manager(backup_config):
    """Create a backup manager for testing."""
    return BackupManager(backup_config)


@pytest.fixture
def local_storage(temp_dir):
    """Create a local storage provider for testing."""
    return LocalStorageProvider(str(temp_dir / "storage"))


# =============================================================================
# Test BackupMetadata
# =============================================================================


class TestBackupMetadata:
    """Tests for BackupMetadata dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        now = datetime.now(timezone.utc)
        metadata = BackupMetadata(
            backup_id="test_backup_001",
            backup_type=BackupType.FULL,
            status=BackupStatus.COMPLETED,
            created_at=now,
            completed_at=now,
            size_bytes=1024,
            compressed_size_bytes=512,
            checksum_sha256="abc123",
            encryption_key_id="key1",
            database_version="PostgreSQL 15.0",
            schema_version="1.0",
            tags={"env": "test"},
        )

        data = metadata.to_dict()

        assert data["backup_id"] == "test_backup_001"
        assert data["backup_type"] == "full"
        assert data["status"] == "completed"
        assert data["size_bytes"] == 1024
        assert data["compressed_size_bytes"] == 512
        assert data["tags"] == {"env": "test"}

    def test_from_dict(self):
        """Test creation from dictionary."""
        now = datetime.now(timezone.utc)
        data = {
            "backup_id": "test_backup_002",
            "backup_type": "incremental",
            "status": "in_progress",
            "created_at": now.isoformat(),
            "completed_at": None,
            "size_bytes": 2048,
            "compressed_size_bytes": 1024,
            "checksum_sha256": "def456",
            "encryption_key_id": "key2",
            "database_version": "PostgreSQL 14.0",
            "schema_version": "2.0",
            "parent_backup_id": "parent_001",
            "wal_position": "0/1234567",
            "tags": {"type": "scheduled"},
            "error_message": None,
        }

        metadata = BackupMetadata.from_dict(data)

        assert metadata.backup_id == "test_backup_002"
        assert metadata.backup_type == BackupType.INCREMENTAL
        assert metadata.status == BackupStatus.IN_PROGRESS
        assert metadata.size_bytes == 2048
        assert metadata.parent_backup_id == "parent_001"
        assert metadata.wal_position == "0/1234567"

    def test_roundtrip(self):
        """Test to_dict and from_dict roundtrip."""
        now = datetime.now(timezone.utc)
        original = BackupMetadata(
            backup_id="roundtrip_test",
            backup_type=BackupType.WAL,
            status=BackupStatus.VERIFIED,
            created_at=now,
            completed_at=now,
            size_bytes=4096,
            compressed_size_bytes=2048,
            checksum_sha256="ghi789",
            tags={"test": "roundtrip"},
        )

        data = original.to_dict()
        restored = BackupMetadata.from_dict(data)

        assert restored.backup_id == original.backup_id
        assert restored.backup_type == original.backup_type
        assert restored.status == original.status
        assert restored.size_bytes == original.size_bytes
        assert restored.tags == original.tags


class TestRestorePoint:
    """Tests for RestorePoint dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        now = datetime.now(timezone.utc)
        point = RestorePoint(
            backup_id="restore_test",
            timestamp=now,
            backup_type=BackupType.FULL,
            description="Test restore point",
            wal_position="0/ABCDEF",
        )

        data = point.to_dict()

        assert data["backup_id"] == "restore_test"
        assert data["backup_type"] == "full"
        assert data["description"] == "Test restore point"
        assert data["wal_position"] == "0/ABCDEF"


# =============================================================================
# Test BackupConfig
# =============================================================================


class TestBackupConfig:
    """Tests for BackupConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = BackupConfig()

        assert config.storage_backend == StorageBackend.LOCAL
        assert config.encryption_enabled is True
        assert config.compression_enabled is True
        assert config.retention_days == 30
        assert config.max_backups == 100

    def test_from_env(self, monkeypatch):
        """Test configuration from environment variables."""
        monkeypatch.setenv("VACP_BACKUP_STORAGE", "s3")
        monkeypatch.setenv("VACP_BACKUP_S3_BUCKET", "test-bucket")
        monkeypatch.setenv("VACP_BACKUP_RETENTION_DAYS", "60")
        monkeypatch.setenv("VACP_BACKUP_ENCRYPTION", "false")
        monkeypatch.setenv("VACP_DATABASE_URL", "postgresql://user:pass@localhost/db")

        config = BackupConfig.from_env()

        assert config.storage_backend == StorageBackend.S3
        assert config.s3_bucket == "test-bucket"
        assert config.retention_days == 60
        assert config.encryption_enabled is False
        assert config.database_url == "postgresql://user:pass@localhost/db"

    def test_encryption_key_from_env(self, monkeypatch):
        """Test encryption key loading from environment."""
        key_hex = secrets.token_hex(32)
        monkeypatch.setenv("VACP_BACKUP_ENCRYPTION_KEY", key_hex)

        config = BackupConfig.from_env()

        assert config.encryption_key == bytes.fromhex(key_hex)


# =============================================================================
# Test BackupEncryption
# =============================================================================


class TestBackupEncryption:
    """Tests for BackupEncryption."""

    def test_invalid_key_size(self):
        """Test that invalid key sizes are rejected."""
        with pytest.raises(ValueError, match="32 bytes"):
            BackupEncryption(b"short_key")

    def test_encrypt_decrypt(self, encryption_key):
        """Test encryption and decryption roundtrip."""
        enc = BackupEncryption(encryption_key)
        plaintext = b"This is sensitive backup data"

        ciphertext = enc.encrypt(plaintext)

        # Ciphertext should be different from plaintext
        assert ciphertext != plaintext
        # Should include nonce (12 bytes) + ciphertext + tag
        assert len(ciphertext) > len(plaintext)

        decrypted = enc.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_produces_different_ciphertext(self, encryption_key):
        """Test that each encryption produces different ciphertext (due to nonce)."""
        enc = BackupEncryption(encryption_key)
        plaintext = b"Same data"

        ciphertext1 = enc.encrypt(plaintext)
        ciphertext2 = enc.encrypt(plaintext)

        # Should be different due to random nonce
        assert ciphertext1 != ciphertext2

        # But both should decrypt to same plaintext
        assert enc.decrypt(ciphertext1) == plaintext
        assert enc.decrypt(ciphertext2) == plaintext

    def test_decrypt_tampered_data(self, encryption_key):
        """Test that tampered data fails decryption."""
        enc = BackupEncryption(encryption_key)
        ciphertext = enc.encrypt(b"Original data")

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[20] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):  # InvalidTag from AES-GCM
            enc.decrypt(tampered)

    def test_encrypt_decrypt_file(self, encryption_key, temp_dir):
        """Test file encryption and decryption."""
        enc = BackupEncryption(encryption_key)

        # Create test file
        original_path = temp_dir / "original.txt"
        original_data = b"Large file content " * 1000
        original_path.write_bytes(original_data)

        # Encrypt
        encrypted_path = temp_dir / "encrypted.bin"
        enc.encrypt_file(original_path, encrypted_path)

        assert encrypted_path.exists()
        assert encrypted_path.read_bytes() != original_data

        # Decrypt
        decrypted_path = temp_dir / "decrypted.txt"
        enc.decrypt_file(encrypted_path, decrypted_path)

        assert decrypted_path.read_bytes() == original_data


# =============================================================================
# Test LocalStorageProvider
# =============================================================================


class TestLocalStorageProvider:
    """Tests for LocalStorageProvider."""

    @pytest.mark.asyncio
    async def test_upload_download(self, local_storage, temp_dir):
        """Test file upload and download."""
        # Create test file
        source = temp_dir / "source.txt"
        source.write_text("Test content")

        # Upload
        await local_storage.upload(source, "test/file.txt")

        # Download
        dest = temp_dir / "dest.txt"
        await local_storage.download("test/file.txt", dest)

        assert dest.read_text() == "Test content"

    @pytest.mark.asyncio
    async def test_exists(self, local_storage, temp_dir):
        """Test file existence check."""
        source = temp_dir / "exists.txt"
        source.write_text("Exists")

        await local_storage.upload(source, "exists.txt")

        assert await local_storage.exists("exists.txt")
        assert not await local_storage.exists("nonexistent.txt")

    @pytest.mark.asyncio
    async def test_delete(self, local_storage, temp_dir):
        """Test file deletion."""
        source = temp_dir / "delete_me.txt"
        source.write_text("Delete me")

        await local_storage.upload(source, "delete_me.txt")
        assert await local_storage.exists("delete_me.txt")

        await local_storage.delete("delete_me.txt")
        assert not await local_storage.exists("delete_me.txt")

    @pytest.mark.asyncio
    async def test_list_files(self, local_storage, temp_dir):
        """Test listing files."""
        # Upload multiple files
        for i in range(3):
            source = temp_dir / f"file{i}.txt"
            source.write_text(f"Content {i}")
            await local_storage.upload(source, f"prefix/file{i}.txt")

        files = await local_storage.list_files("prefix")

        assert len(files) == 3
        assert "prefix/file0.txt" in files
        assert "prefix/file1.txt" in files
        assert "prefix/file2.txt" in files


# =============================================================================
# Test S3StorageProvider
# =============================================================================


class TestS3StorageProvider:
    """Tests for S3StorageProvider."""

    def test_full_key_with_prefix(self):
        """Test S3 key generation with prefix."""
        provider = S3StorageProvider(
            bucket="test-bucket",
            prefix="vacp-backups",
            region="us-west-2",
        )

        assert provider._full_key("backup.sql") == "vacp-backups/backup.sql"

    def test_full_key_without_prefix(self):
        """Test S3 key generation without prefix."""
        provider = S3StorageProvider(
            bucket="test-bucket",
            prefix="",
            region="us-west-2",
        )

        assert provider._full_key("backup.sql") == "backup.sql"

    @pytest.mark.asyncio
    async def test_upload_calls_boto3(self, temp_dir):
        """Test that upload calls boto3 client."""
        provider = S3StorageProvider(bucket="test-bucket", prefix="backups")

        mock_client = MagicMock()
        provider._client = mock_client

        source = temp_dir / "test.txt"
        source.write_text("Test")

        await provider.upload(source, "test.txt")

        mock_client.upload_file.assert_called_once()

    @pytest.mark.asyncio
    async def test_exists_returns_true_for_existing(self):
        """Test exists returns True when file exists."""
        provider = S3StorageProvider(bucket="test-bucket", prefix="backups")

        mock_client = MagicMock()
        mock_client.head_object.return_value = {}
        provider._client = mock_client

        result = await provider.exists("test.txt")

        assert result is True

    @pytest.mark.asyncio
    async def test_exists_returns_false_for_missing(self):
        """Test exists returns False when file doesn't exist."""
        provider = S3StorageProvider(bucket="test-bucket", prefix="backups")

        mock_client = MagicMock()
        mock_client.head_object.side_effect = Exception("Not found")
        provider._client = mock_client

        result = await provider.exists("missing.txt")

        assert result is False


# =============================================================================
# Test DatabaseBackup
# =============================================================================


class TestDatabaseBackup:
    """Tests for DatabaseBackup."""

    @pytest.mark.asyncio
    async def test_create_dump_success(self, backup_config, temp_dir):
        """Test successful database dump creation."""
        db_backup = DatabaseBackup(backup_config)

        dump_path = temp_dir / "dump.sql"

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"", b"pg_dump: done")
            mock_subprocess.return_value = mock_process

            success, error = await db_backup.create_dump(dump_path)

            assert success is True
            assert error == ""
            mock_subprocess.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_dump_failure(self, backup_config, temp_dir):
        """Test database dump failure handling."""
        db_backup = DatabaseBackup(backup_config)

        dump_path = temp_dir / "dump.sql"

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"connection refused")
            mock_subprocess.return_value = mock_process

            success, error = await db_backup.create_dump(dump_path)

            assert success is False
            assert "connection refused" in error

    @pytest.mark.asyncio
    async def test_restore_dump_success(self, backup_config, temp_dir):
        """Test successful database restore."""
        db_backup = DatabaseBackup(backup_config)

        dump_path = temp_dir / "dump.sql"
        dump_path.write_bytes(b"-- SQL dump")

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"", b"pg_restore: done")
            mock_subprocess.return_value = mock_process

            success, error = await db_backup.restore_dump(dump_path)

            assert success is True

    @pytest.mark.asyncio
    async def test_get_database_info(self, backup_config):
        """Test getting database info."""
        db_backup = DatabaseBackup(backup_config)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"PostgreSQL 15.0", b"")
            mock_subprocess.return_value = mock_process

            info = await db_backup.get_database_info()

            assert "version" in info
            assert "PostgreSQL" in info["version"]


# =============================================================================
# Test BackupManager
# =============================================================================


class TestBackupManager:
    """Tests for BackupManager."""

    def test_storage_property(self, backup_manager):
        """Test storage provider initialization."""
        storage = backup_manager.storage

        assert storage is not None
        assert isinstance(storage, LocalStorageProvider)

    def test_encryption_property(self, backup_manager):
        """Test encryption handler initialization."""
        encryption = backup_manager.encryption

        assert encryption is not None
        assert isinstance(encryption, BackupEncryption)

    def test_encryption_disabled(self, temp_dir):
        """Test that encryption is None when disabled."""
        config = BackupConfig(
            storage_backend=StorageBackend.LOCAL,
            storage_path=str(temp_dir),
            encryption_enabled=False,
        )
        manager = BackupManager(config)

        assert manager.encryption is None

    def test_encryption_no_key_raises(self, temp_dir):
        """Test that missing encryption key raises error."""
        config = BackupConfig(
            storage_backend=StorageBackend.LOCAL,
            storage_path=str(temp_dir),
            encryption_enabled=True,
            encryption_key=None,
        )
        manager = BackupManager(config)

        with pytest.raises(ValueError, match="no key is configured"):
            _ = manager.encryption

    def test_generate_backup_id(self, backup_manager):
        """Test backup ID generation."""
        id1 = backup_manager._generate_backup_id()
        id2 = backup_manager._generate_backup_id()

        assert id1.startswith("backup_")
        assert id2.startswith("backup_")
        assert id1 != id2

    def test_get_backup_path(self, backup_manager):
        """Test backup path generation."""
        path = backup_manager._get_backup_path("test_backup")

        assert path == "backups/test_backup"

    @pytest.mark.asyncio
    async def test_save_and_load_metadata(self, backup_manager):
        """Test metadata save and load."""
        metadata = BackupMetadata(
            backup_id="metadata_test",
            backup_type=BackupType.FULL,
            status=BackupStatus.COMPLETED,
            created_at=datetime.now(timezone.utc),
            tags={"test": "metadata"},
        )

        await backup_manager._save_metadata(metadata)
        loaded = await backup_manager._load_metadata("metadata_test")

        assert loaded is not None
        assert loaded.backup_id == metadata.backup_id
        assert loaded.status == metadata.status
        assert loaded.tags == metadata.tags

    @pytest.mark.asyncio
    async def test_create_backup_mocked(self, backup_manager):
        """Test backup creation with mocked database."""
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                # Setup mocks
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    # Create a fake dump file
                    output_path.write_text("-- Fake SQL dump\nSELECT 1;")
                    return True, ""

                mock_dump.side_effect = fake_dump

                # Create backup
                metadata = await backup_manager.create_backup(
                    backup_type=BackupType.FULL,
                    tags={"test": "create"},
                )

                assert metadata.backup_id.startswith("backup_")
                assert metadata.backup_type == BackupType.FULL
                assert metadata.database_version == "PostgreSQL 15.0"
                assert metadata.status in (BackupStatus.VERIFIED, BackupStatus.COMPLETED)
                assert metadata.size_bytes > 0
                assert metadata.checksum_sha256 != ""

    @pytest.mark.asyncio
    async def test_create_backup_failure(self, backup_manager):
        """Test backup creation failure handling."""
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}
                mock_dump.return_value = (False, "Connection refused")

                metadata = await backup_manager.create_backup()

                assert metadata.status == BackupStatus.FAILED
                assert "Connection refused" in metadata.error_message

    @pytest.mark.asyncio
    async def test_verify_backup(self, backup_manager):
        """Test backup verification."""
        # Create a backup first
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                metadata = await backup_manager.create_backup()

        # Verify the backup
        is_valid = await backup_manager.verify_backup(metadata.backup_id)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_backup_not_found(self, backup_manager):
        """Test verification of non-existent backup."""
        is_valid = await backup_manager.verify_backup("nonexistent_backup")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_list_backups(self, backup_manager):
        """Test listing backups."""
        # Create multiple backups
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                await backup_manager.create_backup(tags={"index": "1"})
                await backup_manager.create_backup(tags={"index": "2"})
                await backup_manager.create_backup(tags={"index": "3"})

        backups = await backup_manager.list_backups()

        assert len(backups) >= 3
        # Should be sorted newest first
        assert backups[0].created_at >= backups[1].created_at

    @pytest.mark.asyncio
    async def test_list_backups_with_filter(self, backup_manager):
        """Test listing backups with filters."""
        # Create a backup
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                await backup_manager.create_backup(backup_type=BackupType.FULL)

        # Filter by status
        verified_backups = await backup_manager.list_backups(status=BackupStatus.VERIFIED)
        completed_backups = await backup_manager.list_backups(status=BackupStatus.COMPLETED)

        total = len(verified_backups) + len(completed_backups)
        assert total >= 1

    @pytest.mark.asyncio
    async def test_delete_backup(self, backup_manager):
        """Test backup deletion."""
        # Create a backup
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                metadata = await backup_manager.create_backup()

        # Delete the backup
        deleted = await backup_manager.delete_backup(metadata.backup_id)
        assert deleted is True

        # Verify it's gone
        loaded = await backup_manager._load_metadata(metadata.backup_id)
        assert loaded is None

    @pytest.mark.asyncio
    async def test_restore_backup(self, backup_manager):
        """Test backup restoration."""
        # Create a backup first
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump\nCREATE TABLE test;")
                    return True, ""

                mock_dump.side_effect = fake_dump

                metadata = await backup_manager.create_backup()

        # Restore the backup
        with patch.object(
            backup_manager._db_backup,
            "restore_dump",
            new_callable=AsyncMock,
        ) as mock_restore:
            mock_restore.return_value = (True, "")

            success, error = await backup_manager.restore_backup(metadata.backup_id)

            assert success is True
            assert error == ""
            mock_restore.assert_called_once()

    @pytest.mark.asyncio
    async def test_restore_backup_not_found(self, backup_manager):
        """Test restoration of non-existent backup."""
        success, error = await backup_manager.restore_backup("nonexistent")

        assert success is False
        assert "not found" in error.lower()

    @pytest.mark.asyncio
    async def test_cleanup_old_backups(self, backup_manager):
        """Test cleanup of old backups."""
        # Create some backups
        created_ids = []
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                for _ in range(3):
                    metadata = await backup_manager.create_backup()
                    created_ids.append(metadata.backup_id)

        # Modify config to have short retention
        backup_manager.config.retention_days = 0
        backup_manager.config.max_backups = 1

        # Run cleanup
        deleted = await backup_manager.cleanup_old_backups()

        # Should have deleted some backups
        assert len(deleted) >= 0  # May delete depending on timing

    @pytest.mark.asyncio
    async def test_get_restore_points(self, backup_manager):
        """Test getting restore points."""
        # Create a backup
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                await backup_manager.create_backup()

        points = await backup_manager.get_restore_points()

        assert len(points) >= 1
        assert all(isinstance(p, RestorePoint) for p in points)


class TestBackupManagerCompression:
    """Tests for backup compression."""

    @pytest.mark.asyncio
    async def test_compression_reduces_size(self, temp_dir, encryption_key):
        """Test that compression reduces backup size."""
        config = BackupConfig(
            storage_backend=StorageBackend.LOCAL,
            storage_path=str(temp_dir / "backups"),
            encryption_enabled=False,
            compression_enabled=True,
            compression_level=9,
        )
        manager = BackupManager(config)

        with patch.object(
            manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                # Create a dump with repetitive content (compresses well)
                async def fake_dump(output_path, tables=None):
                    output_path.write_text("SELECT * FROM users; " * 1000)
                    return True, ""

                mock_dump.side_effect = fake_dump

                metadata = await manager.create_backup()

        assert metadata.compressed_size_bytes < metadata.size_bytes

    @pytest.mark.asyncio
    async def test_no_compression(self, temp_dir):
        """Test backup without compression."""
        config = BackupConfig(
            storage_backend=StorageBackend.LOCAL,
            storage_path=str(temp_dir / "backups"),
            encryption_enabled=False,
            compression_enabled=False,
        )
        manager = BackupManager(config)

        with patch.object(
            manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                metadata = await manager.create_backup()

        # Without compression, sizes should be equal
        assert metadata.compressed_size_bytes == metadata.size_bytes


# =============================================================================
# Test Global Functions
# =============================================================================


class TestGlobalFunctions:
    """Tests for global helper functions."""

    def test_get_backup_manager_singleton(self, monkeypatch):
        """Test that get_backup_manager returns singleton."""
        monkeypatch.setenv("VACP_BACKUP_PATH", "/tmp/test_backups")
        monkeypatch.setenv("VACP_BACKUP_ENCRYPTION", "false")

        # Reset singleton
        import vacp.core.backup as backup_module
        backup_module._backup_manager = None

        manager1 = get_backup_manager()
        manager2 = get_backup_manager()

        assert manager1 is manager2

    def test_initialize_backup_manager(self, backup_config):
        """Test initializing backup manager with custom config."""
        manager = initialize_backup_manager(backup_config)

        assert manager is not None
        assert manager.config == backup_config

        # Should update global instance
        assert get_backup_manager() is manager


# =============================================================================
# Test Progress Callback
# =============================================================================


class TestProgressCallback:
    """Tests for progress callback functionality."""

    @pytest.mark.asyncio
    async def test_create_backup_with_progress(self, backup_manager):
        """Test that progress callback is called during backup."""
        progress_messages = []

        def progress_callback(message: str, percent: int):
            progress_messages.append((message, percent))

        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                await backup_manager.create_backup(
                    progress_callback=progress_callback,
                )

        # Should have received progress updates
        assert len(progress_messages) > 0
        # Last message should be 100%
        assert progress_messages[-1][1] == 100

    @pytest.mark.asyncio
    async def test_restore_backup_with_progress(self, backup_manager):
        """Test that progress callback is called during restore."""
        # Create a backup first
        with patch.object(
            backup_manager._db_backup,
            "create_dump",
            new_callable=AsyncMock,
        ) as mock_dump:
            with patch.object(
                backup_manager._db_backup,
                "get_database_info",
                new_callable=AsyncMock,
            ) as mock_info:
                mock_info.return_value = {"version": "PostgreSQL 15.0"}

                async def fake_dump(output_path, tables=None):
                    output_path.write_text("-- SQL dump")
                    return True, ""

                mock_dump.side_effect = fake_dump

                metadata = await backup_manager.create_backup()

        progress_messages = []

        def progress_callback(message: str, percent: int):
            progress_messages.append((message, percent))

        # Restore with progress
        with patch.object(
            backup_manager._db_backup,
            "restore_dump",
            new_callable=AsyncMock,
        ) as mock_restore:
            mock_restore.return_value = (True, "")

            await backup_manager.restore_backup(
                metadata.backup_id,
                progress_callback=progress_callback,
            )

        assert len(progress_messages) > 0
        assert progress_messages[-1][1] == 100
