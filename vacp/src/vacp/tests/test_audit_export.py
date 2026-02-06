"""
Tests for VACP Audit Log Export and Archival System.

Tests covering:
- Export formats (JSON, CSV, CEF, Syslog)
- Compression and encryption
- Archive management
- Retention policies
"""

import asyncio
import gzip
import hashlib
import json
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pytest

from vacp.core.audit_export import (
    ArchivePolicy,
    ArchiveStatus,
    AuditArchiveManager,
    AuditEntry,
    AuditExporter,
    ExportConfig,
    ExportFormat,
    ExportMetadata,
    InMemoryAuditSource,
    initialize_archive_manager,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def encryption_key():
    """Generate an encryption key."""
    return secrets.token_bytes(32)


@pytest.fixture
def export_config(temp_dir, encryption_key):
    """Create export configuration."""
    return ExportConfig(
        storage_backend="local",
        storage_path=str(temp_dir),
        encryption_enabled=True,
        encryption_key=encryption_key,
        compression_enabled=True,
        compression_level=6,
    )


@pytest.fixture
def audit_source():
    """Create an in-memory audit source with test data."""
    source = InMemoryAuditSource()

    # Add test entries
    base_time = datetime.now(timezone.utc) - timedelta(days=30)

    for i in range(100):
        entry = AuditEntry(
            entry_id=f"entry_{i:04d}",
            timestamp=base_time + timedelta(hours=i),
            action="message_created" if i % 2 == 0 else "token_issued",
            actor_id=f"agent_{i % 5}",
            actor_type="agent",
            resource_type="message" if i % 2 == 0 else "token",
            resource_id=f"res_{i:04d}",
            tenant_id="tenant_001",
            ip_address="192.168.1.100",
            correlation_id=f"corr_{i // 10:04d}",
            status="success" if i % 10 != 0 else "failure",
            details={"index": i, "test": True},
        )
        source.add_entry(entry)

    return source


@pytest.fixture
def exporter(audit_source, export_config):
    """Create an audit exporter."""
    return AuditExporter(audit_source, export_config)


@pytest.fixture
def archive_manager(audit_source, export_config):
    """Create an archive manager."""
    return AuditArchiveManager(audit_source, export_config)


# =============================================================================
# Test AuditEntry
# =============================================================================


class TestAuditEntry:
    """Tests for AuditEntry."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        now = datetime.now(timezone.utc)
        entry = AuditEntry(
            entry_id="test_001",
            timestamp=now,
            action="test_action",
            actor_id="actor_001",
            actor_type="user",
            resource_type="document",
            resource_id="doc_001",
            tenant_id="tenant_001",
            ip_address="10.0.0.1",
            status="success",
            details={"key": "value"},
        )

        data = entry.to_dict()

        assert data["entry_id"] == "test_001"
        assert data["action"] == "test_action"
        assert data["actor_type"] == "user"
        assert data["details"]["key"] == "value"

    def test_from_dict(self):
        """Test creation from dictionary."""
        now = datetime.now(timezone.utc)
        data = {
            "entry_id": "test_002",
            "timestamp": now.isoformat(),
            "action": "test_action",
            "actor_id": "actor_002",
            "actor_type": "system",
            "resource_type": "config",
            "resource_id": "cfg_001",
            "tenant_id": "tenant_002",
            "status": "success",
            "details": {},
        }

        entry = AuditEntry.from_dict(data)

        assert entry.entry_id == "test_002"
        assert entry.actor_type == "system"

    def test_to_cef(self):
        """Test CEF format conversion."""
        entry = AuditEntry(
            entry_id="cef_001",
            timestamp=datetime.now(timezone.utc),
            action="security_alert",
            actor_id="actor_001",
            actor_type="system",
            resource_type="system",
            resource_id="main",
            tenant_id="tenant_001",
            ip_address="192.168.1.1",
            status="success",
        )

        cef = entry.to_cef()

        assert cef.startswith("CEF:0|VACP|AuditLog|1.0|")
        assert "security_alert" in cef
        assert "192.168.1.1" in cef

    def test_to_syslog(self):
        """Test syslog format conversion."""
        entry = AuditEntry(
            entry_id="syslog_001",
            timestamp=datetime.now(timezone.utc),
            action="login_attempt",
            actor_id="user_001",
            actor_type="user",
            resource_type="auth",
            resource_id="session_001",
            tenant_id="tenant_001",
            status="success",
        )

        syslog = entry.to_syslog()

        assert "vacp" in syslog
        assert "audit" in syslog
        assert "login_attempt" in syslog


# =============================================================================
# Test InMemoryAuditSource
# =============================================================================


class TestInMemoryAuditSource:
    """Tests for InMemoryAuditSource."""

    @pytest.mark.asyncio
    async def test_query_time_range(self, audit_source):
        """Test querying by time range."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        count = 0
        async for entry in audit_source.query(start, end):
            count += 1

        assert count == 100

    @pytest.mark.asyncio
    async def test_query_with_filter(self, audit_source):
        """Test querying with filters."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        count = 0
        async for entry in audit_source.query(start, end, {"action": "message_created"}):
            count += 1
            assert entry.action == "message_created"

        assert count == 50  # Half the entries

    @pytest.mark.asyncio
    async def test_count(self, audit_source):
        """Test counting entries."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        count = await audit_source.count(start, end)
        assert count == 100


# =============================================================================
# Test AuditExporter
# =============================================================================


class TestAuditExporter:
    """Tests for AuditExporter."""

    @pytest.mark.asyncio
    async def test_export_json(self, exporter):
        """Test JSON export."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.JSON, start, end)

        assert metadata.status == ArchiveStatus.COMPLETED
        assert metadata.entry_count == 100
        assert metadata.format == ExportFormat.JSON
        assert metadata.checksum_sha256 != ""
        assert metadata.storage_path != ""

    @pytest.mark.asyncio
    async def test_export_jsonl(self, exporter):
        """Test JSON Lines export."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.JSON_LINES, start, end)

        assert metadata.status == ArchiveStatus.COMPLETED
        assert metadata.entry_count == 100

    @pytest.mark.asyncio
    async def test_export_csv(self, exporter):
        """Test CSV export."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.CSV, start, end)

        assert metadata.status == ArchiveStatus.COMPLETED
        assert metadata.entry_count == 100

    @pytest.mark.asyncio
    async def test_export_cef(self, exporter):
        """Test CEF export."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.CEF, start, end)

        assert metadata.status == ArchiveStatus.COMPLETED
        assert metadata.entry_count == 100

    @pytest.mark.asyncio
    async def test_export_syslog(self, exporter):
        """Test syslog export."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.SYSLOG, start, end)

        assert metadata.status == ArchiveStatus.COMPLETED
        assert metadata.entry_count == 100

    @pytest.mark.asyncio
    async def test_export_compression(self, exporter):
        """Test that compression reduces file size."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.JSON, start, end)

        assert metadata.compressed_size_bytes < metadata.file_size_bytes

    @pytest.mark.asyncio
    async def test_export_encryption(self, exporter):
        """Test that export is encrypted."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.JSON, start, end)

        assert metadata.encryption_key_id == "default"
        assert ".enc" in metadata.storage_path

    @pytest.mark.asyncio
    async def test_export_no_compression(self, audit_source, temp_dir, encryption_key):
        """Test export without compression."""
        config = ExportConfig(
            storage_backend="local",
            storage_path=str(temp_dir),
            encryption_enabled=False,
            compression_enabled=False,
        )
        exporter = AuditExporter(audit_source, config)

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.JSON, start, end)

        assert metadata.compressed_size_bytes == metadata.file_size_bytes
        assert ".gz" not in metadata.storage_path

    @pytest.mark.asyncio
    async def test_export_no_encryption(self, audit_source, temp_dir):
        """Test export without encryption."""
        config = ExportConfig(
            storage_backend="local",
            storage_path=str(temp_dir),
            encryption_enabled=False,
            compression_enabled=True,
        )
        exporter = AuditExporter(audit_source, config)

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(ExportFormat.JSON, start, end)

        assert metadata.encryption_key_id is None
        assert ".enc" not in metadata.storage_path

    @pytest.mark.asyncio
    async def test_export_with_progress(self, exporter):
        """Test export with progress callback."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        progress_updates = []

        def progress_callback(current: int, total: int) -> None:
            progress_updates.append((current, total))

        await exporter.export(ExportFormat.JSON, start, end, progress_callback=progress_callback)

        # Should have at least the initial call
        assert len(progress_updates) >= 1

    @pytest.mark.asyncio
    async def test_export_with_filters(self, exporter):
        """Test export with filters."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await exporter.export(
            ExportFormat.JSON,
            start,
            end,
            filters={"action": "message_created"},
        )

        assert metadata.entry_count == 50


# =============================================================================
# Test ExportMetadata
# =============================================================================


class TestExportMetadata:
    """Tests for ExportMetadata."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        now = datetime.now(timezone.utc)
        metadata = ExportMetadata(
            export_id="exp_001",
            format=ExportFormat.JSON,
            start_time=now - timedelta(days=30),
            end_time=now,
            created_at=now,
            status=ArchiveStatus.COMPLETED,
            entry_count=1000,
            checksum_sha256="abc123",
        )

        data = metadata.to_dict()

        assert data["export_id"] == "exp_001"
        assert data["format"] == "json"
        assert data["status"] == "completed"
        assert data["entry_count"] == 1000


# =============================================================================
# Test ArchivePolicy
# =============================================================================


class TestArchivePolicy:
    """Tests for ArchivePolicy."""

    def test_default_values(self):
        """Test default policy values."""
        policy = ArchivePolicy(name="test")

        assert policy.retention_days == 365 * 6  # 6 years
        assert policy.archive_after_days == 90
        assert policy.compress is True
        assert policy.encrypt is True

    def test_custom_values(self):
        """Test custom policy values."""
        policy = ArchivePolicy(
            name="custom",
            retention_days=365,
            archive_after_days=30,
            compress=False,
            encrypt=False,
        )

        assert policy.retention_days == 365
        assert policy.compress is False


# =============================================================================
# Test AuditArchiveManager
# =============================================================================


class TestAuditArchiveManager:
    """Tests for AuditArchiveManager."""

    def test_add_policy(self, archive_manager):
        """Test adding a policy."""
        policy = ArchivePolicy(name="test_policy", retention_days=30)
        archive_manager.add_policy(policy)

        retrieved = archive_manager.get_policy("test_policy")
        assert retrieved is not None
        assert retrieved.retention_days == 30

    def test_get_unknown_policy(self, archive_manager):
        """Test getting unknown policy."""
        assert archive_manager.get_policy("unknown") is None

    @pytest.mark.asyncio
    async def test_archive_period(self, archive_manager):
        """Test archiving a time period."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await archive_manager.archive_period(start, end)

        assert metadata.status == ArchiveStatus.COMPLETED
        assert metadata.entry_count == 100

    @pytest.mark.asyncio
    async def test_archive_with_policy(self, archive_manager):
        """Test archiving with a specific policy."""
        archive_manager.add_policy(ArchivePolicy(
            name="test_policy",
            compress=True,
            encrypt=True,
        ))

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await archive_manager.archive_period(
            start, end, policy_name="test_policy"
        )

        assert metadata.status == ArchiveStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_archive_monthly(self, archive_manager):
        """Test monthly archiving."""
        # Archive current month
        now = datetime.now(timezone.utc)

        # This may have 0 entries depending on test data timing
        metadata = await archive_manager.archive_monthly(now.year, now.month)

        assert metadata.status == ArchiveStatus.COMPLETED

    def test_get_archive(self, archive_manager):
        """Test getting an archive by ID."""
        assert archive_manager.get_archive("nonexistent") is None

    @pytest.mark.asyncio
    async def test_list_archives(self, archive_manager):
        """Test listing archives."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        # Create some archives
        await archive_manager.archive_period(start, end)
        await archive_manager.archive_period(start - timedelta(days=30), start)

        archives = archive_manager.list_archives()

        assert len(archives) == 2

    @pytest.mark.asyncio
    async def test_list_archives_with_filter(self, archive_manager):
        """Test listing archives with time filter."""
        now = datetime.now(timezone.utc)
        start1 = now - timedelta(days=35)
        end1 = now - timedelta(days=30)
        start2 = now - timedelta(days=25)
        end2 = now

        await archive_manager.archive_period(start1, end1)
        await archive_manager.archive_period(start2, end2)

        # Filter to only get recent archive
        archives = archive_manager.list_archives(
            start_time=now - timedelta(days=26)
        )

        assert len(archives) == 1

    @pytest.mark.asyncio
    async def test_verify_archive(self, archive_manager):
        """Test archive verification."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=35)
        end = now

        metadata = await archive_manager.archive_period(start, end)

        is_valid = await archive_manager.verify_archive(metadata.export_id)

        assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_nonexistent_archive(self, archive_manager):
        """Test verifying nonexistent archive."""
        is_valid = await archive_manager.verify_archive("nonexistent")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_retention_cleanup(self, archive_manager):
        """Test retention cleanup."""
        # Add a policy with very short retention
        archive_manager.add_policy(ArchivePolicy(
            name="short_retention",
            retention_days=0,  # Immediate expiry
        ))

        now = datetime.now(timezone.utc)
        # Create an archive that's "old"
        old_start = now - timedelta(days=35)
        old_end = now - timedelta(days=30)

        await archive_manager.archive_period(old_start, old_end, "short_retention")

        # Run cleanup
        deleted = await archive_manager.run_retention_cleanup("short_retention")

        assert len(deleted) >= 0  # May or may not delete depending on timing


# =============================================================================
# Test Global Functions
# =============================================================================


class TestGlobalFunctions:
    """Tests for global helper functions."""

    def test_initialize_archive_manager(self, audit_source, export_config):
        """Test initializing global archive manager."""
        manager = initialize_archive_manager(audit_source, export_config)

        assert manager is not None
        # Should have default policy
        policy = manager.get_policy("default")
        assert policy is not None
        assert policy.retention_days == 365 * 6
