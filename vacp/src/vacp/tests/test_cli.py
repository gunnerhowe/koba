"""
Tests for the VACP CLI

Tests command structure and basic functionality.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Try to import click for testing
try:
    from click.testing import CliRunner
    CLICK_AVAILABLE = True
except ImportError:
    CLICK_AVAILABLE = False

# Try to import the CLI
try:
    from vacp.cli.main import cli, get_config_path, save_token, load_token, clear_token
    CLI_AVAILABLE = True
except ImportError:
    CLI_AVAILABLE = False


@pytest.mark.skipif(not CLICK_AVAILABLE or not CLI_AVAILABLE, reason="Click or CLI not available")
class TestCLIStructure:
    """Tests for CLI command structure."""

    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()

    def test_cli_help(self, runner):
        """Test CLI help command."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "VACP CLI" in result.output

    def test_version(self, runner):
        """Test version command."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_server_group(self, runner):
        """Test server command group."""
        result = runner.invoke(cli, ["server", "--help"])
        assert result.exit_code == 0
        assert "start" in result.output
        assert "health" in result.output
        assert "stats" in result.output

    def test_auth_group(self, runner):
        """Test auth command group."""
        result = runner.invoke(cli, ["auth", "--help"])
        assert result.exit_code == 0
        assert "login" in result.output
        assert "logout" in result.output
        assert "whoami" in result.output

    def test_tools_group(self, runner):
        """Test tools command group."""
        result = runner.invoke(cli, ["tools", "--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "execute" in result.output

    def test_policy_group(self, runner):
        """Test policy command group."""
        result = runner.invoke(cli, ["policy", "--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "apply" in result.output
        assert "activate" in result.output

    def test_audit_group(self, runner):
        """Test audit command group."""
        result = runner.invoke(cli, ["audit", "--help"])
        assert result.exit_code == 0
        assert "entries" in result.output
        assert "verify-chain" in result.output
        assert "export" in result.output

    def test_killswitch_group(self, runner):
        """Test killswitch command group."""
        result = runner.invoke(cli, ["killswitch", "--help"])
        assert result.exit_code == 0
        assert "status" in result.output
        assert "activate" in result.output

    def test_approvals_group(self, runner):
        """Test approvals command group."""
        result = runner.invoke(cli, ["approvals", "--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "approve" in result.output
        assert "deny" in result.output

    def test_tokens_group(self, runner):
        """Test tokens command group."""
        result = runner.invoke(cli, ["tokens", "--help"])
        assert result.exit_code == 0
        assert "mint" in result.output
        assert "revoke" in result.output


@pytest.mark.skipif(not CLICK_AVAILABLE or not CLI_AVAILABLE, reason="Click or CLI not available")
class TestTokenStorage:
    """Tests for token storage functionality."""

    def test_save_and_load_token(self):
        """Test saving and loading authentication token."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"VACP_CONFIG_DIR": tmpdir}):
                # Save token
                save_token("test_token_12345")

                # Load token
                token = load_token()
                assert token == "test_token_12345"

    def test_clear_token(self):
        """Test clearing authentication token."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"VACP_CONFIG_DIR": tmpdir}):
                # Save and then clear
                save_token("test_token")
                clear_token()

                # Should be None now
                token = load_token()
                assert token is None

    def test_load_nonexistent_token(self):
        """Test loading token when none exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"VACP_CONFIG_DIR": tmpdir}):
                token = load_token()
                assert token is None


@pytest.mark.skipif(not CLICK_AVAILABLE or not CLI_AVAILABLE, reason="Click or CLI not available")
class TestCLIWithMockedAPI:
    """Tests for CLI commands with mocked API calls."""

    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()

    @pytest.fixture
    def mock_api(self):
        """Mock API request function."""
        with patch("vacp.cli.main.api_request") as mock:
            yield mock

    def test_server_health(self, runner, mock_api):
        """Test server health command."""
        mock_api.return_value = {
            "status": "healthy",
            "version": "0.1.0",
            "uptime_seconds": 3600.5,
            "components": {
                "gateway": "healthy",
                "policy_engine": "healthy",
            }
        }

        result = runner.invoke(cli, ["server", "health"])
        assert result.exit_code == 0
        assert "healthy" in result.output
        assert "0.1.0" in result.output

    def test_tools_list(self, runner, mock_api):
        """Test tools list command."""
        mock_api.return_value = {
            "tools": [
                {"id": "echo", "name": "Echo", "risk_level": "low", "requires_approval": False},
                {"id": "db.query", "name": "Query DB", "risk_level": "medium", "requires_approval": True},
            ]
        }

        result = runner.invoke(cli, ["tools", "list"])
        assert result.exit_code == 0
        assert "echo" in result.output
        assert "db.query" in result.output
        assert "Total: 2 tools" in result.output

    def test_tools_list_json(self, runner, mock_api):
        """Test tools list with JSON output."""
        mock_api.return_value = {
            "tools": [
                {"id": "echo", "name": "Echo"},
            ]
        }

        result = runner.invoke(cli, ["tools", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["id"] == "echo"

    def test_tools_execute(self, runner, mock_api):
        """Test tools execute command."""
        mock_api.return_value = {
            "success": True,
            "result": {"echo": "Hello, World!"},
            "receipt": {"receipt_id": "receipt-123"},
        }

        result = runner.invoke(cli, ["tools", "execute", "echo", "-p", "message=Hello, World!"])
        assert result.exit_code == 0
        assert "successfully" in result.output
        assert "receipt-123" in result.output

    def test_auth_login(self, runner, mock_api):
        """Test auth login command."""
        mock_api.return_value = {
            "access_token": "test_jwt_token",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"VACP_CONFIG_DIR": tmpdir}):
                result = runner.invoke(cli, ["auth", "login"], input="test@test.com\npassword123\n")
                assert result.exit_code == 0
                assert "successful" in result.output

    def test_auth_logout(self, runner):
        """Test auth logout command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"VACP_CONFIG_DIR": tmpdir}):
                # First save a token
                save_token("test_token")

                result = runner.invoke(cli, ["auth", "logout"])
                assert result.exit_code == 0
                assert "Logged out" in result.output

                # Token should be cleared
                assert load_token() is None

    def test_policy_list(self, runner, mock_api):
        """Test policy list command."""
        mock_api.return_value = {
            "bundles": [
                {"id": "default", "version": "1.0.0", "name": "Default Policy", "active": True},
            ]
        }

        result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0
        assert "default" in result.output
        assert "1.0.0" in result.output

    def test_audit_entries(self, runner, mock_api):
        """Test audit entries command."""
        mock_api.return_value = {
            "entries": [
                {"timestamp": "2024-01-01T12:00:00Z", "action": "tool_call", "agent_id": "agent-1", "tool_id": "echo"},
            ]
        }

        result = runner.invoke(cli, ["audit", "entries"])
        assert result.exit_code == 0
        assert "tool_call" in result.output
        assert "agent-1" in result.output

    def test_killswitch_status(self, runner, mock_api):
        """Test killswitch status command."""
        mock_api.return_value = {
            "active": False,
            "required_signatures": 2,
            "registered_key_holders": 3,
        }

        result = runner.invoke(cli, ["killswitch", "status"])
        assert result.exit_code == 0
        assert "Active:" in result.output
        assert "Required Signatures:" in result.output

    def test_tokens_mint(self, runner, mock_api):
        """Test tokens mint command."""
        mock_api.return_value = {
            "token_id": "tok-12345",
            "token_value": "secret_token_value",
            "expires_at": "2024-01-01T13:00:00Z",
        }

        result = runner.invoke(cli, [
            "tokens", "mint",
            "--agent-id", "agent-1",
            "--tenant-id", "tenant-1",
            "-t", "echo",
        ])
        assert result.exit_code == 0
        assert "tok-12345" in result.output
        assert "secret_token_value" in result.output

    def test_approvals_list(self, runner, mock_api):
        """Test approvals list command."""
        mock_api.return_value = {
            "approvals": [
                {
                    "approval_id": "approval-123",
                    "tool_id": "db.write",
                    "agent_id": "agent-1",
                    "created_at": "2024-01-01T12:00:00Z",
                },
            ]
        }

        result = runner.invoke(cli, ["approvals", "list"])
        assert result.exit_code == 0
        assert "approval-123" in result.output
        assert "db.write" in result.output


@pytest.mark.skipif(not CLICK_AVAILABLE or not CLI_AVAILABLE, reason="Click or CLI not available")
class TestCLIFormatting:
    """Tests for CLI output formatting."""

    def test_format_table(self):
        """Test table formatting."""
        from vacp.cli.main import format_table

        rows = [
            ("echo", "Echo Tool", "low"),
            ("db.query", "Query Database", "medium"),
        ]
        headers = ["ID", "Name", "Risk"]

        table = format_table(rows, headers)
        assert "echo" in table
        assert "Echo Tool" in table
        assert "+" in table  # Table borders

    def test_format_table_empty(self):
        """Test table formatting with empty data."""
        from vacp.cli.main import format_table

        table = format_table([], ["A", "B", "C"])
        assert "No data" in table

    def test_format_json(self):
        """Test JSON formatting."""
        from vacp.cli.main import format_json

        data = {"key": "value", "number": 42}
        output = format_json(data)
        parsed = json.loads(output)
        assert parsed["key"] == "value"
        assert parsed["number"] == 42


@pytest.mark.skipif(not CLICK_AVAILABLE or not CLI_AVAILABLE, reason="Click or CLI not available")
class TestCLITestCommands:
    """Tests for CLI test commands."""

    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()

    def test_test_rbac(self, runner):
        """Test RBAC testing command."""
        result = runner.invoke(cli, ["test", "rbac"])
        assert result.exit_code == 0
        assert "RBAC" in result.output

    def test_test_tls(self, runner):
        """Test TLS testing command."""
        result = runner.invoke(cli, ["test", "tls", "--endpoint", "api.example.com"])
        assert result.exit_code == 0
        assert "TLS" in result.output


@pytest.mark.skipif(not CLICK_AVAILABLE or not CLI_AVAILABLE, reason="Click or CLI not available")
class TestCLISystemCommands:
    """Tests for system commands."""

    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()

    def test_maintenance_mode_enable(self, runner):
        """Test enabling maintenance mode."""
        result = runner.invoke(cli, ["system", "maintenance-mode", "enable"])
        assert result.exit_code == 0
        assert "enabled" in result.output

    def test_maintenance_mode_disable(self, runner):
        """Test disabling maintenance mode."""
        result = runner.invoke(cli, ["system", "maintenance-mode", "disable"])
        assert result.exit_code == 0
        assert "disabled" in result.output

    def test_verify_integrity(self, runner):
        """Test system integrity verification."""
        result = runner.invoke(cli, ["system", "verify-integrity"])
        assert result.exit_code == 0
        assert "verified" in result.output
