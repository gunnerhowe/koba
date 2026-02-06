"""
Tests for HashiCorp Vault integration.

Tests cover:
- VaultConfig parsing
- SecretCache operations
- VaultClient with mocked hvac
- SecretsManager high-level API
- Environment variable fallbacks
"""

import os
import pytest
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, PropertyMock

from vacp.core.vault import (
    VaultConfig,
    AuthMethod,
    SecretCache,
    CachedSecret,
    VaultClient,
    SecretsManager,
    get_secrets_manager,
    get_secret,
    set_secret,
)


# ============================================================================
# VaultConfig Tests
# ============================================================================

class TestVaultConfig:
    """Tests for VaultConfig class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = VaultConfig()
        assert config.address == ""
        assert config.mount_point == "secret"
        assert config.verify_ssl is True
        assert config.cache_ttl == 300

    def test_from_env(self):
        """Test loading configuration from environment."""
        with patch.dict(os.environ, {
            "VAULT_ADDR": "https://vault.example.com:8200",
            "VAULT_TOKEN": "test_token",
            "VAULT_MOUNT_POINT": "kv",
            "VAULT_NAMESPACE": "test",
        }):
            config = VaultConfig.from_env()
            assert config.address == "https://vault.example.com:8200"
            assert config.token == "test_token"
            assert config.mount_point == "kv"
            assert config.namespace == "test"

    def test_get_auth_method_token(self):
        """Test auth method detection for token."""
        config = VaultConfig(token="test_token")
        assert config.get_auth_method() == AuthMethod.TOKEN

    def test_get_auth_method_approle(self):
        """Test auth method detection for AppRole."""
        config = VaultConfig(
            role_id="test_role_id",
            secret_id="test_secret_id",
        )
        assert config.get_auth_method() == AuthMethod.APPROLE

    def test_get_auth_method_kubernetes(self):
        """Test auth method detection for Kubernetes."""
        config = VaultConfig(kubernetes_role="test_role")
        assert config.get_auth_method() == AuthMethod.KUBERNETES

    def test_get_auth_method_none(self):
        """Test auth method when no credentials provided."""
        config = VaultConfig()
        assert config.get_auth_method() == AuthMethod.NONE

    def test_approle_takes_precedence(self):
        """Test that AppRole takes precedence over token."""
        config = VaultConfig(
            token="test_token",
            role_id="test_role_id",
            secret_id="test_secret_id",
        )
        assert config.get_auth_method() == AuthMethod.APPROLE


# ============================================================================
# SecretCache Tests
# ============================================================================

class TestSecretCache:
    """Tests for SecretCache class."""

    def test_get_nonexistent(self):
        """Test getting a non-existent key."""
        cache = SecretCache()
        assert cache.get("nonexistent") is None

    def test_set_and_get(self):
        """Test basic set and get operations."""
        cache = SecretCache()
        cache.set("test/path", {"key": "value"})

        result = cache.get("test/path")
        assert result == {"key": "value"}

    def test_expiration(self):
        """Test that cached items expire."""
        cache = SecretCache(default_ttl=1)  # 1 second TTL
        cache.set("test/path", {"key": "value"})

        # Should be present immediately
        assert cache.get("test/path") is not None

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert cache.get("test/path") is None

    def test_custom_ttl(self):
        """Test setting custom TTL per item."""
        cache = SecretCache(default_ttl=60)
        cache.set("test/path", {"key": "value"}, ttl=1)

        assert cache.get("test/path") is not None
        time.sleep(1.1)
        assert cache.get("test/path") is None

    def test_invalidate(self):
        """Test invalidating a cached item."""
        cache = SecretCache()
        cache.set("test/path", {"key": "value"})

        cache.invalidate("test/path")

        assert cache.get("test/path") is None

    def test_clear(self):
        """Test clearing all cached items."""
        cache = SecretCache()
        cache.set("path1", {"key": "value1"})
        cache.set("path2", {"key": "value2"})

        cache.clear()

        assert cache.get("path1") is None
        assert cache.get("path2") is None

    def test_cleanup_expired(self):
        """Test cleanup of expired entries."""
        cache = SecretCache()

        # Add item with short TTL
        cache.set("short", {"key": "short"}, ttl=1)
        # Add item with long TTL
        cache.set("long", {"key": "long"}, ttl=60)

        time.sleep(1.1)

        removed = cache.cleanup_expired()

        assert removed == 1
        assert cache.get("short") is None
        assert cache.get("long") == {"key": "long"}


# ============================================================================
# CachedSecret Tests
# ============================================================================

class TestCachedSecret:
    """Tests for CachedSecret class."""

    def test_not_expired(self):
        """Test that fresh secret is not expired."""
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        cached = CachedSecret(
            value={"key": "value"},
            expires_at=future,
            path="test/path",
        )
        assert not cached.is_expired()

    def test_expired(self):
        """Test that old secret is expired."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        cached = CachedSecret(
            value={"key": "value"},
            expires_at=past,
            path="test/path",
        )
        assert cached.is_expired()


# ============================================================================
# VaultClient Tests (Mocked)
# ============================================================================

class TestVaultClient:
    """Tests for VaultClient class."""

    def test_is_available_without_hvac(self):
        """Test availability when hvac is not installed."""
        with patch("vacp.core.vault.HVAC_AVAILABLE", False):
            client = VaultClient(VaultConfig(address="https://vault:8200"))
            assert not client.is_available

    def test_is_available_without_address(self):
        """Test availability without Vault address."""
        with patch("vacp.core.vault.HVAC_AVAILABLE", True):
            client = VaultClient(VaultConfig())
            assert not client.is_available

    def test_is_available_with_config(self):
        """Test availability with proper configuration."""
        with patch("vacp.core.vault.HVAC_AVAILABLE", True):
            client = VaultClient(VaultConfig(address="https://vault:8200"))
            assert client.is_available

    def test_connect_no_hvac(self):
        """Test connect fails when hvac not available."""
        with patch("vacp.core.vault.HVAC_AVAILABLE", False):
            client = VaultClient(VaultConfig(
                address="https://vault:8200",
                token="test_token",
            ))
            assert not client.connect()

    def test_connect_no_address(self):
        """Test connect fails without address."""
        with patch("vacp.core.vault.HVAC_AVAILABLE", True):
            client = VaultClient(VaultConfig())
            assert not client.connect()

    @patch("vacp.core.vault.HVAC_AVAILABLE", True)
    @patch("vacp.core.vault.hvac")
    def test_connect_with_token(self, mock_hvac):
        """Test connecting with token authentication."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac.Client.return_value = mock_client

        client = VaultClient(VaultConfig(
            address="https://vault:8200",
            token="test_token",
        ))

        result = client.connect()

        assert result is True
        assert mock_client.token == "test_token"

    @patch("vacp.core.vault.HVAC_AVAILABLE", True)
    @patch("vacp.core.vault.hvac")
    def test_connect_with_approle(self, mock_hvac):
        """Test connecting with AppRole authentication."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.auth.approle.login.return_value = {
            "auth": {"client_token": "approle_token"}
        }
        mock_hvac.Client.return_value = mock_client

        client = VaultClient(VaultConfig(
            address="https://vault:8200",
            role_id="test_role_id",
            secret_id="test_secret_id",
        ))

        result = client.connect()

        assert result is True
        mock_client.auth.approle.login.assert_called_once_with(
            role_id="test_role_id",
            secret_id="test_secret_id",
        )

    def test_get_secret_from_cache(self):
        """Test getting secret from cache."""
        client = VaultClient(VaultConfig())
        client._cache.set("test/path", {"key": "cached_value"})

        result = client.get_secret("test/path", "key")

        assert result == "cached_value"

    def test_get_secret_with_key(self):
        """Test getting specific key from secret."""
        client = VaultClient(VaultConfig())
        client._cache.set("test/path", {"key1": "value1", "key2": "value2"})

        result = client.get_secret("test/path", "key1")

        assert result == "value1"

    def test_get_secret_env_fallback(self):
        """Test environment variable fallback."""
        with patch.dict(os.environ, {"VAULT_DATABASE_CREDENTIALS_PASSWORD": "env_password"}):
            client = VaultClient(VaultConfig())

            result = client.get_secret("database/credentials", "password")

            assert result == "env_password"

    def test_get_secret_custom_fallback(self):
        """Test custom fallback value."""
        client = VaultClient(VaultConfig())
        client.set_env_fallback("test/path", "key", "fallback_value")

        result = client.get_secret("test/path", "key")

        assert result == "fallback_value"

    def test_get_secret_default(self):
        """Test default value when secret not found."""
        client = VaultClient(VaultConfig())

        result = client.get_secret("nonexistent/path", "key", default="default_value")

        assert result == "default_value"

    @patch("vacp.core.vault.HVAC_AVAILABLE", True)
    @patch("vacp.core.vault.hvac")
    def test_get_secret_from_vault(self, mock_hvac):
        """Test getting secret from Vault."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"key": "vault_value"}}
        }
        mock_hvac.Client.return_value = mock_client

        client = VaultClient(VaultConfig(
            address="https://vault:8200",
            token="test_token",
            cache_enabled=False,
        ))
        client._client = mock_client

        result = client.get_secret("test/path", "key")

        assert result == "vault_value"

    @patch("vacp.core.vault.HVAC_AVAILABLE", True)
    @patch("vacp.core.vault.hvac")
    def test_set_secret(self, mock_hvac):
        """Test storing a secret in Vault."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac.Client.return_value = mock_client

        client = VaultClient(VaultConfig(
            address="https://vault:8200",
            token="test_token",
        ))
        client._client = mock_client

        result = client.set_secret("test/path", {"key": "value"})

        assert result is True
        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()

    def test_set_secret_not_authenticated(self):
        """Test storing secret fails when not authenticated."""
        client = VaultClient(VaultConfig())

        result = client.set_secret("test/path", {"key": "value"})

        assert result is False

    def test_path_to_env_var(self):
        """Test path to environment variable conversion."""
        client = VaultClient(VaultConfig())

        assert client._path_to_env_var("database/credentials", "password") == "VAULT_DATABASE_CREDENTIALS_PASSWORD"
        assert client._path_to_env_var("api_keys/openai", "key") == "VAULT_API_KEYS_OPENAI_KEY"


# ============================================================================
# SecretsManager Tests
# ============================================================================

class TestSecretsManager:
    """Tests for SecretsManager class."""

    def test_get_database_credentials_env_fallback(self):
        """Test getting database credentials from environment."""
        with patch.dict(os.environ, {
            "DB_HOST": "localhost",
            "DB_PORT": "5432",
            "DB_NAME": "testdb",
            "DB_USER": "testuser",
            "DB_PASSWORD": "testpass",
        }):
            with patch("vacp.core.vault.HVAC_AVAILABLE", False):
                manager = SecretsManager()
                creds = manager.get_database_credentials()

                assert creds["host"] == "localhost"
                assert creds["port"] == "5432"
                assert creds["database"] == "testdb"
                assert creds["username"] == "testuser"
                assert creds["password"] == "testpass"

    def test_get_api_key(self):
        """Test getting API key with fallback."""
        manager = SecretsManager(VaultClient(VaultConfig()))
        manager.vault.set_env_fallback("api_keys/openai", "key", "test_api_key")

        result = manager.get_api_key("openai")

        assert result == "test_api_key"

    def test_get_hedera_credentials_env_fallback(self):
        """Test getting Hedera credentials from environment."""
        with patch.dict(os.environ, {
            "HEDERA_OPERATOR_ID": "0.0.12345",
            "HEDERA_OPERATOR_KEY": "test_key",
            "HEDERA_TOPIC_ID": "0.0.67890",
            "HEDERA_NETWORK": "testnet",
        }):
            with patch("vacp.core.vault.HVAC_AVAILABLE", False):
                manager = SecretsManager()
                creds = manager.get_hedera_credentials()

                assert creds["operator_id"] == "0.0.12345"
                assert creds["operator_key"] == "test_key"
                assert creds["topic_id"] == "0.0.67890"
                assert creds["network"] == "testnet"

    def test_get_ethereum_credentials_env_fallback(self):
        """Test getting Ethereum credentials from environment."""
        with patch.dict(os.environ, {
            "ETHEREUM_RPC_URL": "https://sepolia.infura.io/v3/test",
            "ETHEREUM_PRIVATE_KEY": "0x" + "a" * 64,
            "ETHEREUM_CHAIN_ID": "11155111",
        }):
            with patch("vacp.core.vault.HVAC_AVAILABLE", False):
                manager = SecretsManager()
                creds = manager.get_ethereum_credentials()

                assert creds["rpc_url"] == "https://sepolia.infura.io/v3/test"
                assert creds["private_key"] == "0x" + "a" * 64
                assert creds["chain_id"] == "11155111"

    def test_is_vault_connected_false(self):
        """Test vault connection status when not connected."""
        with patch("vacp.core.vault.HVAC_AVAILABLE", False):
            manager = SecretsManager()
            assert manager.is_vault_connected is False

    def test_get_and_set(self):
        """Test get and set operations."""
        manager = SecretsManager(VaultClient(VaultConfig()))

        # Set via fallback
        manager.vault.set_env_fallback("test/path", "key", "test_value")

        result = manager.get("test/path", "key")
        assert result == "test_value"


# ============================================================================
# Global Functions Tests
# ============================================================================

class TestGlobalFunctions:
    """Tests for module-level convenience functions."""

    def test_get_secrets_manager_singleton(self):
        """Test that get_secrets_manager returns singleton."""
        # Reset singleton
        import vacp.core.vault as vault_module
        vault_module._secrets_manager = None

        manager1 = get_secrets_manager()
        manager2 = get_secrets_manager()

        assert manager1 is manager2

    def test_get_secret_function(self):
        """Test get_secret convenience function."""
        import vacp.core.vault as vault_module
        vault_module._secrets_manager = None

        with patch.dict(os.environ, {"VAULT_TEST_PATH_KEY": "env_value"}):
            with patch("vacp.core.vault.HVAC_AVAILABLE", False):
                result = get_secret("test/path", "key")
                # Should get from env fallback
                assert result == "env_value"


# ============================================================================
# Integration Tests
# ============================================================================

class TestVaultIntegration:
    """Integration tests for Vault workflows."""

    def test_cache_invalidation_on_set(self):
        """Test that cache is invalidated when setting a secret."""
        with patch("vacp.core.vault.HVAC_AVAILABLE", True):
            with patch("vacp.core.vault.hvac"):
                client = VaultClient(VaultConfig())

                # Add to cache
                client._cache.set("test/path", {"key": "old_value"})

                # Mock client for set operation
                mock_client = MagicMock()
                mock_client.is_authenticated.return_value = True
                client._client = mock_client

                # Set new value
                client.set_secret("test/path", {"key": "new_value"})

                # Cache should be invalidated
                assert client._cache.get("test/path") is None

    def test_full_workflow_with_fallback(self):
        """Test complete workflow using environment fallbacks."""
        with patch.dict(os.environ, {
            "DB_HOST": "test_host",
            "DB_PASSWORD": "test_pass",
            "VAULT_API_KEYS_STRIPE_KEY": "sk_test_xxx",
        }):
            with patch("vacp.core.vault.HVAC_AVAILABLE", False):
                manager = SecretsManager()

                # Get database creds
                db_creds = manager.get_database_credentials()
                assert db_creds["host"] == "test_host"
                assert db_creds["password"] == "test_pass"

                # Get API key from env var
                api_key = manager.get("api_keys/stripe", "key")
                assert api_key == "sk_test_xxx"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
