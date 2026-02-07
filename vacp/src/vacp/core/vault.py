"""
HashiCorp Vault Integration

Provides secure secrets management via HashiCorp Vault with support for:
- Multiple authentication methods (Token, AppRole, Kubernetes)
- Automatic token renewal
- Secret caching with TTL
- Transit engine for encryption operations
- Fallback to environment variables for development

Configuration via environment variables:
- VAULT_ADDR: Vault server address (e.g., https://vault.example.com:8200)
- VAULT_TOKEN: Static token for authentication (development only)
- VAULT_ROLE_ID: AppRole role ID
- VAULT_SECRET_ID: AppRole secret ID
- VAULT_KUBERNETES_ROLE: Kubernetes auth role
- VAULT_MOUNT_POINT: KV secrets mount point (default: secret)
- VAULT_NAMESPACE: Vault namespace (enterprise only)
"""

import base64
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Try to import hvac (HashiCorp Vault client)
try:
    import hvac
    from hvac.exceptions import VaultError, InvalidRequest, Forbidden
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False
    hvac = None
    VaultError = Exception
    InvalidRequest = Exception
    Forbidden = Exception


class AuthMethod(Enum):
    """Supported Vault authentication methods."""
    TOKEN = "token"
    APPROLE = "approle"
    KUBERNETES = "kubernetes"
    AWS_IAM = "aws_iam"
    NONE = "none"  # For fallback/development


@dataclass
class VaultConfig:
    """Configuration for Vault connection."""
    address: str = ""
    token: str = ""
    role_id: str = ""
    secret_id: str = ""
    kubernetes_role: str = ""
    mount_point: str = "secret"
    namespace: str = ""
    verify_ssl: bool = True
    timeout: int = 30

    # Token renewal settings
    auto_renew: bool = True
    renew_threshold: int = 300  # Renew if TTL < 5 minutes

    # Cache settings
    cache_ttl: int = 300  # 5 minutes
    cache_enabled: bool = True

    @classmethod
    def from_env(cls) -> "VaultConfig":
        """Load configuration from environment variables."""
        return cls(
            address=os.getenv("VAULT_ADDR", ""),
            token=os.getenv("VAULT_TOKEN", ""),
            role_id=os.getenv("VAULT_ROLE_ID", ""),
            secret_id=os.getenv("VAULT_SECRET_ID", ""),
            kubernetes_role=os.getenv("VAULT_KUBERNETES_ROLE", ""),
            mount_point=os.getenv("VAULT_MOUNT_POINT", "secret"),
            namespace=os.getenv("VAULT_NAMESPACE", ""),
            verify_ssl=os.getenv("VAULT_SKIP_VERIFY", "").lower() != "true",
            cache_ttl=int(os.getenv("VAULT_CACHE_TTL", "300")),
        )

    def get_auth_method(self) -> AuthMethod:
        """Determine which auth method to use based on available credentials."""
        if self.role_id and self.secret_id:
            return AuthMethod.APPROLE
        if self.kubernetes_role:
            return AuthMethod.KUBERNETES
        if self.token:
            return AuthMethod.TOKEN
        return AuthMethod.NONE


@dataclass
class CachedSecret:
    """A cached secret with expiration."""
    value: Dict[str, Any]
    expires_at: datetime
    path: str

    def is_expired(self) -> bool:
        """Check if secret has expired."""
        return datetime.now(timezone.utc) >= self.expires_at


class SecretCache:
    """Thread-safe secret cache with TTL."""

    def __init__(self, default_ttl: int = 300):
        """
        Initialize cache.

        Args:
            default_ttl: Default TTL in seconds
        """
        self._cache: Dict[str, CachedSecret] = {}
        self._lock = threading.RLock()
        self._default_ttl = default_ttl

    def get(self, path: str) -> Optional[Dict[str, Any]]:
        """Get a secret from cache if not expired."""
        with self._lock:
            cached = self._cache.get(path)
            if cached and not cached.is_expired():
                return cached.value
            if cached:
                del self._cache[path]
            return None

    def set(self, path: str, value: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Store a secret in cache."""
        ttl = ttl if ttl is not None else self._default_ttl
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        with self._lock:
            self._cache[path] = CachedSecret(
                value=value,
                expires_at=expires_at,
                path=path,
            )

    def invalidate(self, path: str) -> None:
        """Remove a secret from cache."""
        with self._lock:
            self._cache.pop(path, None)

    def clear(self) -> None:
        """Clear all cached secrets."""
        with self._lock:
            self._cache.clear()

    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count removed."""
        removed = 0
        with self._lock:
            expired = [p for p, c in self._cache.items() if c.is_expired()]
            for path in expired:
                del self._cache[path]
                removed += 1
        return removed


class VaultClient:
    """
    HashiCorp Vault client with automatic token renewal and caching.

    Provides secure access to secrets stored in Vault with:
    - Multiple authentication methods
    - Automatic token renewal
    - Secret caching
    - Transit encryption operations
    - Fallback to environment variables
    """

    def __init__(self, config: Optional[VaultConfig] = None):
        """
        Initialize Vault client.

        Args:
            config: Vault configuration. If None, loads from environment.
        """
        self.config = config or VaultConfig.from_env()
        self._client: Optional[Any] = None
        self._cache = SecretCache(default_ttl=self.config.cache_ttl)
        self._renew_thread: Optional[threading.Thread] = None
        self._stop_renewal = threading.Event()

        # Environment fallback cache
        self._env_fallback: Dict[str, str] = {}

    @property
    def is_available(self) -> bool:
        """Check if Vault is available and configured."""
        return HVAC_AVAILABLE and bool(self.config.address)

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        if not self._client:
            return False
        try:
            return self._client.is_authenticated()
        except Exception:
            return False

    def connect(self) -> bool:
        """
        Connect and authenticate to Vault.

        Returns:
            True if connection successful
        """
        if not HVAC_AVAILABLE:
            logger.warning("hvac library not installed. Install with: pip install hvac")
            return False

        if not self.config.address:
            logger.warning("Vault address not configured")
            return False

        try:
            # Create client
            self._client = hvac.Client(
                url=self.config.address,
                namespace=self.config.namespace or None,
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
            )

            # Authenticate based on method
            auth_method = self.config.get_auth_method()

            if auth_method == AuthMethod.TOKEN:
                self._client.token = self.config.token

            elif auth_method == AuthMethod.APPROLE:
                response = self._client.auth.approle.login(
                    role_id=self.config.role_id,
                    secret_id=self.config.secret_id,
                )
                self._client.token = response["auth"]["client_token"]

            elif auth_method == AuthMethod.KUBERNETES:
                # Read service account token
                jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
                if os.path.exists(jwt_path):
                    with open(jwt_path) as f:
                        jwt = f.read()
                    response = self._client.auth.kubernetes.login(
                        role=self.config.kubernetes_role,
                        jwt=jwt,
                    )
                    self._client.token = response["auth"]["client_token"]
                else:
                    logger.error("Kubernetes service account token not found")
                    return False

            else:
                logger.warning("No Vault authentication method configured")
                return False

            # Verify authentication
            if not self._client.is_authenticated():
                logger.error("Vault authentication failed")
                return False

            # Start token renewal if enabled
            if self.config.auto_renew:
                self._start_renewal()

            logger.info(f"Connected to Vault at {self.config.address}")
            return True

        except VaultError as e:
            logger.error(f"Vault connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to Vault: {e}")
            return False

    def disconnect(self) -> None:
        """Disconnect from Vault and stop renewal."""
        self._stop_renewal.set()
        if self._renew_thread:
            self._renew_thread.join(timeout=5)
        self._cache.clear()
        if self._client:
            try:
                self._client.auth.token.revoke_self()
            except Exception:
                pass
            self._client = None

    def _start_renewal(self) -> None:
        """Start background token renewal thread."""
        if self._renew_thread and self._renew_thread.is_alive():
            return

        self._stop_renewal.clear()
        self._renew_thread = threading.Thread(
            target=self._renewal_loop,
            daemon=True,
            name="vault-token-renewal",
        )
        self._renew_thread.start()

    def _renewal_loop(self) -> None:
        """Background loop for token renewal."""
        while not self._stop_renewal.is_set():
            try:
                if self._client and self._client.is_authenticated():
                    # Check token TTL
                    token_data = self._client.auth.token.lookup_self()
                    ttl = token_data["data"].get("ttl", 0)

                    if ttl > 0 and ttl < self.config.renew_threshold:
                        # Renew token
                        self._client.auth.token.renew_self()
                        logger.debug("Vault token renewed")

                # Sleep before next check
                self._stop_renewal.wait(timeout=60)

            except Exception as e:
                logger.warning(f"Token renewal error: {e}")
                self._stop_renewal.wait(timeout=30)

    def get_secret(
        self,
        path: str,
        key: Optional[str] = None,
        default: Any = None,
        version: Optional[int] = None,
    ) -> Any:
        """
        Get a secret from Vault or fallback.

        Args:
            path: Secret path (e.g., "database/credentials")
            key: Specific key within the secret data
            default: Default value if not found
            version: Specific version (KV v2 only)

        Returns:
            Secret value or default
        """
        # Try cache first
        if self.config.cache_enabled:
            cached = self._cache.get(path)
            if cached:
                if key:
                    return cached.get(key, default)
                return cached

        # Try Vault
        if self._client and self._client.is_authenticated():
            try:
                response = self._client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=self.config.mount_point,
                    version=version,
                )
                data = response["data"]["data"]

                # Cache the result
                if self.config.cache_enabled:
                    self._cache.set(path, data)

                if key:
                    return data.get(key, default)
                return data

            except InvalidRequest:
                # Try KV v1
                try:
                    response = self._client.secrets.kv.v1.read_secret(
                        path=path,
                        mount_point=self.config.mount_point,
                    )
                    data = response["data"]

                    if self.config.cache_enabled:
                        self._cache.set(path, data)

                    if key:
                        return data.get(key, default)
                    return data

                except Exception:
                    pass

            except Forbidden:
                logger.warning(f"Permission denied for path: {path}")

            except Exception as e:
                logger.warning(f"Error reading secret {path}: {e}")

        # Fallback to environment variables
        env_key = self._path_to_env_var(path, key)
        env_value = os.getenv(env_key)
        if env_value is not None:
            return env_value

        # Check stored fallback
        fallback_key = f"{path}/{key}" if key else path
        if fallback_key in self._env_fallback:
            return self._env_fallback[fallback_key]

        return default

    def set_secret(
        self,
        path: str,
        data: Dict[str, Any],
        cas: Optional[int] = None,
    ) -> bool:
        """
        Store a secret in Vault.

        Args:
            path: Secret path
            data: Secret data as dictionary
            cas: Check-and-set version (for conditional updates)

        Returns:
            True if successful
        """
        if not self._client or not self._client.is_authenticated():
            logger.error("Not connected to Vault")
            return False

        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                cas=cas,
                mount_point=self.config.mount_point,
            )

            # Invalidate cache
            self._cache.invalidate(path)

            logger.debug(f"Secret stored at {path}")
            return True

        except Exception as e:
            logger.error(f"Error storing secret: {e}")
            return False

    def delete_secret(self, path: str) -> bool:
        """
        Delete a secret from Vault.

        Args:
            path: Secret path

        Returns:
            True if successful
        """
        if not self._client or not self._client.is_authenticated():
            return False

        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=self.config.mount_point,
            )
            self._cache.invalidate(path)
            return True

        except Exception as e:
            logger.error(f"Error deleting secret: {e}")
            return False

    def list_secrets(self, path: str = "") -> List[str]:
        """
        List secrets at a path.

        Args:
            path: Path prefix to list

        Returns:
            List of secret names
        """
        if not self._client or not self._client.is_authenticated():
            return []

        try:
            response = self._client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=self.config.mount_point,
            )
            return response["data"]["keys"]

        except Exception as e:
            logger.warning(f"Error listing secrets: {e}")
            return []

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key_name: str,
        context: Optional[bytes] = None,
    ) -> Optional[str]:
        """
        Encrypt data using Vault Transit engine.

        Args:
            plaintext: Data to encrypt
            key_name: Transit key name
            context: Optional context for derived keys

        Returns:
            Ciphertext or None if failed
        """
        if not self._client or not self._client.is_authenticated():
            return None

        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")

            encoded = base64.b64encode(plaintext).decode("utf-8")

            response = self._client.secrets.transit.encrypt_data(
                name=key_name,
                plaintext=encoded,
                context=base64.b64encode(context).decode("utf-8") if context else None,
            )

            return response["data"]["ciphertext"]

        except Exception as e:
            logger.error(f"Transit encryption error: {e}")
            return None

    def decrypt(
        self,
        ciphertext: str,
        key_name: str,
        context: Optional[bytes] = None,
    ) -> Optional[bytes]:
        """
        Decrypt data using Vault Transit engine.

        Args:
            ciphertext: Encrypted data (vault:v1:...)
            key_name: Transit key name
            context: Optional context for derived keys

        Returns:
            Decrypted data or None if failed
        """
        if not self._client or not self._client.is_authenticated():
            return None

        try:
            response = self._client.secrets.transit.decrypt_data(
                name=key_name,
                ciphertext=ciphertext,
                context=base64.b64encode(context).decode("utf-8") if context else None,
            )

            decoded = base64.b64decode(response["data"]["plaintext"])
            return decoded

        except Exception as e:
            logger.error(f"Transit decryption error: {e}")
            return None

    def generate_data_key(
        self,
        key_name: str,
        key_type: str = "aes256-gcm96",
        context: Optional[bytes] = None,
    ) -> Optional[Tuple[bytes, str]]:
        """
        Generate a data encryption key.

        Args:
            key_name: Transit key name
            key_type: Key type (aes256-gcm96, chacha20-poly1305, etc.)
            context: Optional context for derived keys

        Returns:
            Tuple of (plaintext_key, encrypted_key) or None
        """
        if not self._client or not self._client.is_authenticated():
            return None

        try:
            response = self._client.secrets.transit.generate_data_key(
                name=key_name,
                key_type="plaintext",
                context=base64.b64encode(context).decode("utf-8") if context else None,
            )

            plaintext_key = base64.b64decode(response["data"]["plaintext"])
            encrypted_key = response["data"]["ciphertext"]

            return (plaintext_key, encrypted_key)

        except Exception as e:
            logger.error(f"Data key generation error: {e}")
            return None

    def set_env_fallback(self, path: str, key: str, value: str) -> None:
        """
        Set a fallback value for when Vault is unavailable.

        Useful for development/testing without Vault.

        Args:
            path: Secret path
            key: Secret key
            value: Fallback value
        """
        fallback_key = f"{path}/{key}"
        self._env_fallback[fallback_key] = value

    def _path_to_env_var(self, path: str, key: Optional[str] = None) -> str:
        """Convert Vault path to environment variable name."""
        parts = path.replace("/", "_").upper()
        if key:
            return f"VAULT_{parts}_{key.upper()}"
        return f"VAULT_{parts}"


class SecretsManager:
    """
    High-level secrets manager with Vault integration.

    Provides a simple interface for common secret operations with
    automatic fallback to environment variables.
    """

    def __init__(self, vault_client: Optional[VaultClient] = None):
        """
        Initialize secrets manager.

        Args:
            vault_client: Vault client instance. If None, creates one.
        """
        self.vault = vault_client or VaultClient()
        self._connected = False

        # Try to connect if configured
        if self.vault.is_available:
            self._connected = self.vault.connect()

    def get_database_credentials(self) -> Dict[str, str]:
        """Get database connection credentials."""
        return {
            "host": self.get("database/config", "host", os.getenv("DB_HOST", "localhost")),
            "port": self.get("database/config", "port", os.getenv("DB_PORT", "5432")),
            "database": self.get("database/config", "database", os.getenv("DB_NAME", "vacp")),
            "username": self.get("database/credentials", "username", os.getenv("DB_USER", "vacp")),
            "password": self.get("database/credentials", "password", os.getenv("DB_PASSWORD", "")),
        }

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service."""
        return self.get(f"api_keys/{service}", "key")

    def get_encryption_key(self, key_name: str = "vacp-master") -> Optional[bytes]:
        """Get an encryption key."""
        key_b64 = self.get(f"encryption/{key_name}", "key")
        if key_b64:
            try:
                return base64.b64decode(key_b64)
            except Exception:
                return key_b64.encode("utf-8") if isinstance(key_b64, str) else key_b64
        return None

    def get_hedera_credentials(self) -> Dict[str, str]:
        """Get Hedera network credentials."""
        return {
            "operator_id": self.get("hedera/credentials", "operator_id", os.getenv("HEDERA_OPERATOR_ID", "")),
            "operator_key": self.get("hedera/credentials", "operator_key", os.getenv("HEDERA_OPERATOR_KEY", "")),
            "topic_id": self.get("hedera/config", "topic_id", os.getenv("HEDERA_TOPIC_ID", "")),
            "network": self.get("hedera/config", "network", os.getenv("HEDERA_NETWORK", "testnet")),
        }

    def get_ethereum_credentials(self) -> Dict[str, str]:
        """Get Ethereum network credentials."""
        return {
            "rpc_url": self.get("ethereum/config", "rpc_url", os.getenv("ETHEREUM_RPC_URL", "")),
            "private_key": self.get("ethereum/credentials", "private_key", os.getenv("ETHEREUM_PRIVATE_KEY", "")),
            "chain_id": self.get("ethereum/config", "chain_id", os.getenv("ETHEREUM_CHAIN_ID", "1")),
        }

    def get(
        self,
        path: str,
        key: Optional[str] = None,
        default: Any = None,
    ) -> Any:
        """
        Get a secret value.

        Args:
            path: Secret path
            key: Specific key within the secret
            default: Default value if not found

        Returns:
            Secret value or default
        """
        return self.vault.get_secret(path, key, default)

    def set(self, path: str, data: Dict[str, Any]) -> bool:
        """
        Store a secret.

        Args:
            path: Secret path
            data: Secret data

        Returns:
            True if successful
        """
        return self.vault.set_secret(path, data)

    def delete(self, path: str) -> bool:
        """
        Delete a secret.

        Args:
            path: Secret path

        Returns:
            True if successful
        """
        return self.vault.delete_secret(path)

    def rotate_secret(
        self,
        path: str,
        generate_new: Callable[[], Dict[str, Any]],
    ) -> bool:
        """
        Rotate a secret by generating a new value.

        Args:
            path: Secret path
            generate_new: Function that generates new secret data

        Returns:
            True if successful
        """
        try:
            new_data = generate_new()
            return self.set(path, new_data)
        except Exception as e:
            logger.error(f"Secret rotation failed: {e}")
            return False

    @property
    def is_vault_connected(self) -> bool:
        """Check if connected to Vault."""
        return self._connected and self.vault.is_authenticated


# Singleton instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """Get the global secrets manager instance."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


def get_secret(path: str, key: Optional[str] = None, default: Any = None) -> Any:
    """Convenience function to get a secret."""
    return get_secrets_manager().get(path, key, default)


def set_secret(path: str, data: Dict[str, Any]) -> bool:
    """Convenience function to store a secret."""
    return get_secrets_manager().set(path, data)
