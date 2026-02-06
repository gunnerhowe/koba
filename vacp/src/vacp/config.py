"""
VACP Configuration

Environment-based configuration for production deployment.
"""

import os
import sys
import secrets
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""
    pass


@dataclass
class VACPConfig:
    """Configuration for VACP server."""

    # Database
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./vacp.db"))
    db_path: Optional[Path] = None

    # Server
    host: str = field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "8000")))

    # Security
    jwt_secret: str = field(default_factory=lambda: os.getenv("JWT_SECRET", ""))
    jwt_expiry_hours: int = field(default_factory=lambda: int(os.getenv("JWT_EXPIRY_HOURS", "1")))

    # CORS
    cors_origins: List[str] = field(default_factory=list)

    # Feature flags
    demo_mode: bool = field(default_factory=lambda: os.getenv("DEMO_MODE", "false").lower() == "true")
    create_demo_data: bool = field(default_factory=lambda: os.getenv("CREATE_DEMO_DATA", "false").lower() == "true")

    # Validation
    _validated: bool = field(default=False, repr=False)

    def __post_init__(self):
        # Parse CORS origins from env
        cors_env = os.getenv("CORS_ORIGINS", "http://localhost:3000")
        self.cors_origins = [origin.strip() for origin in cors_env.split(",")]

        # Set up database path
        if self.database_url.startswith("sqlite"):
            db_file = self.database_url.replace("sqlite:///", "")
            if db_file != ":memory:":
                self.db_path = Path(db_file)
                self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Handle JWT secret
        if not self.jwt_secret:
            if is_production():
                raise ConfigurationError(
                    "JWT_SECRET environment variable is required in production.\n"
                    "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            else:
                # Auto-generate for development (warn user)
                self.jwt_secret = secrets.token_hex(32)
                logger.warning(
                    "JWT_SECRET not set - using auto-generated secret. "
                    "This is fine for development but MUST be set in production."
                )
        elif len(self.jwt_secret) < 32:
            if is_production():
                raise ConfigurationError(
                    "JWT_SECRET must be at least 32 characters for security.\n"
                    "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            else:
                logger.warning("JWT_SECRET is too short (< 32 chars). Use a longer secret in production.")

    def validate(self) -> List[str]:
        """Validate configuration and return list of warnings."""
        warnings = []

        # Check database URL
        if "sqlite" in self.database_url and is_production():
            warnings.append("Using SQLite in production is not recommended. Use PostgreSQL.")

        # Check CORS
        if "*" in self.cors_origins and is_production():
            warnings.append("CORS allows all origins (*). Restrict this in production.")

        # Check demo mode - BLOCK in production unless explicitly allowed
        if self.demo_mode and is_production():
            if os.getenv("ALLOW_DEMO_IN_PRODUCTION", "").lower() == "true":
                warnings.append("Demo mode is enabled in production. This is a security risk.")
            else:
                raise ConfigurationError(
                    "Demo mode cannot be enabled in production. "
                    "Set DEMO_MODE=false or set ALLOW_DEMO_IN_PRODUCTION=true to override."
                )

        self._validated = True
        return warnings


_config_instance: Optional[VACPConfig] = None


def get_config() -> VACPConfig:
    """Get the current configuration (cached singleton)."""
    global _config_instance
    if _config_instance is None:
        _config_instance = VACPConfig()
    return _config_instance


# Production environment detection
def is_production() -> bool:
    return os.getenv("ENVIRONMENT", "development") == "production"


def is_railway() -> bool:
    return os.getenv("RAILWAY_ENVIRONMENT") is not None


def is_render() -> bool:
    return os.getenv("RENDER") is not None
