"""
VACP CLI - Command Line Interface for VACP

Provides commands for:
- Server management
- Policy management
- Tool execution
- Audit log inspection
- Kill switch management
- Health checks
"""

from vacp.cli.main import cli

__all__ = ["cli"]
