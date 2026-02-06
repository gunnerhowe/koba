"""
VACP Testing Module

Provides tools for testing security properties:
- Attack harness for prompt injection testing
- Tool misuse simulation
- Policy bypass attempts
- Fuzzing utilities
"""

from vacp.testing.harness import AttackHarness, AttackResult, AttackCategory
from vacp.testing.vectors import INJECTION_VECTORS, ESCALATION_VECTORS

__all__ = [
    "AttackHarness",
    "AttackResult",
    "AttackCategory",
    "INJECTION_VECTORS",
    "ESCALATION_VECTORS",
]
