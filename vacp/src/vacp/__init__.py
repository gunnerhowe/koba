"""
Verifiable Agent Action Control Plane (VACP)

A cryptographically verifiable policy enforcement layer for tool-calling AI agents.
Provides runtime enforcement, Signed Action Receipts (SARs), and tamper-evident audit logs.

Core Components:
- Policy Engine: Deterministic policy evaluation
- Tool Gateway: Intercepts and mediates all tool calls
- Receipt Service: Issues cryptographically signed action receipts
- Merkle Log: Tamper-evident transparency log
- Sandbox: Isolated execution environment
- Tripwire: Anomaly detection over action sequences

"""

__version__ = "0.1.0"
__author__ = "VACP Team"

from vacp.core.receipts import SignedActionReceipt, ReceiptService
from vacp.core.policy import PolicyEngine, PolicyBundle, PolicyDecision
from vacp.core.gateway import ToolGateway
from vacp.core.merkle import MerkleLog
from vacp.core.registry import ToolRegistry

__all__ = [
    "SignedActionReceipt",
    "ReceiptService",
    "PolicyEngine",
    "PolicyBundle",
    "PolicyDecision",
    "ToolGateway",
    "MerkleLog",
    "ToolRegistry",
]
