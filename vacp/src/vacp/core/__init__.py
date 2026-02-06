"""
VACP Core Components

This module contains the foundational components of the Verifiable Agent Action Control Plane.
"""

from vacp.core.crypto import (
    generate_keypair,
    sign_message,
    verify_signature,
    hash_data,
    hash_json,
)
from vacp.core.receipts import SignedActionReceipt, ReceiptService
from vacp.core.policy import PolicyEngine, PolicyBundle, PolicyDecision
from vacp.core.gateway import ToolGateway
from vacp.core.merkle import MerkleLog
from vacp.core.registry import ToolRegistry, ToolDefinition
from vacp.core.kill_switch import (
    EnhancedKillSwitch,
    KillSwitchState,
    ActivationChannel,
    DeadManConfig,
    FailsafeConfig,
    SystemShutdownError,
    DistributedKillSwitch,
)

__all__ = [
    # Crypto
    "generate_keypair",
    "sign_message",
    "verify_signature",
    "hash_data",
    "hash_json",
    # Receipts
    "SignedActionReceipt",
    "ReceiptService",
    # Policy
    "PolicyEngine",
    "PolicyBundle",
    "PolicyDecision",
    # Gateway
    "ToolGateway",
    # Merkle
    "MerkleLog",
    # Registry
    "ToolRegistry",
    "ToolDefinition",
    # Kill Switch
    "EnhancedKillSwitch",
    "KillSwitchState",
    "ActivationChannel",
    "DeadManConfig",
    "FailsafeConfig",
    "SystemShutdownError",
    "DistributedKillSwitch",
]
