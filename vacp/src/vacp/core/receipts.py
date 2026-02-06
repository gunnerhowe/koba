"""
Signed Action Receipt (SAR) System

This module implements the core cryptographic evidence layer:
- SignedActionReceipt: The immutable record of a tool action
- ReceiptService: Issues and verifies receipts

A Signed Action Receipt provides cryptographic proof that:
1. A specific tool call was requested
2. A specific policy version was applied
3. The policy decision was allow/deny
4. The action executed in a specific sandbox (optional)
5. The receipt was issued at a specific time
6. The receipt is part of a tamper-evident log

Receipts are signed using Ed25519 and include Merkle log roots
for integration with the transparency log.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any, Dict, List
from enum import Enum

from vacp.core.crypto import (
    KeyPair,
    generate_keypair,
    sign_message,
    verify_signature,
    hash_data,
    hash_json,
    canonicalize_json,
    generate_random_id,
    encode_signature,
    decode_signature,
    encode_public_key,
    decode_public_key,
)
from vacp.core.policy import PolicyDecision


@dataclass
class ToolInfo:
    """Information about the tool being invoked."""
    name: str
    request_hash: str
    id: Optional[str] = None  # Tool ID
    response_hash: Optional[str] = None
    request_summary: Optional[str] = None  # Redacted/summarized request for audit

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "name": self.name,
            "req_hash": self.request_hash,
        }
        if self.id:
            d["id"] = self.id
        if self.response_hash:
            d["res_hash"] = self.response_hash
        if self.request_summary:
            d["summary"] = self.request_summary
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolInfo":
        return cls(
            name=data["name"],
            request_hash=data["req_hash"],
            id=data.get("id"),
            response_hash=data.get("res_hash"),
            request_summary=data.get("summary"),
        )


@dataclass
class PolicyInfo:
    """Information about the policy applied."""
    bundle_id: str
    policy_hash: str
    decision: PolicyDecision
    rules_matched: List[str] = field(default_factory=list)
    conditions: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "bundle_id": self.bundle_id,
            "hash": self.policy_hash,
            "decision": self.decision.value,
        }
        if self.rules_matched:
            d["rules"] = self.rules_matched
        if self.conditions:
            d["conditions"] = self.conditions
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyInfo":
        return cls(
            bundle_id=data["bundle_id"],
            policy_hash=data["hash"],
            decision=PolicyDecision(data["decision"]),
            rules_matched=data.get("rules", []),
            conditions=data.get("conditions"),
        )


@dataclass
class SandboxInfo:
    """Information about the sandbox execution environment."""
    environment_id: str
    attestation_hash: str
    transcript_hash: Optional[str] = None
    egress_allowed: bool = False
    filesystem_isolated: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "env_id": self.environment_id,
            "attestation": self.attestation_hash,
            "egress": self.egress_allowed,
            "fs_isolated": self.filesystem_isolated,
        }
        if self.transcript_hash:
            d["transcript_hash"] = self.transcript_hash
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SandboxInfo":
        return cls(
            environment_id=data["env_id"],
            attestation_hash=data["attestation"],
            transcript_hash=data.get("transcript_hash"),
            egress_allowed=data.get("egress", False),
            filesystem_isolated=data.get("fs_isolated", True),
        )


@dataclass
class LogInfo:
    """Information about the Merkle log state at receipt issuance."""
    merkle_root: str
    log_index: int
    previous_receipt_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "merkle_root": self.merkle_root,
            "index": self.log_index,
        }
        if self.previous_receipt_hash:
            d["prev_hash"] = self.previous_receipt_hash
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogInfo":
        return cls(
            merkle_root=data["merkle_root"],
            log_index=data["index"],
            previous_receipt_hash=data.get("prev_hash"),
        )


@dataclass
class ConstraintsApplied:
    """Constraints that were applied to the action."""
    budget_remaining: Optional[Dict[str, float]] = None
    redactions_applied: List[str] = field(default_factory=list)
    rate_limit_remaining: Optional[int] = None
    approval_required: bool = False
    approver_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.budget_remaining:
            d["budget"] = self.budget_remaining
        if self.redactions_applied:
            d["redactions"] = self.redactions_applied
        if self.rate_limit_remaining is not None:
            d["rate_limit"] = self.rate_limit_remaining
        if self.approval_required:
            d["approval_required"] = True
            if self.approver_id:
                d["approver"] = self.approver_id
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConstraintsApplied":
        return cls(
            budget_remaining=data.get("budget"),
            redactions_applied=data.get("redactions", []),
            rate_limit_remaining=data.get("rate_limit"),
            approval_required=data.get("approval_required", False),
            approver_id=data.get("approver"),
        )


@dataclass
class SignedActionReceipt:
    """
    A cryptographically signed record of an agent tool action.

    This receipt provides verifiable proof that:
    1. A specific tool call was made
    2. A specific policy was evaluated
    3. The decision was made at a specific time
    4. The receipt is part of an append-only log

    The receipt is signed by the control plane's private key.
    """
    receipt_id: str
    timestamp: datetime
    agent_id: str
    tenant_id: str
    session_id: str
    tool: ToolInfo
    policy: PolicyInfo
    log: LogInfo
    sandbox: Optional[SandboxInfo] = None
    constraints: Optional[ConstraintsApplied] = None
    signature: Optional[str] = None
    issuer_public_key: Optional[str] = None

    def to_dict(self, include_signature: bool = True) -> Dict[str, Any]:
        """Convert receipt to dictionary representation."""
        d = {
            "receipt_id": self.receipt_id,
            "ts": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "tool": self.tool.to_dict(),
            "policy": self.policy.to_dict(),
            "log": self.log.to_dict(),
        }
        if self.sandbox:
            d["sandbox"] = self.sandbox.to_dict()
        if self.constraints:
            d["constraints"] = self.constraints.to_dict()
        if include_signature and self.signature:
            d["sig"] = self.signature
            if self.issuer_public_key:
                d["issuer"] = self.issuer_public_key
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedActionReceipt":
        """Reconstruct receipt from dictionary."""
        return cls(
            receipt_id=data["receipt_id"],
            timestamp=datetime.fromisoformat(data["ts"]),
            agent_id=data["agent_id"],
            tenant_id=data["tenant_id"],
            session_id=data["session_id"],
            tool=ToolInfo.from_dict(data["tool"]),
            policy=PolicyInfo.from_dict(data["policy"]),
            log=LogInfo.from_dict(data["log"]),
            sandbox=SandboxInfo.from_dict(data["sandbox"]) if "sandbox" in data else None,
            constraints=ConstraintsApplied.from_dict(data["constraints"]) if "constraints" in data else None,
            signature=data.get("sig"),
            issuer_public_key=data.get("issuer"),
        )

    def canonical_bytes(self) -> bytes:
        """Get canonical byte representation for signing/hashing."""
        return canonicalize_json(self.to_dict(include_signature=False)).encode("utf-8")

    def compute_hash(self) -> str:
        """Compute the hash of this receipt (excluding signature)."""
        return hash_data(self.canonical_bytes())

    def to_json(self, indent: int = 2) -> str:
        """Serialize receipt to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> "SignedActionReceipt":
        """Deserialize receipt from JSON string."""
        return cls.from_dict(json.loads(json_str))


class ReceiptService:
    """
    Service for issuing and verifying Signed Action Receipts.

    The ReceiptService:
    1. Maintains the signing keypair for the control plane
    2. Issues receipts with cryptographic signatures
    3. Verifies receipt signatures
    4. Integrates with the Merkle log for tamper evidence
    """

    def __init__(
        self,
        keypair: Optional[KeyPair] = None,
        issuer_id: Optional[str] = None,
    ):
        """
        Initialize the receipt service.

        Args:
            keypair: Ed25519 keypair for signing. If None, generates new keypair.
            issuer_id: Identifier for this issuer (used in receipts)
        """
        self.keypair = keypair or generate_keypair()
        self.issuer_id = issuer_id or f"vacp-issuer-{generate_random_id(length=8)}"
        self._receipt_counter = 0

    @property
    def public_key(self) -> str:
        """Get the issuer's public key in encoded form."""
        return encode_public_key(self.keypair.public_key_bytes)

    def issue_receipt(
        self,
        agent_id: str,
        tenant_id: str,
        session_id: str,
        tool: ToolInfo,
        policy: PolicyInfo,
        merkle_root: str,
        log_index: int,
        previous_receipt_hash: Optional[str] = None,
        sandbox: Optional[SandboxInfo] = None,
        constraints: Optional[ConstraintsApplied] = None,
    ) -> SignedActionReceipt:
        """
        Issue a new Signed Action Receipt.

        Args:
            agent_id: Cryptographic identity of the agent
            tenant_id: Tenant/organization identifier
            session_id: Session identifier
            tool: Information about the tool call
            policy: Information about the policy applied
            merkle_root: Current Merkle log root
            log_index: Current log index
            previous_receipt_hash: Hash of previous receipt in chain
            sandbox: Optional sandbox execution info
            constraints: Optional constraints applied

        Returns:
            A signed action receipt
        """
        self._receipt_counter += 1

        # Create log info
        log = LogInfo(
            merkle_root=merkle_root,
            log_index=log_index,
            previous_receipt_hash=previous_receipt_hash,
        )

        # Generate receipt ID from content hash
        timestamp = datetime.now(timezone.utc)

        # Create preliminary receipt to hash
        prelim_receipt = SignedActionReceipt(
            receipt_id="pending",
            timestamp=timestamp,
            agent_id=agent_id,
            tenant_id=tenant_id,
            session_id=session_id,
            tool=tool,
            policy=policy,
            log=log,
            sandbox=sandbox,
            constraints=constraints,
        )

        # Generate receipt ID from content
        content_hash = hash_json({
            "ts": timestamp.isoformat(),
            "agent": agent_id,
            "session": session_id,
            "tool": tool.to_dict(),
            "counter": self._receipt_counter,
        })
        receipt_id = content_hash

        # Create final receipt
        receipt = SignedActionReceipt(
            receipt_id=receipt_id,
            timestamp=timestamp,
            agent_id=agent_id,
            tenant_id=tenant_id,
            session_id=session_id,
            tool=tool,
            policy=policy,
            log=log,
            sandbox=sandbox,
            constraints=constraints,
        )

        # Sign the receipt
        signature_bytes = sign_message(
            receipt.canonical_bytes(),
            self.keypair.private_key_bytes,
        )
        receipt.signature = encode_signature(signature_bytes)
        receipt.issuer_public_key = self.public_key

        return receipt

    def verify_receipt(self, receipt: SignedActionReceipt) -> bool:
        """
        Verify a receipt's signature.

        Args:
            receipt: The receipt to verify

        Returns:
            True if signature is valid, False otherwise
        """
        if not receipt.signature or not receipt.issuer_public_key:
            return False

        try:
            signature_bytes = decode_signature(receipt.signature)
            public_key_bytes = decode_public_key(receipt.issuer_public_key)
            return verify_signature(
                receipt.canonical_bytes(),
                signature_bytes,
                public_key_bytes,
            )
        except Exception:
            return False

    def verify_receipt_chain(
        self,
        receipts: List[SignedActionReceipt],
    ) -> tuple[bool, Optional[str]]:
        """
        Verify a chain of receipts for integrity.

        Checks:
        1. Each receipt has a valid signature
        2. Each receipt references the previous receipt's hash
        3. Log indices are sequential

        Args:
            receipts: List of receipts in chronological order

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not receipts:
            return True, None

        prev_hash = None
        prev_index = -1

        for i, receipt in enumerate(receipts):
            # Verify signature
            if not self.verify_receipt(receipt):
                return False, f"Invalid signature on receipt {i}: {receipt.receipt_id}"

            # Verify chain link
            if prev_hash and receipt.log.previous_receipt_hash != prev_hash:
                return False, f"Chain break at receipt {i}: expected prev_hash {prev_hash}"

            # Verify index sequence
            if receipt.log.log_index <= prev_index:
                return False, f"Invalid log index at receipt {i}: {receipt.log.log_index} <= {prev_index}"

            prev_hash = receipt.compute_hash()
            prev_index = receipt.log.log_index

        return True, None


def create_tool_info(
    tool_name: str,
    request: Any,
    response: Optional[Any] = None,
    summarize_request: bool = False,
    tool_id: Optional[str] = None,
) -> ToolInfo:
    """
    Helper to create ToolInfo from actual request/response objects.

    Args:
        tool_name: Name of the tool
        request: The request object (will be hashed)
        response: Optional response object (will be hashed)
        summarize_request: Whether to include a summary of the request
        tool_id: Optional tool ID

    Returns:
        ToolInfo object
    """
    request_hash = hash_json(request) if not isinstance(request, str) else hash_data(request.encode())
    response_hash = None
    if response is not None:
        response_hash = hash_json(response) if not isinstance(response, str) else hash_data(response.encode())

    summary: Optional[str] = None
    if summarize_request:
        # Create a safe summary (e.g., for audit purposes)
        if isinstance(request, dict):
            # Only include non-sensitive keys
            safe_keys = ["action", "method", "resource", "type"]
            safe_dict = {k: v for k, v in request.items() if k in safe_keys}
            summary = json.dumps(safe_dict)
        else:
            summary = f"[{tool_name} call]"

    return ToolInfo(
        name=tool_name,
        request_hash=request_hash,
        id=tool_id or tool_name,  # Use tool_id if provided, otherwise use name
        response_hash=response_hash,
        request_summary=summary,
    )
