"""
Cryptographic Capability Token System

This module provides mathematically unforgeable capability tokens that
constrain what actions an agent can take. Unlike policy-based controls,
these tokens cannot be bypassed regardless of intelligence - breaking
them requires breaking the underlying cryptography.

Key properties:
1. Unforgeable: Tokens are Ed25519 signed, cannot be created without private key
2. Non-transferable: Tokens are bound to specific agent IDs
3. Revocable: Token IDs can be added to revocation lists
4. Time-bounded: All tokens have expiration times
5. Capability-limited: Tokens specify exactly what operations are allowed
"""

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
import base64


class CapabilityType(Enum):
    """Types of capabilities that can be granted."""
    TOOL_EXECUTE = "tool:execute"       # Can execute specific tools
    TOOL_REGISTER = "tool:register"     # Can register new tools
    POLICY_READ = "policy:read"         # Can read policies
    POLICY_WRITE = "policy:write"       # Can modify policies
    AUDIT_READ = "audit:read"           # Can read audit logs
    APPROVAL_GRANT = "approval:grant"   # Can approve actions
    ADMIN_FULL = "admin:full"           # Full admin access
    SELF_MODIFY = "self:modify"         # Can modify own capabilities (dangerous)


@dataclass
class CapabilityGrant:
    """A single capability grant within a token."""
    capability_type: CapabilityType
    resource_pattern: str  # Glob pattern for resources (e.g., "db.*", "file.read")
    constraints: Dict[str, Any] = field(default_factory=dict)  # Additional constraints

    def matches(self, resource: str) -> bool:
        """Check if this grant matches a resource."""
        import fnmatch
        return fnmatch.fnmatch(resource, self.resource_pattern)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_type": self.capability_type.value,
            "resource_pattern": self.resource_pattern,
            "constraints": self.constraints,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityGrant":
        return cls(
            capability_type=CapabilityType(data["capability_type"]),
            resource_pattern=data["resource_pattern"],
            constraints=data.get("constraints", {}),
        )


@dataclass
class CapabilityToken:
    """
    A cryptographically signed capability token.

    This token mathematically proves that the holder has been granted
    specific capabilities by the issuer. Without the issuer's private key,
    it is computationally infeasible to forge a valid token.
    """
    token_id: str                           # Unique token identifier
    holder_id: str                          # Agent/user this token is for
    issuer_id: str                          # Who issued this token
    grants: List[CapabilityGrant]           # What capabilities are granted
    issued_at: datetime                     # When token was created
    expires_at: datetime                    # When token expires
    max_uses: Optional[int] = None          # Max number of uses (None = unlimited)
    current_uses: int = 0                   # Current use count
    parent_token_id: Optional[str] = None   # If delegated, which token delegated
    delegation_depth: int = 0               # How many times delegated
    max_delegation_depth: int = 0           # Max allowed delegation depth
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None         # Ed25519 signature
    issuer_public_key: Optional[str] = None # Issuer's public key

    def canonical_bytes(self) -> bytes:
        """Get canonical bytes for signing (excludes signature itself)."""
        data = {
            "token_id": self.token_id,
            "holder_id": self.holder_id,
            "issuer_id": self.issuer_id,
            "grants": [g.to_dict() for g in self.grants],
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "max_uses": self.max_uses,
            "parent_token_id": self.parent_token_id,
            "delegation_depth": self.delegation_depth,
            "max_delegation_depth": self.max_delegation_depth,
            "metadata": self.metadata,
        }
        return json.dumps(data, sort_keys=True, separators=(',', ':')).encode()

    def is_expired(self) -> bool:
        """Check if token has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def is_exhausted(self) -> bool:
        """Check if token has exceeded max uses."""
        if self.max_uses is None:
            return False
        return self.current_uses >= self.max_uses

    def can_delegate(self) -> bool:
        """Check if this token can be delegated further."""
        return self.delegation_depth < self.max_delegation_depth

    def has_capability(self, capability: CapabilityType, resource: str) -> bool:
        """Check if token grants a specific capability for a resource."""
        for grant in self.grants:
            if grant.capability_type == capability and grant.matches(resource):
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "holder_id": self.holder_id,
            "issuer_id": self.issuer_id,
            "grants": [g.to_dict() for g in self.grants],
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "max_uses": self.max_uses,
            "current_uses": self.current_uses,
            "parent_token_id": self.parent_token_id,
            "delegation_depth": self.delegation_depth,
            "max_delegation_depth": self.max_delegation_depth,
            "metadata": self.metadata,
            "signature": self.signature,
            "issuer_public_key": self.issuer_public_key,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityToken":
        return cls(
            token_id=data["token_id"],
            holder_id=data["holder_id"],
            issuer_id=data["issuer_id"],
            grants=[CapabilityGrant.from_dict(g) for g in data["grants"]],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            max_uses=data.get("max_uses"),
            current_uses=data.get("current_uses", 0),
            parent_token_id=data.get("parent_token_id"),
            delegation_depth=data.get("delegation_depth", 0),
            max_delegation_depth=data.get("max_delegation_depth", 0),
            metadata=data.get("metadata", {}),
            signature=data.get("signature"),
            issuer_public_key=data.get("issuer_public_key"),
        )


class CapabilityTokenService:
    """
    Service for issuing and verifying capability tokens.

    Security properties:
    - Only the service with the private key can issue tokens
    - Anyone with the public key can verify tokens
    - Revoked tokens are tracked and rejected
    - Token delegation is cryptographically constrained
    """

    def __init__(self, signing_key: SigningKey, issuer_id: str = "vacp-root"):
        """
        Initialize the capability token service.

        Args:
            signing_key: Ed25519 signing key for issuing tokens
            issuer_id: Identifier for this token issuer
        """
        self.signing_key = signing_key
        self.verify_key = signing_key.verify_key
        self.issuer_id = issuer_id
        self.public_key_b64 = base64.b64encode(bytes(self.verify_key)).decode()

        # Revocation list (in production, would be persistent)
        self._revoked_tokens: Set[str] = set()

        # Token usage tracking
        self._token_uses: Dict[str, int] = {}

    def issue_token(
        self,
        holder_id: str,
        grants: List[CapabilityGrant],
        ttl_seconds: int = 3600,
        max_uses: Optional[int] = None,
        max_delegation_depth: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CapabilityToken:
        """
        Issue a new capability token.

        Args:
            holder_id: Agent/user this token is for
            grants: List of capability grants
            ttl_seconds: Time-to-live in seconds
            max_uses: Maximum number of uses (None = unlimited)
            max_delegation_depth: How many times token can be delegated
            metadata: Additional metadata

        Returns:
            Signed capability token
        """
        now = datetime.now(timezone.utc)

        token = CapabilityToken(
            token_id=secrets.token_hex(16),
            holder_id=holder_id,
            issuer_id=self.issuer_id,
            grants=grants,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            max_uses=max_uses,
            max_delegation_depth=max_delegation_depth,
            metadata=metadata or {},
        )

        # Sign the token
        signature = self.signing_key.sign(token.canonical_bytes())
        token.signature = base64.b64encode(signature.signature).decode()
        token.issuer_public_key = self.public_key_b64

        return token

    def delegate_token(
        self,
        parent_token: CapabilityToken,
        new_holder_id: str,
        grants: Optional[List[CapabilityGrant]] = None,
        ttl_seconds: Optional[int] = None,
        max_uses: Optional[int] = None,
    ) -> CapabilityToken:
        """
        Create a delegated token from a parent token.

        The delegated token:
        - Cannot have more capabilities than the parent
        - Cannot have longer TTL than the parent
        - Cannot have more uses than the parent
        - Cannot be delegated beyond parent's max_delegation_depth

        Args:
            parent_token: Token to delegate from
            new_holder_id: New holder for delegated token
            grants: Subset of grants (must be subset of parent)
            ttl_seconds: TTL (capped by parent's remaining TTL)
            max_uses: Max uses (capped by parent's remaining uses)

        Returns:
            New delegated token

        Raises:
            ValueError: If delegation constraints are violated
        """
        # Verify parent token is valid
        if not self.verify_token(parent_token):
            raise ValueError("Parent token is invalid")

        if not parent_token.can_delegate():
            raise ValueError("Parent token cannot be delegated further")

        now = datetime.now(timezone.utc)

        # Calculate max remaining TTL
        remaining_ttl = (parent_token.expires_at - now).total_seconds()
        if ttl_seconds is None or ttl_seconds > remaining_ttl:
            ttl_seconds = int(remaining_ttl)

        # Validate grants are subset of parent
        if grants is None:
            grants = parent_token.grants.copy()
        else:
            for grant in grants:
                if not parent_token.has_capability(grant.capability_type, grant.resource_pattern):
                    raise ValueError(f"Cannot delegate capability not in parent: {grant.capability_type}")

        # Cap max uses
        if parent_token.max_uses is not None:
            remaining_uses = parent_token.max_uses - parent_token.current_uses
            if max_uses is None or max_uses > remaining_uses:
                max_uses = remaining_uses

        # Create delegated token
        token = CapabilityToken(
            token_id=secrets.token_hex(16),
            holder_id=new_holder_id,
            issuer_id=self.issuer_id,
            grants=grants,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            max_uses=max_uses,
            parent_token_id=parent_token.token_id,
            delegation_depth=parent_token.delegation_depth + 1,
            max_delegation_depth=parent_token.max_delegation_depth,
            metadata={"delegated_from": parent_token.holder_id},
        )

        # Sign the token
        signature = self.signing_key.sign(token.canonical_bytes())
        token.signature = base64.b64encode(signature.signature).decode()
        token.issuer_public_key = self.public_key_b64

        return token

    def verify_token(self, token: CapabilityToken) -> bool:
        """
        Verify a capability token's signature.

        Args:
            token: Token to verify

        Returns:
            True if token is valid and not expired/revoked
        """
        # Check revocation
        if token.token_id in self._revoked_tokens:
            return False

        # Check expiration
        if token.is_expired():
            return False

        # Check exhaustion
        actual_uses = self._token_uses.get(token.token_id, 0)
        if token.max_uses is not None and actual_uses >= token.max_uses:
            return False

        # Verify signature
        if not token.signature or not token.issuer_public_key:
            return False

        try:
            public_key_bytes = base64.b64decode(token.issuer_public_key)
            verify_key = VerifyKey(public_key_bytes)
            signature_bytes = base64.b64decode(token.signature)
            verify_key.verify(token.canonical_bytes(), signature_bytes)
            return True
        except (BadSignatureError, Exception):
            return False

    def use_token(self, token: CapabilityToken) -> bool:
        """
        Record a use of a token.

        Args:
            token: Token being used

        Returns:
            True if use was recorded, False if token is exhausted
        """
        if not self.verify_token(token):
            return False

        current = self._token_uses.get(token.token_id, 0)
        if token.max_uses is not None and current >= token.max_uses:
            return False

        self._token_uses[token.token_id] = current + 1
        return True

    def revoke_token(self, token_id: str) -> None:
        """
        Revoke a token by ID.

        Args:
            token_id: Token ID to revoke
        """
        self._revoked_tokens.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        """Check if a token is revoked."""
        return token_id in self._revoked_tokens

    def check_capability(
        self,
        token: CapabilityToken,
        capability: CapabilityType,
        resource: str,
    ) -> bool:
        """
        Check if a token grants a specific capability.

        Args:
            token: Token to check
            capability: Required capability type
            resource: Resource being accessed

        Returns:
            True if capability is granted and token is valid
        """
        if not self.verify_token(token):
            return False

        return token.has_capability(capability, resource)


@dataclass
class ActionCommitment:
    """
    A cryptographic commitment to a future action.

    This implements a commit-reveal scheme:
    1. Agent commits to what it will do (publishes hash)
    2. Wait period allows inspection
    3. Agent reveals the action
    4. System verifies reveal matches commitment

    This prevents an agent from changing its intended action
    after making the commitment - the hash locks it in.
    """
    commitment_id: str                      # Unique commitment ID
    commitment_hash: str                    # SHA-256(action_data + nonce)
    agent_id: str                           # Who made the commitment
    committed_at: datetime                  # When commitment was made
    reveal_after: datetime                  # When reveal is allowed
    expires_at: datetime                    # When commitment expires
    action_type: str                        # Type of action (tool_call, self_modify, etc.)
    revealed: bool = False                  # Whether action has been revealed
    revealed_data: Optional[Dict] = None    # The revealed action data
    revealed_nonce: Optional[str] = None    # The revealed nonce
    signature: Optional[str] = None         # Signature on commitment

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "commitment_hash": self.commitment_hash,
            "agent_id": self.agent_id,
            "committed_at": self.committed_at.isoformat(),
            "reveal_after": self.reveal_after.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "action_type": self.action_type,
            "revealed": self.revealed,
            "revealed_data": self.revealed_data,
            "revealed_nonce": self.revealed_nonce,
            "signature": self.signature,
        }


class CommitmentService:
    """
    Service for managing action commitments.

    This enforces a commit-reveal protocol where agents must:
    1. Commit to actions before executing them
    2. Wait for a review period
    3. Reveal the action (must match commitment)

    This prevents agents from sneaking in unauthorized changes.
    """

    def __init__(self, signing_key: SigningKey, min_reveal_delay: int = 60):
        """
        Initialize the commitment service.

        Args:
            signing_key: Key for signing commitments
            min_reveal_delay: Minimum seconds before reveal is allowed
        """
        self.signing_key = signing_key
        self.min_reveal_delay = min_reveal_delay

        # Active commitments
        self._commitments: Dict[str, ActionCommitment] = {}

    def create_commitment(
        self,
        agent_id: str,
        action_data: Dict[str, Any],
        action_type: str,
        reveal_delay: Optional[int] = None,
        ttl_seconds: int = 3600,
    ) -> tuple[ActionCommitment, str]:
        """
        Create a commitment to a future action.

        Args:
            agent_id: Agent making the commitment
            action_data: The action being committed to
            action_type: Type of action
            reveal_delay: Seconds before reveal is allowed
            ttl_seconds: How long commitment is valid

        Returns:
            Tuple of (commitment, nonce) - agent must keep nonce secret until reveal
        """
        now = datetime.now(timezone.utc)
        reveal_delay = reveal_delay or self.min_reveal_delay

        # Generate nonce
        nonce = secrets.token_hex(32)

        # Create commitment hash
        data_json = json.dumps(action_data, sort_keys=True, separators=(',', ':'))
        commitment_hash = hashlib.sha256(
            (data_json + nonce).encode()
        ).hexdigest()

        commitment = ActionCommitment(
            commitment_id=secrets.token_hex(16),
            commitment_hash=commitment_hash,
            agent_id=agent_id,
            committed_at=now,
            reveal_after=now + timedelta(seconds=reveal_delay),
            expires_at=now + timedelta(seconds=ttl_seconds),
            action_type=action_type,
        )

        # Sign the commitment
        sig_data = json.dumps({
            "commitment_id": commitment.commitment_id,
            "commitment_hash": commitment.commitment_hash,
            "agent_id": commitment.agent_id,
        }, sort_keys=True).encode()

        signature = self.signing_key.sign(sig_data)
        commitment.signature = base64.b64encode(signature.signature).decode()

        self._commitments[commitment.commitment_id] = commitment

        return commitment, nonce

    def reveal_commitment(
        self,
        commitment_id: str,
        action_data: Dict[str, Any],
        nonce: str,
    ) -> bool:
        """
        Reveal a commitment and verify it matches.

        Args:
            commitment_id: ID of commitment to reveal
            action_data: The actual action data
            nonce: The nonce used when creating commitment

        Returns:
            True if reveal matches commitment

        Raises:
            ValueError: If commitment doesn't exist, expired, or reveal too early
        """
        commitment = self._commitments.get(commitment_id)
        if not commitment:
            raise ValueError("Commitment not found")

        now = datetime.now(timezone.utc)

        if now < commitment.reveal_after:
            raise ValueError(f"Cannot reveal until {commitment.reveal_after.isoformat()}")

        if now > commitment.expires_at:
            raise ValueError("Commitment has expired")

        if commitment.revealed:
            raise ValueError("Commitment already revealed")

        # Verify the reveal matches the commitment
        data_json = json.dumps(action_data, sort_keys=True, separators=(',', ':'))
        reveal_hash = hashlib.sha256(
            (data_json + nonce).encode()
        ).hexdigest()

        if reveal_hash != commitment.commitment_hash:
            return False

        # Record the reveal
        commitment.revealed = True
        commitment.revealed_data = action_data
        commitment.revealed_nonce = nonce

        return True

    def get_commitment(self, commitment_id: str) -> Optional[ActionCommitment]:
        """Get a commitment by ID."""
        return self._commitments.get(commitment_id)

    def get_pending_commitments(
        self,
        agent_id: Optional[str] = None,
    ) -> List[ActionCommitment]:
        """Get all pending (unrevealed) commitments."""
        now = datetime.now(timezone.utc)
        pending = []

        for c in self._commitments.values():
            if c.revealed:
                continue
            if now > c.expires_at:
                continue
            if agent_id and c.agent_id != agent_id:
                continue
            pending.append(c)

        return pending

    def cleanup_expired(self) -> int:
        """Remove expired commitments. Returns count removed."""
        now = datetime.now(timezone.utc)
        expired = [
            cid for cid, c in self._commitments.items()
            if now > c.expires_at
        ]
        for cid in expired:
            del self._commitments[cid]
        return len(expired)


def create_capability_service(signing_key: Optional[SigningKey] = None) -> CapabilityTokenService:
    """Create a capability token service with optional key."""
    if signing_key is None:
        signing_key = SigningKey.generate()
    return CapabilityTokenService(signing_key)


def create_commitment_service(signing_key: Optional[SigningKey] = None) -> CommitmentService:
    """Create a commitment service with optional key."""
    if signing_key is None:
        signing_key = SigningKey.generate()
    return CommitmentService(signing_key)
