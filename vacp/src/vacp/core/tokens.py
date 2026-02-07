"""
Token Minting Service for VACP

This module provides Just-In-Time (JIT) scoped credential minting:
- Short-lived tokens for tool operations
- Scoped permissions (least privilege)
- Automatic revocation
- Token introspection and validation

The key principle is: credentials are NEVER embedded in prompts.
Instead, the gateway mints short-lived, scoped tokens for each
tool invocation, which are automatically revoked after use.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from vacp.core.crypto import (
    KeyPair,
    generate_keypair,
    sign_message,
    encode_signature,
    generate_random_id,
)


class TokenType(Enum):
    """Types of tokens that can be minted."""
    BEARER = "bearer"           # Standard bearer token
    SCOPED = "scoped"           # Scoped to specific operations
    DELEGATED = "delegated"     # Delegated from another token
    SERVICE = "service"         # Service-to-service token
    EPHEMERAL = "ephemeral"     # Single-use token


class TokenStatus(Enum):
    """Status of a token."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    USED = "used"  # For single-use tokens


@dataclass
class TokenScope:
    """Scope of permissions for a token."""
    tools: List[str] = field(default_factory=list)  # Allowed tools (glob patterns)
    methods: List[str] = field(default_factory=list)  # Allowed methods
    resources: List[str] = field(default_factory=list)  # Allowed resources
    actions: List[str] = field(default_factory=list)  # Specific actions

    # Constraints
    max_calls: Optional[int] = None
    max_data_bytes: Optional[int] = None

    def allows_tool(self, tool_name: str) -> bool:
        """Check if tool is allowed."""
        if not self.tools:
            return True  # No restrictions
        import fnmatch
        return any(fnmatch.fnmatch(tool_name, pattern) for pattern in self.tools)

    def allows_resource(self, resource: str) -> bool:
        """Check if resource is allowed."""
        if not self.resources:
            return True
        import fnmatch
        return any(fnmatch.fnmatch(resource, pattern) for pattern in self.resources)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.tools:
            d["tools"] = self.tools
        if self.methods:
            d["methods"] = self.methods
        if self.resources:
            d["resources"] = self.resources
        if self.actions:
            d["actions"] = self.actions
        if self.max_calls:
            d["max_calls"] = self.max_calls
        if self.max_data_bytes:
            d["max_data_bytes"] = self.max_data_bytes
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenScope":
        return cls(
            tools=data.get("tools", []),
            methods=data.get("methods", []),
            resources=data.get("resources", []),
            actions=data.get("actions", []),
            max_calls=data.get("max_calls"),
            max_data_bytes=data.get("max_data_bytes"),
        )


@dataclass
class Token:
    """A scoped access token."""
    token_id: str
    token_type: TokenType
    tenant_id: str
    agent_id: str
    session_id: str

    # Timing
    issued_at: datetime
    expires_at: datetime
    not_before: Optional[datetime] = None

    # Scope
    scope: TokenScope = field(default_factory=TokenScope)

    # Metadata
    purpose: str = ""
    parent_token_id: Optional[str] = None  # For delegated tokens

    # Status tracking
    status: TokenStatus = TokenStatus.ACTIVE
    use_count: int = 0
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None

    # Cryptographic
    token_hash: Optional[str] = None  # Hash of token value (we don't store raw tokens)
    signature: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        """Check if token is currently valid."""
        if self.status != TokenStatus.ACTIVE:
            return False

        now = datetime.now(timezone.utc)

        if self.expires_at < now:
            return False

        if self.not_before and self.not_before > now:
            return False

        if self.scope.max_calls and self.use_count >= self.scope.max_calls:
            return False

        return True

    @property
    def time_remaining(self) -> timedelta:
        """Get remaining time until expiration."""
        now = datetime.now(timezone.utc)
        return max(timedelta(0), self.expires_at - now)

    def to_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        d = {
            "token_id": self.token_id,
            "token_type": self.token_type.value,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "scope": self.scope.to_dict(),
            "purpose": self.purpose,
            "status": self.status.value,
            "use_count": self.use_count,
        }
        if self.not_before:
            d["not_before"] = self.not_before.isoformat()
        if self.parent_token_id:
            d["parent_token_id"] = self.parent_token_id
        if self.last_used_at:
            d["last_used_at"] = self.last_used_at.isoformat()
        if self.revoked_at:
            d["revoked_at"] = self.revoked_at.isoformat()
            d["revocation_reason"] = self.revocation_reason
        if self.signature:
            d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Token":
        return cls(
            token_id=data["token_id"],
            token_type=TokenType(data["token_type"]),
            tenant_id=data["tenant_id"],
            agent_id=data["agent_id"],
            session_id=data["session_id"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            not_before=datetime.fromisoformat(data["not_before"]) if data.get("not_before") else None,
            scope=TokenScope.from_dict(data.get("scope", {})),
            purpose=data.get("purpose", ""),
            parent_token_id=data.get("parent_token_id"),
            status=TokenStatus(data.get("status", "active")),
            use_count=data.get("use_count", 0),
            last_used_at=datetime.fromisoformat(data["last_used_at"]) if data.get("last_used_at") else None,
            revoked_at=datetime.fromisoformat(data["revoked_at"]) if data.get("revoked_at") else None,
            revocation_reason=data.get("revocation_reason"),
            token_hash=data.get("token_hash"),
            signature=data.get("signature"),
        )


@dataclass
class TokenMintRequest:
    """Request to mint a new token."""
    tenant_id: str
    agent_id: str
    session_id: str
    scope: TokenScope
    purpose: str
    token_type: TokenType = TokenType.SCOPED
    ttl_seconds: int = 300  # 5 minutes default
    max_uses: Optional[int] = None
    parent_token_value: Optional[str] = None  # For delegation


class TokenService:
    """
    Service for minting and managing scoped tokens.

    Key principles:
    - Tokens are short-lived (minutes, not hours)
    - Tokens are scoped to specific operations
    - Token values are never logged (only hashes)
    - Tokens can be revoked at any time
    """

    def __init__(
        self,
        keypair: Optional[KeyPair] = None,
        default_ttl_seconds: int = 300,
    ):
        """
        Initialize the token service.

        Args:
            keypair: Keypair for signing tokens
            default_ttl_seconds: Default token TTL
        """
        self.keypair = keypair or generate_keypair()
        self.default_ttl_seconds = default_ttl_seconds

        # Token storage (in production, use secure storage)
        self._tokens: Dict[str, Token] = {}
        self._token_hashes: Dict[str, str] = {}  # hash -> token_id

        # Statistics
        self._stats = {
            "tokens_minted": 0,
            "tokens_validated": 0,
            "tokens_revoked": 0,
            "tokens_expired": 0,
            "validation_failures": 0,
        }

    def mint(
        self,
        request: TokenMintRequest,
    ) -> tuple[Token, str]:
        """
        Mint a new token.

        Args:
            request: Token mint request

        Returns:
            Tuple of (Token metadata, token value string)
        """
        now = datetime.now(timezone.utc)

        # Validate delegation if parent token provided
        if request.parent_token_value:
            parent_valid, parent_token = self.validate(request.parent_token_value)
            if not parent_valid or not parent_token:
                raise ValueError("Invalid parent token for delegation")
            # Delegated scope cannot exceed parent scope
            # (simplified - in production would do proper scope intersection)
            request.scope.tools = request.scope.tools or parent_token.scope.tools

        # Generate token ID and value
        token_id = generate_random_id("tok")
        token_value = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token_value)

        # Create token
        token = Token(
            token_id=token_id,
            token_type=request.token_type,
            tenant_id=request.tenant_id,
            agent_id=request.agent_id,
            session_id=request.session_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=request.ttl_seconds),
            scope=request.scope,
            purpose=request.purpose,
            parent_token_id=self._token_hashes.get(self._hash_token(request.parent_token_value)) if request.parent_token_value else None,
            token_hash=token_hash,
        )

        # Set max uses if specified
        if request.max_uses:
            token.scope.max_calls = request.max_uses

        # Sign the token
        token.signature = self._sign_token(token)

        # Store
        self._tokens[token_id] = token
        self._token_hashes[token_hash] = token_id

        self._stats["tokens_minted"] += 1

        # Return full token string
        full_token = f"{token_id}.{token_value}"
        return token, full_token

    def validate(
        self,
        token_value: str,
        tool_name: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> tuple[bool, Optional[Token]]:
        """
        Validate a token.

        Args:
            token_value: The full token string
            tool_name: Optional tool to check against scope
            resource: Optional resource to check against scope

        Returns:
            Tuple of (is_valid, Token if valid)
        """
        self._stats["tokens_validated"] += 1

        # Parse token
        parts = token_value.split(".", 1)
        if len(parts) != 2:
            self._stats["validation_failures"] += 1
            return False, None

        token_id, secret = parts

        # Look up token
        token = self._tokens.get(token_id)
        if not token:
            self._stats["validation_failures"] += 1
            return False, None

        # Verify hash (constant-time comparison to prevent timing attacks)
        import hmac as _hmac
        expected_hash = self._hash_token(secret)
        if not _hmac.compare_digest(token.token_hash, expected_hash):
            self._stats["validation_failures"] += 1
            return False, None

        # Check validity
        if not token.is_valid:
            if token.status == TokenStatus.ACTIVE:
                # Must have expired
                token.status = TokenStatus.EXPIRED
                self._stats["tokens_expired"] += 1
            self._stats["validation_failures"] += 1
            return False, token

        # Check scope
        if tool_name and not token.scope.allows_tool(tool_name):
            self._stats["validation_failures"] += 1
            return False, token

        if resource and not token.scope.allows_resource(resource):
            self._stats["validation_failures"] += 1
            return False, token

        # Update usage
        token.use_count += 1
        token.last_used_at = datetime.now(timezone.utc)

        # Check if single-use and now used up
        if token.token_type == TokenType.EPHEMERAL:
            token.status = TokenStatus.USED

        return True, token

    def revoke(
        self,
        token_id: str,
        reason: str = "Manually revoked",
    ) -> bool:
        """
        Revoke a token.

        Args:
            token_id: ID of token to revoke
            reason: Reason for revocation

        Returns:
            True if token was revoked
        """
        token = self._tokens.get(token_id)
        if not token:
            return False

        if token.status != TokenStatus.ACTIVE:
            return False

        token.status = TokenStatus.REVOKED
        token.revoked_at = datetime.now(timezone.utc)
        token.revocation_reason = reason

        self._stats["tokens_revoked"] += 1
        return True

    def revoke_by_session(
        self,
        session_id: str,
        reason: str = "Session terminated",
    ) -> int:
        """
        Revoke all tokens for a session.

        Args:
            session_id: Session ID
            reason: Revocation reason

        Returns:
            Number of tokens revoked
        """
        count = 0
        for token in self._tokens.values():
            if token.session_id == session_id and token.status == TokenStatus.ACTIVE:
                self.revoke(token.token_id, reason)
                count += 1
        return count

    def revoke_by_agent(
        self,
        agent_id: str,
        reason: str = "Agent terminated",
    ) -> int:
        """Revoke all tokens for an agent."""
        count = 0
        for token in self._tokens.values():
            if token.agent_id == agent_id and token.status == TokenStatus.ACTIVE:
                self.revoke(token.token_id, reason)
                count += 1
        return count

    def cleanup_expired(self) -> int:
        """
        Clean up expired tokens.

        Returns:
            Number of tokens cleaned up
        """
        now = datetime.now(timezone.utc)
        expired = []

        for token_id, token in self._tokens.items():
            if token.status == TokenStatus.ACTIVE and token.expires_at < now:
                token.status = TokenStatus.EXPIRED
                self._stats["tokens_expired"] += 1
                expired.append(token_id)

        return len(expired)

    def get_active_tokens(
        self,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[Token]:
        """Get list of active tokens, optionally filtered."""
        tokens = []
        for token in self._tokens.values():
            if token.status != TokenStatus.ACTIVE:
                continue
            if tenant_id and token.tenant_id != tenant_id:
                continue
            if agent_id and token.agent_id != agent_id:
                continue
            if session_id and token.session_id != session_id:
                continue
            tokens.append(token)
        return tokens

    def get_token_info(self, token_id: str) -> Optional[Token]:
        """Get token metadata (not the secret value)."""
        return self._tokens.get(token_id)

    def introspect(self, token_value: str) -> Dict[str, Any]:
        """
        Introspect a token.

        Returns token metadata without validating for use.
        """
        parts = token_value.split(".", 1)
        if len(parts) != 2:
            return {"active": False, "error": "Invalid token format"}

        token_id, secret = parts
        token = self._tokens.get(token_id)

        if not token:
            return {"active": False, "error": "Token not found"}

        # Verify hash
        expected_hash = self._hash_token(secret)
        if token.token_hash != expected_hash:
            return {"active": False, "error": "Invalid token"}

        return {
            "active": token.is_valid,
            "token_id": token.token_id,
            "token_type": token.token_type.value,
            "tenant_id": token.tenant_id,
            "agent_id": token.agent_id,
            "session_id": token.session_id,
            "scope": token.scope.to_dict(),
            "issued_at": token.issued_at.isoformat(),
            "expires_at": token.expires_at.isoformat(),
            "time_remaining_seconds": token.time_remaining.total_seconds(),
            "use_count": token.use_count,
            "status": token.status.value,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get token service statistics."""
        active_count = sum(1 for t in self._tokens.values() if t.status == TokenStatus.ACTIVE)
        return {
            **self._stats,
            "active_tokens": active_count,
            "total_tokens": len(self._tokens),
        }

    def _hash_token(self, token_value: str) -> str:
        """Hash a token value."""
        return hashlib.sha256(token_value.encode()).hexdigest()

    def _sign_token(self, token: Token) -> str:
        """Sign a token."""
        data = json.dumps({
            "token_id": token.token_id,
            "tenant_id": token.tenant_id,
            "agent_id": token.agent_id,
            "scope": token.scope.to_dict(),
            "expires_at": token.expires_at.isoformat(),
        }, sort_keys=True).encode()

        signature_bytes = sign_message(data, self.keypair.private_key_bytes)
        return encode_signature(signature_bytes)


# Convenience functions

def mint_tool_token(
    service: TokenService,
    tenant_id: str,
    agent_id: str,
    session_id: str,
    tool_name: str,
    ttl_seconds: int = 60,
) -> tuple[Token, str]:
    """Mint a token scoped to a single tool."""
    request = TokenMintRequest(
        tenant_id=tenant_id,
        agent_id=agent_id,
        session_id=session_id,
        scope=TokenScope(tools=[tool_name], max_calls=1),
        purpose=f"Single use for {tool_name}",
        token_type=TokenType.EPHEMERAL,
        ttl_seconds=ttl_seconds,
        max_uses=1,
    )
    return service.mint(request)


def mint_session_token(
    service: TokenService,
    tenant_id: str,
    agent_id: str,
    session_id: str,
    allowed_tools: List[str],
    ttl_seconds: int = 3600,
) -> tuple[Token, str]:
    """Mint a session token with multiple tool access."""
    request = TokenMintRequest(
        tenant_id=tenant_id,
        agent_id=agent_id,
        session_id=session_id,
        scope=TokenScope(tools=allowed_tools),
        purpose="Session access token",
        token_type=TokenType.SCOPED,
        ttl_seconds=ttl_seconds,
    )
    return service.mint(request)
