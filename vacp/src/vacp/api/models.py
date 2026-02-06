"""
API Models for VACP

Pydantic models for request/response validation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from enum import Enum


# Use dataclasses for simplicity (can upgrade to Pydantic if installed)
from dataclasses import dataclass, field, asdict


class DecisionType(str, Enum):
    """Policy decision types."""
    ALLOW = "allow"
    DENY = "deny"
    ALLOW_WITH_CONDITIONS = "allow_with_conditions"
    PENDING_APPROVAL = "pending_approval"


@dataclass
class ToolCallRequest:
    """Request to execute a tool."""
    tool_id: str
    parameters: Dict[str, Any]
    agent_id: str
    tenant_id: str
    session_id: str
    method: Optional[str] = None
    resource: Optional[str] = None
    trust_level: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReceiptInfo:
    """Receipt information in response."""
    receipt_id: str
    timestamp: str
    tool_hash: str
    policy_hash: str
    decision: str
    log_index: int
    merkle_root: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolCallResponse:
    """Response from tool execution."""
    request_id: str
    tool_id: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    receipt: Optional[ReceiptInfo] = None
    execution_time_ms: float = 0.0
    policy_decision: Optional[str] = None
    approval_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.receipt:
            d["receipt"] = self.receipt.to_dict()
        return d


@dataclass
class ReceiptResponse:
    """Full receipt response."""
    receipt_id: str
    timestamp: str
    agent_id: str
    tenant_id: str
    session_id: str
    tool: Dict[str, Any]
    policy: Dict[str, Any]
    log: Dict[str, Any]
    sandbox: Optional[Dict[str, Any]] = None
    constraints: Optional[Dict[str, Any]] = None
    signature: str = ""
    issuer_public_key: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReceiptProof:
    """Receipt with inclusion proof."""
    receipt: ReceiptResponse
    proof: Dict[str, Any]
    verified: bool

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["receipt"] = self.receipt.to_dict()
        return d


@dataclass
class PolicyRuleRequest:
    """Request to add a policy rule."""
    id: str
    name: str
    description: str = ""
    priority: int = 100
    tool_patterns: List[str] = field(default_factory=list)
    agent_patterns: List[str] = field(default_factory=list)
    tenant_patterns: List[str] = field(default_factory=list)
    decision: str = "deny"
    require_sandbox: bool = False
    require_approval: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyBundleRequest:
    """Request to create/update policy bundle."""
    id: str
    version: str
    name: str
    description: str = ""
    rules: List[PolicyRuleRequest] = field(default_factory=list)
    default_decision: str = "deny"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["rules"] = [r.to_dict() for r in self.rules]
        return d


@dataclass
class ApprovalRequest:
    """Request to approve/reject a pending action."""
    approval_id: str
    approved: bool
    approver_id: str
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApprovalInfo:
    """Information about a pending approval."""
    approval_id: str
    request: ToolCallRequest
    created_at: str
    tool_id: str
    agent_id: str
    session_id: str
    policy_decision: str
    policy_rule_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["request"] = self.request.to_dict()
        return d


@dataclass
class ToolDefinitionRequest:
    """Request to register a tool."""
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    requires_sandbox: bool = False
    requires_approval: bool = False
    timeout_seconds: int = 30

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TokenMintRequest:
    """Request to mint a token."""
    tenant_id: str
    agent_id: str
    session_id: str
    tools: List[str] = field(default_factory=list)
    ttl_seconds: int = 300
    purpose: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TokenResponse:
    """Token mint response."""
    token_id: str
    token_value: str
    expires_at: str
    scope: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnomalyEventResponse:
    """Anomaly event response."""
    event_id: str
    anomaly_type: str
    session_id: str
    agent_id: str
    timestamp: str
    score: float
    confidence: float
    description: str
    triggered_action: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StatsResponse:
    """Statistics response."""
    gateway: Dict[str, Any]
    policy: Dict[str, Any]
    registry: Dict[str, Any]
    tokens: Dict[str, Any]
    tripwire: Dict[str, Any]
    audit_log: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HealthResponse:
    """Health check response."""
    status: str
    version: str
    uptime_seconds: float
    components: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorResponse:
    """Error response."""
    error: str
    code: str
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
