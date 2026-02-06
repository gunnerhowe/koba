"""
Policy Engine for VACP

This module implements the deterministic policy evaluation system:
- Policy DSL for defining rules
- Default-deny semantics
- Budget tracking (tokens, calls, cost)
- Rate limiting
- Approval requirements
- DLP/redaction rules

Policy evaluation is DETERMINISTIC - given the same inputs, it always
produces the same output. This is critical for verifiability.
"""

import re
import json
import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)
from enum import Enum
from copy import deepcopy

from vacp.core.crypto import hash_json, generate_random_id


class PolicyDecision(Enum):
    """The result of policy evaluation."""
    ALLOW = "allow"
    DENY = "deny"
    ALLOW_WITH_CONDITIONS = "allow_with_conditions"
    PENDING_APPROVAL = "pending_approval"


class MatchType(Enum):
    """How to match against patterns."""
    EXACT = "exact"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    GLOB = "glob"
    REGEX = "regex"


@dataclass
class ResourcePattern:
    """A pattern for matching resources."""
    pattern: str
    match_type: MatchType = MatchType.GLOB

    def matches(self, resource: str) -> bool:
        """Check if resource matches this pattern."""
        if self.match_type == MatchType.EXACT:
            return resource == self.pattern
        elif self.match_type == MatchType.PREFIX:
            return resource.startswith(self.pattern)
        elif self.match_type == MatchType.SUFFIX:
            return resource.endswith(self.pattern)
        elif self.match_type == MatchType.GLOB:
            return fnmatch.fnmatch(resource, self.pattern)
        elif self.match_type == MatchType.REGEX:
            if len(self.pattern) > 500:
                return False  # Reject overly complex patterns
            try:
                import sys
                if sys.version_info >= (3, 11):
                    return bool(re.match(self.pattern, resource, timeout=1))
                else:
                    # On Python < 3.11, guard against ReDoS by limiting input length
                    # and rejecting known problematic patterns (nested quantifiers)
                    if len(resource) > 10000:
                        return False
                    import signal
                    _redos_pattern = re.compile(r'(\.\*|\.\+|\.\?)\1|(\([^)]*(\*|\+)[^)]*\))(\*|\+)')
                    if _redos_pattern.search(self.pattern):
                        return False  # Reject patterns with nested quantifiers
                    return bool(re.match(self.pattern, resource))
            except (re.error, TimeoutError):
                return False
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "match_type": self.match_type.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResourcePattern":
        return cls(
            pattern=data["pattern"],
            match_type=MatchType(data.get("match_type", "glob")),
        )


@dataclass
class Budget:
    """Resource budget for an agent/tenant."""
    max_tokens: Optional[int] = None
    max_calls: Optional[int] = None
    max_cost_cents: Optional[int] = None
    window_seconds: int = 3600  # 1 hour default

    # Current usage (tracked externally)
    tokens_used: int = 0
    calls_used: int = 0
    cost_cents_used: int = 0
    window_start: Optional[datetime] = None

    def reset_if_needed(self, now: Optional[datetime] = None) -> None:
        """Reset budget if window has expired."""
        now = now or datetime.now(timezone.utc)
        if self.window_start is None:
            self.window_start = now
            return

        window_end = self.window_start + timedelta(seconds=self.window_seconds)
        if now >= window_end:
            self.tokens_used = 0
            self.calls_used = 0
            self.cost_cents_used = 0
            self.window_start = now

    def check_budget(
        self,
        tokens: int = 0,
        calls: int = 1,
        cost_cents: int = 0,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if operation fits within budget.

        Returns:
            Tuple of (allowed, denial_reason)
        """
        self.reset_if_needed()

        if self.max_tokens is not None:
            if self.tokens_used + tokens > self.max_tokens:
                return False, f"Token budget exceeded: {self.tokens_used + tokens} > {self.max_tokens}"

        if self.max_calls is not None:
            if self.calls_used + calls > self.max_calls:
                return False, f"Call budget exceeded: {self.calls_used + calls} > {self.max_calls}"

        if self.max_cost_cents is not None:
            if self.cost_cents_used + cost_cents > self.max_cost_cents:
                return False, f"Cost budget exceeded: {self.cost_cents_used + cost_cents} > {self.max_cost_cents}"

        return True, None

    def check_and_consume(
        self,
        tokens: int = 0,
        calls: int = 1,
        cost_cents: int = 0,
    ) -> Tuple[bool, Optional[str]]:
        """
        Atomically check and consume budget in one step.

        Prevents TOCTOU race between check_budget() and consume().

        Returns:
            Tuple of (allowed, denial_reason)
        """
        allowed, reason = self.check_budget(tokens, calls, cost_cents)
        if allowed:
            self.consume(tokens, calls, cost_cents)
        return allowed, reason

    def consume(
        self,
        tokens: int = 0,
        calls: int = 1,
        cost_cents: int = 0,
    ) -> None:
        """Record consumption of budget."""
        self.reset_if_needed()
        self.tokens_used += tokens
        self.calls_used += calls
        self.cost_cents_used += cost_cents

    def remaining(self) -> Dict[str, Optional[int]]:
        """Get remaining budget."""
        self.reset_if_needed()
        return {
            "tokens": None if self.max_tokens is None else max(0, self.max_tokens - self.tokens_used),
            "calls": None if self.max_calls is None else max(0, self.max_calls - self.calls_used),
            "cost_cents": None if self.max_cost_cents is None else max(0, self.max_cost_cents - self.cost_cents_used),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_tokens": self.max_tokens,
            "max_calls": self.max_calls,
            "max_cost_cents": self.max_cost_cents,
            "window_seconds": self.window_seconds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Budget":
        return cls(
            max_tokens=data.get("max_tokens"),
            max_calls=data.get("max_calls"),
            max_cost_cents=data.get("max_cost_cents"),
            window_seconds=data.get("window_seconds", 3600),
        )


@dataclass
class RateLimit:
    """Rate limiting configuration."""
    max_requests: int
    window_seconds: int
    burst_limit: Optional[int] = None

    # Tracking
    _requests: List[datetime] = field(default_factory=list)

    def check_rate_limit(self, now: Optional[datetime] = None) -> Tuple[bool, int]:
        """
        Check if request is allowed under rate limit.

        Returns:
            Tuple of (allowed, remaining_requests)
        """
        now = now or datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.window_seconds)

        # Clean old requests
        self._requests = [r for r in self._requests if r > window_start]

        if len(self._requests) >= self.max_requests:
            return False, 0

        return True, self.max_requests - len(self._requests) - 1

    def record_request(self, now: Optional[datetime] = None) -> None:
        """Record a request for rate limiting."""
        now = now or datetime.now(timezone.utc)
        self._requests.append(now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "burst_limit": self.burst_limit,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RateLimit":
        return cls(
            max_requests=data["max_requests"],
            window_seconds=data["window_seconds"],
            burst_limit=data.get("burst_limit"),
        )


@dataclass
class RedactionRule:
    """Rule for redacting sensitive data from requests/responses."""
    name: str
    pattern: str
    replacement: str = "[REDACTED]"
    apply_to: str = "both"  # "request", "response", "both"

    def redact(self, text: str) -> str:
        """Apply redaction to text.

        Handles multiple encodings of the same content to prevent
        evasion via unicode normalization, mixed case, etc.
        """
        if len(self.pattern) > 500:
            return text  # Skip overly complex patterns
        try:
            import sys
            import unicodedata
            # Normalize unicode to catch homoglyph/encoding evasion
            normalized = unicodedata.normalize("NFKC", text)
            if sys.version_info >= (3, 11):
                result = re.sub(self.pattern, self.replacement, normalized, timeout=1)
            else:
                if len(normalized) > 10000:
                    return text  # Guard against ReDoS on long inputs
                _redos_pattern = re.compile(r'(\.\*|\.\+|\.\?)\1|(\([^)]*(\*|\+)[^)]*\))(\*|\+)')
                if _redos_pattern.search(self.pattern):
                    return text
                result = re.sub(self.pattern, self.replacement, normalized)
            return result
        except (re.error, TimeoutError):
            return text

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "pattern": self.pattern,
            "replacement": self.replacement,
            "apply_to": self.apply_to,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RedactionRule":
        return cls(
            name=data["name"],
            pattern=data["pattern"],
            replacement=data.get("replacement", "[REDACTED]"),
            apply_to=data.get("apply_to", "both"),
        )


@dataclass
class PolicyRule:
    """
    A single policy rule.

    Rules are evaluated in order. First matching rule determines outcome.
    """
    id: str
    name: str
    description: str = ""
    priority: int = 100  # Lower = higher priority

    # Subject matching
    agent_patterns: List[str] = field(default_factory=list)  # Empty = all agents
    tenant_patterns: List[str] = field(default_factory=list)  # Empty = all tenants
    trust_levels: List[str] = field(default_factory=list)  # e.g., ["high", "medium"]

    # Action matching
    tool_patterns: List[str] = field(default_factory=list)  # Empty = all tools
    method_patterns: List[str] = field(default_factory=list)  # For tools with methods

    # Resource matching
    resource_patterns: List[ResourcePattern] = field(default_factory=list)

    # Context conditions
    time_restrictions: Optional[Dict[str, Any]] = None  # e.g., {"hours": [9, 17], "days": [1-5]}
    require_sandbox: bool = False
    require_approval: bool = False
    approver_roles: List[str] = field(default_factory=list)

    # Decision
    decision: PolicyDecision = PolicyDecision.DENY
    conditions: Optional[Dict[str, Any]] = None  # For ALLOW_WITH_CONDITIONS

    # Budget/rate limit references
    budget_id: Optional[str] = None
    rate_limit_id: Optional[str] = None

    # Redactions
    redaction_rules: List[str] = field(default_factory=list)  # IDs of redaction rules

    def matches_subject(
        self,
        agent_id: str,
        tenant_id: str,
        trust_level: Optional[str] = None,
    ) -> bool:
        """Check if rule matches the subject."""
        # Check agent patterns
        if self.agent_patterns:
            if not any(fnmatch.fnmatch(agent_id, p) for p in self.agent_patterns):
                return False

        # Check tenant patterns
        if self.tenant_patterns:
            if not any(fnmatch.fnmatch(tenant_id, p) for p in self.tenant_patterns):
                return False

        # Check trust level - if rule specifies trust levels, reject requests
        # that don't provide one or provide a non-matching one
        if self.trust_levels:
            if not trust_level or trust_level not in self.trust_levels:
                return False

        return True

    def matches_action(
        self,
        tool_name: str,
        method: Optional[str] = None,
    ) -> bool:
        """Check if rule matches the action."""
        # Check tool patterns
        if self.tool_patterns:
            if not any(fnmatch.fnmatch(tool_name, p) for p in self.tool_patterns):
                return False

        # Check method patterns - if rule specifies method patterns, reject
        # requests that don't provide a method or provide a non-matching one
        if self.method_patterns:
            if not method or not any(fnmatch.fnmatch(method, p) for p in self.method_patterns):
                return False

        return True

    def matches_resource(self, resource: Optional[str]) -> bool:
        """Check if rule matches the resource."""
        if not self.resource_patterns:
            return True  # No patterns = match all

        if not resource:
            return False  # No resource but patterns required

        return any(p.matches(resource) for p in self.resource_patterns)

    def matches_context(
        self,
        now: Optional[datetime] = None,
        has_sandbox: bool = False,
        has_approval: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if rule matches the context.

        Returns:
            Tuple of (matches, reason_if_not)
        """
        now = now or datetime.now(timezone.utc)

        # Check time restrictions
        if self.time_restrictions:
            hours = self.time_restrictions.get("hours")
            if hours and len(hours) == 2:
                if not (hours[0] <= now.hour < hours[1]):
                    return False, f"Outside allowed hours ({hours[0]}-{hours[1]})"

            days = self.time_restrictions.get("days")
            if days:
                if now.weekday() + 1 not in days:  # weekday() is 0-indexed
                    return False, f"Day {now.weekday() + 1} not in allowed days"

        # Check sandbox requirement
        if self.require_sandbox and not has_sandbox:
            return False, "Sandbox required but not available"

        # Check approval requirement
        if self.require_approval and not has_approval:
            return False, "Approval required"

        return True, None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "agent_patterns": self.agent_patterns,
            "tenant_patterns": self.tenant_patterns,
            "trust_levels": self.trust_levels,
            "tool_patterns": self.tool_patterns,
            "method_patterns": self.method_patterns,
            "resource_patterns": [r.to_dict() for r in self.resource_patterns],
            "time_restrictions": self.time_restrictions,
            "require_sandbox": self.require_sandbox,
            "require_approval": self.require_approval,
            "approver_roles": self.approver_roles,
            "decision": self.decision.value,
            "conditions": self.conditions,
            "budget_id": self.budget_id,
            "rate_limit_id": self.rate_limit_id,
            "redaction_rules": self.redaction_rules,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyRule":
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            priority=data.get("priority", 100),
            agent_patterns=data.get("agent_patterns", []),
            tenant_patterns=data.get("tenant_patterns", []),
            trust_levels=data.get("trust_levels", []),
            tool_patterns=data.get("tool_patterns", []),
            method_patterns=data.get("method_patterns", []),
            resource_patterns=[ResourcePattern.from_dict(r) for r in data.get("resource_patterns", [])],
            time_restrictions=data.get("time_restrictions"),
            require_sandbox=data.get("require_sandbox", False),
            require_approval=data.get("require_approval", False),
            approver_roles=data.get("approver_roles", []),
            decision=PolicyDecision(data.get("decision", "deny")),
            conditions=data.get("conditions"),
            budget_id=data.get("budget_id"),
            rate_limit_id=data.get("rate_limit_id"),
            redaction_rules=data.get("redaction_rules", []),
        )


@dataclass
class PolicyBundle:
    """
    A complete policy bundle containing rules and associated resources.

    Policy bundles are versioned and signed for integrity.
    """
    id: str
    version: str
    name: str
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Rules (evaluated in priority order)
    rules: List[PolicyRule] = field(default_factory=list)

    # Resources
    budgets: Dict[str, Budget] = field(default_factory=dict)
    rate_limits: Dict[str, RateLimit] = field(default_factory=dict)
    redaction_rules: Dict[str, RedactionRule] = field(default_factory=dict)

    # Default behavior
    default_decision: PolicyDecision = PolicyDecision.DENY

    # Signature (set by PolicyEngine.sign_bundle)
    signature: Optional[str] = None
    signer_public_key: Optional[str] = None

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule to the bundle."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def get_rules_by_priority(self) -> List[PolicyRule]:
        """Get rules sorted by priority."""
        return sorted(self.rules, key=lambda r: r.priority)

    def compute_hash(self) -> str:
        """Compute hash of the policy bundle (excluding signature)."""
        data = self.to_dict(include_signature=False)
        return hash_json(data)

    def to_dict(self, include_signature: bool = True) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "rules": [r.to_dict() for r in self.rules],
            "budgets": {k: v.to_dict() for k, v in self.budgets.items()},
            "rate_limits": {k: v.to_dict() for k, v in self.rate_limits.items()},
            "redaction_rules": {k: v.to_dict() for k, v in self.redaction_rules.items()},
            "default_decision": self.default_decision.value,
        }
        if include_signature and self.signature:
            d["signature"] = self.signature
            d["signer_public_key"] = self.signer_public_key
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyBundle":
        return cls(
            id=data["id"],
            version=data["version"],
            name=data["name"],
            description=data.get("description", ""),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(timezone.utc),
            rules=[PolicyRule.from_dict(r) for r in data.get("rules", [])],
            budgets={k: Budget.from_dict(v) for k, v in data.get("budgets", {}).items()},
            rate_limits={k: RateLimit.from_dict(v) for k, v in data.get("rate_limits", {}).items()},
            redaction_rules={k: RedactionRule.from_dict(v) for k, v in data.get("redaction_rules", {}).items()},
            default_decision=PolicyDecision(data.get("default_decision", "deny")),
            signature=data.get("signature"),
            signer_public_key=data.get("signer_public_key"),
        )


@dataclass
class PolicyEvaluationContext:
    """Context for policy evaluation."""
    agent_id: str
    tenant_id: str
    session_id: str
    tool_name: str
    method: Optional[str] = None
    resource: Optional[str] = None
    trust_level: Optional[str] = None
    has_sandbox: bool = False
    has_approval: bool = False
    approver_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    request_data: Optional[Dict[str, Any]] = None  # For DLP checks


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation."""
    decision: PolicyDecision
    matched_rule: Optional[PolicyRule]
    matched_rule_id: Optional[str]
    denial_reason: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    redactions_applied: List[str] = field(default_factory=list)
    budget_remaining: Optional[Dict[str, Optional[int]]] = None
    rate_limit_remaining: Optional[int] = None
    evaluation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "matched_rule_id": self.matched_rule_id,
            "denial_reason": self.denial_reason,
            "conditions": self.conditions,
            "redactions_applied": self.redactions_applied,
            "budget_remaining": self.budget_remaining,
            "rate_limit_remaining": self.rate_limit_remaining,
            "evaluation_time_ms": self.evaluation_time_ms,
        }


class PolicyEngine:
    """
    The core policy evaluation engine.

    Features:
    - Deterministic evaluation
    - Default-deny semantics
    - Budget tracking
    - Rate limiting
    - Approval workflows
    - DLP/redaction

    The engine is stateful for budget/rate-limit tracking but
    evaluation is deterministic given the same state.
    """

    def __init__(self, keypair=None):
        """Initialize the policy engine."""
        self.keypair = keypair
        self._bundles: Dict[str, PolicyBundle] = {}
        self._active_bundle_id: Optional[str] = None

        # Shared state (for budget/rate tracking across bundles)
        self._budget_state: Dict[str, Budget] = {}
        self._rate_limit_state: Dict[str, RateLimit] = {}

    def load_bundle(
        self,
        bundle: PolicyBundle,
        activate: bool = True,
        verify_signature: bool = False,
    ) -> bool:
        """
        Load a policy bundle.

        Args:
            bundle: The bundle to load
            activate: Whether to make this the active bundle
            verify_signature: Whether to verify bundle signature

        Returns:
            True if loaded successfully
        """
        if verify_signature and bundle.signature:
            if not self._verify_bundle_signature(bundle):
                return False

        self._bundles[bundle.id] = bundle

        # Initialize budget and rate limit state
        for budget_id, budget in bundle.budgets.items():
            key = f"{bundle.id}:{budget_id}"
            if key not in self._budget_state:
                self._budget_state[key] = deepcopy(budget)

        for rl_id, rate_limit in bundle.rate_limits.items():
            key = f"{bundle.id}:{rl_id}"
            if key not in self._rate_limit_state:
                self._rate_limit_state[key] = deepcopy(rate_limit)

        if activate:
            self._active_bundle_id = bundle.id

        return True

    def get_active_bundle(self) -> Optional[PolicyBundle]:
        """Get the currently active policy bundle."""
        if self._active_bundle_id:
            return self._bundles.get(self._active_bundle_id)
        return None

    def set_active_bundle(self, bundle_id: str) -> bool:
        """Set the active policy bundle by ID."""
        if bundle_id not in self._bundles:
            return False
        self._active_bundle_id = bundle_id
        return True

    def get_bundle(self, bundle_id: str) -> Optional['PolicyBundle']:
        """Get a policy bundle by ID."""
        return self._bundles.get(bundle_id)

    def has_bundle(self, bundle_id: str) -> bool:
        """Check if a bundle exists."""
        return bundle_id in self._bundles

    def remove_bundle(self, bundle_id: str) -> bool:
        """Remove a policy bundle. Returns True if removed.

        Records the deletion in the audit trail for accountability.
        """
        if bundle_id in self._bundles:
            bundle = self._bundles[bundle_id]
            # Record deletion in audit trail
            import logging
            logger = logging.getLogger("vacp.policy")
            logger.warning(
                "Policy bundle deleted: id=%s name=%s rules=%d hash=%s",
                bundle_id,
                getattr(bundle, 'name', 'unknown'),
                len(getattr(bundle, 'rules', [])),
                getattr(bundle, 'compute_hash', lambda: 'unknown')(),
            )
            if not hasattr(self, '_deletion_log'):
                self._deletion_log = []
            self._deletion_log.append({
                "bundle_id": bundle_id,
                "deleted_at": datetime.now(timezone.utc).isoformat(),
                "bundle_hash": getattr(bundle, 'compute_hash', lambda: 'unknown')(),
            })
            del self._bundles[bundle_id]
            return True
        return False

    @property
    def active_bundle_id(self) -> Optional[str]:
        """Get the active bundle ID."""
        return self._active_bundle_id

    def evaluate(
        self,
        context: PolicyEvaluationContext,
        bundle_id: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate policy for a given context.

        This is the core evaluation function. It is DETERMINISTIC -
        given the same inputs and state, it produces the same output.

        Args:
            context: The evaluation context
            bundle_id: Optional specific bundle to use

        Returns:
            PolicyEvaluationResult with decision and metadata
        """
        import time
        start_time = time.perf_counter()

        # Get bundle
        bid = bundle_id or self._active_bundle_id
        if not bid or bid not in self._bundles:
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                matched_rule=None,
                matched_rule_id=None,
                denial_reason="No active policy bundle",
            )

        bundle = self._bundles[bid]
        now = context.timestamp or datetime.now(timezone.utc)

        # Evaluate rules in priority order
        for rule in bundle.get_rules_by_priority():
            # Check subject
            if not rule.matches_subject(
                context.agent_id,
                context.tenant_id,
                context.trust_level,
            ):
                continue

            # Check action
            if not rule.matches_action(context.tool_name, context.method):
                continue

            # Check resource
            if not rule.matches_resource(context.resource):
                continue

            # Check context (time, sandbox, approval)
            ctx_match, ctx_reason = rule.matches_context(
                now=now,
                has_sandbox=context.has_sandbox,
                has_approval=context.has_approval,
            )
            if not ctx_match:
                # Rule matches but context doesn't allow it
                if rule.require_approval and not context.has_approval:
                    elapsed = (time.perf_counter() - start_time) * 1000
                    return PolicyEvaluationResult(
                        decision=PolicyDecision.PENDING_APPROVAL,
                        matched_rule=rule,
                        matched_rule_id=rule.id,
                        denial_reason=ctx_reason,
                        evaluation_time_ms=elapsed,
                    )
                continue

            # Check budget
            budget_remaining = None
            if rule.budget_id:
                budget_key = f"{bid}:{rule.budget_id}"
                budget = self._budget_state.get(budget_key)
                if budget:
                    allowed, reason = budget.check_budget(calls=1)
                    if not allowed:
                        elapsed = (time.perf_counter() - start_time) * 1000
                        return PolicyEvaluationResult(
                            decision=PolicyDecision.DENY,
                            matched_rule=rule,
                            matched_rule_id=rule.id,
                            denial_reason=reason,
                            evaluation_time_ms=elapsed,
                        )
                    budget_remaining = budget.remaining()

            # Check rate limit
            rate_limit_remaining = None
            if rule.rate_limit_id:
                rl_key = f"{bid}:{rule.rate_limit_id}"
                rate_limit = self._rate_limit_state.get(rl_key)
                if rate_limit:
                    allowed, remaining = rate_limit.check_rate_limit(now)
                    if not allowed:
                        elapsed = (time.perf_counter() - start_time) * 1000
                        return PolicyEvaluationResult(
                            decision=PolicyDecision.DENY,
                            matched_rule=rule,
                            matched_rule_id=rule.id,
                            denial_reason="Rate limit exceeded",
                            rate_limit_remaining=0,
                            evaluation_time_ms=elapsed,
                        )
                    rate_limit_remaining = remaining

            # Determine redactions
            redactions = []
            for redaction_id in rule.redaction_rules:
                if redaction_id in bundle.redaction_rules:
                    redactions.append(redaction_id)

            # Rule matched - return decision
            elapsed = (time.perf_counter() - start_time) * 1000
            return PolicyEvaluationResult(
                decision=rule.decision,
                matched_rule=rule,
                matched_rule_id=rule.id,
                conditions=rule.conditions,
                redactions_applied=redactions,
                budget_remaining=budget_remaining,
                rate_limit_remaining=rate_limit_remaining,
                evaluation_time_ms=elapsed,
            )

        # No rule matched - apply default
        elapsed = (time.perf_counter() - start_time) * 1000
        return PolicyEvaluationResult(
            decision=bundle.default_decision,
            matched_rule=None,
            matched_rule_id=None,
            denial_reason="No matching rule, default decision applied",
            evaluation_time_ms=elapsed,
        )

    def record_action(
        self,
        context: PolicyEvaluationContext,
        result: PolicyEvaluationResult,
        bundle_id: Optional[str] = None,
    ) -> None:
        """
        Record that an action was taken (for budget/rate limit tracking).

        Call this AFTER the action is executed.
        """
        bid = bundle_id or self._active_bundle_id
        if not bid or not result.matched_rule:
            return

        rule = result.matched_rule
        now = context.timestamp or datetime.now(timezone.utc)

        # Update budget
        if rule.budget_id:
            budget_key = f"{bid}:{rule.budget_id}"
            budget = self._budget_state.get(budget_key)
            if budget:
                budget.consume(calls=1)

        # Update rate limit
        if rule.rate_limit_id:
            rl_key = f"{bid}:{rule.rate_limit_id}"
            rate_limit = self._rate_limit_state.get(rl_key)
            if rate_limit:
                rate_limit.record_request(now)

    def apply_redactions(
        self,
        text: str,
        redaction_ids: List[str],
        bundle_id: Optional[str] = None,
    ) -> str:
        """Apply redaction rules to text."""
        bid = bundle_id or self._active_bundle_id
        if not bid or bid not in self._bundles:
            return text

        bundle = self._bundles[bid]
        result = text

        for redaction_id in redaction_ids:
            rule = bundle.redaction_rules.get(redaction_id)
            if rule:
                result = rule.redact(result)

        return result

    def sign_bundle(self, bundle: PolicyBundle) -> PolicyBundle:
        """Sign a policy bundle."""
        if not self.keypair:
            raise ValueError("No keypair configured for signing")

        from vacp.core.crypto import sign_message, encode_signature, encode_public_key

        canonical = json.dumps(bundle.to_dict(include_signature=False), sort_keys=True).encode()
        signature_bytes = sign_message(canonical, self.keypair.private_key_bytes)

        bundle.signature = encode_signature(signature_bytes)
        bundle.signer_public_key = encode_public_key(self.keypair.public_key_bytes)

        return bundle

    def _verify_bundle_signature(self, bundle: PolicyBundle) -> bool:
        """Verify a bundle's signature."""
        if not bundle.signature or not bundle.signer_public_key:
            return False

        from vacp.core.crypto import verify_signature, decode_signature, decode_public_key

        try:
            canonical = json.dumps(bundle.to_dict(include_signature=False), sort_keys=True).encode()
            signature_bytes = decode_signature(bundle.signature)
            public_key_bytes = decode_public_key(bundle.signer_public_key)
            return verify_signature(canonical, signature_bytes, public_key_bytes)
        except Exception:
            return False


# Convenience functions for creating common policy patterns

def create_allow_rule(
    rule_id: str,
    name: str,
    tool_patterns: List[str],
    agent_patterns: Optional[List[str]] = None,
    tenant_patterns: Optional[List[str]] = None,
    priority: int = 100,
    require_sandbox: bool = False,
) -> PolicyRule:
    """Create a simple allow rule."""
    return PolicyRule(
        id=rule_id,
        name=name,
        tool_patterns=tool_patterns,
        agent_patterns=agent_patterns or [],
        tenant_patterns=tenant_patterns or [],
        priority=priority,
        require_sandbox=require_sandbox,
        decision=PolicyDecision.ALLOW,
    )


def create_deny_rule(
    rule_id: str,
    name: str,
    tool_patterns: List[str],
    description: str = "",
    priority: int = 50,  # Deny rules typically higher priority
) -> PolicyRule:
    """Create a simple deny rule."""
    return PolicyRule(
        id=rule_id,
        name=name,
        description=description,
        tool_patterns=tool_patterns,
        priority=priority,
        decision=PolicyDecision.DENY,
    )


def create_default_bundle(bundle_id: str = "default") -> PolicyBundle:
    """
    Create a default policy bundle with sensible security defaults.

    Default behavior:
    - Deny all by default
    - Allow safe read-only tools
    - Require approval for destructive operations
    """
    bundle = PolicyBundle(
        id=bundle_id,
        version="1.0.0",
        name="Default Security Policy",
        description="Default-deny policy with safe read operations allowed",
        default_decision=PolicyDecision.DENY,
    )

    # Allow safe read operations
    bundle.add_rule(PolicyRule(
        id="allow-read-ops",
        name="Allow Read Operations",
        description="Allow safe read-only tool calls",
        tool_patterns=["*"],
        method_patterns=["read", "get", "list", "query", "search",
                         "check_balance", "pull", "download", "browse"],
        priority=100,
        decision=PolicyDecision.ALLOW,
    ))

    # Require approval for write operations
    bundle.add_rule(PolicyRule(
        id="approval-write-ops",
        name="Require Approval for Writes",
        description="Write operations require human approval",
        tool_patterns=["*"],
        method_patterns=["write", "create", "update", "delete", "send",
                         "execute", "post", "put", "transfer", "move",
                         "copy", "insert", "upload", "commit", "push",
                         "branch", "merge", "refund", "request", "draft",
                         "sudo", "install", "compile", "convert", "print",
                         "share", "schedule", "cancel", "join", "leave",
                         "create_user", "delete_user", "change_role"],
        priority=90,
        require_approval=True,
        decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
        conditions={"approval_required": True},
    ))

    # Deny dangerous system operations
    bundle.add_rule(PolicyRule(
        id="deny-dangerous",
        name="Block Shell/System Execution",
        description="Block dangerous system-level operations",
        tool_patterns=["system"],
        method_patterns=["execute"],
        priority=10,
        decision=PolicyDecision.DENY,
    ))

    # Add common redaction rules
    bundle.redaction_rules["api-keys"] = RedactionRule(
        name="API Keys",
        pattern=r"(?i)(api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{20,})",
        replacement="[API_KEY_REDACTED]",
    )

    bundle.redaction_rules["passwords"] = RedactionRule(
        name="Passwords",
        pattern=r"(?i)(password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\s\"']+)",
        replacement="[PASSWORD_REDACTED]",
    )

    bundle.redaction_rules["tokens"] = RedactionRule(
        name="Tokens",
        pattern=r"(?i)(bearer|token|jwt|auth)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-\.]{20,})",
        replacement="[TOKEN_REDACTED]",
    )

    # Add default budget
    bundle.budgets["default"] = Budget(
        max_calls=1000,
        window_seconds=3600,
    )

    # Add default rate limit
    bundle.rate_limits["default"] = RateLimit(
        max_requests=100,
        window_seconds=60,
    )

    return bundle
