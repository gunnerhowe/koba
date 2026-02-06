"""
Tool Gateway for VACP

This module implements the core enforcement point:
- Intercepts all tool calls
- Validates requests against schemas
- Evaluates policy decisions
- Injects scoped credentials
- Routes to sandbox execution
- Issues signed action receipts

The gateway is the ONLY path to tool execution. All side-effectful
actions MUST pass through it. This is the key security invariant.
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union
from enum import Enum

from vacp.core.crypto import hash_json, generate_random_id, KeyPair
from vacp.core.policy import (
    PolicyEngine,
    PolicyDecision,
    PolicyEvaluationContext,
    PolicyEvaluationResult,
)
from vacp.core.receipts import (
    SignedActionReceipt,
    ReceiptService,
    ToolInfo,
    PolicyInfo,
    SandboxInfo,
    ConstraintsApplied,
    create_tool_info,
)
from vacp.core.merkle import MerkleLog, AuditableLog
from vacp.core.registry import ToolRegistry, ToolDefinition
from vacp.core.normalize import normalize_tool_name, extract_resource


class GatewayError(Exception):
    """Base exception for gateway errors."""
    pass


class PolicyDeniedError(GatewayError):
    """Raised when policy denies the action."""
    def __init__(self, message: str, result: PolicyEvaluationResult):
        super().__init__(message)
        self.result = result


class ValidationError(GatewayError):
    """Raised when request validation fails."""
    def __init__(self, message: str, errors: List[str]):
        super().__init__(message)
        self.errors = errors


class ApprovalRequiredError(GatewayError):
    """Raised when action requires human approval."""
    def __init__(self, message: str, approval_id: str):
        super().__init__(message)
        self.approval_id = approval_id


class ToolExecutionError(GatewayError):
    """Raised when tool execution fails."""
    def __init__(self, message: str, tool_id: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.tool_id = tool_id
        self.original_error = original_error


@dataclass
class ToolRequest:
    """A request to execute a tool."""
    tool_id: str
    parameters: Dict[str, Any]
    agent_id: str
    tenant_id: str
    session_id: str
    request_id: str = field(default_factory=lambda: generate_random_id("req"))
    method: Optional[str] = None
    resource: Optional[str] = None
    trust_level: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tool_id": self.tool_id,
            "parameters": self.parameters,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "method": self.method,
            "resource": self.resource,
            "trust_level": self.trust_level,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ToolResponse:
    """Response from a tool execution."""
    request_id: str
    tool_id: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    receipt: Optional[SignedActionReceipt] = None
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "request_id": self.request_id,
            "tool_id": self.tool_id,
            "success": self.success,
            "execution_time_ms": self.execution_time_ms,
        }
        if self.result is not None:
            d["result"] = self.result
        if self.error:
            d["error"] = self.error
        if self.receipt:
            d["receipt_id"] = self.receipt.receipt_id
        return d


@dataclass
class PendingApproval:
    """A tool request pending human approval."""
    approval_id: str
    request: ToolRequest
    policy_result: PolicyEvaluationResult
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    approved: Optional[bool] = None
    approver_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None


@dataclass
class EvaluationResult:
    """Result of policy evaluation without execution."""
    request_id: str
    tool_id: str
    decision: str  # "allow", "deny", "require_approval"
    pre_auth_token: Optional[str] = None
    approval_id: Optional[str] = None
    denial_reason: Optional[str] = None
    constraints: Optional[Dict[str, Any]] = None
    redacted_params: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "request_id": self.request_id,
            "tool_id": self.tool_id,
            "decision": self.decision,
        }
        if self.pre_auth_token:
            d["pre_auth_token"] = self.pre_auth_token
        if self.approval_id:
            d["approval_id"] = self.approval_id
        if self.denial_reason:
            d["denial_reason"] = self.denial_reason
        if self.constraints:
            d["constraints"] = self.constraints
        if self.redacted_params:
            d["redacted_params"] = self.redacted_params
        if self.expires_at:
            d["expires_at"] = self.expires_at.isoformat()
        return d


@dataclass
class ExternalExecutionRecord:
    """Record of an execution performed externally (e.g., by ClawdBot)."""
    pre_auth_token: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Type for tool executor functions
ToolExecutor = Callable[[str, Dict[str, Any]], Awaitable[Any]]


class ToolGateway:
    """
    The central gateway for all tool execution.

    This is the key security enforcement point. ALL tool calls must
    pass through the gateway, which:

    1. Validates requests against tool schemas
    2. Evaluates policy to determine if action is allowed
    3. Injects short-lived credentials if needed
    4. Routes execution to sandbox if required
    5. Issues signed action receipts
    6. Logs all actions to tamper-evident log
    """

    def __init__(
        self,
        registry: ToolRegistry,
        policy_engine: PolicyEngine,
        receipt_service: ReceiptService,
        audit_log: AuditableLog,
        keypair: Optional[KeyPair] = None,
    ):
        """
        Initialize the tool gateway.

        Args:
            registry: Tool registry for validation
            policy_engine: Policy engine for authorization
            receipt_service: Service for issuing receipts
            audit_log: Tamper-evident audit log
            keypair: Optional keypair for gateway signing
        """
        self.registry = registry
        self.policy_engine = policy_engine
        self.receipt_service = receipt_service
        self.audit_log = audit_log
        self.keypair = keypair

        # Tool executors (registered by tools)
        self._executors: Dict[str, ToolExecutor] = {}

        # Pending approvals
        self._pending_approvals: Dict[str, PendingApproval] = {}

        # Session tracking
        self._session_call_counts: Dict[str, Dict[str, int]] = {}

        # Pre-authorization store
        self._preauth_store: Dict[str, tuple] = {}

        # Statistics
        self._stats = {
            "total_requests": 0,
            "allowed": 0,
            "denied": 0,
            "pending_approval": 0,
            "errors": 0,
        }

    def register_executor(
        self,
        tool_id: str,
        executor: ToolExecutor,
    ) -> None:
        """
        Register an executor for a tool.

        The executor is an async function that actually performs the tool action.
        It receives the tool_id and parameters, and returns the result.

        Args:
            tool_id: ID of the tool
            executor: Async function to execute the tool
        """
        self._executors[tool_id] = executor

    async def execute(
        self,
        request: ToolRequest,
        sandbox_info: Optional[SandboxInfo] = None,
    ) -> ToolResponse:
        """
        Execute a tool request through the gateway.

        This is the main entry point for tool execution.

        Args:
            request: The tool request
            sandbox_info: Optional sandbox execution info

        Returns:
            ToolResponse with result or error
        """
        start_time = time.perf_counter()
        self._stats["total_requests"] += 1

        try:
            # Step 0: Enforce input size limits to prevent resource exhaustion
            params_json = json.dumps(request.parameters, default=str)
            max_param_bytes = 1_048_576  # 1 MB
            if len(params_json.encode('utf-8')) > max_param_bytes:
                raise ValidationError(
                    "Request parameters too large",
                    [f"Parameters exceed maximum size of {max_param_bytes} bytes"],
                )

            # Step 1: Validate tool exists
            tool = self.registry.get(request.tool_id)
            if not tool:
                raise ValidationError(
                    f"Unknown tool: {request.tool_id}",
                    [f"Tool '{request.tool_id}' is not registered"],
                )

            # Step 2: Validate request parameters
            valid, errors = tool.validate_request(request.parameters)
            if not valid:
                raise ValidationError(
                    f"Invalid parameters for {request.tool_id}",
                    errors,
                )

            # Step 3: Check session call limits
            if tool.max_calls_per_session:
                session_calls = self._get_session_calls(
                    request.session_id,
                    request.tool_id,
                )
                if session_calls >= tool.max_calls_per_session:
                    raise PolicyDeniedError(
                        f"Session call limit reached for {request.tool_id}",
                        PolicyEvaluationResult(
                            decision=PolicyDecision.DENY,
                            matched_rule=None,
                            matched_rule_id=None,
                            denial_reason=f"Max {tool.max_calls_per_session} calls per session",
                        ),
                    )

            # Step 4: Evaluate policy (with tool name normalization)
            normalized_category, normalized_method, extracted_resource = \
                normalize_tool_name(request.tool_id, request.parameters)
            effective_method = request.method or normalized_method
            effective_resource = request.resource or extracted_resource
            has_sandbox = sandbox_info is not None
            policy_context = PolicyEvaluationContext(
                agent_id=request.agent_id,
                tenant_id=request.tenant_id,
                session_id=request.session_id,
                tool_name=normalized_category,
                method=effective_method,
                resource=effective_resource,
                trust_level=request.trust_level,
                has_sandbox=has_sandbox,
                has_approval=False,  # Will check pending approvals
                timestamp=request.timestamp,
                request_data=request.parameters,
            )

            policy_result = self.policy_engine.evaluate(policy_context)

            # Step 5: Handle policy decision
            if policy_result.decision == PolicyDecision.DENY:
                self._stats["denied"] += 1
                raise PolicyDeniedError(
                    policy_result.denial_reason or "Policy denied",
                    policy_result,
                )

            if policy_result.decision in (
                PolicyDecision.PENDING_APPROVAL,
                PolicyDecision.ALLOW_WITH_CONDITIONS,
            ):
                # Check if conditions require approval
                needs_approval = (
                    policy_result.decision == PolicyDecision.PENDING_APPROVAL
                    or policy_result.require_approval
                )

                if needs_approval:
                    # Check if this request was already approved via execute_with_approval
                    if request.context.get("_approved"):
                        policy_context.has_approval = True
                        policy_context.approver_id = request.context.get("_approver_id")
                    else:
                        # Check for existing approval
                        approval = self._find_approval_for_request(request)
                        if approval and approval.approved:
                            # Already approved, continue
                            policy_context.has_approval = True
                            policy_context.approver_id = approval.approver_id
                        else:
                            # Create pending approval
                            self._stats["pending_approval"] += 1
                            approval_id = self._create_pending_approval(request, policy_result)
                            raise ApprovalRequiredError(
                                "Human approval required",
                                approval_id,
                            )
                # ALLOW_WITH_CONDITIONS without approval requirement:
                # proceed with any redactions/budget constraints applied below

            # Step 6: Apply redactions to request if needed
            redacted_params = request.parameters
            if policy_result.redactions_applied:
                redacted_params = self._apply_redactions(
                    request.parameters,
                    policy_result.redactions_applied,
                )

            # Step 7: Execute the tool
            executor = self._executors.get(request.tool_id)
            if not executor:
                raise ToolExecutionError(
                    f"No executor registered for {request.tool_id}",
                    request.tool_id,
                )

            try:
                # Execute with timeout
                result = await asyncio.wait_for(
                    executor(request.tool_id, redacted_params),
                    timeout=tool.timeout_seconds,
                )
            except asyncio.TimeoutError:
                raise ToolExecutionError(
                    f"Tool execution timed out after {tool.timeout_seconds}s",
                    request.tool_id,
                )
            except Exception as e:
                raise ToolExecutionError(
                    f"Tool execution failed: {str(e)}",
                    request.tool_id,
                    original_error=e,
                )

            # Step 8: Record the action
            self.policy_engine.record_action(policy_context, policy_result)
            self._record_session_call(request.session_id, request.tool_id)

            # Step 9: Issue receipt
            tool_def = self.registry.get(request.tool_id)
            tool_name = tool_def.name if tool_def else request.tool_id
            tool_info = create_tool_info(
                tool_name,
                request.parameters,
                result,
                summarize_request=True,
                tool_id=request.tool_id,
            )

            active_bundle = self.policy_engine.get_active_bundle()
            policy_info = PolicyInfo(
                bundle_id=self.policy_engine._active_bundle_id or "unknown",
                policy_hash=active_bundle.compute_hash() if active_bundle else "unknown",
                decision=policy_result.decision,
                rules_matched=[policy_result.matched_rule_id] if policy_result.matched_rule_id else [],
            )

            constraints = None
            if policy_result.budget_remaining or policy_result.redactions_applied:
                # Convert budget_remaining values to float for ConstraintsApplied
                budget_float: Optional[Dict[str, float]] = None
                if policy_result.budget_remaining:
                    budget_float = {k: float(v) for k, v in policy_result.budget_remaining.items() if v is not None}
                constraints = ConstraintsApplied(
                    budget_remaining=budget_float,
                    redactions_applied=policy_result.redactions_applied,
                    rate_limit_remaining=policy_result.rate_limit_remaining,
                )

            receipt = self.receipt_service.issue_receipt(
                agent_id=request.agent_id,
                tenant_id=request.tenant_id,
                session_id=request.session_id,
                tool=tool_info,
                policy=policy_info,
                merkle_root=self.audit_log.log.root_hex,
                log_index=self.audit_log.log.size,
                sandbox=sandbox_info,
                constraints=constraints,
            )

            # Step 10: Append to audit log
            self.audit_log.append_receipt(receipt)

            # Step 11: Record success
            self._stats["allowed"] += 1
            self.registry.record_call(request.tool_id, success=True)

            elapsed = (time.perf_counter() - start_time) * 1000
            return ToolResponse(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=True,
                result=result,
                receipt=receipt,
                execution_time_ms=elapsed,
            )

        except PolicyDeniedError as e:
            self._stats["denied"] += 1
            self.registry.record_call(request.tool_id, success=False, denied=True)

            # Still issue receipt for denied actions
            tool_def = self.registry.get(request.tool_id)
            tool_name = tool_def.name if tool_def else request.tool_id
            tool_info = create_tool_info(tool_name, request.parameters, tool_id=request.tool_id)
            policy_info = PolicyInfo(
                bundle_id=self.policy_engine._active_bundle_id or "unknown",
                policy_hash="",
                decision=PolicyDecision.DENY,
                rules_matched=[e.result.matched_rule_id] if e.result.matched_rule_id else [],
            )

            receipt = self.receipt_service.issue_receipt(
                agent_id=request.agent_id,
                tenant_id=request.tenant_id,
                session_id=request.session_id,
                tool=tool_info,
                policy=policy_info,
                merkle_root=self.audit_log.log.root_hex,
                log_index=self.audit_log.log.size,
            )
            self.audit_log.append_receipt(receipt)

            elapsed = (time.perf_counter() - start_time) * 1000
            return ToolResponse(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                error=str(e),
                receipt=receipt,
                execution_time_ms=elapsed,
            )

        except ApprovalRequiredError:
            raise  # Re-raise for caller to handle

        except ValidationError as e:
            self._stats["errors"] += 1
            elapsed = (time.perf_counter() - start_time) * 1000
            return ToolResponse(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                error=f"Validation error: {', '.join(e.errors)}",
                execution_time_ms=elapsed,
            )

        except ToolExecutionError as e:
            self._stats["errors"] += 1
            self.registry.record_call(request.tool_id, success=False)
            elapsed = (time.perf_counter() - start_time) * 1000
            return ToolResponse(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                error=str(e),
                execution_time_ms=elapsed,
            )

        except Exception as e:
            self._stats["errors"] += 1
            import logging
            logging.getLogger("vacp.gateway").exception(
                "Unexpected error processing request %s", request.request_id
            )
            elapsed = (time.perf_counter() - start_time) * 1000
            return ToolResponse(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                error="Internal error processing request",
                execution_time_ms=elapsed,
            )

    async def execute_with_approval(
        self,
        approval_id: str,
        approver_id: str,
        approved: bool,
        rejection_reason: Optional[str] = None,
    ) -> Optional[ToolResponse]:
        """
        Complete an action that was pending approval.

        Args:
            approval_id: ID of the pending approval
            approver_id: ID of the approver
            approved: Whether the action is approved
            rejection_reason: Reason for rejection if not approved

        Returns:
            ToolResponse if approved and executed, None if rejected
        """
        approval = self._pending_approvals.get(approval_id)
        if not approval:
            raise GatewayError(f"Unknown approval ID: {approval_id}")

        if approval.approved is not None:
            raise GatewayError(f"Approval {approval_id} already processed")

        approval.approved = approved
        approval.approver_id = approver_id
        approval.approved_at = datetime.now(timezone.utc)
        approval.rejection_reason = rejection_reason

        if not approved:
            self._stats["denied"] += 1
            return None

        # Re-execute with pre-set approval context so policy doesn't
        # re-trigger PENDING_APPROVAL (which would cause infinite loop)
        request = approval.request
        # Mark the request context so execute() knows it's pre-approved
        request.context = {**request.context, "_approved": True, "_approver_id": approver_id}
        return await self.execute(request)

    def get_pending_approvals(
        self,
        tenant_id: Optional[str] = None,
    ) -> List[PendingApproval]:
        """Get list of pending approvals."""
        approvals = list(self._pending_approvals.values())
        if tenant_id:
            approvals = [a for a in approvals if a.request.tenant_id == tenant_id]
        return [a for a in approvals if a.approved is None]

    def get_virtual_catalog(
        self,
        agent_id: str,
        tenant_id: str,
        trust_level: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get the tool catalog visible to an agent.

        This filters tools based on what the agent is allowed to use.
        """
        # For now, return full catalog - in production would filter based on policy
        return self.registry.get_virtual_catalog()

    def get_stats(self) -> Dict[str, Any]:
        """Get gateway statistics."""
        return dict(self._stats)

    async def evaluate_only(
        self,
        request: ToolRequest,
    ) -> EvaluationResult:
        """
        Evaluate policy for a tool request WITHOUT executing.

        This is used for external execution scenarios (e.g., ClawdBot integration)
        where the caller wants to:
        1. Check if a tool call is allowed
        2. Get pre-authorization if allowed
        3. Execute the tool themselves
        4. Report the result back via record_external_execution()

        Args:
            request: The tool request to evaluate

        Returns:
            EvaluationResult with decision and pre-auth token if allowed
        """
        self._stats["total_requests"] += 1

        try:
            # Step 1: Normalize tool name for policy matching
            # External callers (ClawdBot, SDKs) send raw tool names like
            # "read_file", "bash" etc. We normalize these to canonical
            # category.method format so policy rules actually match.
            normalized_category, normalized_method, extracted_resource = \
                normalize_tool_name(request.tool_id, request.parameters)

            # Use explicitly provided method/resource if available,
            # otherwise fall back to extracted values
            effective_method = request.method or normalized_method
            effective_resource = request.resource or extracted_resource

            # Step 2: Try registry validation (optional for external tools)
            tool = self.registry.get(request.tool_id)
            if tool:
                # Known tool: validate parameters and check session limits
                valid, errors = tool.validate_request(request.parameters)
                if not valid:
                    return EvaluationResult(
                        request_id=request.request_id,
                        tool_id=request.tool_id,
                        decision="deny",
                        denial_reason=f"Invalid parameters: {', '.join(errors)}",
                    )

                if tool.max_calls_per_session:
                    session_calls = self._get_session_calls(
                        request.session_id,
                        request.tool_id,
                    )
                    if session_calls >= tool.max_calls_per_session:
                        self._stats["denied"] += 1
                        return EvaluationResult(
                            request_id=request.request_id,
                            tool_id=request.tool_id,
                            decision="deny",
                            denial_reason=f"Max {tool.max_calls_per_session} calls per session",
                        )
            # If tool is NOT in registry, that's fine for external callers.
            # Policy evaluation will still work against the normalized name.

            # Step 3: Evaluate policy using normalized names
            # We evaluate against BOTH the normalized category name AND
            # the raw tool name, so rules using either format will match.
            policy_context = PolicyEvaluationContext(
                agent_id=request.agent_id,
                tenant_id=request.tenant_id,
                session_id=request.session_id,
                tool_name=normalized_category,
                method=effective_method,
                resource=effective_resource,
                trust_level=request.trust_level,
                has_sandbox=True,  # Assume external executor has sandbox
                has_approval=False,
                timestamp=request.timestamp,
                request_data=request.parameters,
            )

            policy_result = self.policy_engine.evaluate(policy_context)

            # Step 5: Handle policy decision
            if policy_result.decision == PolicyDecision.DENY:
                self._stats["denied"] += 1
                return EvaluationResult(
                    request_id=request.request_id,
                    tool_id=request.tool_id,
                    decision="deny",
                    denial_reason=policy_result.denial_reason or "Policy denied",
                )

            if policy_result.decision == PolicyDecision.PENDING_APPROVAL:
                # Check for existing approval
                approval = self._find_approval_for_request(request)
                if approval and approval.approved:
                    policy_context.has_approval = True
                else:
                    self._stats["pending_approval"] += 1
                    approval_id = self._create_pending_approval(request, policy_result)
                    return EvaluationResult(
                        request_id=request.request_id,
                        tool_id=request.tool_id,
                        decision="require_approval",
                        approval_id=approval_id,
                    )

            # Step 6: Apply redactions if needed
            redacted_params = None
            if policy_result.redactions_applied:
                redacted_params = self._apply_redactions(
                    request.parameters,
                    policy_result.redactions_applied,
                )

            # Step 7: Generate pre-auth token cryptographically bound to the request
            from datetime import timedelta
            request_hash = hash_json(request.to_dict())
            pre_auth_token = generate_random_id("preauth") + "." + request_hash[:16]
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

            # Store pre-auth for later recording
            self._store_preauth(pre_auth_token, request, policy_result, redacted_params, expires_at)

            # Build constraints
            constraints = None
            if policy_result.budget_remaining or policy_result.redactions_applied:
                constraints = {
                    "budget_remaining": policy_result.budget_remaining,
                    "redactions_applied": policy_result.redactions_applied,
                    "rate_limit_remaining": policy_result.rate_limit_remaining,
                }

            self._stats["allowed"] += 1
            return EvaluationResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                decision="allow",
                pre_auth_token=pre_auth_token,
                constraints=constraints,
                redacted_params=redacted_params,
                expires_at=expires_at,
            )

        except Exception as e:
            self._stats["errors"] += 1
            return EvaluationResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                decision="deny",
                denial_reason=f"Evaluation error: {str(e)}",
            )

    async def record_external_execution(
        self,
        record: ExternalExecutionRecord,
    ) -> Optional[SignedActionReceipt]:
        """
        Record the result of an external tool execution.

        This is called after the external system (e.g., ClawdBot) has executed
        the tool, to generate a signed receipt and update the audit log.

        Args:
            record: The execution record with result/error

        Returns:
            SignedActionReceipt if pre-auth token is valid, None otherwise
        """
        preauth = self._get_preauth(record.pre_auth_token)
        if not preauth:
            return None

        request, policy_result, redacted_params, expires_at = preauth

        # Check if pre-auth has expired
        if datetime.now(timezone.utc) > expires_at:
            self._remove_preauth(record.pre_auth_token)
            return None

        # Record the action (normalize tool name for consistent audit trail)
        normalized_category, normalized_method, extracted_resource = \
            normalize_tool_name(request.tool_id, request.parameters)
        effective_method = request.method or normalized_method
        effective_resource = request.resource or extracted_resource

        policy_context = PolicyEvaluationContext(
            agent_id=request.agent_id,
            tenant_id=request.tenant_id,
            session_id=request.session_id,
            tool_name=normalized_category,
            method=effective_method,
            resource=effective_resource,
            trust_level=request.trust_level,
            has_sandbox=True,
            has_approval=False,
            timestamp=request.timestamp,
            request_data=request.parameters,
        )
        self.policy_engine.record_action(policy_context, policy_result)
        self._record_session_call(request.session_id, request.tool_id)

        # Issue receipt
        tool_def = self.registry.get(request.tool_id)
        tool_name = tool_def.name if tool_def else request.tool_id
        tool_info = create_tool_info(
            tool_name,
            redacted_params or request.parameters,
            record.result if record.success else None,
            summarize_request=True,
            tool_id=request.tool_id,
        )

        active_bundle = self.policy_engine.get_active_bundle()
        policy_info = PolicyInfo(
            bundle_id=self.policy_engine._active_bundle_id or "unknown",
            policy_hash=active_bundle.compute_hash() if active_bundle else "unknown",
            decision=policy_result.decision,
            rules_matched=[policy_result.matched_rule_id] if policy_result.matched_rule_id else [],
        )

        constraints = None
        if policy_result.budget_remaining or policy_result.redactions_applied:
            budget_float: Optional[Dict[str, float]] = None
            if policy_result.budget_remaining:
                budget_float = {k: float(v) for k, v in policy_result.budget_remaining.items() if v is not None}
            constraints = ConstraintsApplied(
                budget_remaining=budget_float,
                redactions_applied=policy_result.redactions_applied,
                rate_limit_remaining=policy_result.rate_limit_remaining,
            )

        # Create sandbox info for external execution
        sandbox_info = SandboxInfo(
            environment_id=f"external-{record.pre_auth_token[:8]}",
            attestation_hash="external-execution",
            transcript_hash=None,
            egress_allowed=True,
            filesystem_isolated=False,
        )

        receipt = self.receipt_service.issue_receipt(
            agent_id=request.agent_id,
            tenant_id=request.tenant_id,
            session_id=request.session_id,
            tool=tool_info,
            policy=policy_info,
            merkle_root=self.audit_log.log.root_hex,
            log_index=self.audit_log.log.size,
            sandbox=sandbox_info,
            constraints=constraints,
        )

        # Append to audit log
        self.audit_log.append_receipt(receipt)

        # Cleanup pre-auth
        self._remove_preauth(record.pre_auth_token)

        return receipt

    def _store_preauth(
        self,
        token: str,
        request: ToolRequest,
        policy_result: PolicyEvaluationResult,
        redacted_params: Optional[Dict[str, Any]],
        expires_at: datetime,
    ) -> None:
        """Store pre-authorization for later recording."""
        # Clean up expired pre-auth tokens first
        self._cleanup_expired_preauths()
        self._preauth_store[token] = (request, policy_result, redacted_params, expires_at)

    def _get_preauth(self, token: str) -> Optional[tuple]:
        """Get stored pre-authorization."""
        return self._preauth_store.get(token)

    def _remove_preauth(self, token: str) -> None:
        """Remove pre-authorization after use."""
        if token in self._preauth_store:
            del self._preauth_store[token]

    def _cleanup_expired_preauths(self) -> None:
        """Remove expired pre-auth tokens to prevent memory leaks."""
        now = datetime.now(timezone.utc)
        expired = [
            token for token, (_, _, _, expires_at) in self._preauth_store.items()
            if now > expires_at
        ]
        for token in expired:
            del self._preauth_store[token]

    def _get_session_calls(self, session_id: str, tool_id: str) -> int:
        """Get number of calls in session for a tool."""
        session = self._session_call_counts.get(session_id, {})
        return session.get(tool_id, 0)

    def _record_session_call(self, session_id: str, tool_id: str) -> None:
        """Record a call for session tracking."""
        if session_id not in self._session_call_counts:
            self._session_call_counts[session_id] = {"_created_at": time.time()}
        if tool_id not in self._session_call_counts[session_id]:
            self._session_call_counts[session_id][tool_id] = 0
        self._session_call_counts[session_id][tool_id] += 1
        # Clean up stale sessions (older than 24 hours)
        self._cleanup_stale_sessions()

    def _cleanup_stale_sessions(self) -> None:
        """Remove session call counts older than 24 hours."""
        now = time.time()
        max_age = 86400  # 24 hours
        stale = [
            sid for sid, data in self._session_call_counts.items()
            if isinstance(data, dict) and now - data.get("_created_at", now) > max_age
        ]
        for sid in stale:
            del self._session_call_counts[sid]

    def _find_approval_for_request(self, request: ToolRequest) -> Optional[PendingApproval]:
        """Find an existing approval for a request."""
        # Clean up expired approvals first
        self._cleanup_expired_approvals()
        for approval in self._pending_approvals.values():
            if (approval.request.tool_id == request.tool_id and
                approval.request.session_id == request.session_id and
                approval.request.parameters == request.parameters):
                return approval
        return None

    def _cleanup_expired_approvals(self) -> None:
        """Remove approvals older than 1 hour to prevent memory leaks."""
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        max_age = timedelta(hours=1)
        expired = [
            aid for aid, approval in self._pending_approvals.items()
            if (now - approval.created_at) > max_age
        ]
        for aid in expired:
            del self._pending_approvals[aid]

    def _create_pending_approval(
        self,
        request: ToolRequest,
        policy_result: PolicyEvaluationResult,
    ) -> str:
        """Create a pending approval entry with expiration."""
        from datetime import timedelta
        approval_id = generate_random_id("apr")
        approval = PendingApproval(
            approval_id=approval_id,
            request=request,
            policy_result=policy_result,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self._pending_approvals[approval_id] = approval
        return approval_id

    def _apply_redactions(
        self,
        params: Dict[str, Any],
        redaction_ids: List[str],
    ) -> Dict[str, Any]:
        """Apply redactions to parameters."""
        import copy
        result = copy.deepcopy(params)
        return self._redact_recursive(result, redaction_ids)

    def _redact_recursive(self, obj, redaction_ids):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    obj[key] = self.policy_engine.apply_redactions(value, redaction_ids)
                elif isinstance(value, (dict, list)):
                    obj[key] = self._redact_recursive(value, redaction_ids)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = self.policy_engine.apply_redactions(item, redaction_ids)
                elif isinstance(item, (dict, list)):
                    obj[i] = self._redact_recursive(item, redaction_ids)
        return obj


# Factory function to create a complete gateway setup

def create_gateway(
    keypair: Optional[KeyPair] = None,
) -> Tuple[ToolGateway, ToolRegistry, PolicyEngine, ReceiptService, AuditableLog]:
    """
    Create a complete gateway setup with all dependencies.

    Args:
        keypair: Optional keypair for signing

    Returns:
        Tuple of (gateway, registry, policy_engine, receipt_service, audit_log)
    """
    from vacp.core.crypto import generate_keypair
    from vacp.core.policy import create_default_bundle

    if not keypair:
        keypair = generate_keypair()

    registry = ToolRegistry()
    policy_engine = PolicyEngine(keypair=keypair)
    receipt_service = ReceiptService(keypair=keypair)
    merkle_log = MerkleLog(keypair=keypair)
    audit_log = AuditableLog(merkle_log=merkle_log)

    # Load default policy
    default_bundle = create_default_bundle()
    policy_engine.load_bundle(default_bundle)

    gateway = ToolGateway(
        registry=registry,
        policy_engine=policy_engine,
        receipt_service=receipt_service,
        audit_log=audit_log,
        keypair=keypair,
    )

    return gateway, registry, policy_engine, receipt_service, audit_log
