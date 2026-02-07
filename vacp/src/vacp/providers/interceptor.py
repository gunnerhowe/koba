"""
Tool Call Interceptor for VACP

Intercepts and validates AI tool calls against VACP policies before execution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
import logging

from vacp.providers.base import ToolCall, CompletionResponse, Message
from vacp.core.policy import PolicyEngine, PolicyDecision, PolicyEvaluationContext, PolicyEvaluationResult
from vacp.security.injection_detection import PromptInjectionDetector
from vacp.security.sanitizer import InputSanitizer, SanitizationAction


logger = logging.getLogger(__name__)


class InterceptionAction(str, Enum):
    """Actions that can be taken on an intercepted tool call."""
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    AUDIT_ONLY = "audit_only"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class InterceptionResult:
    """Result of intercepting a tool call."""
    action: InterceptionAction
    tool_call: ToolCall
    modified_tool_call: Optional[ToolCall] = None
    denial_reason: Optional[str] = None
    policy_decision: Optional[PolicyDecision] = None
    audit_id: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "action": self.action.value,
            "tool_call": self.tool_call.to_dict(),
            "denial_reason": self.denial_reason,
            "warnings": self.warnings,
        }
        if self.modified_tool_call:
            result["modified_tool_call"] = self.modified_tool_call.to_dict()
        if self.audit_id:
            result["audit_id"] = self.audit_id
        return result


class ToolInterceptor:
    """
    Intercepts AI tool calls and validates them against VACP policies.

    Features:
    - Policy-based access control
    - Parameter validation and sanitization
    - Injection attack detection
    - Audit logging
    - Approval workflows
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        sanitizer: Optional[InputSanitizer] = None,
        injection_detector: Optional[PromptInjectionDetector] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.policy_engine = policy_engine
        self.sanitizer = sanitizer or InputSanitizer(mode="strict")
        self.injection_detector = injection_detector or PromptInjectionDetector()
        self.audit_callback = audit_callback

        # Approval queue for tools requiring human approval
        self._pending_approvals: Dict[str, InterceptionResult] = {}

        # Tool-specific handlers
        self._tool_validators: Dict[str, Callable[[ToolCall], Tuple[bool, Optional[str]]]] = {}
        self._tool_sanitizers: Dict[str, Callable[[ToolCall], ToolCall]] = {}

    def register_tool_validator(
        self,
        tool_name: str,
        validator: Callable[[ToolCall], Tuple[bool, Optional[str]]],
    ) -> None:
        """Register a custom validator for a specific tool."""
        self._tool_validators[tool_name] = validator

    def register_tool_sanitizer(
        self,
        tool_name: str,
        sanitizer: Callable[[ToolCall], ToolCall],
    ) -> None:
        """Register a custom sanitizer for a specific tool."""
        self._tool_sanitizers[tool_name] = sanitizer

    def intercept(
        self,
        tool_call: ToolCall,
        tenant_id: str,
        agent_id: str,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> InterceptionResult:
        """
        Intercept and validate a tool call.

        Args:
            tool_call: The tool call to intercept
            tenant_id: The tenant making the call
            agent_id: The agent making the call
            session_id: Optional session ID
            context: Additional context for policy evaluation

        Returns:
            InterceptionResult with the action to take
        """
        warnings: List[str] = []
        metadata: Dict[str, Any] = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Step 1: Check for injection attacks in parameters
        injection_result = self._check_injection(tool_call)
        if injection_result:
            return InterceptionResult(
                action=InterceptionAction.DENY,
                tool_call=tool_call,
                denial_reason=f"Injection attack detected: {injection_result}",
                metadata=metadata,
            )

        # Step 2: Sanitize parameters
        sanitized_call, sanitize_warnings = self._sanitize_parameters(tool_call)
        warnings.extend(sanitize_warnings)

        if sanitized_call is None:
            return InterceptionResult(
                action=InterceptionAction.DENY,
                tool_call=tool_call,
                denial_reason="Parameters failed sanitization",
                warnings=warnings,
                metadata=metadata,
            )

        # Step 3: Custom tool validation
        if tool_call.name in self._tool_validators:
            is_valid, error = self._tool_validators[tool_call.name](sanitized_call)
            if not is_valid:
                return InterceptionResult(
                    action=InterceptionAction.DENY,
                    tool_call=tool_call,
                    denial_reason=error or "Tool validation failed",
                    warnings=warnings,
                    metadata=metadata,
                )

        # Step 4: Policy evaluation
        if self.policy_engine:
            policy_result = self._evaluate_policy(
                sanitized_call, tenant_id, agent_id, context
            )
            metadata["policy_result"] = policy_result.to_dict() if hasattr(policy_result, 'to_dict') else str(policy_result)

            if policy_result.decision == PolicyDecision.DENY:
                return InterceptionResult(
                    action=InterceptionAction.DENY,
                    tool_call=tool_call,
                    denial_reason=policy_result.denial_reason or "Policy denied",
                    warnings=warnings,
                    metadata=metadata,
                )

            # Check for pending approval
            if policy_result.decision == PolicyDecision.PENDING_APPROVAL:
                result = InterceptionResult(
                    action=InterceptionAction.REQUIRE_APPROVAL,
                    tool_call=tool_call,
                    modified_tool_call=sanitized_call if sanitized_call != tool_call else None,
                    warnings=warnings,
                    metadata=metadata,
                )
                # Store for approval
                approval_id = f"{tool_call.id}_{datetime.now(timezone.utc).timestamp()}"
                self._pending_approvals[approval_id] = result
                result.audit_id = approval_id
                return result

        # Step 5: Audit logging
        if self.audit_callback:
            audit_entry = {
                "type": "tool_call_intercepted",
                "tool_call": tool_call.to_dict(),
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "session_id": session_id,
                "action": InterceptionAction.ALLOW.value,
                "timestamp": metadata["timestamp"],
            }
            self.audit_callback(audit_entry)

        # Tool call is allowed
        return InterceptionResult(
            action=InterceptionAction.ALLOW,
            tool_call=tool_call,
            modified_tool_call=sanitized_call if sanitized_call != tool_call else None,
            warnings=warnings,
            metadata=metadata,
        )

    def intercept_multiple(
        self,
        tool_calls: List[ToolCall],
        tenant_id: str,
        agent_id: str,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[InterceptionResult]:
        """Intercept multiple tool calls."""
        return [
            self.intercept(tc, tenant_id, agent_id, session_id, context)
            for tc in tool_calls
        ]

    def approve_tool_call(self, approval_id: str, approver_id: str) -> bool:
        """Approve a pending tool call."""
        if approval_id not in self._pending_approvals:
            return False

        result = self._pending_approvals[approval_id]
        result.action = InterceptionAction.ALLOW
        result.metadata["approved_by"] = approver_id
        result.metadata["approved_at"] = datetime.now(timezone.utc).isoformat()

        if self.audit_callback:
            self.audit_callback({
                "type": "tool_call_approved",
                "approval_id": approval_id,
                "approver_id": approver_id,
                "tool_call": result.tool_call.to_dict(),
                "timestamp": result.metadata["approved_at"],
            })

        del self._pending_approvals[approval_id]
        return True

    def reject_tool_call(self, approval_id: str, rejector_id: str, reason: str) -> bool:
        """Reject a pending tool call."""
        if approval_id not in self._pending_approvals:
            return False

        result = self._pending_approvals[approval_id]
        result.action = InterceptionAction.DENY
        result.denial_reason = reason
        result.metadata["rejected_by"] = rejector_id
        result.metadata["rejected_at"] = datetime.now(timezone.utc).isoformat()

        if self.audit_callback:
            self.audit_callback({
                "type": "tool_call_rejected",
                "approval_id": approval_id,
                "rejector_id": rejector_id,
                "reason": reason,
                "tool_call": result.tool_call.to_dict(),
                "timestamp": result.metadata["rejected_at"],
            })

        del self._pending_approvals[approval_id]
        return True

    def get_pending_approvals(self) -> Dict[str, InterceptionResult]:
        """Get all pending approvals."""
        return dict(self._pending_approvals)

    def _check_injection(self, tool_call: ToolCall) -> Optional[str]:
        """Check for injection attacks in tool call parameters."""
        # Check each parameter value
        for param_name, param_value in tool_call.arguments.items():
            if isinstance(param_value, str):
                attempts = self.injection_detector.detect(param_value)
                if attempts:
                    high_severity = [a for a in attempts if a.severity.value in ("critical", "high")]
                    if high_severity:
                        return f"Parameter '{param_name}': {high_severity[0].pattern_name}"

        # Check raw arguments if available
        if tool_call.raw_arguments:
            attempts = self.injection_detector.detect(tool_call.raw_arguments)
            if attempts:
                high_severity = [a for a in attempts if a.severity.value in ("critical", "high")]
                if high_severity:
                    return f"Raw arguments: {high_severity[0].pattern_name}"

        return None

    def _sanitize_parameters(
        self,
        tool_call: ToolCall,
    ) -> Tuple[Optional[ToolCall], List[str]]:
        """Sanitize tool call parameters."""
        warnings = []
        modified = False
        new_arguments = {}

        # Use custom sanitizer if registered
        if tool_call.name in self._tool_sanitizers:
            return self._tool_sanitizers[tool_call.name](tool_call), []

        # Default sanitization
        for param_name, param_value in tool_call.arguments.items():
            if isinstance(param_value, str):
                result = self.sanitizer.sanitize(param_value)
                if result.action == SanitizationAction.BLOCKED:
                    return None, [f"Parameter '{param_name}' blocked by sanitizer"]
                if result.action == SanitizationAction.SANITIZED:
                    new_arguments[param_name] = result.sanitized
                    warnings.append(f"Parameter '{param_name}' was sanitized")
                    modified = True
                else:
                    new_arguments[param_name] = param_value
            else:
                new_arguments[param_name] = param_value

        if modified:
            return ToolCall(
                id=tool_call.id,
                name=tool_call.name,
                arguments=new_arguments,
                raw_arguments=tool_call.raw_arguments,
            ), warnings

        return tool_call, warnings

    def _evaluate_policy(
        self,
        tool_call: ToolCall,
        tenant_id: str,
        agent_id: str,
        context: Optional[Dict[str, Any]],
    ) -> PolicyEvaluationResult:
        """Evaluate tool call against policies."""
        if not self.policy_engine:
            # No policy engine - allow by default
            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                matched_rule=None,
                matched_rule_id=None,
            )

        # Build context for policy evaluation
        eval_context = PolicyEvaluationContext(
            agent_id=agent_id,
            tenant_id=tenant_id,
            session_id=context.get("session_id", "") if context else "",
            tool_name=tool_call.name,
            request_data=tool_call.arguments,
        )

        return self.policy_engine.evaluate(eval_context)


class ResponseValidator:
    """
    Validates AI responses before returning them to the user.

    Checks for:
    - Sensitive data leakage
    - Policy violations in generated content
    - Prompt injection in responses
    """

    def __init__(
        self,
        injection_detector: Optional[PromptInjectionDetector] = None,
        sensitive_patterns: Optional[List[str]] = None,
    ):
        self.injection_detector = injection_detector or PromptInjectionDetector()
        self.sensitive_patterns = sensitive_patterns or []

        # Default patterns for sensitive data
        self._sensitive_data_patterns = [
            r"(?i)password\s*[=:]\s*['\"]?[\w!@#$%^&*]+",
            r"(?i)api[_-]?key\s*[=:]\s*['\"]?[\w-]+",
            r"(?i)secret\s*[=:]\s*['\"]?[\w-]+",
            r"(?i)token\s*[=:]\s*['\"]?[\w.-]+",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",  # SSN pattern
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # Credit card pattern
        ]

    def validate(
        self,
        response: CompletionResponse,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, List[str], Optional[CompletionResponse]]:
        """
        Validate an AI response.

        Returns:
            (is_valid, list_of_issues, optional_modified_response)
        """
        issues = []
        content = response.message.content

        if not content:
            return True, [], None

        # Check for injection attempts in response
        injection_attempts = self.injection_detector.detect(content)
        if injection_attempts:
            high_severity = [a for a in injection_attempts if a.severity.value in ("critical", "high")]
            if high_severity:
                issues.append(f"Potential injection in response: {high_severity[0].pattern_name}")

        # Check for sensitive data patterns
        import re
        for pattern in self._sensitive_data_patterns + self.sensitive_patterns:
            if re.search(pattern, content):
                issues.append(f"Potential sensitive data exposure (pattern: {pattern[:30]}...)")

        # If issues found, response is invalid
        if issues:
            return False, issues, None

        return True, [], None

    def filter_response(
        self,
        response: CompletionResponse,
    ) -> CompletionResponse:
        """
        Filter sensitive data from a response.

        Returns a modified response with sensitive data redacted.
        """
        content = response.message.content
        if not content:
            return response

        import re
        filtered_content = content

        # Redact sensitive patterns
        for pattern in self._sensitive_data_patterns:
            filtered_content = re.sub(pattern, "[REDACTED]", filtered_content)

        if filtered_content != content:
            return CompletionResponse(
                message=Message(
                    role=response.message.role,
                    content=filtered_content,
                    tool_calls=response.message.tool_calls,
                ),
                usage=response.usage,
                model=response.model,
                finish_reason=response.finish_reason,
                metadata={**(response.metadata or {}), "filtered": True},
            )

        return response
