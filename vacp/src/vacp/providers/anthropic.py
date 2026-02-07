"""
Anthropic Provider Integration

Provides secure integration with Anthropic's Claude API including:
- Tool call interception
- Rate limiting
- Token tracking
- Response validation
"""

import json
import time
from typing import Any, Dict, List, Optional
import logging

from vacp.providers.base import (
    AIProvider,
    ProviderConfig,
    ToolCall,
    ToolDefinition,
    Message,
    MessageRole,
    CompletionRequest,
    CompletionResponse,
    UsageStats,
    ProviderError,
    RateLimitError,
    AuthenticationError,
)

logger = logging.getLogger(__name__)


class AnthropicProvider(AIProvider):
    """
    Anthropic Claude API provider implementation.

    Supports Claude 3 Opus, Sonnet, Haiku and other Claude models with tool use.
    """

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self._client = None
        self._last_request_timestamps: List[float] = []

        # Default to Claude 3 Sonnet if not specified
        if config.model == "gpt-4":  # Default from base config
            config.model = "claude-3-sonnet-20240229"

    @property
    def provider_name(self) -> str:
        return "anthropic"

    def _get_client(self):
        """Get or create the Anthropic client."""
        if self._client is None:
            try:
                from anthropic import Anthropic
                kwargs = {
                    "api_key": self.config.api_key,
                    "timeout": self.config.timeout,
                    "max_retries": self.config.max_retries,
                }
                if self.config.base_url:
                    kwargs["base_url"] = self.config.base_url
                self._client = Anthropic(**kwargs)
            except ImportError:
                raise ProviderError(
                    "Anthropic package not installed. Install with: pip install anthropic"
                )
        return self._client

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Generate a completion using Anthropic's API."""
        self._check_rate_limit()

        client = self._get_client()
        model = request.model or self.config.model

        # Extract system message and convert others to Anthropic format
        system_message, messages = self._format_messages(request.messages)

        # Build request kwargs
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": request.max_tokens or 4096,
        }

        if system_message:
            kwargs["system"] = system_message

        if request.stop_sequences:
            kwargs["stop_sequences"] = request.stop_sequences

        # Temperature is optional in Anthropic
        if request.temperature != 0.7:  # Non-default
            kwargs["temperature"] = request.temperature

        # Add tools if provided
        if request.tools:
            kwargs["tools"] = self._format_tools(request.tools)

        try:
            response = client.messages.create(**kwargs)
            return self._parse_response(response)

        except Exception as e:
            error_message = str(e)

            # Check for specific error types
            if "rate_limit" in error_message.lower():
                retry_after = None
                if hasattr(e, "response") and hasattr(e.response, "headers"):
                    retry_after = e.response.headers.get("retry-after")
                    if retry_after:
                        retry_after = float(retry_after)
                raise RateLimitError(error_message, retry_after)

            if "authentication" in error_message.lower() or "api key" in error_message.lower():
                raise AuthenticationError(error_message)

            raise ProviderError(f"Anthropic API error: {error_message}")

    def validate_tool_call(self, tool_call: ToolCall) -> bool:
        """Validate a tool call."""
        # Basic validation - tool name should be valid identifier
        if not tool_call.name or not tool_call.name.replace("_", "").isalnum():
            return False

        # Arguments should be a dict
        if not isinstance(tool_call.arguments, dict):
            return False

        return True

    def _check_rate_limit(self) -> None:
        """Check and enforce rate limits."""
        if not self.config.requests_per_minute:
            return

        current_time = time.time()

        # Remove timestamps older than 1 minute
        self._last_request_timestamps = [
            ts for ts in self._last_request_timestamps
            if current_time - ts < 60
        ]

        if len(self._last_request_timestamps) >= self.config.requests_per_minute:
            oldest = self._last_request_timestamps[0]
            wait_time = 60 - (current_time - oldest)
            if wait_time > 0:
                raise RateLimitError(
                    f"Rate limit exceeded. Limit: {self.config.requests_per_minute}/min",
                    retry_after=wait_time,
                )

        self._last_request_timestamps.append(current_time)

    def _format_messages(self, messages: List[Message]) -> tuple[Optional[str], List[Dict[str, Any]]]:
        """
        Convert internal messages to Anthropic format.

        Returns (system_message, other_messages) since Anthropic handles system separately.
        """
        system_message: Optional[str] = None
        result: List[Dict[str, Any]] = []

        for msg in messages:
            if msg.role == MessageRole.SYSTEM:
                # Anthropic handles system message separately
                system_message = msg.content
                continue

            formatted: Dict[str, Any] = {"role": msg.role.value}

            # Build content array for Anthropic
            content: List[Dict[str, Any]] = []

            if msg.content:
                content.append({"type": "text", "text": msg.content})

            if msg.tool_calls:
                # Anthropic uses tool_use blocks
                for tc in msg.tool_calls:
                    content.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    })

            if msg.role == MessageRole.TOOL:
                # Tool results in Anthropic format
                formatted["role"] = "user"  # Tool results come from user role
                content = [{
                    "type": "tool_result",
                    "tool_use_id": msg.tool_call_id,
                    "content": msg.content,
                }]

            formatted["content"] = content if content else msg.content or ""
            result.append(formatted)

        return system_message, result

    def _format_tools(self, tools: List[ToolDefinition]) -> List[Dict[str, Any]]:
        """Convert tool definitions to Anthropic format."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.parameters,
            }
            for tool in tools
        ]

    def _parse_response(self, response) -> CompletionResponse:
        """Parse Anthropic response to internal format."""
        # Extract content from response
        content_text = None
        tool_calls = []

        for block in response.content:
            if block.type == "text":
                content_text = block.text
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=block.input if isinstance(block.input, dict) else {},
                    raw_arguments=json.dumps(block.input) if block.input else None,
                ))

        # Build internal message
        internal_message = Message(
            role=MessageRole.ASSISTANT,
            content=content_text,
            tool_calls=tool_calls if tool_calls else None,
        )

        # Parse usage stats
        usage = None
        if response.usage:
            usage = UsageStats(
                prompt_tokens=response.usage.input_tokens,
                completion_tokens=response.usage.output_tokens,
                total_tokens=response.usage.input_tokens + response.usage.output_tokens,
            )

        result = CompletionResponse(
            message=internal_message,
            usage=usage,
            model=response.model,
            finish_reason=response.stop_reason,
        )

        self._update_usage(result)
        return result

    def count_tokens(self, text: str) -> int:
        """Estimate token count for Anthropic models."""
        # Claude uses a different tokenizer than OpenAI
        # This is a rough estimate: ~3.5 characters per token for Claude
        return int(len(text) / 3.5)


class AnthropicProviderWithInterception(AnthropicProvider):
    """
    Anthropic provider with built-in VACP tool interception.

    Automatically intercepts and validates all tool calls before execution.
    """

    def __init__(
        self,
        config: ProviderConfig,
        interceptor: Optional["ToolInterceptor"] = None,
    ):
        super().__init__(config)
        self._interceptor = interceptor

    def set_interceptor(self, interceptor: "ToolInterceptor") -> None:
        """Set the tool interceptor."""
        self._interceptor = interceptor

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Generate a completion with tool call interception."""
        response = super().complete(request)

        # If no interceptor or no tool calls, return as-is
        if not self._interceptor or not response.message.tool_calls:
            return response

        # Intercept all tool calls
        intercepted = []
        blocked = []
        allowed_calls = []
        violations = []

        for tool_call in response.message.tool_calls:
            result = self._interceptor.intercept(
                tool_call=tool_call,
                tenant_id=request.tenant_id or "default",
                agent_id=request.agent_id or "unknown",
                session_id=request.session_id,
            )

            intercepted.append(tool_call)

            if result.action == InterceptionAction.ALLOW:
                allowed_calls.append(result.modified_tool_call or tool_call)
            elif result.action == InterceptionAction.DENY:
                blocked.append(tool_call)
                if result.denial_reason:
                    violations.append(result.denial_reason)
            elif result.action == InterceptionAction.AUDIT_ONLY:
                allowed_calls.append(result.modified_tool_call or tool_call)
            elif result.action == InterceptionAction.REQUIRE_APPROVAL:
                blocked.append(tool_call)
                violations.append(f"Requires approval: {result.audit_id}")

        # Update response with interception results
        response.intercepted_tool_calls = intercepted
        response.blocked_tool_calls = blocked if blocked else None
        response.policy_violations = violations if violations else None

        # Update message with only allowed tool calls
        if allowed_calls:
            response.message = Message(
                role=response.message.role,
                content=response.message.content,
                tool_calls=allowed_calls,
            )
        else:
            response.message = Message(
                role=response.message.role,
                content=response.message.content or "Tool calls were blocked by policy.",
                tool_calls=None,
            )

        return response


# Import at end to avoid circular dependency
from vacp.providers.interceptor import ToolInterceptor, InterceptionAction  # noqa: E402
