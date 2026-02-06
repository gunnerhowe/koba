"""
OpenAI Provider Integration

Provides secure integration with OpenAI's API including:
- Tool call interception
- Rate limiting
- Token tracking
- Response validation
"""

import json
import time
from datetime import datetime, timezone
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


class OpenAIProvider(AIProvider):
    """
    OpenAI API provider implementation.

    Supports GPT-4, GPT-3.5-turbo and other OpenAI models with function calling.
    """

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self._client = None
        self._last_request_timestamps: List[float] = []

    @property
    def provider_name(self) -> str:
        return "openai"

    def _get_client(self):
        """Get or create the OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.config.api_key,
                    base_url=self.config.base_url,
                    timeout=self.config.timeout,
                    max_retries=self.config.max_retries,
                )
            except ImportError:
                raise ProviderError(
                    "OpenAI package not installed. Install with: pip install openai"
                )
        return self._client

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Generate a completion using OpenAI's API."""
        self._check_rate_limit()

        client = self._get_client()
        model = request.model or self.config.model

        # Convert messages to OpenAI format
        messages = self._format_messages(request.messages)

        # Build request kwargs
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": request.temperature,
        }

        if request.max_tokens:
            kwargs["max_tokens"] = request.max_tokens

        if request.stop_sequences:
            kwargs["stop"] = request.stop_sequences

        # Add tools if provided
        if request.tools:
            kwargs["tools"] = self._format_tools(request.tools)
            kwargs["tool_choice"] = "auto"

        try:
            response = client.chat.completions.create(**kwargs)
            return self._parse_response(response)

        except Exception as e:
            error_message = str(e)

            # Check for specific error types
            if "rate_limit" in error_message.lower():
                # Try to extract retry-after
                retry_after = None
                if hasattr(e, "response") and hasattr(e.response, "headers"):
                    retry_after = e.response.headers.get("retry-after")
                    if retry_after:
                        retry_after = float(retry_after)
                raise RateLimitError(error_message, retry_after)

            if "authentication" in error_message.lower() or "api key" in error_message.lower():
                raise AuthenticationError(error_message)

            raise ProviderError(f"OpenAI API error: {error_message}")

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
            # Calculate wait time
            oldest = self._last_request_timestamps[0]
            wait_time = 60 - (current_time - oldest)
            if wait_time > 0:
                raise RateLimitError(
                    f"Rate limit exceeded. Limit: {self.config.requests_per_minute}/min",
                    retry_after=wait_time,
                )

        self._last_request_timestamps.append(current_time)

    def _format_messages(self, messages: List[Message]) -> List[Dict[str, Any]]:
        """Convert internal messages to OpenAI format."""
        result: List[Dict[str, Any]] = []
        for msg in messages:
            formatted: Dict[str, Any] = {"role": msg.role.value}

            if msg.content is not None:
                formatted["content"] = msg.content

            if msg.tool_calls:
                formatted["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in msg.tool_calls
                ]

            if msg.tool_call_id:
                formatted["tool_call_id"] = msg.tool_call_id

            if msg.name:
                formatted["name"] = msg.name

            result.append(formatted)

        return result

    def _format_tools(self, tools: List[ToolDefinition]) -> List[Dict[str, Any]]:
        """Convert tool definitions to OpenAI format."""
        return [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                },
            }
            for tool in tools
        ]

    def _parse_response(self, response) -> CompletionResponse:
        """Parse OpenAI response to internal format."""
        choice = response.choices[0]
        message = choice.message

        # Parse tool calls if present
        tool_calls = None
        if message.tool_calls:
            tool_calls = []
            for tc in message.tool_calls:
                try:
                    arguments = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    arguments = {}

                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=arguments,
                    raw_arguments=tc.function.arguments,
                ))

        # Build internal message
        internal_message = Message(
            role=MessageRole(message.role),
            content=message.content,
            tool_calls=tool_calls,
        )

        # Parse usage stats
        usage = None
        if response.usage:
            usage = UsageStats(
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
            )

        result = CompletionResponse(
            message=internal_message,
            usage=usage,
            model=response.model,
            finish_reason=choice.finish_reason,
        )

        self._update_usage(result)
        return result

    def count_tokens(self, text: str) -> int:
        """Count tokens using tiktoken if available."""
        try:
            import tiktoken
            encoding = tiktoken.encoding_for_model(self.config.model)
            return len(encoding.encode(text))
        except ImportError:
            # Fall back to rough estimate
            return super().count_tokens(text)
        except Exception:
            return super().count_tokens(text)


class OpenAIProviderWithInterception(OpenAIProvider):
    """
    OpenAI provider with built-in VACP tool interception.

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
                # Use modified call if provided
                allowed_calls.append(result.modified_tool_call or tool_call)
            elif result.action == InterceptionAction.DENY:
                blocked.append(tool_call)
                if result.denial_reason:
                    violations.append(result.denial_reason)
            elif result.action == InterceptionAction.AUDIT_ONLY:
                # Allow but log
                allowed_calls.append(result.modified_tool_call or tool_call)
            elif result.action == InterceptionAction.REQUIRE_APPROVAL:
                # Block until approved
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
            # All tool calls were blocked
            response.message = Message(
                role=response.message.role,
                content=response.message.content or "Tool calls were blocked by policy.",
                tool_calls=None,
            )

        return response


# Import at end to avoid circular dependency
from vacp.providers.interceptor import ToolInterceptor, InterceptionAction
