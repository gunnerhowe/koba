"""
Base AI Provider Interface

Defines the common interface for all AI provider integrations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
import json


class ProviderError(Exception):
    """Base exception for provider errors."""
    pass


class RateLimitError(ProviderError):
    """Raised when rate limit is exceeded."""
    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class AuthenticationError(ProviderError):
    """Raised when authentication fails."""
    pass


class MessageRole(str, Enum):
    """Message roles in a conversation."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class ToolCall:
    """Represents a tool call from the AI."""
    id: str
    name: str
    arguments: Dict[str, Any]
    raw_arguments: Optional[str] = None  # Original JSON string

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolCall":
        return cls(
            id=data["id"],
            name=data["name"],
            arguments=data.get("arguments", {}),
            raw_arguments=data.get("raw_arguments"),
        )


@dataclass
class ToolResult:
    """Represents the result of a tool execution."""
    tool_call_id: str
    content: str
    is_error: bool = False
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_call_id": self.tool_call_id,
            "content": self.content,
            "is_error": self.is_error,
        }


@dataclass
class Message:
    """Represents a message in a conversation."""
    role: MessageRole
    content: Optional[str] = None
    name: Optional[str] = None  # For tool results
    tool_calls: Optional[List[ToolCall]] = None
    tool_call_id: Optional[str] = None  # For tool results
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"role": self.role.value}
        if self.content is not None:
            result["content"] = self.content
        if self.name is not None:
            result["name"] = self.name
        if self.tool_calls:
            result["tool_calls"] = [tc.to_dict() for tc in self.tool_calls]
        if self.tool_call_id:
            result["tool_call_id"] = self.tool_call_id
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Message":
        tool_calls = None
        if "tool_calls" in data:
            tool_calls = [ToolCall.from_dict(tc) for tc in data["tool_calls"]]

        return cls(
            role=MessageRole(data["role"]),
            content=data.get("content"),
            name=data.get("name"),
            tool_calls=tool_calls,
            tool_call_id=data.get("tool_call_id"),
        )


@dataclass
class ToolDefinition:
    """Definition of a tool that can be called by the AI."""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema for parameters
    handler: Optional[Callable[..., Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }


@dataclass
class CompletionRequest:
    """Request for an AI completion."""
    messages: List[Message]
    tools: Optional[List[ToolDefinition]] = None
    model: Optional[str] = None
    temperature: float = 0.7
    max_tokens: Optional[int] = None
    stop_sequences: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

    # VACP-specific fields
    tenant_id: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class UsageStats:
    """Token usage statistics."""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass
class CompletionResponse:
    """Response from an AI completion."""
    message: Message
    usage: Optional[UsageStats] = None
    model: Optional[str] = None
    finish_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    # VACP-specific fields
    intercepted_tool_calls: Optional[List[ToolCall]] = None
    blocked_tool_calls: Optional[List[ToolCall]] = None
    policy_violations: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "message": self.message.to_dict(),
            "finish_reason": self.finish_reason,
        }
        if self.usage:
            result["usage"] = self.usage.to_dict()
        if self.model:
            result["model"] = self.model
        if self.intercepted_tool_calls:
            result["intercepted_tool_calls"] = [tc.to_dict() for tc in self.intercepted_tool_calls]
        if self.blocked_tool_calls:
            result["blocked_tool_calls"] = [tc.to_dict() for tc in self.blocked_tool_calls]
        if self.policy_violations:
            result["policy_violations"] = self.policy_violations
        return result


@dataclass
class ProviderConfig:
    """Configuration for an AI provider."""
    api_key: str
    model: str = "gpt-4"
    base_url: Optional[str] = None
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0

    # Rate limiting
    requests_per_minute: Optional[int] = None
    tokens_per_minute: Optional[int] = None

    # VACP integration
    enable_tool_interception: bool = True
    enable_response_validation: bool = True
    log_all_requests: bool = True


class AIProvider(ABC):
    """
    Abstract base class for AI providers.

    Implementations must be:
    - Thread-safe
    - Support tool calling
    - Support streaming (optional)
    """

    def __init__(self, config: ProviderConfig):
        self.config = config
        self._request_count = 0
        self._token_count = 0
        self._last_request_time: Optional[datetime] = None

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the name of this provider (e.g., 'openai', 'anthropic')."""
        pass

    @abstractmethod
    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """
        Generate a completion for the given request.

        Args:
            request: The completion request

        Returns:
            The completion response

        Raises:
            ProviderError: If the request fails
            RateLimitError: If rate limit is exceeded
            AuthenticationError: If authentication fails
        """
        pass

    @abstractmethod
    def validate_tool_call(self, tool_call: ToolCall) -> bool:
        """
        Validate a tool call before execution.

        Returns True if the tool call is valid, False otherwise.
        """
        pass

    def format_tool_result(self, result: ToolResult) -> Message:
        """Format a tool result as a message."""
        return Message(
            role=MessageRole.TOOL,
            content=result.content,
            tool_call_id=result.tool_call_id,
        )

    def count_tokens(self, text: str) -> int:
        """
        Estimate the number of tokens in a text.

        This is a rough estimate; providers may override with more accurate counting.
        """
        # Rough estimate: 1 token ≈ 4 characters
        return len(text) // 4

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics for this provider."""
        return {
            "request_count": self._request_count,
            "token_count": self._token_count,
            "last_request_time": self._last_request_time.isoformat() if self._last_request_time else None,
        }

    def reset_usage_stats(self) -> None:
        """Reset usage statistics."""
        self._request_count = 0
        self._token_count = 0
        self._last_request_time = None

    def _update_usage(self, response: CompletionResponse) -> None:
        """Update usage statistics from a response."""
        self._request_count += 1
        self._last_request_time = datetime.now(timezone.utc)
        if response.usage:
            self._token_count += response.usage.total_tokens


class MockProvider(AIProvider):
    """
    Mock AI provider for testing.

    Allows setting up canned responses and tool calls.
    """

    def __init__(self, config: Optional[ProviderConfig] = None):
        if config is None:
            config = ProviderConfig(api_key="mock-key", model="mock-model")
        super().__init__(config)
        self._responses: List[CompletionResponse] = []
        self._response_index = 0
        self._requests: List[CompletionRequest] = []

    @property
    def provider_name(self) -> str:
        return "mock"

    def add_response(self, response: CompletionResponse) -> None:
        """Add a canned response."""
        self._responses.append(response)

    def add_text_response(self, text: str) -> None:
        """Add a simple text response."""
        self._responses.append(CompletionResponse(
            message=Message(role=MessageRole.ASSISTANT, content=text),
            finish_reason="stop",
        ))

    def add_tool_call_response(self, tool_calls: List[ToolCall]) -> None:
        """Add a response with tool calls."""
        self._responses.append(CompletionResponse(
            message=Message(role=MessageRole.ASSISTANT, tool_calls=tool_calls),
            finish_reason="tool_calls",
        ))

    def get_requests(self) -> List[CompletionRequest]:
        """Get all requests made to this provider."""
        return self._requests

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Return the next canned response."""
        self._requests.append(request)

        if self._response_index >= len(self._responses):
            # Default response if no canned responses
            return CompletionResponse(
                message=Message(role=MessageRole.ASSISTANT, content="Mock response"),
                finish_reason="stop",
            )

        response = self._responses[self._response_index]
        self._response_index += 1
        self._update_usage(response)
        return response

    def validate_tool_call(self, tool_call: ToolCall) -> bool:
        """All tool calls are valid in mock mode."""
        return True
