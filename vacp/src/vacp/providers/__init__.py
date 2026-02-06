"""
AI Provider Integration for Koba/VACP

Provides secure integration with AI providers:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)

Features:
- Tool call interception and validation
- Response filtering
- Token tracking and billing
- Rate limiting
"""

from vacp.providers.base import (
    AIProvider,
    ProviderConfig,
    ToolCall,
    ToolResult,
    Message,
    MessageRole,
    CompletionRequest,
    CompletionResponse,
    ProviderError,
    RateLimitError,
    AuthenticationError,
)
from vacp.providers.interceptor import (
    ToolInterceptor,
    InterceptionResult,
    InterceptionAction,
)

__all__ = [
    "AIProvider",
    "ProviderConfig",
    "ToolCall",
    "ToolResult",
    "Message",
    "MessageRole",
    "CompletionRequest",
    "CompletionResponse",
    "ProviderError",
    "RateLimitError",
    "AuthenticationError",
    "ToolInterceptor",
    "InterceptionResult",
    "InterceptionAction",
]
