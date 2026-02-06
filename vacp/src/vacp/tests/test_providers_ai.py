"""
Tests for AI Provider Integrations

Tests for OpenAI and Anthropic provider implementations.
Tests focus on the non-API-calling functionality to avoid external dependencies.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone

from vacp.providers.base import (
    ProviderConfig,
    Message,
    MessageRole,
    CompletionRequest,
    CompletionResponse,
    UsageStats,
    ToolCall,
    ToolDefinition,
    ProviderError,
    RateLimitError,
)


# =============================================================================
# OpenAI Provider Tests
# =============================================================================

class TestOpenAIProvider:
    """Tests for OpenAI provider."""

    @pytest.fixture
    def openai_config(self):
        """Create a test configuration."""
        return ProviderConfig(
            api_key="test-api-key",
            model="gpt-4",
            timeout=30.0,
            max_retries=3,
            requests_per_minute=60,
        )

    def test_provider_name(self, openai_config):
        """Test provider name property."""
        from vacp.providers.openai import OpenAIProvider
        provider = OpenAIProvider(openai_config)
        assert provider.provider_name == "openai"

    def test_config_stored(self, openai_config):
        """Test that config is stored correctly."""
        from vacp.providers.openai import OpenAIProvider
        provider = OpenAIProvider(openai_config)
        assert provider.config.api_key == "test-api-key"
        assert provider.config.model == "gpt-4"

    def test_format_messages(self, openai_config):
        """Test message formatting."""
        from vacp.providers.openai import OpenAIProvider

        provider = OpenAIProvider(openai_config)
        messages = [
            Message(role=MessageRole.SYSTEM, content="You are helpful"),
            Message(role=MessageRole.USER, content="Hello"),
            Message(role=MessageRole.ASSISTANT, content="Hi there!"),
        ]

        formatted = provider._format_messages(messages)

        assert len(formatted) == 3
        assert formatted[0]["role"] == "system"
        assert formatted[1]["role"] == "user"
        assert formatted[2]["role"] == "assistant"

    def test_format_tools(self, openai_config):
        """Test tool formatting for OpenAI."""
        from vacp.providers.openai import OpenAIProvider

        provider = OpenAIProvider(openai_config)
        tools = [
            ToolDefinition(
                name="get_weather",
                description="Get weather for a location",
                parameters={"location": {"type": "string"}},
            )
        ]

        formatted = provider._format_tools(tools)

        assert len(formatted) == 1
        assert formatted[0]["type"] == "function"
        assert formatted[0]["function"]["name"] == "get_weather"

    def test_validate_tool_call(self, openai_config):
        """Test tool call validation."""
        from vacp.providers.openai import OpenAIProvider

        provider = OpenAIProvider(openai_config)
        tool_call = ToolCall(
            id="call_123",
            name="get_weather",
            arguments={"location": "NYC"},
        )

        # Should return True for valid tool calls
        assert provider.validate_tool_call(tool_call) is True

    def test_validate_tool_call_empty_name(self, openai_config):
        """Test tool call validation with empty name."""
        from vacp.providers.openai import OpenAIProvider

        provider = OpenAIProvider(openai_config)
        tool_call = ToolCall(
            id="call_123",
            name="",
            arguments={},
        )

        # Should return False for invalid tool calls
        assert provider.validate_tool_call(tool_call) is False

    def test_format_tool_result(self, openai_config):
        """Test formatting tool results."""
        from vacp.providers.openai import OpenAIProvider
        from vacp.providers.base import ToolResult

        provider = OpenAIProvider(openai_config)
        result = ToolResult(
            tool_call_id="call_123",
            content="Weather is sunny",
            is_error=False,
        )

        message = provider.format_tool_result(result)
        assert message.role == MessageRole.TOOL
        assert message.content == "Weather is sunny"


# =============================================================================
# Anthropic Provider Tests
# =============================================================================

class TestAnthropicProvider:
    """Tests for Anthropic provider."""

    @pytest.fixture
    def anthropic_config(self):
        """Create a test configuration."""
        return ProviderConfig(
            api_key="test-anthropic-key",
            model="claude-3-sonnet-20240229",
            timeout=30.0,
            max_retries=3,
            requests_per_minute=60,
        )

    def test_provider_name(self, anthropic_config):
        """Test provider name property."""
        from vacp.providers.anthropic import AnthropicProvider
        provider = AnthropicProvider(anthropic_config)
        assert provider.provider_name == "anthropic"

    def test_default_model_override(self):
        """Test that GPT-4 default is overridden to Claude."""
        from vacp.providers.anthropic import AnthropicProvider

        config = ProviderConfig(
            api_key="test-key",
            model="gpt-4",  # Default from base
        )
        provider = AnthropicProvider(config)

        # Should be overridden to Claude
        assert "claude" in provider.config.model

    def test_config_stored(self, anthropic_config):
        """Test that config is stored correctly."""
        from vacp.providers.anthropic import AnthropicProvider
        provider = AnthropicProvider(anthropic_config)
        assert provider.config.api_key == "test-anthropic-key"
        assert "claude" in provider.config.model

    def test_format_messages_extracts_system(self, anthropic_config):
        """Test that system message is extracted for Anthropic API."""
        from vacp.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider(anthropic_config)
        messages = [
            Message(role=MessageRole.SYSTEM, content="You are helpful"),
            Message(role=MessageRole.USER, content="Hello"),
        ]

        system, formatted = provider._format_messages(messages)

        # System message should be extracted
        assert system == "You are helpful"
        # Only user message should remain
        assert len(formatted) == 1

    def test_format_messages_no_system(self, anthropic_config):
        """Test formatting when no system message present."""
        from vacp.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider(anthropic_config)
        messages = [
            Message(role=MessageRole.USER, content="Hello"),
            Message(role=MessageRole.ASSISTANT, content="Hi!"),
        ]

        system, formatted = provider._format_messages(messages)

        assert system is None
        assert len(formatted) == 2

    def test_format_tools(self, anthropic_config):
        """Test tool formatting for Anthropic."""
        from vacp.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider(anthropic_config)
        tools = [
            ToolDefinition(
                name="get_weather",
                description="Get weather for a location",
                parameters={
                    "type": "object",
                    "properties": {
                        "location": {"type": "string"}
                    },
                },
            )
        ]

        formatted = provider._format_tools(tools)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "get_weather"
        assert "input_schema" in formatted[0]

    def test_validate_tool_call(self, anthropic_config):
        """Test tool call validation."""
        from vacp.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider(anthropic_config)
        tool_call = ToolCall(
            id="toolu_123",
            name="get_weather",
            arguments={"location": "NYC"},
        )

        assert provider.validate_tool_call(tool_call) is True

    def test_validate_tool_call_invalid(self, anthropic_config):
        """Test tool call validation with invalid data."""
        from vacp.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider(anthropic_config)
        tool_call = ToolCall(
            id="",
            name="",
            arguments={},
        )

        assert provider.validate_tool_call(tool_call) is False


# =============================================================================
# Base Class Tests
# =============================================================================

class TestProviderConfig:
    """Tests for ProviderConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ProviderConfig(api_key="test")

        assert config.api_key == "test"
        assert config.model == "gpt-4"
        assert config.timeout == 60.0
        assert config.max_retries == 3

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ProviderConfig(
            api_key="my-key",
            model="gpt-3.5-turbo",
            timeout=120.0,
            max_retries=5,
            base_url="https://custom.api.com",
        )

        assert config.api_key == "my-key"
        assert config.model == "gpt-3.5-turbo"
        assert config.timeout == 120.0
        assert config.max_retries == 5
        assert config.base_url == "https://custom.api.com"


class TestDataClasses:
    """Tests for provider data classes."""

    def test_usage_stats(self):
        """Test UsageStats dataclass."""
        stats = UsageStats(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )

        assert stats.prompt_tokens == 100
        assert stats.completion_tokens == 50
        assert stats.total_tokens == 150

    def test_tool_call(self):
        """Test ToolCall dataclass."""
        call = ToolCall(
            id="call_123",
            name="get_weather",
            arguments={"location": "NYC"},
        )

        assert call.id == "call_123"
        assert call.name == "get_weather"
        assert call.arguments["location"] == "NYC"

    def test_tool_call_to_dict(self):
        """Test ToolCall serialization."""
        call = ToolCall(
            id="call_123",
            name="get_weather",
            arguments={"location": "NYC"},
        )

        d = call.to_dict()
        assert d["id"] == "call_123"
        assert d["name"] == "get_weather"

    def test_message(self):
        """Test Message dataclass."""
        msg = Message(
            role=MessageRole.USER,
            content="Hello",
        )

        assert msg.role == MessageRole.USER
        assert msg.content == "Hello"

    def test_message_to_dict(self):
        """Test Message serialization."""
        msg = Message(
            role=MessageRole.ASSISTANT,
            content="Hi there!",
        )

        d = msg.to_dict()
        assert d["role"] == "assistant"
        assert d["content"] == "Hi there!"

    def test_tool_definition(self):
        """Test ToolDefinition dataclass."""
        tool = ToolDefinition(
            name="search",
            description="Search the web",
            parameters={"query": {"type": "string"}},
        )

        assert tool.name == "search"
        assert tool.description == "Search the web"

    def test_completion_request(self):
        """Test CompletionRequest dataclass."""
        request = CompletionRequest(
            messages=[Message(role=MessageRole.USER, content="Hi")],
            model="gpt-4",
            max_tokens=100,
            temperature=0.7,
        )

        assert len(request.messages) == 1
        assert request.model == "gpt-4"
        assert request.max_tokens == 100
        assert request.temperature == 0.7


class TestProviderInteroperability:
    """Test provider interoperability."""

    def test_all_providers_have_provider_name(self):
        """Test that all providers implement provider_name."""
        from vacp.providers.openai import OpenAIProvider
        from vacp.providers.anthropic import AnthropicProvider

        config = ProviderConfig(api_key="test")

        openai = OpenAIProvider(config)
        anthropic = AnthropicProvider(ProviderConfig(api_key="test", model="claude-3-sonnet"))

        assert openai.provider_name == "openai"
        assert anthropic.provider_name == "anthropic"

    def test_providers_share_base_interface(self):
        """Test that providers share the same base interface."""
        from vacp.providers.openai import OpenAIProvider
        from vacp.providers.anthropic import AnthropicProvider
        from vacp.providers.base import AIProvider

        config = ProviderConfig(api_key="test")

        openai = OpenAIProvider(config)
        anthropic = AnthropicProvider(config)

        # Both should be AIProvider instances
        assert isinstance(openai, AIProvider)
        assert isinstance(anthropic, AIProvider)

        # Both should have required methods
        assert hasattr(openai, "complete")
        assert hasattr(openai, "validate_tool_call")
        assert hasattr(anthropic, "complete")
        assert hasattr(anthropic, "validate_tool_call")
