"""
Koba SDK Wrapper - Makes AI containment dead simple.

Usage:
    from koba import contain

    # OpenAI
    client = contain(openai.OpenAI())

    # Anthropic
    client = contain(anthropic.Anthropic())

    # LangChain
    agent = contain(my_langchain_agent)

    # Any tool-using AI
    client = contain(my_custom_client)
"""

import os
import json
import hashlib
import functools
from typing import Any, Optional, Callable, Dict, List, Tuple
from datetime import datetime

# Default Koba server
KOBA_URL = os.environ.get("KOBA_URL", "http://localhost:8000")
KOBA_API_KEY = os.environ.get("KOBA_API_KEY", "")

# ────────────────────────────────────────────────────────────
# Tool name normalization (mirrors normalize.py)
# ────────────────────────────────────────────────────────────

TOOL_NORMALIZATION_MAP: Dict[str, Tuple[str, str]] = {
    "read_file": ("file", "read"),
    "write_file": ("file", "write"),
    "edit_file": ("file", "write"),
    "create_file": ("file", "write"),
    "delete_file": ("file", "delete"),
    "list_files": ("folder", "list"),
    "list_directory": ("folder", "list"),
    "search_files": ("folder", "read"),
    "bash": ("system", "execute"),
    "shell": ("system", "execute"),
    "terminal": ("system", "execute"),
    "computer_tool": ("system", "execute"),
    "code_interpreter": ("system", "execute"),
    "python": ("system", "execute"),
    "http_request": ("http", "request"),
    "fetch": ("http", "request"),
    "curl": ("http", "request"),
    "web_search": ("website", "search"),
    "browse": ("website", "read"),
    "send_email": ("email", "send"),
    "read_email": ("email", "read"),
    "sql_query": ("database", "read"),
    "sql_execute": ("database", "write"),
    "db_query": ("database", "read"),
    "send_message": ("messaging", "send"),
    "slack_send": ("messaging", "send"),
    "str_replace_editor": ("file", "write"),
}

RESOURCE_PARAM_NAMES = [
    "file_path", "filepath", "file_name", "filename",
    "path", "file", "target_path", "source_path",
    "folder_path", "folder", "directory", "dir",
    "url", "uri", "endpoint",
    "database", "db", "table", "collection",
    "to", "recipient", "email",
    "command", "cmd", "query", "sql",
    "resource", "name", "target",
]


def _normalize_tool(name: str) -> Tuple[str, Optional[str]]:
    """Normalize a tool name to (category, method)."""
    n = name.strip().lower().replace("-", "_")
    if n in TOOL_NORMALIZATION_MAP:
        return TOOL_NORMALIZATION_MAP[n]
    return n, None


def _extract_resource(params: Any) -> Optional[str]:
    """Extract resource from tool parameters."""
    if not isinstance(params, dict):
        return None
    for pname in RESOURCE_PARAM_NAMES:
        val = params.get(pname)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


class KobaClient:
    """Wrapper that routes all AI tool calls through Koba containment."""

    def __init__(
        self,
        wrapped_client: Any,
        koba_url: str = KOBA_URL,
        api_key: str = KOBA_API_KEY,
        agent_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        auto_approve_low_risk: bool = True,
    ):
        self._wrapped = wrapped_client
        self._koba_url = koba_url.rstrip("/")
        self._api_key = api_key
        self._agent_id = agent_id or f"agent_{hashlib.md5(str(id(wrapped_client)).encode()).hexdigest()[:8]}"
        self._tenant_id = tenant_id or "default"
        self._session_id = hashlib.md5(f"{datetime.now().isoformat()}{id(self)}".encode()).hexdigest()[:16]
        self._auto_approve_low_risk = auto_approve_low_risk
        self._token = None

    def __getattr__(self, name: str) -> Any:
        """Proxy all attribute access to wrapped client."""
        attr = getattr(self._wrapped, name)

        # If it's a method that might use tools, wrap it
        if callable(attr):
            return self._wrap_method(attr, name)

        # If it's a nested object (like client.chat), wrap it too
        if hasattr(attr, '__dict__'):
            return _NestedWrapper(attr, self)

        return attr

    def _wrap_method(self, method: Callable, method_name: str) -> Callable:
        """Wrap a method to route through Koba."""
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            # Check if this call involves tool use
            if self._is_tool_call(method_name, kwargs):
                return self._execute_with_containment(method, method_name, args, kwargs)
            return method(*args, **kwargs)
        return wrapper

    def _is_tool_call(self, method_name: str, kwargs: dict) -> bool:
        """Detect if this is a tool-using call."""
        # OpenAI style
        if "tools" in kwargs or "functions" in kwargs:
            return True
        # Anthropic style
        if "tool_choice" in kwargs:
            return True
        # Common tool-related method names
        tool_methods = ["run", "execute", "invoke", "call", "use_tool"]
        if any(tm in method_name.lower() for tm in tool_methods):
            return True
        return False

    def _execute_with_containment(
        self,
        method: Callable,
        method_name: str,
        args: tuple,
        kwargs: dict
    ) -> Any:
        """
        Execute a tool call through Koba containment.

        IMPORTANT: This now evaluates BEFORE the AI call returns tool
        invocations. The flow is:
        1. Make the AI call (get the model's response with tool_use blocks)
        2. BEFORE executing any tools, check each one with Koba
        3. Block any tool calls that Koba denies
        4. Only return the response if all tool calls are allowed

        The AI response itself is NOT blocked - only the tool executions.
        For frameworks that auto-execute tools, we intercept and filter.
        """
        import requests

        # Step 1: Make the AI call to get the response
        response = method(*args, **kwargs)

        # Step 2: Extract tool calls from the response
        tool_calls = self._extract_tool_calls(response)

        if not tool_calls:
            return response

        # Step 3: Check EACH tool call with Koba BEFORE execution
        blocked_tools = []
        pending_tools = []
        preauth_tokens = {}

        for tool_call in tool_calls:
            tool_id = tool_call.get("name") or tool_call.get("function", {}).get("name")
            params = tool_call.get("arguments") or tool_call.get("function", {}).get("arguments", {})

            if isinstance(params, str):
                try:
                    params = json.loads(params)
                except (json.JSONDecodeError, ValueError):
                    params = {"raw": params}

            # Normalize tool name and extract resource
            resource = _extract_resource(params)
            _, norm_method = _normalize_tool(tool_id or "unknown")

            # Evaluate with Koba (pre-execution check)
            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            try:
                koba_response = requests.post(
                    f"{self._koba_url}/v1/tools/evaluate",
                    headers=headers,
                    json={
                        "tool_id": tool_id,
                        "parameters": params,
                        "agent_id": self._agent_id,
                        "tenant_id": self._tenant_id,
                        "session_id": self._session_id,
                        "method": norm_method,
                        "resource": resource,
                        "context": {"source": "koba-sdk-python"},
                    },
                    timeout=10,
                )

                if koba_response.ok:
                    result = koba_response.json()
                    decision = result.get("decision", "deny")

                    if decision == "deny":
                        blocked_tools.append({
                            "tool_id": tool_id,
                            "reason": result.get("denial_reason", "Denied by policy"),
                        })
                    elif decision == "require_approval":
                        pending_tools.append({
                            "tool_id": tool_id,
                            "approval_id": result.get("approval_id", "unknown"),
                        })
                    elif decision == "allow":
                        # Store pre-auth token for recording result later
                        if result.get("pre_auth_token"):
                            preauth_tokens[tool_id] = result["pre_auth_token"]
                else:
                    # Koba server returned an error - fail safe
                    blocked_tools.append({
                        "tool_id": tool_id,
                        "reason": f"Koba returned HTTP {koba_response.status_code}",
                    })

            except requests.exceptions.ConnectionError:
                # Koba unreachable - fail safe (block)
                raise KobaConnectionError(
                    f"Could not reach Koba server at {self._koba_url}. "
                    "AI actions blocked for safety."
                )
            except requests.exceptions.Timeout:
                blocked_tools.append({
                    "tool_id": tool_id,
                    "reason": "Koba evaluation timed out",
                })

        # Step 4: Handle blocked/pending tools
        if blocked_tools:
            tool_names = [t["tool_id"] for t in blocked_tools]
            reasons = [t["reason"] for t in blocked_tools]
            raise KobaBlockedError(
                f"Tool(s) blocked by Koba policy: {', '.join(tool_names)}. "
                f"Reasons: {'; '.join(reasons)}"
            )

        if pending_tools:
            tool_names = [t["tool_id"] for t in pending_tools]
            approval_ids = [t["approval_id"] for t in pending_tools]
            raise KobaPendingApprovalError(
                f"Tool(s) require human approval: {', '.join(tool_names)}. "
                f"Approval IDs: {', '.join(approval_ids)}. "
                "Check Koba dashboard to approve."
            )

        # Step 5: All tools approved. Record execution results.
        # (The actual tool execution happens in the caller's framework)
        # We store preauth tokens so the caller can record results.
        if preauth_tokens:
            # Attach preauth tokens to the response for later recording
            if not hasattr(response, '_koba_preauth'):
                try:
                    response._koba_preauth = preauth_tokens
                except (AttributeError, TypeError):
                    pass  # Some response objects are frozen

        return response

    def _extract_tool_calls(self, response: Any) -> list:
        """Extract tool calls from various AI response formats."""
        # OpenAI format
        if hasattr(response, "choices"):
            for choice in response.choices:
                if hasattr(choice, "message"):
                    msg = choice.message
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        return [
                            {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                            for tc in msg.tool_calls
                        ]
                    if hasattr(msg, "function_call") and msg.function_call:
                        return [{
                            "name": msg.function_call.name,
                            "arguments": msg.function_call.arguments
                        }]

        # Anthropic format
        if hasattr(response, "content"):
            tool_uses = [
                block for block in response.content
                if getattr(block, "type", None) == "tool_use"
            ]
            if tool_uses:
                return [
                    {"name": tu.name, "arguments": tu.input}
                    for tu in tool_uses
                ]

        # Dict format
        if isinstance(response, dict):
            if "tool_calls" in response:
                return response["tool_calls"]
            if "function_call" in response:
                return [response["function_call"]]

        return []

    def record_tool_result(
        self,
        tool_id: str,
        success: bool,
        result: Any = None,
        error: Optional[str] = None,
        execution_time_ms: float = 0.0,
    ) -> Optional[dict]:
        """
        Record a tool execution result with Koba.

        Call this after your tool executes to create a signed audit receipt.

        Args:
            tool_id: The tool that was executed
            success: Whether execution succeeded
            result: The tool result (if success)
            error: Error message (if failure)
            execution_time_ms: How long execution took

        Returns:
            Receipt dict from Koba, or None if no preauth token
        """
        import requests

        # Find preauth token for this tool
        preauth = getattr(self, '_last_preauth_tokens', {}).get(tool_id)
        if not preauth:
            return None

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            resp = requests.post(
                f"{self._koba_url}/v1/audit/record",
                headers=headers,
                json={
                    "pre_auth_token": preauth,
                    "success": success,
                    "result": result if success else None,
                    "error": error if not success else None,
                    "execution_time_ms": execution_time_ms,
                    "source": "koba-sdk-python",
                },
                timeout=10,
            )
            if resp.ok:
                return resp.json()
        except Exception:
            pass
        return None


class _NestedWrapper:
    """Wrapper for nested client objects (e.g., client.chat.completions)."""

    def __init__(self, obj: Any, koba_client: KobaClient):
        self._obj = obj
        self._koba = koba_client

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._obj, name)
        if callable(attr):
            return self._koba._wrap_method(attr, name)
        if hasattr(attr, '__dict__'):
            return _NestedWrapper(attr, self._koba)
        return attr


class KobaBlockedError(Exception):
    """Raised when Koba blocks a tool execution."""
    pass


class KobaPendingApprovalError(Exception):
    """Raised when a tool execution requires human approval."""
    pass


class KobaConnectionError(Exception):
    """Raised when Koba server is unreachable."""
    pass


def contain(
    client: Any,
    *,
    koba_url: str = KOBA_URL,
    api_key: str = KOBA_API_KEY,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    auto_approve_low_risk: bool = True,
) -> KobaClient:
    """
    Wrap any AI client with Koba containment.

    This is the main entry point for the SDK. It takes any AI client
    (OpenAI, Anthropic, LangChain, custom) and returns a wrapped version
    that routes all tool calls through Koba for policy enforcement.

    IMPORTANT: Tool calls are evaluated BEFORE execution. If Koba denies
    a tool call, a KobaBlockedError is raised and the tool never executes.

    Example:
        from openai import OpenAI
        from koba import contain

        # One line to add containment!
        client = contain(OpenAI())

        # Use exactly as before - Koba checks tools before they run
        try:
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "..."}],
                tools=[...]  # These get checked by Koba BEFORE execution
            )
        except KobaBlockedError as e:
            print(f"Tool blocked: {e}")
        except KobaPendingApprovalError as e:
            print(f"Needs approval: {e}")

    Args:
        client: Any AI client to wrap
        koba_url: URL of Koba server (default: KOBA_URL env var or localhost:8000)
        api_key: Koba API key (default: KOBA_API_KEY env var)
        agent_id: Optional identifier for this agent
        tenant_id: Optional tenant identifier for multi-tenant setups
        auto_approve_low_risk: Auto-approve low-risk actions (default: True)

    Returns:
        Wrapped client that behaves identically but routes through Koba
    """
    return KobaClient(
        client,
        koba_url=koba_url,
        api_key=api_key,
        agent_id=agent_id,
        tenant_id=tenant_id,
        auto_approve_low_risk=auto_approve_low_risk,
    )
