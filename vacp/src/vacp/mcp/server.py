"""
VACP MCP Server Implementation

This MCP server wraps the VACP gateway, providing:
1. Tool registration from external sources
2. Policy enforcement on all tool calls
3. Cryptographic receipts for every action
4. Real-time anomaly detection

Usage:
    # Add to Claude Desktop config (~/.claude/claude_desktop_config.json):
    {
        "mcpServers": {
            "vacp": {
                "command": "python",
                "args": ["-m", "vacp.mcp"]
            }
        }
    }

    # Or run standalone:
    python -m vacp.mcp
"""

import asyncio
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Callable, Awaitable

from vacp.core.gateway import (
    ToolRequest,
    create_gateway,
    ApprovalRequiredError,
    PolicyDeniedError,
)
from vacp.core.registry import (
    ToolDefinition,
    ToolSchema,
    ParameterSchema,
    ToolCategory,
    ToolRiskLevel,
)


class VACPMCPServer:
    """
    MCP Server that enforces VACP policies on all tool calls.

    Every tool call from the LLM:
    1. Gets validated against the policy engine
    2. Executes through the VACP gateway
    3. Produces a signed receipt
    4. Gets logged to the Merkle audit log
    """

    def __init__(
        self,
        agent_id: str = "mcp-agent",
        tenant_id: str = "mcp-tenant",
        session_id: Optional[str] = None,
    ):
        """
        Initialize the VACP MCP server.

        Args:
            agent_id: Identifier for this agent
            tenant_id: Tenant/organization ID
            session_id: Session ID (auto-generated if not provided)
        """
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.session_id = session_id or f"mcp-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        # Initialize VACP components
        self.gateway, self.registry, self.policy_engine, self.receipt_service, self.audit_log = create_gateway()

        # Tool executors (external implementations)
        self._executors: Dict[str, Callable[[str, Dict[str, Any]], Awaitable[Any]]] = {}

        # MCP protocol state
        self._request_id = 0
        self._initialized = False

        # Register built-in tools
        self._register_builtin_tools()

    def _register_builtin_tools(self) -> None:
        """Register built-in VACP management tools."""
        # Tool to check policy
        check_policy = ToolDefinition(
            id="vacp.check_policy",
            name="Check Policy",
            description="Check what policy would apply to a tool call without executing it",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="tool_id", type="string", required=True, description="Tool ID to check"),
            ]),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.LOW,
        )
        self.registry.register(check_policy)

        async def check_policy_executor(tool_id: str, params: Dict[str, Any]) -> Any:
            target_tool = params.get("tool_id", "")
            result = self.policy_engine.evaluate(
                tool_name=target_tool,
                agent_id=self.agent_id,
                tenant_id=self.tenant_id,
            )
            return {
                "tool_id": target_tool,
                "decision": result.decision.value,
                "matched_rule": result.matched_rule_id,
                "requires_approval": result.require_approval,
            }
        self.gateway.register_executor("vacp.check_policy", check_policy_executor)

        # Tool to list recent receipts
        list_receipts = ToolDefinition(
            id="vacp.list_receipts",
            name="List Receipts",
            description="List recent action receipts from this session",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="limit", type="integer", default=10, description="Max receipts to return"),
            ]),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.LOW,
        )
        self.registry.register(list_receipts)

        async def list_receipts_executor(tool_id: str, params: Dict[str, Any]) -> Any:
            limit = min(params.get("limit", 10), 100)
            receipts = []
            for i in range(max(0, self.audit_log.log.size - limit), self.audit_log.log.size):
                receipt = self.audit_log.get_receipt(i)
                if receipt and receipt.session_id == self.session_id:
                    receipts.append({
                        "receipt_id": receipt.receipt_id[:16] + "...",
                        "tool": receipt.tool.name,
                        "decision": receipt.policy.decision.value,
                        "timestamp": receipt.timestamp.isoformat(),
                    })
            return {"receipts": receipts, "total": len(receipts)}
        self.gateway.register_executor("vacp.list_receipts", list_receipts_executor)

        # Tool to verify a receipt
        verify_receipt = ToolDefinition(
            id="vacp.verify_receipt",
            name="Verify Receipt",
            description="Verify a receipt's cryptographic signature and Merkle proof",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="receipt_id", type="string", required=True, description="Receipt ID to verify"),
            ]),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.LOW,
        )
        self.registry.register(verify_receipt)

        async def verify_receipt_executor(tool_id: str, params: Dict[str, Any]) -> Any:
            receipt_id = params.get("receipt_id", "")
            receipt = self.audit_log.get_receipt_by_id(receipt_id)
            if not receipt:
                return {"error": "Receipt not found", "valid": False}

            sig_valid = self.receipt_service.verify_receipt(receipt)
            proof = self.audit_log.get_proof_for_receipt(receipt_id)
            proof_valid = self.audit_log.verify_receipt_in_log(receipt, proof) if proof else False

            return {
                "receipt_id": receipt_id,
                "signature_valid": sig_valid,
                "merkle_proof_valid": proof_valid,
                "overall_valid": sig_valid and proof_valid,
            }
        self.gateway.register_executor("vacp.verify_receipt", verify_receipt_executor)

    def register_tool(
        self,
        tool_id: str,
        name: str,
        description: str,
        parameters: List[Dict[str, Any]],
        executor: Callable[[str, Dict[str, Any]], Awaitable[Any]],
        categories: Optional[List[str]] = None,
        risk_level: str = "medium",
        requires_approval: bool = False,
    ) -> None:
        """
        Register a tool with VACP.

        Args:
            tool_id: Unique tool identifier
            name: Human-readable name
            description: Tool description
            parameters: List of parameter definitions
            executor: Async function that executes the tool
            categories: Tool categories (read, write, etc.)
            risk_level: Risk level (low, medium, high, critical)
            requires_approval: Whether to require human approval
        """
        # Convert categories
        cat_list = []
        for cat in (categories or ["read"]):
            try:
                cat_list.append(ToolCategory(cat.lower()))
            except ValueError:
                cat_list.append(ToolCategory.READ)

        # Convert risk level
        try:
            risk = ToolRiskLevel(risk_level.lower())
        except ValueError:
            risk = ToolRiskLevel.MEDIUM

        # Create tool definition
        tool = ToolDefinition(
            id=tool_id,
            name=name,
            description=description,
            schema=ToolSchema(
                parameters=[
                    ParameterSchema(
                        name=p["name"],
                        type=p.get("type", "string"),
                        description=p.get("description", ""),
                        required=p.get("required", False),
                        default=p.get("default"),
                    )
                    for p in parameters
                ]
            ),
            categories=cat_list,
            risk_level=risk,
            requires_approval=requires_approval,
        )

        self.registry.register(tool)
        self.gateway.register_executor(tool_id, executor)
        self._executors[tool_id] = executor

    async def call_tool(
        self,
        tool_id: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Call a tool through the VACP gateway.

        All calls are:
        1. Validated against policy
        2. Executed (if allowed)
        3. Recorded with a signed receipt

        Args:
            tool_id: Tool to call
            arguments: Tool arguments

        Returns:
            Result dict with 'content' or 'error', plus 'receipt_id'
        """
        request = ToolRequest(
            tool_id=tool_id,
            parameters=arguments,
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            session_id=self.session_id,
        )

        try:
            response = await self.gateway.execute(request)

            result = {
                "success": response.success,
                "receipt_id": response.receipt.receipt_id if response.receipt else None,
            }

            if response.success:
                result["content"] = response.result
            else:
                result["error"] = response.error

            return result

        except ApprovalRequiredError as e:
            return {
                "success": False,
                "error": "This action requires human approval",
                "approval_id": e.approval_id,
                "requires_approval": True,
            }
        except PolicyDeniedError as e:
            return {
                "success": False,
                "error": f"Policy denied: {e}",
                "policy_denied": True,
            }

    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """Get MCP-formatted tool schemas."""
        tools = []
        for tool in self.registry.list_tools():
            schema = {
                "name": tool.id,
                "description": tool.description or tool.name,
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            }

            if tool.schema and tool.schema.parameters:
                for param in tool.schema.parameters:
                    schema["inputSchema"]["properties"][param.name] = {
                        "type": param.type,
                        "description": param.description or "",
                    }
                    if param.default is not None:
                        schema["inputSchema"]["properties"][param.name]["default"] = param.default
                    if param.required:
                        schema["inputSchema"]["required"].append(param.name)

            tools.append(schema)

        return tools

    # MCP Protocol Methods

    async def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP initialize request."""
        self._initialized = True
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {},
                "prompts": {},
            },
            "serverInfo": {
                "name": "vacp",
                "version": "0.1.0",
            },
        }

    async def handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP tools/list request."""
        return {"tools": self.get_tools_schema()}

    async def handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP tools/call request."""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        result = await self.call_tool(tool_name, arguments)

        if result.get("success"):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result.get("content", {}), indent=2),
                    }
                ],
                "isError": False,
                "_meta": {
                    "receipt_id": result.get("receipt_id"),
                },
            }
        else:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": result.get("error", "Unknown error"),
                    }
                ],
                "isError": True,
                "_meta": {
                    "receipt_id": result.get("receipt_id"),
                    "requires_approval": result.get("requires_approval", False),
                    "approval_id": result.get("approval_id"),
                },
            }

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an MCP JSON-RPC request."""
        method = request.get("method", "")
        params = request.get("params", {})
        request_id = request.get("id")

        handlers = {
            "initialize": self.handle_initialize,
            "initialized": lambda p: {},
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
            "ping": lambda p: {},
        }

        handler = handlers.get(method)
        if not handler:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }

        try:
            result = await handler(params)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": result,
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": str(e),
                },
            }

    async def run_stdio(self) -> None:
        """Run the MCP server over stdio."""
        print("[VACP MCP] Server starting...", file=sys.stderr)
        print(f"[VACP MCP] Agent: {self.agent_id}, Session: {self.session_id}", file=sys.stderr)

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        writer = asyncio.StreamWriter(writer_transport, writer_protocol, reader, asyncio.get_event_loop())

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break

                request = json.loads(line.decode())
                response = await self.handle_request(request)

                response_line = json.dumps(response) + "\n"
                writer.write(response_line.encode())
                await writer.drain()

            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[VACP MCP] Error: {e}", file=sys.stderr)
                continue

        print("[VACP MCP] Server stopped", file=sys.stderr)


async def run_mcp_server(
    agent_id: str = "mcp-agent",
    tenant_id: str = "mcp-tenant",
) -> None:
    """Run the VACP MCP server."""
    server = VACPMCPServer(agent_id=agent_id, tenant_id=tenant_id)
    await server.run_stdio()


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="VACP MCP Server")
    parser.add_argument("--agent-id", default="mcp-agent", help="Agent identifier")
    parser.add_argument("--tenant-id", default="mcp-tenant", help="Tenant identifier")
    args = parser.parse_args()

    asyncio.run(run_mcp_server(agent_id=args.agent_id, tenant_id=args.tenant_id))


if __name__ == "__main__":
    main()
