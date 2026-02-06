"""
VACP MCP Server

Model Context Protocol server that wraps VACP gateway.
All tool calls from the LLM pass through VACP policy enforcement
and produce cryptographic receipts.
"""

from vacp.mcp.server import VACPMCPServer, run_mcp_server

__all__ = ["VACPMCPServer", "run_mcp_server"]
