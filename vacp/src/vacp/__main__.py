"""
VACP CLI Entry Point

Run with: python -m vacp
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="vacp",
        description="Verifiable Agent Action Control Plane",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Server command
    server_parser = subparsers.add_parser("server", help="Run the HTTP API server")
    server_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")  # nosec B104
    server_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    server_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    server_parser.add_argument("--demo", action="store_true", default=True, help="Load demo data on startup (default: True)")
    server_parser.add_argument("--no-demo", action="store_true", help="Disable demo data loading")

    # Test command
    test_parser = subparsers.add_parser("test", help="Run the test suite")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Audit UI command
    audit_parser = subparsers.add_parser("audit", help="Run the audit UI")
    audit_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    audit_parser.add_argument("--port", type=int, default=8080, help="Port to bind to")

    # Example command
    subparsers.add_parser("example", help="Run the basic example")

    # Security test command
    subparsers.add_parser("security-test", help="Run security tests")

    # Demo command
    subparsers.add_parser("demo", help="Run demo server with populated data")

    # MCP command
    mcp_parser = subparsers.add_parser("mcp", help="Run as MCP server (for Claude Desktop)")
    mcp_parser.add_argument("--agent-id", default="mcp-agent", help="Agent identifier")
    mcp_parser.add_argument("--tenant-id", default="mcp-tenant", help="Tenant identifier")

    args = parser.parse_args()

    if args.command == "server":
        from vacp.api.server import run_server
        demo = args.demo and not getattr(args, 'no_demo', False)
        run_server(host=args.host, port=args.port, reload=args.reload, demo=demo)

    elif args.command == "test":
        from vacp.tests.test_core import run_tests
        success = run_tests()
        sys.exit(0 if success else 1)

    elif args.command == "audit":
        from vacp.core.gateway import create_gateway
        from vacp.ui.audit import run_audit_ui

        _, _, _, receipt_service, audit_log = create_gateway()
        run_audit_ui(audit_log, receipt_service, host=args.host, port=args.port)

    elif args.command == "example":
        import asyncio
        from vacp.examples.basic_usage import main as example_main
        asyncio.run(example_main())

    elif args.command == "security-test":
        import asyncio
        from vacp.core.gateway import create_gateway
        from vacp.testing.harness import run_security_tests

        async def run():
            gateway, registry, policy_engine, _, _ = create_gateway()
            await run_security_tests(gateway, registry, policy_engine)

        asyncio.run(run())

    elif args.command == "demo":
        from vacp.demo_server import main as demo_main
        demo_main()

    elif args.command == "mcp":
        import asyncio
        from vacp.mcp.server import run_mcp_server
        asyncio.run(run_mcp_server(agent_id=args.agent_id, tenant_id=args.tenant_id))

    else:
        parser.print_help()
        print("\nVACP - Verifiable Agent Action Control Plane")
        print("The cryptographic settlement layer for agent actions.\n")
        print("Quick start:")
        print("  python -m vacp server         # API server (demo data enabled by default)")
        print("  python -m vacp server --no-demo  # API server without demo data")
        print("  python -m vacp mcp            # MCP server for Claude Desktop")
        print("  python -m vacp demo           # Demo with simple UI")
        print("  python -m vacp test           # Run tests")


if __name__ == "__main__":
    main()
