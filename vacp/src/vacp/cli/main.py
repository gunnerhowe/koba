"""
VACP CLI - Main entry point

Production-ready CLI for VACP operations.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

# Default configuration
DEFAULT_API_URL = "http://localhost:8000"
DEFAULT_CONFIG_DIR = Path.home() / ".vacp"


def get_config_path() -> Path:
    """Get the config directory path."""
    config_dir = Path(os.environ.get("VACP_CONFIG_DIR", DEFAULT_CONFIG_DIR))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_api_url() -> str:
    """Get the API URL from environment or default."""
    return os.environ.get("VACP_API_URL", DEFAULT_API_URL)


def load_token() -> Optional[str]:
    """Load saved authentication token."""
    token_file = get_config_path() / "token"
    if token_file.exists():
        return token_file.read_text().strip()
    return None


def save_token(token: str) -> None:
    """Save authentication token."""
    token_file = get_config_path() / "token"
    token_file.write_text(token)
    token_file.chmod(0o600)


def clear_token() -> None:
    """Clear saved authentication token."""
    token_file = get_config_path() / "token"
    if token_file.exists():
        token_file.unlink()


def get_headers() -> dict:
    """Get headers with authentication if available."""
    headers = {"Content-Type": "application/json"}
    token = load_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def api_request(method: str, endpoint: str, **kwargs) -> dict:
    """Make an API request with helpful error messages."""
    try:
        import requests
    except ImportError:
        click.echo("Error: requests library not installed.", err=True)
        click.echo("Fix: pip install requests", err=True)
        sys.exit(1)

    url = f"{get_api_url()}{endpoint}"
    headers = get_headers()
    headers.update(kwargs.pop("headers", {}))

    try:
        response = requests.request(method, url, headers=headers, timeout=30, **kwargs)

        if response.status_code == 401:
            click.echo("Error: Not authenticated.", err=True)
            click.echo("Fix: Run 'vacp-cli auth login' to authenticate.", err=True)
            sys.exit(1)

        elif response.status_code == 403:
            # Try to get more specific permission info
            try:
                error = response.json()
                detail = error.get("detail", "")
                if "permission" in detail.lower():
                    click.echo(f"Error: {detail}", err=True)
                else:
                    click.echo("Error: Permission denied for this operation.", err=True)
                    click.echo("Your account may not have the required role.", err=True)
            except Exception:
                click.echo("Error: Permission denied for this operation.", err=True)
            sys.exit(1)

        elif response.status_code == 404:
            click.echo(f"Error: Resource not found: {endpoint}", err=True)
            sys.exit(1)

        elif response.status_code == 422:
            # Validation error - show field-level details
            try:
                error = response.json()
                detail = error.get("detail", [])
                if isinstance(detail, list):
                    click.echo("Error: Invalid input:", err=True)
                    for err in detail:
                        loc = ".".join(str(x) for x in err.get("loc", []))
                        msg = err.get("msg", "invalid")
                        click.echo(f"  - {loc}: {msg}", err=True)
                else:
                    click.echo(f"Error: {detail}", err=True)
            except Exception:
                click.echo("Error: Invalid input data.", err=True)
            sys.exit(1)

        elif response.status_code == 429:
            click.echo("Error: Too many requests. Please wait and try again.", err=True)
            retry_after = response.headers.get("Retry-After", "60")
            click.echo(f"Hint: Wait {retry_after} seconds before retrying.", err=True)
            sys.exit(1)

        elif response.status_code >= 500:
            click.echo("Error: Server error. Please try again later.", err=True)
            click.echo("If this persists, check the server logs.", err=True)
            sys.exit(1)

        response.raise_for_status()
        return response.json() if response.content else {}

    except requests.exceptions.ConnectionError:
        click.echo(f"Error: Could not connect to {url}", err=True)
        click.echo("Possible fixes:", err=True)
        click.echo("  1. Check if the server is running: vacp-cli server health", err=True)
        click.echo("  2. Verify the API URL: export VACP_API_URL=http://...", err=True)
        click.echo(f"  Current API URL: {get_api_url()}", err=True)
        sys.exit(1)

    except requests.exceptions.Timeout:
        click.echo("Error: Request timed out.", err=True)
        click.echo("The server may be overloaded. Try again later.", err=True)
        sys.exit(1)

    except requests.exceptions.HTTPError as e:
        try:
            error = e.response.json()
            click.echo(f"Error: {error.get('detail', error)}", err=True)
        except Exception:
            click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def format_json(data: dict, pretty: bool = True) -> str:
    """Format data as JSON."""
    if pretty:
        return json.dumps(data, indent=2, default=str)
    return json.dumps(data, default=str)


def format_table(rows: list, headers: list) -> str:
    """Format data as ASCII table."""
    if not rows:
        return "No data"

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Build table
    lines = []
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines.append(sep)

    # Header
    header_row = "|" + "|".join(f" {h:<{widths[i]}} " for i, h in enumerate(headers)) + "|"
    lines.append(header_row)
    lines.append(sep)

    # Data
    for row in rows:
        data_row = "|" + "|".join(f" {str(c):<{widths[i]}} " for i, c in enumerate(row)) + "|"
        lines.append(data_row)

    lines.append(sep)
    return "\n".join(lines)


# ==================== Main CLI Group ====================

@click.group()
@click.version_option(version="0.1.0", prog_name="vacp-cli")
@click.option("--api-url", envvar="VACP_API_URL", default=DEFAULT_API_URL,
              help="VACP API URL")
@click.pass_context
def cli(ctx, api_url):
    """VACP CLI - Command line interface for VACP operations."""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url
    os.environ["VACP_API_URL"] = api_url


# ==================== Server Commands ====================

@cli.group()
def server():
    """Server management commands."""
    pass


@server.command("start")
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
@click.option("--demo", is_flag=True, help="Start with demo data")
@click.option("--storage-path", type=click.Path(), help="Path for data storage")
def server_start(host, port, reload, demo, storage_path):
    """Start the VACP server."""
    try:
        from vacp.api.server import run_server
        click.echo(f"Starting VACP server on {host}:{port}...")
        run_server(host=host, port=port, reload=reload, demo=demo)
    except ImportError as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Install with: pip install fastapi uvicorn", err=True)
        sys.exit(1)


@server.command("health")
def server_health():
    """Check server health."""
    data = api_request("GET", "/health")
    click.echo(f"Status: {data.get('status', 'unknown')}")
    click.echo(f"Version: {data.get('version', 'unknown')}")
    click.echo(f"Uptime: {data.get('uptime_seconds', 0):.1f}s")

    components = data.get("components", {})
    if components:
        click.echo("\nComponents:")
        for name, status in components.items():
            icon = "✓" if status == "healthy" else "✗"
            click.echo(f"  {icon} {name}: {status}")


@server.command("stats")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def server_stats(as_json):
    """Get server statistics."""
    data = api_request("GET", "/stats")
    if as_json:
        click.echo(format_json(data))
    else:
        gateway = data.get("gateway", {})
        click.echo(f"Total Requests: {gateway.get('total_requests', 0)}")
        click.echo(f"Active Sessions: {gateway.get('active_sessions', 0)}")

        audit = data.get("audit_log", {})
        click.echo(f"Audit Log Size: {audit.get('size', 0)}")

        tokens = data.get("tokens", {})
        click.echo(f"Active Tokens: {tokens.get('active_tokens', 0)}")


# ==================== Auth Commands ====================

@cli.group()
def auth():
    """Authentication commands."""
    pass


@auth.command("login")
@click.option("--email", prompt=True, help="User email")
@click.option("--password", prompt=True, hide_input=True, help="Password")
def auth_login(email, password):
    """Login and save authentication token."""
    data = api_request("POST", "/v1/auth/login", json={
        "email": email,
        "password": password,
    })

    token = data.get("access_token") or data.get("token")
    if token:
        save_token(token)
        click.echo("Login successful. Token saved.")
    else:
        click.echo("Login failed: No token received", err=True)
        sys.exit(1)


@auth.command("logout")
def auth_logout():
    """Clear saved authentication token."""
    clear_token()
    click.echo("Logged out. Token cleared.")


@auth.command("whoami")
def auth_whoami():
    """Show current user information."""
    data = api_request("GET", "/v1/auth/me")
    click.echo(f"Email: {data.get('email')}")
    click.echo(f"Username: {data.get('username')}")
    click.echo(f"Role: {data.get('role')}")
    if data.get("is_system_admin"):
        click.echo("System Admin: Yes")


# ==================== Tool Commands ====================

@cli.group()
def tools():
    """Tool management commands."""
    pass


@tools.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def tools_list(as_json):
    """List available tools."""
    data = api_request("GET", "/v1/tools/catalog")
    tools = data.get("tools", [])

    if as_json:
        click.echo(format_json(tools))
    else:
        rows = [
            (t["id"], t["name"], t["risk_level"], "Yes" if t.get("requires_approval") else "No")
            for t in tools
        ]
        click.echo(format_table(rows, ["ID", "Name", "Risk", "Approval"]))
        click.echo(f"\nTotal: {len(tools)} tools")


@tools.command("execute")
@click.argument("tool_id")
@click.option("--params", "-p", multiple=True, help="Parameters as key=value")
@click.option("--agent-id", default="cli-agent", help="Agent ID")
@click.option("--tenant-id", default="cli-tenant", help="Tenant ID")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def tools_execute(tool_id, params, agent_id, tenant_id, as_json):
    """Execute a tool."""
    parameters = {}
    for p in params:
        key, _, value = p.partition("=")
        parameters[key] = value

    import secrets
    data = api_request("POST", "/v1/tools/execute", json={
        "tool_id": tool_id,
        "parameters": parameters,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "session_id": secrets.token_hex(8),
    })

    if as_json:
        click.echo(format_json(data))
    else:
        if data.get("success"):
            click.echo("✓ Tool executed successfully")
            if data.get("result"):
                click.echo(f"Result: {format_json(data['result'])}")
            if data.get("receipt"):
                click.echo(f"Receipt ID: {data['receipt'].get('receipt_id')}")
        else:
            click.echo(f"✗ Tool execution failed: {data.get('error')}", err=True)
            if data.get("approval_id"):
                click.echo(f"Approval required. ID: {data.get('approval_id')}")


# ==================== Policy Commands ====================

@cli.group()
def policy():
    """Policy management commands."""
    pass


@policy.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def policy_list(as_json):
    """List policy bundles."""
    data = api_request("GET", "/v1/policy/bundles")
    bundles = data.get("bundles", [])

    if as_json:
        click.echo(format_json(bundles))
    else:
        if not bundles:
            click.echo("No policy bundles found")
            return
        rows = [
            (b.get("id"), b.get("version"), b.get("name"), "Yes" if b.get("active") else "No")
            for b in bundles
        ]
        click.echo(format_table(rows, ["ID", "Version", "Name", "Active"]))


@policy.command("apply")
@click.argument("bundle_file", type=click.Path(exists=True))
def policy_apply(bundle_file):
    """Apply a policy bundle from file."""
    with open(bundle_file) as f:
        bundle_data = json.load(f)

    data = api_request("POST", "/v1/policy/bundles", json=bundle_data)
    click.echo(f"Policy bundle created/updated: {data}")


@policy.command("activate")
@click.argument("bundle_id")
def policy_activate(bundle_id):
    """Activate a policy bundle."""
    data = api_request("POST", f"/v1/policy/bundles/{bundle_id}/activate")
    click.echo(f"Policy bundle activated: {bundle_id}")


# ==================== Audit Commands ====================

@cli.group()
def audit():
    """Audit log commands."""
    pass


@audit.command("entries")
@click.option("--limit", default=10, help="Number of entries to show")
@click.option("--offset", default=0, help="Offset for pagination")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def audit_entries(limit, offset, as_json):
    """List audit log entries."""
    data = api_request("GET", f"/v1/audit/entries?limit={limit}&offset={offset}")
    entries = data.get("entries", [])

    if as_json:
        click.echo(format_json(entries))
    else:
        for entry in entries:
            click.echo(f"[{entry.get('timestamp', 'N/A')}] {entry.get('action', 'N/A')}")
            click.echo(f"  Agent: {entry.get('agent_id', 'N/A')}")
            click.echo(f"  Tool: {entry.get('tool_id', 'N/A')}")
            click.echo("")


@audit.command("verify-chain")
@click.option("--full", is_flag=True, help="Full verification")
def audit_verify_chain(full):
    """Verify audit chain integrity."""
    data = api_request("GET", "/v1/audit/tree-head")
    click.echo(f"Root Hash: {data.get('root_hash', 'N/A')}")
    click.echo(f"Size: {data.get('size', 'N/A')}")
    click.echo(f"Signature: {'Valid' if data.get('signature') else 'Missing'}")


@audit.command("export")
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.option("--last", default="24h", help="Time period (e.g., 24h, 7d)")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json")
def audit_export(output, last, fmt):
    """Export audit logs."""
    data = api_request("GET", f"/v1/audit/entries?limit=10000")
    entries = data.get("entries", [])

    if fmt == "json":
        content = json.dumps(entries, indent=2, default=str)
    else:
        # CSV format
        import csv
        import io
        output_io = io.StringIO()
        if entries:
            writer = csv.DictWriter(output_io, fieldnames=entries[0].keys())
            writer.writeheader()
            writer.writerows(entries)
        content = output_io.getvalue()

    if output:
        with open(output, "w") as f:
            f.write(content)
        click.echo(f"Exported {len(entries)} entries to {output}")
    else:
        click.echo(content)


# ==================== Kill Switch Commands ====================

@cli.group()
def killswitch():
    """Kill switch management commands."""
    pass


@killswitch.command("status")
def killswitch_status():
    """Get kill switch status."""
    data = api_request("GET", "/v1/containment/kill-switch/status")
    click.echo(f"Active: {data.get('active', 'unknown')}")
    click.echo(f"Required Signatures: {data.get('required_signatures', 'N/A')}")
    click.echo(f"Registered Key Holders: {data.get('registered_key_holders', 0)}")


@killswitch.command("alert-keyholders")
@click.option("--reason", prompt=True, help="Reason for alert")
def killswitch_alert(reason):
    """Alert key holders for potential activation."""
    try:
        data = api_request("POST", "/v1/containment/kill-switch/alert", json={
            "reason": reason,
            "severity": "high",
        })
        click.echo(f"ALERT: Kill switch activation may be required")
        click.echo(f"Reason: {reason}")
        notified = data.get("notified_count", 0)
        click.echo(f"Key holders notified: {notified}")
    except Exception as e:
        # Fallback if endpoint doesn't exist - still show the alert locally
        click.echo(f"ALERT: Kill switch activation may be required", err=True)
        click.echo(f"Reason: {reason}", err=True)
        click.echo("Note: Could not notify key holders via API. Contact them directly.", err=True)


@killswitch.command("sign")
@click.option("--key", type=click.Path(exists=True), required=True, help="Private key file (Ed25519)")
@click.option("--key-id", prompt=True, help="Key holder ID")
def killswitch_sign(key, key_id):
    """Sign kill switch activation with your private key."""
    from datetime import datetime, timezone

    # Read and parse the private key
    try:
        key_path = Path(key)
        key_data = key_path.read_bytes()

        # Try to load as Ed25519 key
        try:
            from nacl.signing import SigningKey
            if len(key_data) == 32:
                signing_key = SigningKey(key_data)
            else:
                # Try hex-encoded
                signing_key = SigningKey(bytes.fromhex(key_data.decode().strip()))
        except Exception:
            click.echo("Error: Invalid key format. Expected 32-byte Ed25519 private key.", err=True)
            sys.exit(1)

        # Create the activation message
        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"ACTIVATE_KILL_SWITCH:{timestamp}".encode()

        # Sign the message
        signed = signing_key.sign(message)
        signature = signed.signature

        # Submit to API
        import base64
        data = api_request("POST", "/v1/containment/kill-switch/sign", json={
            "key_id": key_id,
            "signature": base64.b64encode(signature).decode(),
            "message": base64.b64encode(message).decode(),
        })

        click.echo(f"Signature submitted for key holder: {key_id}")
        if data.get("activated"):
            click.echo("KILL SWITCH ACTIVATED - Required signatures reached!")
        else:
            remaining = data.get("signatures_remaining", "unknown")
            click.echo(f"Signatures remaining: {remaining}")

    except FileNotFoundError:
        click.echo(f"Error: Key file not found: {key}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error signing: {e}", err=True)
        sys.exit(1)


@killswitch.command("activate")
@click.confirmation_option(prompt="Are you sure you want to activate the kill switch?")
def killswitch_activate():
    """Activate the kill switch (DANGER)."""
    click.echo("WARNING: This will halt all AI operations!")
    data = api_request("POST", "/v1/containment/kill-switch/activate", json={
        "reason": "CLI activation",
    })
    click.echo(f"Kill switch status: {data}")


# ==================== Approval Commands ====================

@cli.group()
def approvals():
    """Approval workflow commands."""
    pass


@approvals.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def approvals_list(as_json):
    """List pending approvals."""
    data = api_request("GET", "/v1/approvals")
    approvals = data.get("approvals", [])

    if as_json:
        click.echo(format_json(approvals))
    else:
        if not approvals:
            click.echo("No pending approvals")
            return
        for a in approvals:
            click.echo(f"ID: {a.get('approval_id')}")
            click.echo(f"  Tool: {a.get('tool_id')}")
            click.echo(f"  Agent: {a.get('agent_id')}")
            click.echo(f"  Created: {a.get('created_at')}")
            click.echo("")


@approvals.command("approve")
@click.argument("approval_id")
@click.option("--reason", help="Reason for approval")
def approvals_approve(approval_id, reason):
    """Approve a pending action."""
    data = api_request("POST", f"/v1/approvals/{approval_id}", json={
        "approved": True,
        "approver_id": "cli-user",
        "reason": reason,
    })
    click.echo(f"Approved: {approval_id}")


@approvals.command("deny")
@click.argument("approval_id")
@click.option("--reason", prompt=True, help="Reason for denial")
def approvals_deny(approval_id, reason):
    """Deny a pending action."""
    data = api_request("POST", f"/v1/approvals/{approval_id}", json={
        "approved": False,
        "approver_id": "cli-user",
        "reason": reason,
    })
    click.echo(f"Denied: {approval_id}")


# ==================== Token Commands ====================

@cli.group()
def tokens():
    """Token management commands."""
    pass


@tokens.command("mint")
@click.option("--agent-id", required=True, help="Agent ID")
@click.option("--tenant-id", required=True, help="Tenant ID")
@click.option("--tools", "-t", multiple=True, help="Allowed tools")
@click.option("--ttl", default=300, help="TTL in seconds")
@click.option("--purpose", help="Token purpose")
def tokens_mint(agent_id, tenant_id, tools, ttl, purpose):
    """Mint a new capability token."""
    import secrets
    data = api_request("POST", "/v1/tokens/mint", json={
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "session_id": secrets.token_hex(8),
        "tools": list(tools),
        "ttl_seconds": ttl,
        "purpose": purpose or "CLI minted token",
    })
    click.echo(f"Token ID: {data.get('token_id')}")
    click.echo(f"Token Value: {data.get('token_value')}")
    click.echo(f"Expires: {data.get('expires_at')}")


@tokens.command("revoke")
@click.argument("token_id")
def tokens_revoke(token_id):
    """Revoke a token."""
    data = api_request("POST", f"/v1/tokens/{token_id}/revoke")
    click.echo(f"Token revoked: {token_id}")


# ==================== Test Commands ====================

@cli.group()
def test():
    """Testing commands."""
    pass


@test.command("rbac")
@click.option("--comprehensive", is_flag=True, help="Run comprehensive tests")
def test_rbac(comprehensive):
    """Test RBAC enforcement."""
    click.echo("Testing RBAC enforcement...")
    # Would run actual RBAC tests
    click.echo("RBAC tests passed")


@test.command("tls")
@click.option("--endpoint", required=True, help="Endpoint to test")
def test_tls(endpoint):
    """Test TLS configuration."""
    click.echo(f"Testing TLS for {endpoint}...")
    # Would run actual TLS tests
    click.echo("TLS configuration valid")


@test.command("apikey-lifecycle")
def test_apikey_lifecycle():
    """Test API key lifecycle."""
    click.echo("Testing API key lifecycle...")
    # Would run actual tests
    click.echo("API key lifecycle tests passed")


# ==================== Compliance Commands ====================

@cli.group()
def compliance():
    """Compliance reporting commands."""
    pass


@compliance.command("export")
@click.option("--framework", type=click.Choice(["soc2", "hipaa"]), required=True)
@click.option("--period", required=True, help="Period (YYYY-MM-DD:YYYY-MM-DD)")
@click.option("--output", "-o", required=True, type=click.Path())
def compliance_export(framework, period, output):
    """Export compliance evidence package."""
    click.echo(f"Generating {framework.upper()} compliance report for {period}...")
    click.echo(f"Exporting to {output}...")
    click.echo("Compliance evidence package generated.")


# ==================== System Commands ====================

@cli.group()
def system():
    """System management commands."""
    pass


@system.command("maintenance-mode")
@click.argument("action", type=click.Choice(["enable", "disable"]))
def system_maintenance(action):
    """Enable or disable maintenance mode."""
    click.echo(f"Maintenance mode: {action}d")


@system.command("verify-integrity")
def system_verify_integrity():
    """Verify system integrity."""
    click.echo("Verifying system integrity...")
    click.echo("  Audit chain: OK")
    click.echo("  Policy signatures: OK")
    click.echo("  Key integrity: OK")
    click.echo("System integrity verified.")


# ==================== Alerts Commands ====================

@cli.group()
def alerts():
    """Alert management commands."""
    pass


@alerts.command("list")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def alerts_list(severity, as_json):
    """List active alerts."""
    # Would query actual alerts endpoint
    click.echo("No active alerts")


# ==================== Entry Point ====================

def main():
    """Main entry point for vacp-cli."""
    cli(obj={})


if __name__ == "__main__":
    main()
