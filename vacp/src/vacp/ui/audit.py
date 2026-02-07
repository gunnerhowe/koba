"""
Audit UI for VACP

A simple web-based interface for auditing agent actions.
Uses only standard library for minimal dependencies.
"""

import html
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from urllib.parse import parse_qs, urlparse

from vacp.core.receipts import ReceiptService
from vacp.core.merkle import AuditableLog
from vacp.core.policy import PolicyEngine


class AuditUI:
    """
    Simple audit UI for viewing and verifying receipts.
    """

    def __init__(
        self,
        audit_log: AuditableLog,
        receipt_service: ReceiptService,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        """
        Initialize the audit UI.

        Args:
            audit_log: The auditable log to display
            receipt_service: Receipt service for verification
            policy_engine: Optional policy engine for policy info
        """
        self.audit_log = audit_log
        self.receipt_service = receipt_service
        self.policy_engine = policy_engine

    def get_html_page(self, content: str, title: str = "VACP Audit") -> str:
        """Generate an HTML page with the given content."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        :root {{
            --bg: #0a0a0f;
            --bg-secondary: #12121a;
            --text: #e0e0e0;
            --text-secondary: #888;
            --accent: #6366f1;
            --accent-light: #818cf8;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --border: #2a2a3a;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', monospace;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: var(--accent-light); margin-bottom: 1rem; }}
        h1 {{ font-size: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
        h2 {{ font-size: 1.2rem; }}
        h3 {{ font-size: 1rem; }}
        a {{ color: var(--accent-light); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .receipt-list {{ list-style: none; }}
        .receipt-item {{
            padding: 0.75rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .receipt-item:last-child {{ border-bottom: none; }}
        .receipt-item:hover {{ background: rgba(99, 102, 241, 0.1); }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
        }}
        .badge-allow {{ background: var(--success); color: white; }}
        .badge-deny {{ background: var(--danger); color: white; }}
        .badge-pending {{ background: var(--warning); color: black; }}
        .field {{ margin-bottom: 0.75rem; }}
        .field-label {{ color: var(--text-secondary); font-size: 0.75rem; text-transform: uppercase; }}
        .field-value {{ font-family: monospace; word-break: break-all; }}
        .hash {{ font-size: 0.8rem; color: var(--text-secondary); }}
        .verified {{ color: var(--success); }}
        .invalid {{ color: var(--danger); }}
        pre {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 1rem;
            overflow-x: auto;
            font-size: 0.8rem;
        }}
        .nav {{ margin-bottom: 1rem; }}
        .nav a {{ margin-right: 1rem; }}
        .search-form {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }}
        .search-form input {{
            flex: 1;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.5rem;
            color: var(--text);
            font-family: inherit;
        }}
        .search-form button {{
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 4px;
            padding: 0.5rem 1rem;
            cursor: pointer;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        .stat-card {{ text-align: center; }}
        .stat-value {{ font-size: 2rem; color: var(--accent-light); }}
        .stat-label {{ font-size: 0.75rem; color: var(--text-secondary); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ color: var(--text-secondary); font-size: 0.75rem; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/receipts">Receipts</a>
            <a href="/verify">Verify</a>
            <a href="/tree">Merkle Tree</a>
        </div>
        {content}
    </div>
</body>
</html>"""

    def render_dashboard(self) -> str:
        """Render the main dashboard."""
        log_size = self.audit_log.log.size
        merkle_root = self.audit_log.log.root_hex

        # Get recent receipts
        recent = []
        for i in range(max(0, log_size - 5), log_size):
            receipt = self.audit_log.get_receipt(i)
            if receipt:
                recent.append(receipt)

        recent_html = ""
        for r in reversed(recent):
            decision_badge = f'<span class="badge badge-{r.policy.decision.value}">{r.policy.decision.value}</span>'
            recent_html += f'''
            <div class="receipt-item">
                <div>
                    <strong>{html.escape(r.tool.name)}</strong>
                    <span class="hash">{r.receipt_id[:16]}...</span>
                </div>
                <div>
                    {decision_badge}
                    <a href="/receipts/{html.escape(r.receipt_id)}">View</a>
                </div>
            </div>'''

        content = f'''
        <h1>VACP Audit Dashboard</h1>

        <div class="stats-grid">
            <div class="card stat-card">
                <div class="stat-value">{log_size}</div>
                <div class="stat-label">Total Receipts</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value">{merkle_root[:8]}...</div>
                <div class="stat-label">Merkle Root</div>
            </div>
        </div>

        <div class="card">
            <h2>Recent Actions</h2>
            <div class="receipt-list">
                {recent_html if recent_html else '<p>No receipts yet</p>'}
            </div>
        </div>

        <div class="card">
            <h2>Quick Verify</h2>
            <form class="search-form" action="/verify" method="get">
                <input type="text" name="receipt_id" placeholder="Enter receipt ID...">
                <button type="submit">Verify</button>
            </form>
        </div>
        '''
        return self.get_html_page(content, "VACP Dashboard")

    def render_receipt_list(self, page: int = 0, per_page: int = 20) -> str:
        """Render the receipt list page."""
        log_size = self.audit_log.log.size
        start = max(0, log_size - (page + 1) * per_page)
        end = min(log_size, log_size - page * per_page)

        rows = ""
        for i in range(end - 1, start - 1, -1):
            receipt = self.audit_log.get_receipt(i)
            if receipt:
                decision_badge = f'<span class="badge badge-{receipt.policy.decision.value}">{receipt.policy.decision.value}</span>'
                rows += f'''
                <tr>
                    <td>{i}</td>
                    <td><a href="/receipts/{html.escape(receipt.receipt_id)}">{receipt.receipt_id[:16]}...</a></td>
                    <td>{html.escape(receipt.tool.name)}</td>
                    <td>{decision_badge}</td>
                    <td>{receipt.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>'''

        content = f'''
        <h1>Receipts</h1>

        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Index</th>
                        <th>Receipt ID</th>
                        <th>Tool</th>
                        <th>Decision</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {rows if rows else '<tr><td colspan="5">No receipts</td></tr>'}
                </tbody>
            </table>
        </div>
        '''
        return self.get_html_page(content, "Receipts")

    def render_receipt_detail(self, receipt_id: str) -> str:
        """Render a single receipt detail page."""
        receipt = self.audit_log.get_receipt_by_id(receipt_id)
        if not receipt:
            return self.get_html_page('<h1>Receipt Not Found</h1><p>The requested receipt does not exist.</p>', "Not Found")

        # Verify signature
        sig_valid = self.receipt_service.verify_receipt(receipt)
        sig_status = '<span class="verified">✓ Valid</span>' if sig_valid else '<span class="invalid">✗ Invalid</span>'

        # Get proof
        proof = self.audit_log.get_proof_for_receipt(receipt_id)
        proof_html = ""
        if proof:
            proof_valid = self.audit_log.verify_receipt_in_log(receipt, proof)
            proof_status = '<span class="verified">✓ Verified</span>' if proof_valid else '<span class="invalid">✗ Invalid</span>'
            proof_html = f'''
            <div class="card">
                <h2>Merkle Proof {proof_status}</h2>
                <div class="field">
                    <div class="field-label">Leaf Index</div>
                    <div class="field-value">{proof.leaf_index}</div>
                </div>
                <div class="field">
                    <div class="field-label">Tree Size</div>
                    <div class="field-value">{proof.tree_size}</div>
                </div>
                <div class="field">
                    <div class="field-label">Proof Hashes</div>
                    <pre>{json.dumps([h.hex() for h in proof.hashes], indent=2)}</pre>
                </div>
            </div>
            '''

        decision_badge = f'<span class="badge badge-{receipt.policy.decision.value}">{receipt.policy.decision.value}</span>'

        content = f'''
        <h1>Receipt Detail</h1>

        <div class="card">
            <h2>Receipt {sig_status}</h2>
            <div class="field">
                <div class="field-label">Receipt ID</div>
                <div class="field-value hash">{html.escape(receipt.receipt_id)}</div>
            </div>
            <div class="field">
                <div class="field-label">Timestamp</div>
                <div class="field-value">{receipt.timestamp.isoformat()}</div>
            </div>
            <div class="field">
                <div class="field-label">Agent ID</div>
                <div class="field-value">{html.escape(receipt.agent_id)}</div>
            </div>
            <div class="field">
                <div class="field-label">Tenant ID</div>
                <div class="field-value">{html.escape(receipt.tenant_id)}</div>
            </div>
            <div class="field">
                <div class="field-label">Session ID</div>
                <div class="field-value">{html.escape(receipt.session_id)}</div>
            </div>
        </div>

        <div class="card">
            <h2>Tool</h2>
            <div class="field">
                <div class="field-label">Name</div>
                <div class="field-value">{html.escape(receipt.tool.name)}</div>
            </div>
            <div class="field">
                <div class="field-label">Request Hash</div>
                <div class="field-value hash">{html.escape(receipt.tool.request_hash)}</div>
            </div>
            {f'<div class="field"><div class="field-label">Response Hash</div><div class="field-value hash">{html.escape(receipt.tool.response_hash)}</div></div>' if receipt.tool.response_hash else ''}
        </div>

        <div class="card">
            <h2>Policy {decision_badge}</h2>
            <div class="field">
                <div class="field-label">Bundle ID</div>
                <div class="field-value">{html.escape(receipt.policy.bundle_id)}</div>
            </div>
            <div class="field">
                <div class="field-label">Policy Hash</div>
                <div class="field-value hash">{html.escape(receipt.policy.policy_hash)}</div>
            </div>
            {f'<div class="field"><div class="field-label">Rules Matched</div><div class="field-value">{", ".join(receipt.policy.rules_matched)}</div></div>' if receipt.policy.rules_matched else ''}
        </div>

        <div class="card">
            <h2>Log Position</h2>
            <div class="field">
                <div class="field-label">Log Index</div>
                <div class="field-value">{receipt.log.log_index}</div>
            </div>
            <div class="field">
                <div class="field-label">Merkle Root</div>
                <div class="field-value hash">{html.escape(receipt.log.merkle_root)}</div>
            </div>
            {f'<div class="field"><div class="field-label">Previous Receipt Hash</div><div class="field-value hash">{html.escape(receipt.log.previous_receipt_hash)}</div></div>' if receipt.log.previous_receipt_hash else ''}
        </div>

        {proof_html}

        <div class="card">
            <h2>Signature</h2>
            <div class="field">
                <div class="field-label">Issuer</div>
                <div class="field-value hash">{html.escape(receipt.issuer_public_key or '')}</div>
            </div>
            <div class="field">
                <div class="field-label">Signature</div>
                <div class="field-value hash">{html.escape(receipt.signature or '')}</div>
            </div>
        </div>

        <div class="card">
            <h2>Raw Receipt</h2>
            <pre>{html.escape(receipt.to_json())}</pre>
        </div>
        '''
        return self.get_html_page(content, f"Receipt {receipt_id[:16]}...")

    def render_verify_page(self, receipt_id: Optional[str] = None) -> str:
        """Render the verification page."""
        result_html = ""
        if receipt_id:
            receipt = self.audit_log.get_receipt_by_id(receipt_id)
            if receipt:
                sig_valid = self.receipt_service.verify_receipt(receipt)
                proof = self.audit_log.get_proof_for_receipt(receipt_id)
                proof_valid = self.audit_log.verify_receipt_in_log(receipt, proof) if proof else False

                result_html = f'''
                <div class="card">
                    <h2>Verification Result</h2>
                    <div class="field">
                        <div class="field-label">Receipt ID</div>
                        <div class="field-value hash">{html.escape(receipt_id)}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Signature</div>
                        <div class="field-value">{'<span class="verified">✓ Valid</span>' if sig_valid else '<span class="invalid">✗ Invalid</span>'}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Merkle Proof</div>
                        <div class="field-value">{'<span class="verified">✓ Verified</span>' if proof_valid else '<span class="invalid">✗ Not Verified</span>'}</div>
                    </div>
                    <p><a href="/receipts/{html.escape(receipt_id)}">View Full Receipt</a></p>
                </div>
                '''
            else:
                result_html = '<div class="card"><p class="invalid">Receipt not found</p></div>'

        content = f'''
        <h1>Verify Receipt</h1>

        <div class="card">
            <form class="search-form" action="/verify" method="get">
                <input type="text" name="receipt_id" placeholder="Enter receipt ID..." value="{html.escape(receipt_id or '')}">
                <button type="submit">Verify</button>
            </form>
        </div>

        {result_html}
        '''
        return self.get_html_page(content, "Verify Receipt")

    def render_tree_page(self) -> str:
        """Render the Merkle tree info page."""
        sth = self.audit_log.log.get_signed_tree_head()
        sig_valid = self.audit_log.log.verify_signed_tree_head(sth)

        content = f'''
        <h1>Merkle Tree</h1>

        <div class="card">
            <h2>Signed Tree Head {'<span class="verified">✓ Valid</span>' if sig_valid else '<span class="invalid">✗ Invalid</span>'}</h2>
            <div class="field">
                <div class="field-label">Tree Size</div>
                <div class="field-value">{sth.tree_size}</div>
            </div>
            <div class="field">
                <div class="field-label">Root Hash</div>
                <div class="field-value hash">{sth.root_hash.hex()}</div>
            </div>
            <div class="field">
                <div class="field-label">Timestamp</div>
                <div class="field-value">{sth.timestamp.isoformat()}</div>
            </div>
            <div class="field">
                <div class="field-label">Signature</div>
                <div class="field-value hash">{html.escape(sth.signature or '')}</div>
            </div>
        </div>

        <div class="card">
            <h2>Tree Properties</h2>
            <p>The Merkle tree provides tamper-evident logging:</p>
            <ul>
                <li>Append-only: entries can only be added, never modified</li>
                <li>Inclusion proofs: prove any entry exists in the log</li>
                <li>Consistency proofs: prove the log only grows</li>
                <li>Signed tree heads: cryptographic commitment to state</li>
            </ul>
        </div>
        '''
        return self.get_html_page(content, "Merkle Tree")


class AuditHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the audit UI."""

    ui: AuditUI = None  # Set by server

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        try:
            if path == "/" or path == "":
                content = self.ui.render_dashboard()
            elif path == "/receipts":
                page = int(query.get("page", ["0"])[0])
                content = self.ui.render_receipt_list(page)
            elif path.startswith("/receipts/"):
                receipt_id = path[10:]  # Remove /receipts/
                content = self.ui.render_receipt_detail(receipt_id)
            elif path == "/verify":
                receipt_id = query.get("receipt_id", [None])[0]
                content = self.ui.render_verify_page(receipt_id)
            elif path == "/tree":
                content = self.ui.render_tree_page()
            else:
                self.send_error(404)
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        except Exception as e:
            self.send_error(500, str(e))

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def run_audit_ui(
    audit_log: AuditableLog,
    receipt_service: ReceiptService,
    host: str = "127.0.0.1",
    port: int = 8080,
):
    """
    Run the audit UI server.

    Args:
        audit_log: The auditable log
        receipt_service: Receipt service for verification
        host: Host to bind to
        port: Port to bind to
    """
    ui = AuditUI(audit_log, receipt_service)
    AuditHTTPHandler.ui = ui

    server = HTTPServer((host, port), AuditHTTPHandler)
    print(f"Audit UI running at http://{host}:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
