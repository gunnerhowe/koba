"""Register common tools via API"""
import os
import requests
import json

API = os.getenv("VACP_API_URL", "http://localhost:8000")

# Login - reads credentials from environment variables
email = os.getenv("VACP_ADMIN_EMAIL", "admin@koba.local")
password = os.getenv("VACP_ADMIN_PASSWORD")
if not password:
    raise SystemExit(
        "VACP_ADMIN_PASSWORD environment variable is required.\n"
        "Usage: VACP_ADMIN_PASSWORD=yourpass python register_tools.py"
    )

res = requests.post(f"{API}/v1/auth/login", json={
    "email": email,
    "password": password
})
token = res.json()["access_token"]
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

tools = [
    # Database
    {"id": "db.query", "name": "Query Database", "description": "Run read-only database queries", "categories": ["read", "database"], "risk_level": "low"},
    {"id": "db.insert", "name": "Insert Records", "description": "Add new records to database", "categories": ["write", "database"], "risk_level": "medium", "requires_approval": True},
    {"id": "db.update", "name": "Update Records", "description": "Modify existing database records", "categories": ["write", "database"], "risk_level": "high", "requires_approval": True},
    {"id": "db.delete", "name": "Delete Records", "description": "Remove records from database", "categories": ["delete", "database"], "risk_level": "critical", "requires_approval": True},

    # PDF
    {"id": "pdf.read", "name": "Read PDF", "description": "Extract text and images from PDF documents", "categories": ["read"], "risk_level": "low"},
    {"id": "pdf.create", "name": "Create PDF", "description": "Generate new PDF documents", "categories": ["write"], "risk_level": "medium"},
    {"id": "pdf.sign", "name": "Sign PDF", "description": "Add digital signatures to PDFs", "categories": ["write"], "risk_level": "high", "requires_approval": True},

    # Word/Office
    {"id": "word.read", "name": "Read Word Document", "description": "Extract content from Word documents", "categories": ["read"], "risk_level": "low"},
    {"id": "word.create", "name": "Create Word Document", "description": "Generate new Word documents", "categories": ["write"], "risk_level": "medium"},
    {"id": "excel.read", "name": "Read Spreadsheet", "description": "Read data from Excel/CSV files", "categories": ["read"], "risk_level": "low"},
    {"id": "excel.write", "name": "Write Spreadsheet", "description": "Create or modify spreadsheets", "categories": ["write"], "risk_level": "medium", "requires_approval": True},

    # CAD
    {"id": "cad.view", "name": "View CAD File", "description": "View CAD drawings and 3D models", "categories": ["read"], "risk_level": "low"},
    {"id": "cad.modify", "name": "Modify CAD Design", "description": "Edit existing CAD drawings", "categories": ["write"], "risk_level": "high", "requires_approval": True},
    {"id": "cad.export_manufacturing", "name": "Export to Manufacturing", "description": "Export designs to G-code, STL", "categories": ["write"], "risk_level": "critical", "requires_approval": True},

    # Email
    {"id": "email.read", "name": "Read Email", "description": "Read emails from inbox", "categories": ["read", "network"], "risk_level": "low"},
    {"id": "email.draft", "name": "Draft Email", "description": "Create email drafts (not sent)", "categories": ["write"], "risk_level": "low"},
    {"id": "email.send", "name": "Send Email", "description": "Send emails to recipients", "categories": ["write", "network"], "risk_level": "high", "requires_approval": True},

    # Web
    {"id": "web.browse", "name": "Browse Website", "description": "View and navigate websites", "categories": ["read", "network"], "risk_level": "low"},
    {"id": "web.search", "name": "Web Search", "description": "Search the internet", "categories": ["read", "network"], "risk_level": "low"},
    {"id": "web.fill_form", "name": "Fill Web Form", "description": "Enter data into web forms", "categories": ["write", "network"], "risk_level": "medium", "requires_approval": True},
    {"id": "web.submit_form", "name": "Submit Web Form", "description": "Submit forms on websites", "categories": ["write", "network"], "risk_level": "high", "requires_approval": True},
    {"id": "web.login", "name": "Login to Website", "description": "Authenticate on websites", "categories": ["write", "network"], "risk_level": "critical", "requires_approval": True},

    # Filesystem
    {"id": "fs.read", "name": "Read File", "description": "Read file contents", "categories": ["read", "filesystem"], "risk_level": "low"},
    {"id": "fs.write", "name": "Write File", "description": "Create or overwrite files", "categories": ["write", "filesystem"], "risk_level": "medium", "requires_approval": True},
    {"id": "fs.delete", "name": "Delete File", "description": "Delete files from system", "categories": ["delete", "filesystem"], "risk_level": "high", "requires_approval": True},
    {"id": "fs.list", "name": "List Directory", "description": "List files in a directory", "categories": ["read", "filesystem"], "risk_level": "low"},

    # Code
    {"id": "code.execute", "name": "Execute Code", "description": "Run code or scripts", "categories": ["execute"], "risk_level": "critical", "requires_approval": True},
    {"id": "code.shell", "name": "Run Shell Command", "description": "Execute shell/terminal commands", "categories": ["execute", "admin"], "risk_level": "critical", "requires_approval": True},

    # Finance
    {"id": "finance.view_balance", "name": "View Balance", "description": "Check account balances", "categories": ["read"], "risk_level": "medium"},
    {"id": "finance.transfer", "name": "Transfer Money", "description": "Transfer funds between accounts", "categories": ["write"], "risk_level": "critical", "requires_approval": True},
    {"id": "finance.payment", "name": "Make Payment", "description": "Send payments to recipients", "categories": ["write", "network"], "risk_level": "critical", "requires_approval": True},
]

registered = 0
for tool in tools:
    res = requests.post(f"{API}/v1/tools/register", headers=headers, json=tool)
    if res.ok:
        registered += 1
        print(f"[OK] {tool['id']}")
    else:
        print(f"[FAIL] {tool['id']}: {res.text}")

print(f"\nRegistered {registered}/{len(tools)} tools")
