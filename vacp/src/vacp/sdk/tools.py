"""
Pre-built tool definitions for common AI agent use cases.

Usage:
    from koba.tools import OFFICE_TOOLS, register_common_tools

    # Register all common tools with one call
    register_common_tools(koba_client)
"""

from typing import List, Dict, Any

# =============================================================================
# DOCUMENT TOOLS
# =============================================================================

PDF_TOOLS = [
    {
        "id": "pdf.read",
        "name": "Read PDF",
        "description": "Extract text and images from PDF documents",
        "categories": ["read", "document"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "pdf.create",
        "name": "Create PDF",
        "description": "Generate new PDF documents",
        "categories": ["write", "document"],
        "risk_level": "medium",
        "requires_approval": False,
    },
    {
        "id": "pdf.modify",
        "name": "Modify PDF",
        "description": "Edit existing PDF documents",
        "categories": ["write", "document"],
        "risk_level": "medium",
        "requires_approval": True,
    },
    {
        "id": "pdf.sign",
        "name": "Sign PDF",
        "description": "Add digital signatures to PDFs",
        "categories": ["write", "document", "security"],
        "risk_level": "high",
        "requires_approval": True,
    },
]

WORD_TOOLS = [
    {
        "id": "word.read",
        "name": "Read Word Document",
        "description": "Extract content from Word documents (.docx, .doc)",
        "categories": ["read", "document"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "word.create",
        "name": "Create Word Document",
        "description": "Generate new Word documents",
        "categories": ["write", "document"],
        "risk_level": "medium",
        "requires_approval": False,
    },
    {
        "id": "word.modify",
        "name": "Modify Word Document",
        "description": "Edit existing Word documents",
        "categories": ["write", "document"],
        "risk_level": "medium",
        "requires_approval": True,
    },
]

EXCEL_TOOLS = [
    {
        "id": "excel.read",
        "name": "Read Spreadsheet",
        "description": "Read data from Excel/CSV files",
        "categories": ["read", "document", "data"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "excel.create",
        "name": "Create Spreadsheet",
        "description": "Generate new spreadsheets",
        "categories": ["write", "document", "data"],
        "risk_level": "medium",
        "requires_approval": False,
    },
    {
        "id": "excel.modify",
        "name": "Modify Spreadsheet",
        "description": "Edit existing spreadsheets",
        "categories": ["write", "document", "data"],
        "risk_level": "medium",
        "requires_approval": True,
    },
    {
        "id": "excel.run_macro",
        "name": "Run Excel Macro",
        "description": "Execute macros in spreadsheets",
        "categories": ["execute", "document"],
        "risk_level": "critical",
        "requires_approval": True,
    },
]

# =============================================================================
# CAD/DESIGN TOOLS
# =============================================================================

CAD_TOOLS = [
    {
        "id": "cad.view",
        "name": "View CAD File",
        "description": "View CAD drawings and 3D models",
        "categories": ["read", "design"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "cad.create",
        "name": "Create CAD Design",
        "description": "Generate new CAD drawings",
        "categories": ["write", "design"],
        "risk_level": "medium",
        "requires_approval": False,
    },
    {
        "id": "cad.modify",
        "name": "Modify CAD Design",
        "description": "Edit existing CAD drawings",
        "categories": ["write", "design"],
        "risk_level": "high",
        "requires_approval": True,
    },
    {
        "id": "cad.export",
        "name": "Export CAD to Manufacturing",
        "description": "Export designs to manufacturing formats (G-code, STL)",
        "categories": ["write", "design", "manufacturing"],
        "risk_level": "critical",
        "requires_approval": True,
    },
]

# =============================================================================
# COMMUNICATION TOOLS
# =============================================================================

EMAIL_TOOLS = [
    {
        "id": "email.read",
        "name": "Read Email",
        "description": "Read emails from inbox",
        "categories": ["read", "communication"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "email.draft",
        "name": "Draft Email",
        "description": "Create email drafts (not sent)",
        "categories": ["write", "communication"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "email.send",
        "name": "Send Email",
        "description": "Send emails to recipients",
        "categories": ["write", "communication", "network"],
        "risk_level": "high",
        "requires_approval": True,
    },
    {
        "id": "email.delete",
        "name": "Delete Email",
        "description": "Delete emails from mailbox",
        "categories": ["delete", "communication"],
        "risk_level": "medium",
        "requires_approval": True,
    },
]

CALENDAR_TOOLS = [
    {
        "id": "calendar.read",
        "name": "Read Calendar",
        "description": "View calendar events",
        "categories": ["read", "communication"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "calendar.create",
        "name": "Create Event",
        "description": "Add new calendar events",
        "categories": ["write", "communication"],
        "risk_level": "medium",
        "requires_approval": False,
    },
    {
        "id": "calendar.send_invite",
        "name": "Send Meeting Invite",
        "description": "Send meeting invitations to others",
        "categories": ["write", "communication", "network"],
        "risk_level": "high",
        "requires_approval": True,
    },
]

# =============================================================================
# WEB/BROWSER TOOLS
# =============================================================================

WEB_TOOLS = [
    {
        "id": "web.browse",
        "name": "Browse Website",
        "description": "View and navigate websites",
        "categories": ["read", "network"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "web.search",
        "name": "Web Search",
        "description": "Search the internet",
        "categories": ["read", "network"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "web.fill_form",
        "name": "Fill Web Form",
        "description": "Enter data into web forms",
        "categories": ["write", "network"],
        "risk_level": "medium",
        "requires_approval": True,
    },
    {
        "id": "web.submit_form",
        "name": "Submit Web Form",
        "description": "Submit forms on websites",
        "categories": ["write", "network"],
        "risk_level": "high",
        "requires_approval": True,
    },
    {
        "id": "web.download",
        "name": "Download File",
        "description": "Download files from the internet",
        "categories": ["write", "network", "filesystem"],
        "risk_level": "medium",
        "requires_approval": True,
    },
    {
        "id": "web.login",
        "name": "Login to Website",
        "description": "Authenticate on websites",
        "categories": ["write", "network", "security"],
        "risk_level": "critical",
        "requires_approval": True,
    },
]

# =============================================================================
# FILE SYSTEM TOOLS
# =============================================================================

FILESYSTEM_TOOLS = [
    {
        "id": "fs.read",
        "name": "Read File",
        "description": "Read file contents",
        "categories": ["read", "filesystem"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "fs.write",
        "name": "Write File",
        "description": "Create or overwrite files",
        "categories": ["write", "filesystem"],
        "risk_level": "medium",
        "requires_approval": True,
    },
    {
        "id": "fs.delete",
        "name": "Delete File",
        "description": "Delete files from system",
        "categories": ["delete", "filesystem"],
        "risk_level": "high",
        "requires_approval": True,
    },
    {
        "id": "fs.list",
        "name": "List Directory",
        "description": "List files in a directory",
        "categories": ["read", "filesystem"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "fs.move",
        "name": "Move File",
        "description": "Move or rename files",
        "categories": ["write", "filesystem"],
        "risk_level": "medium",
        "requires_approval": True,
    },
]

# =============================================================================
# DATABASE TOOLS
# =============================================================================

DATABASE_TOOLS = [
    {
        "id": "db.query",
        "name": "Query Database",
        "description": "Run read-only database queries",
        "categories": ["read", "database"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "db.insert",
        "name": "Insert Records",
        "description": "Add new records to database",
        "categories": ["write", "database"],
        "risk_level": "medium",
        "requires_approval": True,
    },
    {
        "id": "db.update",
        "name": "Update Records",
        "description": "Modify existing database records",
        "categories": ["write", "database"],
        "risk_level": "high",
        "requires_approval": True,
    },
    {
        "id": "db.delete",
        "name": "Delete Records",
        "description": "Remove records from database",
        "categories": ["delete", "database"],
        "risk_level": "critical",
        "requires_approval": True,
    },
]

# =============================================================================
# CODE/EXECUTION TOOLS
# =============================================================================

CODE_TOOLS = [
    {
        "id": "code.read",
        "name": "Read Code",
        "description": "Read source code files",
        "categories": ["read", "code"],
        "risk_level": "low",
        "requires_approval": False,
    },
    {
        "id": "code.write",
        "name": "Write Code",
        "description": "Create or modify source code",
        "categories": ["write", "code"],
        "risk_level": "high",
        "requires_approval": True,
    },
    {
        "id": "code.execute",
        "name": "Execute Code",
        "description": "Run code or scripts",
        "categories": ["execute", "code"],
        "risk_level": "critical",
        "requires_approval": True,
    },
    {
        "id": "code.shell",
        "name": "Run Shell Command",
        "description": "Execute shell/terminal commands",
        "categories": ["execute", "code", "system"],
        "risk_level": "critical",
        "requires_approval": True,
    },
]

# =============================================================================
# FINANCIAL TOOLS
# =============================================================================

FINANCIAL_TOOLS = [
    {
        "id": "finance.view_balance",
        "name": "View Balance",
        "description": "Check account balances",
        "categories": ["read", "financial"],
        "risk_level": "medium",
        "requires_approval": False,
    },
    {
        "id": "finance.view_transactions",
        "name": "View Transactions",
        "description": "View transaction history",
        "categories": ["read", "financial"],
        "risk_level": "medium",
        "requires_approval": False,
    },
    {
        "id": "finance.transfer",
        "name": "Transfer Money",
        "description": "Transfer funds between accounts",
        "categories": ["write", "financial"],
        "risk_level": "critical",
        "requires_approval": True,
    },
    {
        "id": "finance.payment",
        "name": "Make Payment",
        "description": "Send payments to recipients",
        "categories": ["write", "financial", "network"],
        "risk_level": "critical",
        "requires_approval": True,
    },
]

# =============================================================================
# TOOL COLLECTIONS
# =============================================================================

# Office suite (Word, Excel, etc.)
OFFICE_TOOLS = PDF_TOOLS + WORD_TOOLS + EXCEL_TOOLS

# All document tools
DOCUMENT_TOOLS = PDF_TOOLS + WORD_TOOLS + EXCEL_TOOLS + CAD_TOOLS

# Communication tools
COMMUNICATION_TOOLS = EMAIL_TOOLS + CALENDAR_TOOLS

# All tools combined
ALL_TOOLS = (
    PDF_TOOLS + WORD_TOOLS + EXCEL_TOOLS + CAD_TOOLS +
    EMAIL_TOOLS + CALENDAR_TOOLS + WEB_TOOLS +
    FILESYSTEM_TOOLS + DATABASE_TOOLS + CODE_TOOLS + FINANCIAL_TOOLS
)


def register_tools(tools: List[Dict[str, Any]], koba_url: str = None, api_key: str = None):
    """
    Register a list of tools with Koba.

    Example:
        from koba.tools import OFFICE_TOOLS, register_tools

        register_tools(OFFICE_TOOLS, api_key="your-api-key")
    """
    import requests

    url = koba_url or "http://localhost:8000"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    registered = []
    failed = []

    for tool in tools:
        try:
            response = requests.post(
                f"{url}/v1/tools/register",
                headers=headers,
                json=tool
            )
            if response.ok:
                registered.append(tool["id"])
            else:
                failed.append((tool["id"], response.text))
        except Exception as e:
            failed.append((tool["id"], str(e)))

    return {"registered": registered, "failed": failed}


def register_common_tools(koba_url: str = None, api_key: str = None):
    """
    Register all common tools with Koba.

    This is the easiest way to set up a comprehensive tool catalog.

    Example:
        from koba.tools import register_common_tools

        result = register_common_tools(api_key="your-api-key")
        print(f"Registered {len(result['registered'])} tools")
    """
    return register_tools(ALL_TOOLS, koba_url, api_key)
