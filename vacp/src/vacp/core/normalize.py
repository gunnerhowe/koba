"""
Tool Name Normalization for VACP

Maps raw agent tool names (e.g., "read_file", "bash") to canonical
(category, method) pairs that policy rules can match against.

Also extracts resource identifiers from tool parameters so rules
like "block folder /secret/*" actually work.

This is the bridge between how agents name their tools and how
policies reference categories like "file", "email", "database".
"""

import re
from typing import Any, Dict, List, Optional, Tuple


# ────────────────────────────────────────────────────────────
# Canonical categories with human-readable labels
# ────────────────────────────────────────────────────────────

CATEGORIES = {
    "file": {
        "label": "File",
        "description": "Read, write, edit, or delete individual files",
        "icon": "file",
        "methods": ["read", "write", "delete", "list"],
    },
    "folder": {
        "label": "Folder",
        "description": "Access or modify directories and their contents",
        "icon": "folder",
        "methods": ["read", "write", "delete", "list"],
    },
    "system": {
        "label": "System / Shell",
        "description": "Run shell commands, scripts, or system tools",
        "icon": "terminal",
        "methods": ["execute"],
    },
    "email": {
        "label": "Email",
        "description": "Send, read, or delete emails",
        "icon": "mail",
        "methods": ["read", "send", "delete", "list"],
    },
    "database": {
        "label": "Database",
        "description": "Query, insert, update, or delete database records",
        "icon": "database",
        "methods": ["read", "write", "delete", "list"],
    },
    "http": {
        "label": "HTTP Request",
        "description": "Make outbound HTTP/API requests",
        "icon": "globe",
        "methods": ["request", "get", "post", "put", "delete"],
    },
    "website": {
        "label": "Website / Browser",
        "description": "Browse, search, or scrape web pages",
        "icon": "browser",
        "methods": ["read", "search", "scrape"],
    },
    "calendar": {
        "label": "Calendar",
        "description": "Read, create, or delete calendar events",
        "icon": "calendar",
        "methods": ["read", "write", "delete", "list"],
    },
    "messaging": {
        "label": "Messaging",
        "description": "Send messages via Slack, Teams, Discord, etc.",
        "icon": "message",
        "methods": ["send", "read", "delete"],
    },
    "cloud_storage": {
        "label": "Cloud Storage",
        "description": "Access S3, GCS, Azure Blob, or similar cloud storage",
        "icon": "cloud",
        "methods": ["read", "write", "delete", "list"],
    },
    "api": {
        "label": "API Call",
        "description": "Make API calls to third-party services",
        "icon": "api",
        "methods": ["request", "get", "post"],
    },
    "git": {
        "label": "Git / Version Control",
        "description": "Git operations like commit, push, clone",
        "icon": "git",
        "methods": ["read", "write", "execute"],
    },
    "contacts": {
        "label": "Contacts",
        "description": "Access or modify contact information",
        "icon": "contacts",
        "methods": ["read", "write", "delete", "list"],
    },
    "photos": {
        "label": "Photos / Images",
        "description": "Access, create, or delete photos and images",
        "icon": "image",
        "methods": ["read", "write", "delete", "list"],
    },
    "documents": {
        "label": "Documents",
        "description": "Access office documents, PDFs, spreadsheets",
        "icon": "document",
        "methods": ["read", "write", "delete", "list"],
    },
    "clipboard": {
        "label": "Clipboard",
        "description": "Read from or write to the system clipboard",
        "icon": "clipboard",
        "methods": ["read", "write"],
    },
    "screenshot": {
        "label": "Screenshot / Screen",
        "description": "Capture screenshots or access screen content",
        "icon": "screen",
        "methods": ["read", "capture"],
    },
    "notifications": {
        "label": "Notifications",
        "description": "Send or manage notifications",
        "icon": "bell",
        "methods": ["send", "read"],
    },
    "payments": {
        "label": "Payments / Finance",
        "description": "Process payments, transfers, or financial data",
        "icon": "dollar",
        "methods": ["read", "write", "transfer"],
    },
    "secrets": {
        "label": "Secrets / Credentials",
        "description": "Access API keys, passwords, or credentials",
        "icon": "key",
        "methods": ["read", "write", "delete"],
    },
}


# ────────────────────────────────────────────────────────────
# Tool name → (category, method) mapping
# ────────────────────────────────────────────────────────────

TOOL_NORMALIZATION_MAP: Dict[str, Tuple[str, str]] = {
    # File operations
    "read_file": ("file", "read"),
    "write_file": ("file", "write"),
    "edit_file": ("file", "write"),
    "create_file": ("file", "write"),
    "delete_file": ("file", "delete"),
    "rename_file": ("file", "move"),
    "move_file": ("file", "move"),
    "copy_file": ("file", "copy"),
    "cat": ("file", "read"),
    "head": ("file", "read"),
    "tail": ("file", "read"),
    "open_file": ("file", "read"),
    "save_file": ("file", "write"),
    "patch_file": ("file", "write"),
    "str_replace_editor": ("file", "write"),
    "file_editor": ("file", "write"),

    # Folder operations
    "list_files": ("folder", "list"),
    "list_directory": ("folder", "list"),
    "search_files": ("folder", "read"),
    "find_files": ("folder", "read"),
    "create_directory": ("folder", "create"),
    "delete_directory": ("folder", "delete"),
    "mkdir": ("folder", "create"),
    "rmdir": ("folder", "delete"),
    "ls": ("folder", "list"),
    "tree": ("folder", "list"),
    "glob": ("folder", "list"),
    "find": ("folder", "read"),

    # System / shell
    "bash": ("system", "execute"),
    "shell": ("system", "execute"),
    "terminal": ("system", "execute"),
    "exec": ("system", "execute"),
    "execute": ("system", "execute"),
    "run": ("system", "execute"),
    "run_command": ("system", "execute"),
    "computer_tool": ("system", "execute"),
    "computer": ("system", "execute"),
    "code_interpreter": ("system", "execute"),
    "python": ("system", "execute"),
    "python_tool": ("system", "execute"),
    "subprocess": ("system", "execute"),
    "process": ("system", "execute"),
    "powershell": ("system", "execute"),
    "cmd": ("system", "execute"),

    # HTTP / web requests
    "http_request": ("http", "request"),
    "fetch": ("http", "request"),
    "curl": ("http", "request"),
    "wget": ("http", "request"),
    "http_get": ("http", "get"),
    "http_post": ("http", "post"),
    "http_put": ("http", "put"),
    "http_delete": ("http", "delete"),
    "api_call": ("api", "request"),
    "rest_call": ("api", "request"),
    "graphql_query": ("api", "request"),
    "request": ("http", "request"),
    "web_fetch": ("http", "request"),

    # Website / browsing
    "web_search": ("website", "search"),
    "browse": ("website", "read"),
    "scrape": ("website", "scrape"),
    "open_url": ("website", "read"),
    "browser": ("website", "read"),
    "search": ("website", "search"),
    "google_search": ("website", "search"),
    "bing_search": ("website", "search"),
    "tavily_search": ("website", "search"),
    "duckduckgo_search": ("website", "search"),
    "web_browse": ("website", "read"),

    # Email
    "send_email": ("email", "send"),
    "read_email": ("email", "read"),
    "list_emails": ("email", "list"),
    "delete_email": ("email", "delete"),
    "gmail_send": ("email", "send"),
    "gmail_read": ("email", "read"),
    "gmail_search": ("email", "read"),
    "gmail_draft": ("email", "draft"),
    "outlook_send": ("email", "send"),
    "outlook_read": ("email", "read"),
    "compose_email": ("email", "send"),
    "reply_email": ("email", "send"),
    "forward_email": ("email", "send"),
    "email_send": ("email", "send"),
    "email_read": ("email", "read"),

    # Database
    "sql_query": ("database", "read"),
    "sql_execute": ("database", "query"),
    "db_query": ("database", "query"),
    "db_read": ("database", "query"),
    "db_insert": ("database", "insert"),
    "db_update": ("database", "update"),
    "db_delete": ("database", "delete"),
    "query_database": ("database", "read"),
    "execute_sql": ("database", "query"),
    "postgres_query": ("database", "read"),
    "mysql_query": ("database", "read"),
    "mongo_find": ("database", "read"),
    "mongo_insert": ("database", "insert"),
    "redis_get": ("database", "read"),
    "redis_set": ("database", "insert"),
    "sqlite_query": ("database", "read"),

    # Calendar
    "create_event": ("calendar", "create"),
    "read_calendar": ("calendar", "read"),
    "delete_event": ("calendar", "delete"),
    "list_events": ("calendar", "read"),
    "update_event": ("calendar", "update"),
    "google_calendar": ("calendar", "read"),
    "outlook_calendar": ("calendar", "read"),
    "calendar_create": ("calendar", "create"),
    "calendar_read": ("calendar", "read"),

    # Messaging
    "send_message": ("messaging", "send"),
    "slack_send": ("messaging", "send"),
    "slack_post": ("messaging", "send"),
    "discord_send": ("messaging", "send"),
    "teams_send": ("messaging", "send"),
    "sms_send": ("messaging", "send"),
    "chat_send": ("messaging", "send"),
    "slack_read": ("messaging", "read"),
    "read_messages": ("messaging", "read"),
    "telegram_send": ("messaging", "send"),

    # Cloud storage
    "s3_get": ("cloud_storage", "read"),
    "s3_put": ("cloud_storage", "upload"),
    "s3_delete": ("cloud_storage", "delete"),
    "s3_list": ("cloud_storage", "list"),
    "gcs_get": ("cloud_storage", "read"),
    "gcs_put": ("cloud_storage", "upload"),
    "gcs_delete": ("cloud_storage", "delete"),
    "azure_blob_get": ("cloud_storage", "read"),
    "azure_blob_put": ("cloud_storage", "upload"),
    "upload_file": ("cloud_storage", "upload"),
    "download_file": ("cloud_storage", "download"),

    # Git
    "git_clone": ("git", "read"),
    "git_commit": ("git", "commit"),
    "git_push": ("git", "push"),
    "git_pull": ("git", "pull"),
    "git_diff": ("git", "pull"),
    "git_log": ("git", "pull"),
    "git_status": ("git", "pull"),
    "git_checkout": ("git", "branch"),

    # Contacts
    "read_contacts": ("contacts", "read"),
    "create_contact": ("contacts", "create"),
    "delete_contact": ("contacts", "delete"),
    "search_contacts": ("contacts", "read"),

    # Photos / images
    "read_image": ("photos", "read"),
    "create_image": ("photos", "write"),
    "delete_image": ("photos", "delete"),
    "generate_image": ("photos", "write"),
    "dalle": ("photos", "write"),
    "edit_image": ("photos", "write"),
    "screenshot": ("screenshot", "capture"),
    "take_screenshot": ("screenshot", "capture"),

    # Documents
    "read_pdf": ("documents", "read"),
    "create_pdf": ("documents", "create"),
    "read_document": ("documents", "read"),
    "write_document": ("documents", "create"),
    "read_spreadsheet": ("documents", "read"),
    "write_spreadsheet": ("documents", "create"),

    # Clipboard
    "clipboard_read": ("clipboard", "read"),
    "clipboard_write": ("clipboard", "write"),
    "copy_to_clipboard": ("clipboard", "write"),
    "paste_from_clipboard": ("clipboard", "read"),

    # Notifications
    "send_notification": ("notifications", "send"),
    "push_notification": ("notifications", "send"),

    # Payments (methods align with dashboard catalog: send, request, refund, check_balance)
    "create_payment": ("payments", "send"),
    "send_payment": ("payments", "send"),
    "make_payment": ("payments", "send"),
    "read_transactions": ("payments", "check_balance"),
    "get_balance": ("payments", "check_balance"),
    "stripe_charge": ("payments", "send"),
    "process_refund": ("payments", "refund"),
    "request_payment": ("payments", "request"),

    # Secrets
    "get_secret": ("secrets", "read"),
    "set_secret": ("secrets", "write"),
    "read_env": ("secrets", "read"),
    "vault_read": ("secrets", "read"),
    "vault_write": ("secrets", "write"),
}


# ────────────────────────────────────────────────────────────
# Resource extraction: parameter names to look for
# ────────────────────────────────────────────────────────────

# Ordered by specificity: check more specific names first
RESOURCE_PARAM_NAMES: List[str] = [
    # File / path
    "file_path", "filepath", "file_name", "filename",
    "path", "file", "target_path", "source_path", "dest_path",
    "destination", "source",
    # Folder
    "folder_path", "folder", "directory", "dir", "dirpath",
    "working_directory", "cwd",
    # URL / web
    "url", "uri", "endpoint", "href", "link",
    "base_url", "api_url", "target_url",
    # Database
    "database", "db", "db_name", "database_name",
    "table", "table_name", "collection", "collection_name",
    "schema", "connection_string", "dsn",
    # Email
    "to", "recipient", "recipients", "email", "email_address",
    "from_email", "to_email",
    # Cloud
    "bucket", "bucket_name", "key", "object_key",
    "container", "blob_name",
    # Command
    "command", "cmd", "script", "query", "sql",
    # Git
    "repo", "repository", "branch", "remote",
    # General
    "resource", "name", "id", "target",
]


def normalize_tool_name(
    raw_tool_name: str,
    parameters: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Normalize a raw agent tool name into (category, method, resource).

    This is the core normalization function. It maps arbitrary tool names
    from any AI agent/framework into canonical category.method format that
    policy rules can match.

    Args:
        raw_tool_name: The raw tool name from the agent (e.g., "read_file")
        parameters: The tool call parameters (used to extract resource)

    Returns:
        Tuple of (tool_name_for_policy, method, resource)
        - tool_name_for_policy: canonical category name (e.g., "file")
        - method: canonical method (e.g., "read")
        - resource: extracted resource path/identifier or None
    """
    # Normalize the raw name: lowercase, strip whitespace
    normalized = raw_tool_name.strip().lower()

    # Handle dotted IDs from the dashboard catalog (e.g., "email.send")
    if "." in normalized:
        parts = normalized.split(".", 1)
        category_candidate = parts[0]
        method_candidate = parts[1] if len(parts) > 1 else None

        # Map frontend category names to backend canonical categories
        DOTTED_CATEGORY_MAP = {
            "file": "file", "files": "file",
            "folder": "folder",
            "email": "email",
            "calendar": "calendar",
            "chat": "messaging", "slack": "messaging", "teams": "messaging",
            "discord": "messaging", "telegram": "messaging", "sms": "messaging",
            "messages": "messaging",
            "contacts": "contacts",
            "web": "website",
            "db": "database", "database": "database",
            "cloud": "cloud_storage",
            "code": "system", "shell": "system", "system": "system",
            "process": "system",
            "doc": "documents", "documents": "documents",
            "pay": "payments", "payments": "payments",
            "social": "messaging",
            "notify": "notifications", "notifications": "notifications",
            "admin": "secrets", "security": "secrets",
            "git": "git",
            "http": "http", "api": "api",
        }

        if category_candidate in DOTTED_CATEGORY_MAP:
            category = DOTTED_CATEGORY_MAP[category_candidate]
            resource = extract_resource(parameters) if parameters else None
            return category, method_candidate, resource

    # Direct lookup first
    if normalized in TOOL_NORMALIZATION_MAP:
        category, method = TOOL_NORMALIZATION_MAP[normalized]
        resource = extract_resource(parameters) if parameters else None
        return category, method, resource

    # Try with underscores replaced by hyphens
    hyphenated = normalized.replace("-", "_")
    if hyphenated in TOOL_NORMALIZATION_MAP:
        category, method = TOOL_NORMALIZATION_MAP[hyphenated]
        resource = extract_resource(parameters) if parameters else None
        return category, method, resource

    # Try to infer from the tool name using keyword matching
    category, method = _infer_from_name(normalized)
    resource = extract_resource(parameters) if parameters else None
    return category, method, resource


def _infer_from_name(name: str) -> Tuple[str, Optional[str]]:
    """Attempt to infer category and method from the tool name keywords."""

    # Method keywords (check for these in the name)
    method_keywords = {
        "read": "read", "get": "read", "list": "list", "search": "read",
        "find": "read", "query": "read", "fetch": "read", "view": "read",
        "show": "read", "cat": "read", "head": "read", "tail": "read",
        "write": "write", "create": "write", "add": "write", "insert": "write",
        "update": "write", "set": "write", "put": "write", "save": "write",
        "edit": "write", "modify": "write", "patch": "write", "append": "write",
        "delete": "delete", "remove": "delete", "drop": "delete",
        "destroy": "delete", "purge": "delete", "rm": "delete",
        "send": "send", "post": "send", "submit": "send",
        "exec": "execute", "run": "execute", "execute": "execute",
        "invoke": "execute", "call": "execute", "spawn": "execute",
    }

    # Category keywords
    category_keywords = {
        "file": "file", "document": "documents", "doc": "documents",
        "pdf": "documents", "spreadsheet": "documents",
        "folder": "folder", "directory": "folder", "dir": "folder",
        "email": "email", "mail": "email", "gmail": "email", "outlook": "email",
        "database": "database", "db": "database", "sql": "database",
        "mongo": "database", "redis": "database", "postgres": "database",
        "mysql": "database", "sqlite": "database",
        "http": "http", "web": "website", "browser": "website",
        "url": "website", "scrape": "website", "crawl": "website",
        "calendar": "calendar", "event": "calendar", "schedule": "calendar",
        "message": "messaging", "slack": "messaging", "discord": "messaging",
        "teams": "messaging", "chat": "messaging", "telegram": "messaging",
        "sms": "messaging",
        "s3": "cloud_storage", "gcs": "cloud_storage", "blob": "cloud_storage",
        "bucket": "cloud_storage", "storage": "cloud_storage",
        "git": "git", "repo": "git", "commit": "git",
        "contact": "contacts", "address_book": "contacts",
        "photo": "photos", "image": "photos", "picture": "photos",
        "screenshot": "screenshot", "screen": "screenshot",
        "clipboard": "clipboard", "paste": "clipboard", "copy": "clipboard",
        "notification": "notifications", "notify": "notifications",
        "alert": "notifications", "push": "notifications",
        "payment": "payments", "charge": "payments", "invoice": "payments",
        "transfer": "payments", "stripe": "payments",
        "secret": "secrets", "credential": "secrets", "vault": "secrets",
        "password": "secrets", "key": "secrets", "token": "secrets",
        "bash": "system", "shell": "system", "terminal": "system",
        "command": "system", "process": "system", "python": "system",
    }

    # Split on underscores and hyphens (traditional tool names like
    # "read_file").  Also split on dots, but only for simple two-segment
    # names (e.g., "database.read") -- multi-segment dotted names like
    # "root.admin.delete" should not have methods extracted from inner
    # segments to avoid false matches.
    lowered = name.lower()
    if "." in lowered and lowered.count(".") == 1 and "_" not in lowered and "-" not in lowered:
        parts = lowered.split(".")
    else:
        parts = re.split(r'[_\-]', lowered)

    detected_category = None
    detected_method = None

    for part in parts:
        if not detected_category and part in category_keywords:
            detected_category = category_keywords[part]
        if not detected_method and part in method_keywords:
            detected_method = method_keywords[part]

    # If we still don't have a category, use the raw name as the tool_name
    # so policy rules using the raw name can still match
    if not detected_category:
        return name, detected_method

    return detected_category, detected_method


def extract_resource(parameters: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    Extract the resource identifier from tool parameters.

    Looks through known parameter names to find the resource
    being accessed (file path, URL, database name, etc.).

    Args:
        parameters: Tool call parameters dict

    Returns:
        Resource string or None
    """
    if not parameters:
        return None

    for param_name in RESOURCE_PARAM_NAMES:
        value = parameters.get(param_name)
        if value and isinstance(value, str) and value.strip():
            return value.strip()

    # Also check nested params (some tools wrap in an "input" object)
    if "input" in parameters and isinstance(parameters["input"], dict):
        for param_name in RESOURCE_PARAM_NAMES:
            value = parameters["input"].get(param_name)
            if value and isinstance(value, str) and value.strip():
                return value.strip()

    return None


def get_categories() -> Dict[str, Any]:
    """Return all categories with their metadata for the UI."""
    return CATEGORIES


def get_category_actions(category: str) -> List[str]:
    """Get available actions/methods for a category."""
    cat = CATEGORIES.get(category)
    if cat:
        return cat["methods"]
    return ["read", "write", "delete"]


def build_tool_patterns(category: str, methods: Optional[List[str]] = None) -> List[str]:
    """
    Build policy tool_patterns from a category.

    Policy matching works with tool_patterns matched against the normalized
    category name, and method_patterns matched against the method separately.
    So tool_patterns should just be the category name.

    This is used by the simple rule builder to create proper policy rules.
    """
    return [category]


def build_method_patterns(methods: Optional[List[str]] = None) -> List[str]:
    """Build method patterns for policy rules."""
    if not methods:
        return []
    return methods
