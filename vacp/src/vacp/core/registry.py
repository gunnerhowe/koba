"""
Tool Registry for VACP

This module provides:
- Tool registration and discovery
- JSON Schema validation for tool inputs/outputs
- Tool categorization and capability tracking
- Virtual tool catalog (agents only see allowed tools)

The registry is the authoritative source for what tools exist
and what their expected inputs/outputs are.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union
from enum import Enum

from vacp.core.crypto import hash_json


class ToolCategory(Enum):
    """Categories of tools for policy purposes."""
    READ = "read"           # Read-only operations
    WRITE = "write"         # Modifications
    DELETE = "delete"       # Destructive operations
    EXECUTE = "execute"     # Code execution
    NETWORK = "network"     # Network operations
    FILESYSTEM = "filesystem"  # File system access
    DATABASE = "database"   # Database operations
    API = "api"             # External API calls
    ADMIN = "admin"         # Administrative operations
    SENSITIVE = "sensitive" # Access to sensitive data


class ToolRiskLevel(Enum):
    """Risk levels for tools."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ParameterSchema:
    """Schema for a single parameter."""
    name: str
    type: str  # "string", "number", "boolean", "object", "array"
    description: str = ""
    required: bool = False
    default: Optional[Any] = None
    enum: Optional[List[Any]] = None
    pattern: Optional[str] = None  # Regex pattern for strings
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    items_type: Optional[str] = None  # For arrays
    properties: Optional[Dict[str, "ParameterSchema"]] = None  # For objects
    sensitive: bool = False  # Should be redacted in logs

    def validate(self, value: Any) -> tuple[bool, Optional[str]]:
        """
        Validate a value against this schema.

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Type checking - map of JSON schema types to Python types
        type_map: Dict[str, Union[Type[Any], Tuple[Type[Any], ...]]] = {
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "object": dict,
            "array": list,
            "null": type(None),
        }

        if value is None:
            if self.required:
                return False, f"Required parameter '{self.name}' is missing"
            return True, None

        expected_type = type_map.get(self.type)
        if expected_type is not None and not isinstance(value, expected_type):  # type: ignore[arg-type]
            return False, f"Parameter '{self.name}' expected {self.type}, got {type(value).__name__}"

        # String validations
        if self.type == "string" and isinstance(value, str):
            if self.min_length is not None and len(value) < self.min_length:
                return False, f"Parameter '{self.name}' too short (min {self.min_length})"
            if self.max_length is not None and len(value) > self.max_length:
                return False, f"Parameter '{self.name}' too long (max {self.max_length})"
            if self.pattern:
                try:
                    if not re.match(self.pattern, value):
                        return False, f"Parameter '{self.name}' does not match pattern"
                except re.error:
                    pass

        # Numeric validations
        if self.type in ("number", "integer") and isinstance(value, (int, float)):
            if self.minimum is not None and value < self.minimum:
                return False, f"Parameter '{self.name}' below minimum ({self.minimum})"
            if self.maximum is not None and value > self.maximum:
                return False, f"Parameter '{self.name}' above maximum ({self.maximum})"

        # Enum validation
        if self.enum is not None and value not in self.enum:
            return False, f"Parameter '{self.name}' must be one of {self.enum}"

        # Array items validation
        if self.type == "array" and isinstance(value, list) and self.items_type:
            for i, item in enumerate(value):
                item_expected = type_map.get(self.items_type)
                if item_expected is not None and not isinstance(item, item_expected):  # type: ignore[arg-type]
                    return False, f"Array item {i} in '{self.name}' expected {self.items_type}"

        return True, None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "type": self.type,
        }
        if self.description:
            d["description"] = self.description
        if self.required:
            d["required"] = True
        if self.default is not None:
            d["default"] = self.default
        if self.enum:
            d["enum"] = self.enum
        if self.pattern:
            d["pattern"] = self.pattern
        if self.min_length is not None:
            d["minLength"] = self.min_length
        if self.max_length is not None:
            d["maxLength"] = self.max_length
        if self.minimum is not None:
            d["minimum"] = self.minimum
        if self.maximum is not None:
            d["maximum"] = self.maximum
        if self.items_type:
            d["items"] = {"type": self.items_type}
        if self.sensitive:
            d["sensitive"] = True
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ParameterSchema":
        return cls(
            name=data["name"],
            type=data["type"],
            description=data.get("description", ""),
            required=data.get("required", False),
            default=data.get("default"),
            enum=data.get("enum"),
            pattern=data.get("pattern"),
            min_length=data.get("minLength"),
            max_length=data.get("maxLength"),
            minimum=data.get("minimum"),
            maximum=data.get("maximum"),
            items_type=data.get("items", {}).get("type") if data.get("items") else None,
            sensitive=data.get("sensitive", False),
        )


@dataclass
class ToolSchema:
    """Complete schema for a tool's inputs and outputs."""
    parameters: List[ParameterSchema] = field(default_factory=list)
    returns: Optional[ParameterSchema] = None
    errors: List[str] = field(default_factory=list)  # Possible error types

    def validate_input(self, params: Dict[str, Any]) -> tuple[bool, List[str]]:
        """
        Validate input parameters.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check required parameters
        for param in self.parameters:
            if param.required and param.name not in params:
                errors.append(f"Missing required parameter: {param.name}")

        # Validate provided parameters
        for name, value in params.items():
            param_schema = next((p for p in self.parameters if p.name == name), None)
            if param_schema is None:
                # Unknown parameter - could be warning or error
                continue
            valid, error = param_schema.validate(value)
            if not valid and error:
                errors.append(error)

        return len(errors) == 0, errors

    def get_sensitive_params(self) -> List[str]:
        """Get list of sensitive parameter names."""
        return [p.name for p in self.parameters if p.sensitive]

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "parameters": [p.to_dict() for p in self.parameters],
        }
        if self.returns:
            d["returns"] = self.returns.to_dict()
        if self.errors:
            d["errors"] = self.errors
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolSchema":
        return cls(
            parameters=[ParameterSchema.from_dict(p) for p in data.get("parameters", [])],
            returns=ParameterSchema.from_dict(data["returns"]) if data.get("returns") else None,
            errors=data.get("errors", []),
        )


@dataclass
class ToolDefinition:
    """
    Complete definition of a tool.

    This includes metadata, schema, and security classification.
    """
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    schema: ToolSchema = field(default_factory=ToolSchema)

    # Classification
    categories: List[ToolCategory] = field(default_factory=list)
    risk_level: ToolRiskLevel = ToolRiskLevel.MEDIUM

    # Constraints
    requires_sandbox: bool = False
    requires_approval: bool = False
    max_calls_per_session: Optional[int] = None
    timeout_seconds: int = 30

    # Networking
    allowed_hosts: List[str] = field(default_factory=list)  # For network tools
    blocked_hosts: List[str] = field(default_factory=list)

    # Metadata
    author: Optional[str] = None
    documentation_url: Optional[str] = None
    deprecated: bool = False
    deprecation_message: Optional[str] = None

    # Internal
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def validate_request(self, params: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Validate a tool request."""
        return self.schema.validate_input(params)

    def compute_hash(self) -> str:
        """Compute hash of tool definition."""
        data = self.to_dict()
        data.pop("registered_at", None)  # Exclude timestamp from hash
        return hash_json(data)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "schema": self.schema.to_dict(),
            "categories": [c.value for c in self.categories],
            "risk_level": self.risk_level.value,
            "requires_sandbox": self.requires_sandbox,
            "requires_approval": self.requires_approval,
            "max_calls_per_session": self.max_calls_per_session,
            "timeout_seconds": self.timeout_seconds,
            "allowed_hosts": self.allowed_hosts,
            "blocked_hosts": self.blocked_hosts,
            "author": self.author,
            "documentation_url": self.documentation_url,
            "deprecated": self.deprecated,
            "deprecation_message": self.deprecation_message,
            "registered_at": self.registered_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolDefinition":
        return cls(
            id=data["id"],
            name=data["name"],
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            schema=ToolSchema.from_dict(data.get("schema", {})),
            categories=[ToolCategory(c) for c in data.get("categories", [])],
            risk_level=ToolRiskLevel(data.get("risk_level", "medium")),
            requires_sandbox=data.get("requires_sandbox", False),
            requires_approval=data.get("requires_approval", False),
            max_calls_per_session=data.get("max_calls_per_session"),
            timeout_seconds=data.get("timeout_seconds", 30),
            allowed_hosts=data.get("allowed_hosts", []),
            blocked_hosts=data.get("blocked_hosts", []),
            author=data.get("author"),
            documentation_url=data.get("documentation_url"),
            deprecated=data.get("deprecated", False),
            deprecation_message=data.get("deprecation_message"),
            registered_at=datetime.fromisoformat(data["registered_at"]) if "registered_at" in data else datetime.now(timezone.utc),
        )


class ToolRegistry:
    """
    Central registry for all available tools.

    The registry:
    - Stores tool definitions
    - Validates tool requests against schemas
    - Provides filtered views based on permissions
    - Tracks tool usage statistics
    """

    def __init__(self):
        """Initialize the tool registry."""
        self._tools: Dict[str, ToolDefinition] = {}
        self._tools_by_category: Dict[ToolCategory, Set[str]] = {
            cat: set() for cat in ToolCategory
        }
        self._usage_stats: Dict[str, Dict[str, int]] = {}

    def register(self, tool: ToolDefinition) -> None:
        """
        Register a tool.

        Args:
            tool: The tool definition to register
        """
        self._tools[tool.id] = tool

        # Index by category
        for category in tool.categories:
            self._tools_by_category[category].add(tool.id)

        # Initialize stats
        self._usage_stats[tool.id] = {
            "calls": 0,
            "errors": 0,
            "denials": 0,
        }

    def unregister(self, tool_id: str) -> bool:
        """
        Unregister a tool.

        Args:
            tool_id: ID of tool to unregister

        Returns:
            True if tool was unregistered
        """
        if tool_id not in self._tools:
            return False

        tool = self._tools[tool_id]
        for category in tool.categories:
            self._tools_by_category[category].discard(tool_id)

        del self._tools[tool_id]
        return True

    def get(self, tool_id: str) -> Optional[ToolDefinition]:
        """Get a tool by ID."""
        return self._tools.get(tool_id)

    def get_by_name(self, name: str) -> Optional[ToolDefinition]:
        """Get a tool by name."""
        for tool in self._tools.values():
            if tool.name == name:
                return tool
        return None

    def list_tools(
        self,
        categories: Optional[List[ToolCategory]] = None,
        max_risk_level: Optional[ToolRiskLevel] = None,
        include_deprecated: bool = False,
    ) -> List[ToolDefinition]:
        """
        List tools with optional filtering.

        Args:
            categories: Filter by categories (OR)
            max_risk_level: Maximum risk level to include
            include_deprecated: Whether to include deprecated tools

        Returns:
            List of matching tools
        """
        risk_order = [ToolRiskLevel.LOW, ToolRiskLevel.MEDIUM, ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL]

        results = []
        for tool in self._tools.values():
            # Filter by deprecation
            if tool.deprecated and not include_deprecated:
                continue

            # Filter by category
            if categories:
                if not any(cat in tool.categories for cat in categories):
                    continue

            # Filter by risk level
            if max_risk_level:
                max_idx = risk_order.index(max_risk_level)
                tool_idx = risk_order.index(tool.risk_level)
                if tool_idx > max_idx:
                    continue

            results.append(tool)

        return results

    def validate_request(
        self,
        tool_id: str,
        params: Dict[str, Any],
    ) -> tuple[bool, List[str]]:
        """
        Validate a tool request.

        Args:
            tool_id: ID of the tool
            params: Request parameters

        Returns:
            Tuple of (is_valid, errors)
        """
        tool = self._tools.get(tool_id)
        if not tool:
            return False, [f"Unknown tool: {tool_id}"]

        if tool.deprecated:
            # Warning but not error
            pass

        return tool.validate_request(params)

    def record_call(
        self,
        tool_id: str,
        success: bool = True,
        denied: bool = False,
    ) -> None:
        """Record a tool call for statistics."""
        if tool_id in self._usage_stats:
            self._usage_stats[tool_id]["calls"] += 1
            if not success:
                self._usage_stats[tool_id]["errors"] += 1
            if denied:
                self._usage_stats[tool_id]["denials"] += 1

    def get_virtual_catalog(
        self,
        allowed_tools: Optional[Set[str]] = None,
        allowed_categories: Optional[Set[ToolCategory]] = None,
        max_risk_level: Optional[ToolRiskLevel] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get a virtual tool catalog for an agent.

        This is what the agent "sees" - a filtered view of available tools.

        Args:
            allowed_tools: Set of allowed tool IDs (None = all)
            allowed_categories: Set of allowed categories (None = all)
            max_risk_level: Maximum risk level

        Returns:
            Dictionary of tool_id -> tool_info (simplified)
        """
        catalog = {}
        risk_order = [ToolRiskLevel.LOW, ToolRiskLevel.MEDIUM, ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL]

        for tool_id, tool in self._tools.items():
            # Filter by explicit allowlist
            if allowed_tools is not None and tool_id not in allowed_tools:
                continue

            # Filter by category
            if allowed_categories is not None:
                if not any(cat in allowed_categories for cat in tool.categories):
                    continue

            # Filter by risk
            if max_risk_level:
                max_idx = risk_order.index(max_risk_level)
                tool_idx = risk_order.index(tool.risk_level)
                if tool_idx > max_idx:
                    continue

            # Skip deprecated
            if tool.deprecated:
                continue

            # Add simplified view
            catalog[tool_id] = {
                "name": tool.name,
                "description": tool.description,
                "parameters": [
                    {
                        "name": p.name,
                        "type": p.type,
                        "description": p.description,
                        "required": p.required,
                    }
                    for p in tool.schema.parameters
                    if not p.sensitive  # Hide sensitive params from catalog
                ],
            }

        return catalog

    def get_stats(self, tool_id: Optional[str] = None) -> Dict[str, Any]:
        """Get usage statistics."""
        if tool_id:
            return self._usage_stats.get(tool_id, {})
        return dict(self._usage_stats)

    def export_registry(self) -> Dict[str, Any]:
        """Export the entire registry."""
        return {
            "version": "1.0",
            "tools": {tid: t.to_dict() for tid, t in self._tools.items()},
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

    def import_registry(self, data: Dict[str, Any]) -> int:
        """
        Import tools from exported data.

        Returns:
            Number of tools imported
        """
        count = 0
        for tool_data in data.get("tools", {}).values():
            tool = ToolDefinition.from_dict(tool_data)
            self.register(tool)
            count += 1
        return count


# Convenience functions for creating common tool definitions

def create_read_tool(
    tool_id: str,
    name: str,
    description: str,
    parameters: List[ParameterSchema],
) -> ToolDefinition:
    """Create a read-only tool."""
    return ToolDefinition(
        id=tool_id,
        name=name,
        description=description,
        schema=ToolSchema(parameters=parameters),
        categories=[ToolCategory.READ],
        risk_level=ToolRiskLevel.LOW,
    )


def create_write_tool(
    tool_id: str,
    name: str,
    description: str,
    parameters: List[ParameterSchema],
    requires_approval: bool = True,
) -> ToolDefinition:
    """Create a write tool."""
    return ToolDefinition(
        id=tool_id,
        name=name,
        description=description,
        schema=ToolSchema(parameters=parameters),
        categories=[ToolCategory.WRITE],
        risk_level=ToolRiskLevel.MEDIUM,
        requires_approval=requires_approval,
    )


def create_execute_tool(
    tool_id: str,
    name: str,
    description: str,
    parameters: List[ParameterSchema],
) -> ToolDefinition:
    """Create a code execution tool."""
    return ToolDefinition(
        id=tool_id,
        name=name,
        description=description,
        schema=ToolSchema(parameters=parameters),
        categories=[ToolCategory.EXECUTE],
        risk_level=ToolRiskLevel.HIGH,
        requires_sandbox=True,
        requires_approval=True,
    )


def create_api_tool(
    tool_id: str,
    name: str,
    description: str,
    parameters: List[ParameterSchema],
    allowed_hosts: List[str],
) -> ToolDefinition:
    """Create an external API tool."""
    return ToolDefinition(
        id=tool_id,
        name=name,
        description=description,
        schema=ToolSchema(parameters=parameters),
        categories=[ToolCategory.API, ToolCategory.NETWORK],
        risk_level=ToolRiskLevel.MEDIUM,
        allowed_hosts=allowed_hosts,
    )


# Common parameter schemas

def string_param(
    name: str,
    description: str = "",
    required: bool = False,
    max_length: Optional[int] = None,
    pattern: Optional[str] = None,
) -> ParameterSchema:
    """Create a string parameter schema."""
    return ParameterSchema(
        name=name,
        type="string",
        description=description,
        required=required,
        max_length=max_length,
        pattern=pattern,
    )


def int_param(
    name: str,
    description: str = "",
    required: bool = False,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> ParameterSchema:
    """Create an integer parameter schema."""
    return ParameterSchema(
        name=name,
        type="integer",
        description=description,
        required=required,
        minimum=float(minimum) if minimum is not None else None,
        maximum=float(maximum) if maximum is not None else None,
    )


def bool_param(
    name: str,
    description: str = "",
    default: bool = False,
) -> ParameterSchema:
    """Create a boolean parameter schema."""
    return ParameterSchema(
        name=name,
        type="boolean",
        description=description,
        default=default,
    )


def enum_param(
    name: str,
    values: List[Any],
    description: str = "",
    required: bool = False,
) -> ParameterSchema:
    """Create an enum parameter schema."""
    return ParameterSchema(
        name=name,
        type="string",
        description=description,
        required=required,
        enum=values,
    )


def sensitive_param(
    name: str,
    description: str = "",
    required: bool = True,
) -> ParameterSchema:
    """Create a sensitive parameter schema (will be redacted in logs)."""
    return ParameterSchema(
        name=name,
        type="string",
        description=description,
        required=required,
        sensitive=True,
    )
