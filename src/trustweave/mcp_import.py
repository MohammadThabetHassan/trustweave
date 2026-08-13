"""Static normalization of already-provided MCP tools/list snapshots."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from trustweave.models import ValidationError

MCP_TOOL_INVENTORY_SCHEMA_VERSION = "trustweave.dev/mcp-tool-inventory/v1alpha1"
MCP_MANIFEST_SCAFFOLD_SCHEMA_VERSION = "trustweave.dev/mcp-manifest-scaffold/v1alpha1"


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _optional_description(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _text(value, path)


def _annotations(value: Any, path: str) -> dict[str, Any]:
    if value is None:
        return {}
    annotations = _object(value, path)
    normalized: dict[str, Any] = {}
    for key in ("title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
        raw = annotations.get(key)
        if raw is None:
            continue
        if key == "title":
            normalized[key] = _text(raw, f"{path}.{key}")
        elif not isinstance(raw, bool):
            raise ValidationError(f"{path}.{key} must be a boolean")
        else:
            normalized[key] = raw
    return normalized


def normalize_mcp_tools_list(document: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize an existing MCP `tools/list` response without contacting its server.

    The result preserves identifiers, descriptions, schemas, and selected annotation hints as review
    metadata only. It deliberately does not infer TrustWeave action classes or authorize any tool.
    """

    raw_tools = document.get("tools")
    if not isinstance(raw_tools, Sequence) or isinstance(raw_tools, (str, bytes)):
        raise ValidationError("mcp_tools_list.tools must be a list")

    tools: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw_tool in enumerate(raw_tools):
        tool = _object(raw_tool, f"mcp_tools_list.tools[{index}]")
        name = _text(tool.get("name"), f"mcp_tools_list.tools[{index}].name")
        if name in names:
            raise ValidationError(f"mcp_tools_list.tools contains duplicate name: {name}")
        names.add(name)
        input_schema = _object(
            tool.get("inputSchema"), f"mcp_tools_list.tools[{index}].inputSchema"
        )
        normalized: dict[str, Any] = {"name": name, "input_schema": dict(input_schema)}
        description = _optional_description(
            tool.get("description"), f"mcp_tools_list.tools[{index}].description"
        )
        if description is not None:
            normalized["description"] = description
        annotations = _annotations(
            tool.get("annotations"), f"mcp_tools_list.tools[{index}].annotations"
        )
        if annotations:
            normalized["annotations"] = annotations
        tools.append(normalized)

    tools.sort(key=lambda tool: str(tool["name"]))
    return {
        "schema_version": MCP_TOOL_INVENTORY_SCHEMA_VERSION,
        "tools": tools,
        "summary": {
            "tool_count": len(tools),
            "tools_with_annotations": sum("annotations" in tool for tool in tools),
        },
        "limits": [
            (
                "The input is an already-provided local tools/list snapshot. TrustWeave did not "
                "discover, connect to, authenticate with, or invoke an MCP server."
            ),
            (
                "Descriptions, schemas, and annotations are review metadata only. This inventory "
                "does not infer a TrustWeave action class or authorize a tool."
            ),
        ],
    }


def build_manifest_scaffold(inventory: Mapping[str, Any]) -> dict[str, Any]:
    """Create a reviewer-fillable manifest draft from a normalized local MCP inventory."""

    if inventory.get("schema_version") != MCP_TOOL_INVENTORY_SCHEMA_VERSION:
        raise ValidationError(f"inventory must use {MCP_TOOL_INVENTORY_SCHEMA_VERSION}")
    raw_tools = inventory.get("tools")
    if not isinstance(raw_tools, Sequence) or isinstance(raw_tools, (str, bytes)):
        raise ValidationError("inventory.tools must be a list")
    tools: list[dict[str, Any]] = []
    for index, raw_tool in enumerate(raw_tools):
        tool = _object(raw_tool, f"inventory.tools[{index}]")
        tools.append(
            {
                "name": _text(tool.get("name"), f"inventory.tools[{index}].name"),
                "description": tool.get("description", ""),
                "action_class": "REVIEW_REQUIRED",
                "capabilities": [],
            }
        )
    return {
        "schema_version": MCP_MANIFEST_SCAFFOLD_SCHEMA_VERSION,
        "review_required": [
            "Set each tool action_class to read, write, sensitive, or external.",
            "Add declared capabilities and sources before converting this draft to an "
            "Agent Security Manifest.",
            "Define flows and a deterministic policy; this scaffold grants no authorization.",
        ],
        "manifest_draft": {
            "schema_version": "trustweave.dev/v1alpha1",
            "name": "REVIEW_REQUIRED_MCP_INTEGRATION",
            "sources": [],
            "tools": sorted(tools, key=lambda item: str(item["name"])),
            "flows": [],
        },
        "limits": [
            "This is intentionally not a valid Agent Security Manifest until a reviewer "
            "resolves all placeholders.",
            "No server connection, authorization inference, tool execution, or credential "
            "access occurred.",
        ],
    }
