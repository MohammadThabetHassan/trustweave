"""Static review of declared MCP metadata profiles without MCP execution or discovery."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from trustweave.models import VALID_ACTION_CLASSES, AgentManifest, ValidationError
from trustweave.provenance import add_generated_at

MCP_PROFILE_SCHEMA_VERSION = "trustweave.dev/mcp-profile/v1alpha1"
MCP_PROFILE_REVIEW_SCHEMA_VERSION = "trustweave.dev/mcp-profile-review/v1alpha1"
VALID_TRANSPORTS = frozenset({"http", "stdio"})


@dataclass(frozen=True)
class McpToolMapping:
    """One declared MCP tool mapped explicitly to a TrustWeave manifest tool."""

    name: str
    manifest_tool: str
    action_class: str
    description: str


@dataclass(frozen=True)
class McpProfile:
    """A static, non-secret MCP metadata profile supplied by the user."""

    schema_version: str
    name: str
    transport: str
    resource_uri: str | None
    authorization_expected: bool
    tools: tuple[McpToolMapping, ...]


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{path} must be a list")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _unique(values: Sequence[str], path: str) -> None:
    duplicates = sorted(value for value, count in Counter(values).items() if count > 1)
    if duplicates:
        raise ValidationError(f"{path} contains duplicate values: {', '.join(duplicates)}")


def _validate_http_resource_uri(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValidationError("mcp_profile.resource_uri must be an absolute HTTP(S) URI")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValidationError(
            "mcp_profile.resource_uri must not contain credentials, query parameters, or fragments"
        )
    return value


def parse_mcp_profile(document: Mapping[str, Any]) -> McpProfile:
    """Validate an explicit static MCP profile without discovering or calling a server."""

    root = _mapping(document, "mcp_profile")
    schema_version = _text(root.get("schema_version"), "mcp_profile.schema_version")
    if schema_version != MCP_PROFILE_SCHEMA_VERSION:
        raise ValidationError(f"mcp_profile.schema_version must be {MCP_PROFILE_SCHEMA_VERSION}")
    transport = _text(root.get("transport"), "mcp_profile.transport")
    if transport not in VALID_TRANSPORTS:
        raise ValidationError(f"mcp_profile.transport must be one of {sorted(VALID_TRANSPORTS)}")
    authorization_expected = root.get("authorization_expected")
    if not isinstance(authorization_expected, bool):
        raise ValidationError("mcp_profile.authorization_expected must be a boolean")

    resource_uri: str | None = None
    if transport == "http":
        resource_uri = _validate_http_resource_uri(
            _text(root.get("resource_uri"), "mcp_profile.resource_uri")
        )
    elif root.get("resource_uri") is not None:
        resource_uri = _text(root.get("resource_uri"), "mcp_profile.resource_uri")

    tools: list[McpToolMapping] = []
    for index, raw_tool in enumerate(_sequence(root.get("tools"), "mcp_profile.tools")):
        tool = _mapping(raw_tool, f"mcp_profile.tools[{index}]")
        action_class = _text(tool.get("action_class"), f"mcp_profile.tools[{index}].action_class")
        if action_class not in VALID_ACTION_CLASSES:
            raise ValidationError(
                f"mcp_profile.tools[{index}].action_class must be one of "
                f"{sorted(VALID_ACTION_CLASSES)}"
            )
        tools.append(
            McpToolMapping(
                name=_text(tool.get("name"), f"mcp_profile.tools[{index}].name"),
                manifest_tool=_text(
                    tool.get("manifest_tool"), f"mcp_profile.tools[{index}].manifest_tool"
                ),
                action_class=action_class,
                description=_text(
                    tool.get("description"), f"mcp_profile.tools[{index}].description"
                ),
            )
        )
    if not tools:
        raise ValidationError("mcp_profile.tools must contain at least one tool")
    _unique([tool.name for tool in tools], "mcp_profile.tools.name")
    _unique([tool.manifest_tool for tool in tools], "mcp_profile.tools.manifest_tool")

    return McpProfile(
        schema_version=schema_version,
        name=_text(root.get("name"), "mcp_profile.name"),
        transport=transport,
        resource_uri=resource_uri,
        authorization_expected=authorization_expected,
        tools=tuple(tools),
    )


def review_mcp_profile(
    profile: McpProfile, manifest: AgentManifest, generated_at: str | None = None
) -> dict[str, Any]:
    """Review profile-to-manifest consistency with optional application-layer provenance."""

    manifest_tools = {tool.name: tool for tool in manifest.tools}
    findings: list[dict[str, str]] = []
    if profile.transport == "http" and not profile.authorization_expected:
        findings.append(
            {
                "id": "TW-MCP-001",
                "severity": "review",
                "message": (
                    "HTTP profile declares authorization_expected=false; review whether "
                    "the server is intentionally unauthenticated and how the trust "
                    "boundary is protected."
                ),
            }
        )

    mappings: list[dict[str, str]] = []
    for tool in profile.tools:
        manifest_tool = manifest_tools.get(tool.manifest_tool)
        mapping: dict[str, str] = {
            "mcp_tool": tool.name,
            "manifest_tool": tool.manifest_tool,
            "declared_action_class": tool.action_class,
        }
        if manifest_tool is None:
            mapping["status"] = "review_required"
            findings.append(
                {
                    "id": "TW-MCP-002",
                    "severity": "review",
                    "message": (
                        f"MCP tool {tool.name} maps to unknown manifest tool {tool.manifest_tool}."
                    ),
                }
            )
        elif manifest_tool.action_class != tool.action_class:
            mapping["status"] = "review_required"
            mapping["manifest_action_class"] = manifest_tool.action_class
            findings.append(
                {
                    "id": "TW-MCP-003",
                    "severity": "review",
                    "message": (
                        f"MCP tool {tool.name} declares action class {tool.action_class}, but "
                        f"manifest tool {tool.manifest_tool} declares {manifest_tool.action_class}."
                    ),
                }
            )
        else:
            mapping["status"] = "clear"
            mapping["manifest_action_class"] = manifest_tool.action_class
        mappings.append(mapping)

    review: dict[str, object] = {
        "schema_version": MCP_PROFILE_REVIEW_SCHEMA_VERSION,
        "profile": {
            "name": profile.name,
            "transport": profile.transport,
            "resource_uri": profile.resource_uri,
            "authorization_expected": profile.authorization_expected,
        },
        "summary": {
            "tools_reviewed": len(profile.tools),
            "review_findings": len(findings),
            "status": "review_required" if findings else "clear",
        },
        "mappings": mappings,
        "findings": findings,
        "limits": [
            (
                "This review validates a user-supplied local metadata profile only. It does not "
                "discover, connect to, authenticate with, or execute an MCP server."
            ),
            (
                "The resource URI is treated as an identifier. No token, authorization header, "
                "server metadata, or remote capability is retrieved or validated."
            ),
            (
                "A review finding is an invitation to confirm configuration and authorization "
                "design; it is not an MCP conformance or security verdict."
            ),
        ],
    }
    return add_generated_at(review, generated_at)
