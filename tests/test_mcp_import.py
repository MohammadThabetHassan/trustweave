from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.io import load_document, read_json
from trustweave.mcp_import import MCP_TOOL_INVENTORY_SCHEMA_VERSION, normalize_mcp_tools_list
from trustweave.models import ValidationError

ROOT = Path(__file__).resolve().parents[1]
TOOL_LIST = ROOT / "examples" / "mcp-tools" / "support-tools-list.json"


def test_mcp_tools_list_normalizes_snapshot_deterministically() -> None:
    document = load_document(TOOL_LIST)

    first = normalize_mcp_tools_list(document)
    second = normalize_mcp_tools_list(document)

    assert first == second
    assert first["schema_version"] == MCP_TOOL_INVENTORY_SCHEMA_VERSION
    assert [tool["name"] for tool in first["tools"]] == ["customer_export", "knowledge_search"]
    assert first["summary"] == {"tool_count": 2, "tools_with_annotations": 2}
    assert first["tools"][1]["annotations"]["readOnlyHint"] is True
    assert "did not discover, connect to, authenticate" in first["limits"][0]


def test_mcp_tools_list_rejects_invalid_tool_contracts() -> None:
    duplicate = {
        "tools": [
            {"name": "same", "inputSchema": {}},
            {"name": "same", "inputSchema": {}},
        ]
    }
    with pytest.raises(ValidationError, match="duplicate name"):
        normalize_mcp_tools_list(duplicate)

    with pytest.raises(ValidationError, match="must be an object"):
        normalize_mcp_tools_list({"tools": [{"name": "tool", "inputSchema": []}]})

    with pytest.raises(ValidationError, match="must be a boolean"):
        normalize_mcp_tools_list(
            {
                "tools": [
                    {
                        "name": "tool",
                        "inputSchema": {},
                        "annotations": {"readOnlyHint": "yes"},
                    }
                ]
            }
        )


def test_cli_mcp_import_writes_local_inventory(tmp_path: Path) -> None:
    assert main(["mcp-import", "--tool-list", str(TOOL_LIST), "--output-dir", str(tmp_path)]) == 0

    inventory = read_json(tmp_path / "mcp-tool-inventory.json")
    assert inventory["summary"]["tool_count"] == 2
    assert inventory["tools"][0]["name"] == "customer_export"


def test_cli_mcp_import_rejects_missing_tools_list(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"tools": {}}), encoding="utf-8")

    assert main(["mcp-import", "--tool-list", str(invalid), "--output-dir", str(tmp_path)]) == 2


def test_mcp_inventory_scaffold_requires_reviewer_resolution() -> None:
    from trustweave.mcp_import import build_manifest_scaffold

    inventory = normalize_mcp_tools_list(load_document(TOOL_LIST))
    scaffold = build_manifest_scaffold(inventory)

    assert scaffold["schema_version"] == "trustweave.dev/mcp-manifest-scaffold/v1alpha1"
    assert scaffold["manifest_draft"]["name"] == "REVIEW_REQUIRED_MCP_INTEGRATION"
    assert all(
        tool["action_class"] == "REVIEW_REQUIRED" for tool in scaffold["manifest_draft"]["tools"]
    )
    assert "not a valid Agent Security Manifest" in scaffold["limits"][0]

    with pytest.raises(ValidationError, match="inventory must use"):
        build_manifest_scaffold({})
