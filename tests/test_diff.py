from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.diff import diff_bundles
from trustweave.engine import build_bundle
from trustweave.io import load_document, write_json
from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.report import render_diff_report

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"


def _copy_document(path: Path) -> dict[str, object]:
    return json.loads(json.dumps(load_document(path)))


def test_bundle_diff_flags_new_external_tool_and_changed_untrusted_decision() -> None:
    base_manifest_document = _copy_document(MANIFEST)
    head_manifest_document = _copy_document(MANIFEST)
    head_policy_document = _copy_document(POLICY)

    tools = head_manifest_document["tools"]
    assert isinstance(tools, list)
    tools.append(
        {
            "name": "archive_mock_export",
            "action_class": "external",
            "capabilities": ["archive.export"],
            "description": "A synthetic external export endpoint used only by this test.",
        }
    )
    flows = head_manifest_document["flows"]
    assert isinstance(flows, list)
    flows.append(
        {
            "source": "knowledge_base_document",
            "tool": "archive_mock_export",
            "purpose": "Synthetic untrusted external-path addition for deterministic diff testing.",
        }
    )
    rules = head_policy_document["rules"]
    assert isinstance(rules, list)
    for rule in rules:
        assert isinstance(rule, dict)
        if rule["id"] == "TW-004":
            rule["decision"] = "require_approval"
            rule["rationale"] = "Intentional test-only policy change."

    base_bundle = build_bundle(
        parse_manifest(base_manifest_document), parse_policy(_copy_document(POLICY))
    )
    head_bundle = build_bundle(
        parse_manifest(head_manifest_document), parse_policy(head_policy_document)
    )

    diff = diff_bundles(base_bundle, head_bundle)

    assert diff["summary"]["added_tools"] == 1
    assert diff["summary"]["added_paths"] == 1
    assert diff["summary"]["decision_changes"] == 1
    signal_ids = {signal["id"] for signal in diff["signals"]}
    assert {"TW-DIFF-001", "TW-DIFF-002"}.issubset(signal_ids)
    assert "TrustWeave Bundle Diff Report" in render_diff_report(diff)


def test_bundle_diff_rejects_unsupported_bundle_schema() -> None:
    bundle = build_bundle(
        parse_manifest(load_document(MANIFEST)), parse_policy(load_document(POLICY))
    )
    invalid_bundle = json.loads(json.dumps(bundle))
    invalid_bundle["schema_version"] = "invalid"

    with pytest.raises(ValidationError, match="base bundle must use"):
        diff_bundles(invalid_bundle, bundle)


def test_cli_diff_writes_json_and_markdown_artifacts(tmp_path: Path) -> None:
    manifest = parse_manifest(load_document(MANIFEST))
    policy = parse_policy(load_document(POLICY))
    bundle = build_bundle(manifest, policy)
    base_path = write_json(tmp_path / "base.json", bundle)
    head_path = write_json(tmp_path / "head.json", bundle)

    assert (
        main(
            [
                "diff",
                "--base",
                str(base_path),
                "--head",
                str(head_path),
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert (tmp_path / "bundle-diff.json").is_file()
    assert (tmp_path / "bundle-diff.md").is_file()


def test_bundle_diff_inventories_sensitive_capability_growth() -> None:
    base_manifest_document = _copy_document(MANIFEST)
    head_manifest_document = _copy_document(MANIFEST)
    tools = head_manifest_document["tools"]
    assert isinstance(tools, list)
    for tool in tools:
        assert isinstance(tool, dict)
        if tool["name"] == "lookup_customer_record":
            capabilities = tool["capabilities"]
            assert isinstance(capabilities, list)
            capabilities.append("customer-record.export")

    base_bundle = build_bundle(
        parse_manifest(base_manifest_document), parse_policy(_copy_document(POLICY))
    )
    head_bundle = build_bundle(
        parse_manifest(head_manifest_document), parse_policy(_copy_document(POLICY))
    )

    diff = diff_bundles(base_bundle, head_bundle)

    assert diff["summary"]["tools_with_capability_changes"] == 1
    assert diff["summary"]["added_capabilities"] == 1
    assert diff["summary"]["removed_capabilities"] == 0
    assert diff["changes"]["capabilities"] == [
        {
            "name": "lookup_customer_record",
            "action_class": "sensitive",
            "added": ["customer-record.export"],
            "removed": [],
        }
    ]
    signal_ids = {signal["id"] for signal in diff["signals"]}
    assert "TW-DIFF-003" in signal_ids
    report = render_diff_report(diff)
    assert "## Capability changes" in report
    assert "customer-record.export" in report
