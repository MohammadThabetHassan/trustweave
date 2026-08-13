from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.engine import evaluate_manifest
from trustweave.io import load_document
from trustweave.models import ValidationError, parse_manifest, parse_policy

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"


def _policy_document() -> dict[str, object]:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def test_classification_and_capability_glob_change_declared_flow_decision() -> None:
    document = _policy_document()
    rules = document["rules"]
    assert isinstance(rules, list)
    rules.insert(
        0,
        {
            "id": "TW-ATTRIBUTE-001",
            "description": "Deny confidential external email capability paths.",
            "source_trust": ["conditional"],
            "source_data_classifications": ["confidential"],
            "tool_action_classes": ["external"],
            "tool_capabilities": ["email.*"],
            "decision": "deny",
            "severity": "critical",
            "rationale": "The declared confidential-to-email path requires a stricter review rule.",
        },
    )

    findings = evaluate_manifest(parse_manifest(load_document(MANIFEST)), parse_policy(document))
    confidential_email = next(
        finding
        for finding in findings
        if finding.flow.tool == "send_mock_email" and finding.flow.source == "customer_record"
    )
    assert confidential_email.decision == "deny"
    assert confidential_email.severity == "critical"
    assert confidential_email.rule_id == "TW-ATTRIBUTE-001"

    document["rules"][0]["source_data_classifications"] = ["public-content"]
    findings = evaluate_manifest(parse_manifest(load_document(MANIFEST)), parse_policy(document))
    confidential_email = next(
        finding
        for finding in findings
        if finding.flow.tool == "send_mock_email" and finding.flow.source == "customer_record"
    )
    assert confidential_email.decision == "require_approval"
    assert confidential_email.severity == "medium"


def test_policy_attribute_constraints_remain_declarative_and_validate_severity() -> None:
    document = _policy_document()
    rules = document["rules"]
    assert isinstance(rules, list)
    assert isinstance(rules[0], dict)
    rules[0]["tool_capabilities"] = ["email.*"]
    rules[0]["severity"] = "urgent"

    with pytest.raises(ValidationError, match="severity must be one of"):
        parse_policy(document)
