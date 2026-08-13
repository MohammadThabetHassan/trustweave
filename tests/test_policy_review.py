from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.io import load_document
from trustweave.models import ValidationError, parse_policy
from trustweave.policy_review import review_policy
from trustweave.report import render_policy_review_report

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "default-policy.json"


def _copy_policy_document() -> dict[str, object]:
    return json.loads(json.dumps(load_document(POLICY)))


def test_default_policy_has_no_static_review_findings() -> None:
    review = review_policy(parse_policy(_copy_policy_document()))

    assert review["summary"] == {"rules": 4, "review_findings": 0, "status": "clear"}
    assert review["approval_control"] == {
        "high_impact_approval_rules": ["TW-002"],
        "declared": True,
        "mechanism": "human-review-queue",
        "binds_to": ["actor", "tool", "target", "parameters", "issued_at", "expires_at"],
        "fail_closed": True,
        "missing_required_bindings": [],
    }
    report = render_policy_review_report(review)
    assert "## Declared approval boundary" in report
    assert "No deterministic structural review findings" in report


def test_policy_review_flags_allow_default_shadowed_rule_and_untrusted_external_allow() -> None:
    document = _copy_policy_document()
    document["default_decision"] = "allow"
    rules = document["rules"]
    assert isinstance(rules, list)
    rules.append(
        {
            "id": "TW-TEST-001",
            "description": "A deliberately broad test-only rule.",
            "source_trust": ["untrusted"],
            "tool_action_classes": ["external"],
            "decision": "allow",
            "rationale": "Test-only review control.",
        }
    )
    rules.append(
        {
            "id": "TW-TEST-002",
            "description": "A deliberately shadowed test-only rule.",
            "source_trust": ["untrusted"],
            "tool_action_classes": ["external"],
            "decision": "deny",
            "rationale": "Test-only review control.",
        }
    )

    review = review_policy(parse_policy(document))

    ids = {finding["id"] for finding in review["findings"]}
    assert {"TW-POL-001", "TW-POL-002", "TW-POL-003"}.issubset(ids)
    assert review["summary"]["status"] == "review_required"


def test_policy_rejects_explicit_null_approval_control() -> None:
    document = _copy_policy_document()
    document["approval_control"] = None

    with pytest.raises(ValidationError, match="policy.approval_control must be an object"):
        parse_policy(document)


def test_policy_review_flags_missing_or_incomplete_approval_controls() -> None:
    missing_document = _copy_policy_document()
    missing_document.pop("approval_control")
    missing_review = review_policy(parse_policy(missing_document))
    assert {finding["id"] for finding in missing_review["findings"]} == {"TW-POL-004"}

    incomplete_document = _copy_policy_document()
    control = incomplete_document["approval_control"]
    assert isinstance(control, dict)
    control["binds_to"] = ["tool"]
    control["fail_closed"] = False
    incomplete_review = review_policy(parse_policy(incomplete_document))
    assert {"TW-POL-005", "TW-POL-006"}.issubset(
        {finding["id"] for finding in incomplete_review["findings"]}
    )


def test_cli_policy_check_writes_json_markdown_and_optional_review_exit(tmp_path: Path) -> None:
    assert (
        main(
            [
                "policy-check",
                "--policy",
                str(POLICY),
                "--output-dir",
                str(tmp_path),
                "--exit-on-review",
            ]
        )
        == 0
    )
    assert (tmp_path / "policy-review.json").is_file()
    assert (tmp_path / "policy-review.md").is_file()

    review_required_policy = _copy_policy_document()
    review_required_policy.pop("approval_control")
    review_required_path = tmp_path / "approval-control-missing.json"
    review_required_path.write_text(json.dumps(review_required_policy), encoding="utf-8")
    assert (
        main(
            [
                "policy-check",
                "--policy",
                str(review_required_path),
                "--output-dir",
                str(tmp_path / "review-required"),
                "--exit-on-review",
            ]
        )
        == 1
    )
