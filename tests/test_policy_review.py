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
    default_allow_finding = next(
        finding for finding in review["findings"] if finding["id"] == "TW-POL-001"
    )
    assert default_allow_finding == {
        "id": "TW-POL-001",
        "severity": "review",
        "message": (
            "The policy default decision is allow. Unmatched declared paths will be allowed and "
            "require explicit human review."
        ),
        "evidence_kind": "declared_policy_structure",
        "subject": {"policy": "support-agent-boundary-policy"},
    }
    assert review["summary"]["status"] == "review_required"


def test_policy_coverage_reports_redundant_contradictory_and_impossible_rules() -> None:
    document = _copy_policy_document()
    document["schema_version"] = "trustweave.dev/policy/v1alpha2"
    document["classification_taxonomy"] = ["public", "internal", "confidential", "restricted"]
    rules = document["rules"]
    assert isinstance(rules, list)
    rules.extend(
        [
            {
                "id": "TW-COVER-001",
                "description": "Broad deterministic test rule.",
                "source_trust": ["untrusted"],
                "tool_action_classes": ["external"],
                "decision": "deny",
                "rationale": "Test-only policy coverage rule.",
            },
            {
                "id": "TW-COVER-002",
                "description": "Contradictory shadowed deterministic test rule.",
                "source_trust": ["untrusted"],
                "tool_action_classes": ["external"],
                "decision": "allow",
                "rationale": "Test-only policy coverage rule.",
            },
            {
                "id": "TW-COVER-003",
                "description": "Impossible control requirement test rule.",
                "source_trust": ["trusted"],
                "tool_action_classes": ["read"],
                "required_controls": ["approval.fail_closed"],
                "decision": "allow",
                "rationale": "Test-only policy coverage rule.",
            },
        ]
    )
    document.pop("approval_control")

    review = review_policy(parse_policy(document), include_coverage=True)

    ids = {finding["id"] for finding in review["findings"]}
    assert {"TW-POL-007", "TW-POL-008"}.issubset(ids)
    coverage = review["coverage"]
    assert coverage["rules"]["TW-COVER-002"]["reachable"] is False
    assert coverage["rules"]["TW-COVER-002"]["shadowed_by"] == "TW-004"
    assert coverage["rules"]["TW-COVER-003"]["possible"] is False
    findings_by_id = {
        finding["id"]: finding
        for finding in review["findings"]
        if finding["id"] in {"TW-POL-002", "TW-POL-003", "TW-POL-007", "TW-POL-008"}
    }
    assert findings_by_id["TW-POL-002"]["message"] == (
        "Rule TW-COVER-003 is shadowed by earlier rule TW-001 under first-match semantics and "
        "cannot determine a decision."
    )
    assert findings_by_id["TW-POL-003"]["message"] == (
        "Rule TW-COVER-002 allows untrusted input to a sensitive or external action class; review "
        "its authorization and human-control boundary."
    )
    assert findings_by_id["TW-POL-007"]["message"] == (
        "Rule TW-COVER-002 conflicts with shadowing rule TW-004: their declared decisions differ."
    )
    assert findings_by_id["TW-POL-008"]["message"] == (
        "Rule TW-COVER-003 requires declared controls that this policy does not provide and cannot "
        "determine a decision."
    )
    assert all(
        finding["subject"] == {"policy": "support-agent-boundary-policy"}
        for finding in findings_by_id.values()
    )


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
                "--coverage",
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


def test_policy_review_preserves_exact_missing_and_incomplete_approval_artifacts() -> None:
    """Approval review findings retain canonical messages and bounded reviewer metadata."""

    missing_document = _copy_policy_document()
    missing_document.pop("approval_control")
    missing_review = review_policy(
        parse_policy(missing_document), generated_at="2026-08-15T00:00:00+00:00"
    )
    assert missing_review == {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "generated_at": "2026-08-15T00:00:00+00:00",
        "policy": "support-agent-boundary-policy",
        "approval_control": {
            "high_impact_approval_rules": ["TW-002"],
            "declared": False,
        },
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "review",
                "message": (
                    "Sensitive or external paths require approval, but the policy does not declare "
                    "an approval control that reviewers can inspect."
                ),
                "evidence_kind": "declared_policy_structure",
                "subject": {"policy": "support-agent-boundary-policy"},
            }
        ],
        "summary": {"rules": 4, "review_findings": 1, "status": "review_required"},
        "limits": [
            (
                "The review checks only deterministic structure and declared labels; it does not "
                "prove an approval mechanism exists, authenticate approvers, or authorize a "
                "deployed runtime."
            ),
            (
                "Findings indicate review obligations rather than vulnerabilities, compliance "
                "conclusions, or automatic approval decisions."
            ),
        ],
    }

    incomplete_document = _copy_policy_document()
    control = incomplete_document["approval_control"]
    assert isinstance(control, dict)
    control["binds_to"] = ["tool"]
    control["fail_closed"] = False
    incomplete_review = review_policy(
        parse_policy(incomplete_document), generated_at="2026-08-15T00:00:00+00:00"
    )
    assert incomplete_review["approval_control"] == {
        "high_impact_approval_rules": ["TW-002"],
        "declared": True,
        "mechanism": "human-review-queue",
        "binds_to": ["tool"],
        "fail_closed": False,
        "missing_required_bindings": ["actor", "expires_at", "issued_at", "parameters", "target"],
    }
    assert incomplete_review["findings"] == [
        {
            "id": "TW-POL-005",
            "severity": "review",
            "message": (
                "The declared approval control does not bind approvals to: actor, expires_at, "
                "issued_at, parameters, target."
            ),
            "evidence_kind": "declared_policy_structure",
            "subject": {"policy": "support-agent-boundary-policy"},
        },
        {
            "id": "TW-POL-006",
            "severity": "review",
            "message": (
                "The declared approval control is not fail-closed when approval state cannot be "
                "validated."
            ),
            "evidence_kind": "declared_policy_structure",
            "subject": {"policy": "support-agent-boundary-policy"},
        },
    ]
    assert incomplete_review["summary"] == {
        "rules": 4,
        "review_findings": 2,
        "status": "review_required",
    }
