from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

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


def test_policy_coverage_does_not_shadow_with_an_impossible_earlier_rule() -> None:
    """Only a possible earlier rule can make a later first-match rule unreachable."""

    document = {
        "schema_version": "trustweave.dev/policy/v1alpha2",
        "name": "impossible-earlier-audit-policy",
        "classification_taxonomy": ["public", "internal", "confidential", "restricted"],
        "default_decision": "deny",
        "rules": [
            {
                "id": "TW-AUDIT-IMPOSSIBLE",
                "description": "An earlier rule requiring an absent declared control.",
                "source_trust": ["trusted"],
                "tool_action_classes": ["read"],
                "required_controls": ["approval.fail_closed"],
                "decision": "deny",
                "rationale": "The required control is intentionally absent.",
            },
            {
                "id": "TW-AUDIT-REACHABLE",
                "description": "A later rule that remains possible and reachable.",
                "source_trust": ["trusted"],
                "tool_action_classes": ["read"],
                "decision": "allow",
                "rationale": "This rule has no impossible control requirement.",
            },
        ],
    }

    review = review_policy(parse_policy(document), include_coverage=True)

    coverage = review["coverage"]["rules"]
    assert coverage["TW-AUDIT-IMPOSSIBLE"]["possible"] is False
    assert coverage["TW-AUDIT-REACHABLE"] == {
        "reachable": True,
        "possible": True,
        "shadowed_by": None,
        "decision": "allow",
    }
    assert {finding["id"] for finding in review["findings"]} == {"TW-POL-008"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document["rules"][0].update(  # type: ignore[index]
            {"source_trust": ["untrusted", "untrusted"]}
        ),
        lambda document: document["rules"][0].update(  # type: ignore[index]
            {"tool_action_classes": ["external", "external"]}
        ),
        lambda document: document["rules"][0].update(  # type: ignore[index]
            {"source_data_classifications": ["confidential", "confidential"]}
        ),
        lambda document: document["rules"][0].update(  # type: ignore[index]
            {"tool_capabilities": ["records.read", "records.read"]}
        ),
        lambda document: document.update({"name": "p" * 129}),
        lambda document: document["rules"][0].update(  # type: ignore[index]
            {"description": "d" * 4097}
        ),
        lambda document: document["rules"][0].update(  # type: ignore[index]
            {"source_identifiers": [f"source-{index}" for index in range(129)]}
        ),
        lambda document: document["approval_control"].update(  # type: ignore[index]
            {"binds_to": [f"binding-{index}" for index in range(65)]}
        ),
    ],
)
def test_policy_parser_and_schema_reject_the_same_declared_boundary_violations(
    mutate: object,
) -> None:
    """Public parser and schema constraints agree for representative audit boundary cases."""

    document = _copy_policy_document()
    document["schema_version"] = "trustweave.dev/policy/v1alpha2"
    assert callable(mutate)
    mutate(document)

    schema = json.loads((ROOT / "schemas" / "policy-v1alpha2.schema.json").read_text("utf-8"))
    schema_errors = list(Draft202012Validator(schema).iter_errors(document))
    assert schema_errors
    with pytest.raises(ValidationError):
        parse_policy(document)


def _v1alpha2_policy() -> dict[str, object]:
    document = _copy_policy_document()
    document["schema_version"] = "trustweave.dev/policy/v1alpha2"
    return document


def _first_rule(document: dict[str, object]) -> dict[str, object]:
    rules = document["rules"]
    assert isinstance(rules, list)
    first_rule = rules[0]
    assert isinstance(first_rule, dict)
    return first_rule


@pytest.mark.parametrize(
    ("mutate", "expected_message"),
    [
        (
            lambda document: document.update(
                {
                    "classification_taxonomy": ["confidential"]
                    + [f"class-{index}" for index in range(32)]
                }
            ),
            "policy.classification_taxonomy must contain at most 32 entries",
        ),
        (
            lambda document: document.update({"classification_taxonomy": ["x" * 65]}),
            "policy.classification_taxonomy must be at most 64 characters",
        ),
        (
            lambda document: document.update({"name": "n" * 129}),
            "policy.name must be at most 128 characters",
        ),
        (
            lambda document: document.update(
                {
                    "rules": [
                        {
                            **_first_rule(document),
                            "id": f"RULE-{index}",
                        }
                        for index in range(1_001)
                    ]
                }
            ),
            "policy.rules must contain at most 1000 entries",
        ),
        (
            lambda document: _first_rule(document).update(
                {"source_trust": ["trusted", "untrusted", "conditional", "trusted"]}
            ),
            "policy.rules[0].source_trust must contain at most 3 entries",
        ),
        (
            lambda document: _first_rule(document).update(
                {
                    "tool_action_classes": [
                        "read",
                        "write",
                        "sensitive",
                        "external",
                        "read",
                    ]
                }
            ),
            "policy.rules[0].tool_action_classes must contain at most 4 entries",
        ),
        (
            lambda document: _first_rule(document).update(
                {"source_data_classifications": ["confidential"] * 33}
            ),
            "policy.rules[0].source_data_classifications must contain at most 32 entries",
        ),
        (
            lambda document: _first_rule(document).update(
                {"tool_capabilities": ["records.read"] * 129}
            ),
            "policy.rules[0].tool_capabilities must contain at most 128 entries",
        ),
        (
            lambda document: _first_rule(document).update(
                {"source_identifiers": [f"source-{index}" for index in range(129)]}
            ),
            "policy.rules[0].source_identifiers must contain at most 128 entries",
        ),
        (
            lambda document: _first_rule(document).update(
                {"tool_identifiers": [f"tool-{index}" for index in range(129)]}
            ),
            "policy.rules[0].tool_identifiers must contain at most 128 entries",
        ),
        (
            lambda document: _first_rule(document).update(
                {"purpose_tags": [f"tag-{index}" for index in range(129)]}
            ),
            "policy.rules[0].purpose_tags must contain at most 128 entries",
        ),
        (
            lambda document: _first_rule(document).update(
                {"required_controls": ["approval", "approval.fail_closed", "approval"]}
            ),
            "policy.rules[0].required_controls must contain at most 2 entries",
        ),
        (
            lambda document: _first_rule(document).update({"description": "d" * 4_097}),
            "policy.rules[0].description must be at most 4096 characters",
        ),
        (
            lambda document: _first_rule(document).update({"rationale": "r" * 4_097}),
            "policy.rules[0].rationale must be at most 4096 characters",
        ),
        (
            lambda document: document["approval_control"].update(  # type: ignore[index]
                {"binds_to": [f"binding-{index}" for index in range(65)]}
            ),
            "policy.approval_control.binds_to must contain at most 64 entries",
        ),
        (
            lambda document: document["approval_control"].update(  # type: ignore[index]
                {"mechanism": "m" * 4_097}
            ),
            "policy.approval_control.mechanism must be at most 4096 characters",
        ),
        (
            lambda document: document["approval_control"].update(  # type: ignore[index]
                {"binds_to": ["b" * 4_097]}
            ),
            "policy.approval_control.binds_to must be at most 4096 characters",
        ),
    ],
)
def test_policy_v1alpha2_parser_and_schema_enforce_all_exact_boundaries(
    mutate: object, expected_message: str
) -> None:
    """Every newly mirrored public policy bound remains parser/schema-equivalent."""

    document = _v1alpha2_policy()
    assert callable(mutate)
    mutate(document)
    schema = json.loads((ROOT / "schemas" / "policy-v1alpha2.schema.json").read_text("utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(document))
    with pytest.raises(ValidationError, match=re.escape(expected_message)):
        parse_policy(document)


def test_policy_v1alpha2_parser_accepts_values_at_exact_text_boundaries() -> None:
    """Schema maxima are inclusive for current policy documents."""

    document = _v1alpha2_policy()
    document["name"] = "n" * 128
    document["classification_taxonomy"] = ["c" * 64]
    rule = _first_rule(document)
    rule["description"] = "d" * 4_096
    rule["rationale"] = "r" * 4_096
    rule["source_data_classifications"] = ["c" * 64]
    control = document["approval_control"]
    assert isinstance(control, dict)
    control["mechanism"] = "m" * 4_096
    control["binds_to"] = ["b" * 4_096]

    parse_policy(document)
