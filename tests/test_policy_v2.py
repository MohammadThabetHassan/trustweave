from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.engine import decision_for_scenario, evaluate_manifest
from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.scenarios import parse_scenarios, run_scenarios


def _policy_document() -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/policy/v1alpha2",
        "name": "v2-boundary-policy",
        "default_decision": "allow",
        "classification_taxonomy": ["public", "internal", "confidential", "restricted"],
        "approval_control": {
            "mechanism": "declared-ticket",
            "binds_to": ["actor", "tool", "target", "parameters", "issued_at", "expires_at"],
            "fail_closed": True,
        },
        "rules": [
            {
                "id": "TW-V2-001",
                "description": "Deny declared confidential outbound email from the inbox.",
                "source_trust": ["untrusted"],
                "tool_action_classes": ["external"],
                "source_identifiers": ["inbox"],
                "tool_identifiers": ["send_email"],
                "purpose_tags": ["outbound"],
                "source_data_classification_at_least": "confidential",
                "tool_capabilities": ["email.send"],
                "required_controls": ["approval.fail_closed"],
                "decision": "deny",
                "rationale": "Declared confidential inbox content must not reach external email.",
            }
        ],
    }


def test_policy_v2_matches_all_bounded_dimensions() -> None:
    policy = parse_policy(_policy_document())
    observed, rule_id = decision_for_scenario(
        policy,
        "untrusted",
        "external",
        "confidential",
        ("email.send",),
        "inbox",
        "send_email",
        "outbound",
    )
    assert (observed, rule_id) == ("deny", "TW-V2-001")

    for source, tool, classification, capabilities, purpose in (
        ("other", "send_email", "confidential", ("email.send",), "outbound"),
        ("inbox", "other", "confidential", ("email.send",), "outbound"),
        ("inbox", "send_email", "internal", ("email.send",), "outbound"),
        ("inbox", "send_email", "confidential", ("email.read",), "outbound"),
        ("inbox", "send_email", "confidential", ("email.send",), "other"),
        ("inbox", "send_email", "undeclared", ("email.send",), "outbound"),
    ):
        assert decision_for_scenario(
            policy,
            "untrusted",
            "external",
            classification,
            capabilities,
            source,
            tool,
            purpose,
        ) == ("allow", None)


def test_policy_v2_manifest_purpose_tags_are_machine_readable_and_additive() -> None:
    policy = parse_policy(_policy_document())
    manifest = parse_manifest(
        {
            "schema_version": "trustweave.dev/v1alpha1",
            "name": "purpose-tag-manifest",
            "description": "A declared purpose remains prose while tags are identifiers.",
            "sources": [
                {
                    "name": "inbox",
                    "trust": "untrusted",
                    "data_classification": "confidential",
                    "description": "Declared inbox.",
                }
            ],
            "tools": [
                {
                    "name": "send_email",
                    "action_class": "external",
                    "capabilities": ["email.send"],
                    "description": "Declared email route.",
                }
            ],
            "flows": [
                {
                    "source": "inbox",
                    "tool": "send_email",
                    "purpose": "Send the customer the requested account update.",
                    "purpose_tags": ["outbound"],
                }
            ],
        }
    )

    findings = evaluate_manifest(manifest, policy)

    assert findings[0].decision == "deny"
    assert manifest.as_dict()["flows"][0]["purpose_tags"] == ["outbound"]


def test_policy_v2_scenarios_use_identifier_and_purpose_constraints() -> None:
    policy = parse_policy(_policy_document())
    scenarios = parse_scenarios(
        {
            "schema_version": "trustweave.dev/v1alpha1",
            "name": "policy-v2-scenarios",
            "scenarios": [
                {
                    "id": "v2-match",
                    "description": "Synthetic declared metadata only.",
                    "source_trust": "untrusted",
                    "source_data_classification": "confidential",
                    "source_identifier": "inbox",
                    "tool_action_class": "external",
                    "tool_identifier": "send_email",
                    "tool_capabilities": ["email.send"],
                    "purpose_tag": "outbound",
                    "expected_decision": "deny",
                }
            ],
        }
    )
    result = run_scenarios(policy, scenarios, generated_at="2026-08-13T00:00:00+00:00")
    assert result["summary"]["status"] == "passed"
    assert result["results"][0]["input"]["purpose_tag"] == "outbound"


def test_why_command_emits_a_local_machine_readable_rule_trace(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy_document()), encoding="utf-8")
    assert (
        main(
            [
                "why",
                "--policy",
                str(policy_path),
                "--source-trust",
                "untrusted",
                "--source-data-classification",
                "confidential",
                "--source-identifier",
                "inbox",
                "--tool-action-class",
                "external",
                "--tool-identifier",
                "send_email",
                "--tool-capability",
                "email.send",
                "--purpose-tag",
                "outbound",
            ]
        )
        == 0
    )
    explanation = json.loads(capsys.readouterr().out)
    assert explanation["decision"] == "deny"
    assert explanation["rule_id"] == "TW-V2-001"
    assert explanation["checked_rules"] == [
        {
            "id": "TW-V2-001",
            "matched": True,
            "checks": {
                "source_trust": {
                    "matched": True,
                    "actual": "untrusted",
                    "expected_any_of": ["untrusted"],
                },
                "tool_action_class": {
                    "matched": True,
                    "actual": "external",
                    "expected_any_of": ["external"],
                },
                "source_data_classification": {
                    "matched": True,
                    "actual": "confidential",
                    "expected_any_of": [],
                },
                "source_identifier": {
                    "matched": True,
                    "actual": "inbox",
                    "expected_any_of": ["inbox"],
                },
                "tool_identifier": {
                    "matched": True,
                    "actual": "send_email",
                    "expected_any_of": ["send_email"],
                },
                "purpose_tags": {
                    "matched": True,
                    "actual": ["outbound"],
                    "expected_any_of": ["outbound"],
                },
                "source_data_classification_bounds": {
                    "matched": True,
                    "actual": "confidential",
                    "at_least": "confidential",
                    "at_most": None,
                },
                "required_controls": {
                    "matched": True,
                    "actual": ["approval", "approval.fail_closed"],
                    "expected_all_of": ["approval.fail_closed"],
                },
                "tool_capabilities": {
                    "matched": True,
                    "actual": ["email.send"],
                    "expected_any_of": ["email.send"],
                },
            },
        }
    ]


def test_policy_v2_identifier_constraint_does_not_false_shadow_broader_rule() -> None:
    document = _policy_document()
    broad_rule = dict(document["rules"][0])
    broad_rule["id"] = "TW-V2-002"
    broad_rule.pop("source_identifiers")
    document["rules"] = [document["rules"][0], broad_rule]
    findings = review_policy(parse_policy(document))["findings"]
    assert not any(item["id"] == "TW-POL-002" for item in findings)


def test_policy_v2_rejects_unknown_required_controls() -> None:
    document = _policy_document()
    rule = document["rules"][0]
    assert isinstance(rule, dict)
    rule["required_controls"] = ["nonexistent.control"]

    with pytest.raises(ValidationError, match="unknown required controls"):
        parse_policy(document)


def test_policy_v2_rejects_empty_exact_classification_bound_intersection() -> None:
    document = _policy_document()
    rule = document["rules"][0]
    assert isinstance(rule, dict)
    rule["source_data_classifications"] = ["public"]
    rule["source_data_classification_at_least"] = "confidential"

    with pytest.raises(ValidationError, match="empty classification intersection"):
        parse_policy(document)


def test_policy_v2_rejects_impossible_bounds_and_unknown_exact_classification() -> None:
    invalid_bounds = _policy_document()
    rule = invalid_bounds["rules"][0]
    assert isinstance(rule, dict)
    rule["source_data_classification_at_most"] = "internal"
    with pytest.raises(ValidationError, match="impossible classification"):
        parse_policy(invalid_bounds)

    invalid_exact = _policy_document()
    exact_rule = invalid_exact["rules"][0]
    assert isinstance(exact_rule, dict)
    exact_rule["source_data_classifications"] = ["secret"]
    with pytest.raises(ValidationError, match="classification_taxonomy"):
        parse_policy(invalid_exact)


def test_policy_v2_rejects_invalid_taxonomy_references_and_v1_unknown_fields() -> None:
    invalid = _policy_document()
    rule = invalid["rules"][0]
    assert isinstance(rule, dict)
    rule["source_data_classification_at_least"] = "secret"
    with pytest.raises(ValidationError, match="classification_taxonomy"):
        parse_policy(invalid)

    legacy = _policy_document()
    legacy["schema_version"] = "trustweave.dev/v1alpha1"
    with pytest.raises(ValidationError, match="unknown field"):
        parse_policy(legacy)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("classification_taxonomy", [], "must not be empty"),
        ("classification_taxonomy", ["public", "public"], "duplicate values"),
    ],
)
def test_policy_v2_rejects_invalid_taxonomy_declarations(
    field: str, value: object, message: str
) -> None:
    document = _policy_document()
    document[field] = value

    with pytest.raises(ValidationError, match=message):
        parse_policy(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_identifiers", ["inbox", "inbox"]),
        ("tool_identifiers", ["send_email", "send_email"]),
        ("purpose_tags", ["outbound", "outbound"]),
        ("required_controls", ["approval", "approval"]),
    ],
)
def test_policy_v2_rejects_duplicate_optional_rule_constraints(
    field: str, value: list[str]
) -> None:
    document = _policy_document()
    rule = document["rules"][0]
    assert isinstance(rule, dict)
    rule[field] = value

    with pytest.raises(ValidationError, match="duplicate values"):
        parse_policy(document)


@pytest.mark.parametrize(
    ("control", "message"),
    [
        (None, "approval_control must be an object"),
        ({"mechanism": "declared", "binds_to": [], "fail_closed": True}, "must not be empty"),
        (
            {"mechanism": "declared", "binds_to": ["tool", "tool"], "fail_closed": True},
            "duplicate values",
        ),
        ({"mechanism": "declared", "binds_to": ["tool"], "fail_closed": "true"}, "boolean"),
    ],
)
def test_policy_v2_rejects_invalid_approval_control_contracts(
    control: object, message: str
) -> None:
    document = _policy_document()
    document["approval_control"] = control

    with pytest.raises(ValidationError, match=message):
        parse_policy(document)


def test_policy_coverage_detects_shadowing_when_declared_controls_are_static() -> None:
    document = _policy_document()
    first = dict(document["rules"][0])
    first["id"] = "TW-V2-STATIC-CONTROL-FIRST"
    first["source_identifiers"] = []
    first["tool_identifiers"] = []
    first["purpose_tags"] = []
    first["source_data_classification_at_least"] = None
    first["tool_capabilities"] = []
    first["required_controls"] = ["approval"]
    first["decision"] = "deny"

    later = dict(first)
    later["id"] = "TW-V2-STATIC-CONTROL-LATER"
    later["required_controls"] = ["approval.fail_closed"]
    document["rules"] = [first, later]

    review = review_policy(parse_policy(document), include_coverage=True)

    assert review["coverage"] == {
        "rules": {
            "TW-V2-STATIC-CONTROL-FIRST": {
                "reachable": True,
                "possible": True,
                "shadowed_by": None,
                "decision": "deny",
            },
            "TW-V2-STATIC-CONTROL-LATER": {
                "reachable": False,
                "possible": True,
                "shadowed_by": "TW-V2-STATIC-CONTROL-FIRST",
                "decision": "deny",
            },
        },
        "shadowed_rules": ["TW-V2-STATIC-CONTROL-LATER"],
        "impossible_rules": [],
    }
