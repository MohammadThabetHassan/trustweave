from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.engine import decision_for_scenario
from trustweave.models import ValidationError, parse_policy
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
    assert explanation["checked_rules"] == [{"id": "TW-V2-001", "matched": True}]


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
