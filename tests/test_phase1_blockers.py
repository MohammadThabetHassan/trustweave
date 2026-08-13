from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.scenarios import explain_scenario, parse_scenarios, run_scenarios

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "default-policy.json"


def _policy(rules: list[dict[str, object]], default: str = "deny") -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "blocker-regression-policy",
        "default_decision": default,
        "rules": rules,
    }


def _rule(identifier: str, **constraints: object) -> dict[str, object]:
    return {
        "id": identifier,
        "description": f"Rule {identifier}",
        "source_trust": ["conditional"],
        "tool_action_classes": ["external"],
        "decision": "deny",
        "rationale": "Synthetic regression rule.",
        **constraints,
    }


def _shadowed_rule_ids(review: dict[str, object]) -> list[str]:
    findings = review["findings"]
    assert isinstance(findings, list)
    return [str(finding["message"]) for finding in findings if finding["id"] == "TW-POL-002"]


def test_shadow_analysis_is_conservative_for_attribute_constraints() -> None:
    constrained_first = parse_policy(
        _policy(
            [
                _rule("FIRST", source_data_classifications=["confidential"]),
                _rule("LATER"),
            ]
        )
    )
    assert not _shadowed_rule_ids(review_policy(constrained_first))

    broad_first = parse_policy(
        _policy(
            [
                _rule("FIRST"),
                _rule("LATER", source_data_classifications=["confidential"]),
            ]
        )
    )
    assert any(
        "Rule LATER is shadowed" in message
        for message in _shadowed_rule_ids(review_policy(broad_first))
    )

    namespace_first = parse_policy(
        _policy(
            [
                _rule("FIRST", tool_capabilities=["email.*"]),
                _rule("LATER", tool_capabilities=["email.send"]),
            ]
        )
    )
    assert any(
        "Rule LATER is shadowed" in message
        for message in _shadowed_rule_ids(review_policy(namespace_first))
    )

    exact_first = parse_policy(
        _policy(
            [
                _rule("FIRST", tool_capabilities=["email.send"]),
                _rule("LATER", tool_capabilities=["email.*"]),
            ]
        )
    )
    assert not _shadowed_rule_ids(review_policy(exact_first))


def test_capability_patterns_are_bounded_and_manifest_capabilities_are_exact() -> None:
    for pattern in ("email.?", "email.[ab]", "email.*.send", "email.*.*", "Email.send", "a" * 129):
        with pytest.raises(ValidationError):
            parse_policy(_policy([_rule("BAD", tool_capabilities=[pattern])]))

    valid = parse_policy(_policy([_rule("GOOD", tool_capabilities=["email.*"])]))
    assert valid.rules[0].tool_capabilities == ("email.*",)

    manifest = {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "manifest",
        "description": "manifest",
        "sources": [
            {
                "name": "source",
                "trust": "trusted",
                "data_classification": "public",
                "description": "source",
            }
        ],
        "tools": [
            {
                "name": "tool",
                "action_class": "read",
                "capabilities": ["email.*"],
                "description": "tool",
            }
        ],
        "flows": [{"source": "source", "tool": "tool", "purpose": "read"}],
    }
    with pytest.raises(ValidationError, match="exact capability"):
        parse_manifest(manifest)


def test_non_string_contract_keys_raise_validation_error() -> None:
    with pytest.raises(ValidationError, match="field names must be strings"):
        parse_manifest({1: "not-a-field"})


def test_attribute_aware_scenarios_use_manifest_equivalent_matching() -> None:
    policy = parse_policy(
        _policy(
            [
                _rule(
                    "ATTRIBUTE-DENY",
                    source_data_classifications=["confidential"],
                    tool_capabilities=["email.*"],
                ),
                {
                    **_rule("FALLBACK"),
                    "decision": "require_approval",
                },
            ],
            default="allow",
        )
    )
    scenarios = parse_scenarios(
        {
            "schema_version": "trustweave.dev/v1alpha1",
            "scenarios": [
                {
                    "id": "ATTRIBUTE-MATCH",
                    "description": "Matching synthetic attributes are denied.",
                    "source_trust": "conditional",
                    "source_data_classification": "confidential",
                    "tool_action_class": "external",
                    "tool_capabilities": ["email.send"],
                    "expected_decision": "deny",
                },
                {
                    "id": "ATTRIBUTE-MISMATCH",
                    "description": "Different attributes reach the fallback rule.",
                    "source_trust": "conditional",
                    "source_data_classification": "public",
                    "tool_action_class": "external",
                    "tool_capabilities": ["email.send"],
                    "expected_decision": "require_approval",
                },
                {
                    "id": "ATTRIBUTE-CAPABILITY-MISMATCH",
                    "description": "Different capability reaches the fallback rule.",
                    "source_trust": "conditional",
                    "source_data_classification": "confidential",
                    "tool_action_class": "external",
                    "tool_capabilities": ["ticket.create"],
                    "expected_decision": "require_approval",
                },
            ],
        }
    )
    result = run_scenarios(policy, scenarios)
    assert result["summary"]["status"] == "passed"
    assert result["results"][0]["rule_id"] == "ATTRIBUTE-DENY"
    assert result["results"][1]["rule_id"] == "FALLBACK"
    assert "confidential" in explain_scenario(scenarios, "ATTRIBUTE-MATCH")


def test_existing_default_scenarios_remain_compatible() -> None:
    policy = parse_policy(json.loads(POLICY.read_text(encoding="utf-8")))
    scenarios_path = ROOT / "scenarios" / "default-scenarios.json"
    scenarios = parse_scenarios(json.loads(scenarios_path.read_text(encoding="utf-8")))
    assert run_scenarios(policy, scenarios)["summary"]["status"] == "passed"
