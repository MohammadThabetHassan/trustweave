from __future__ import annotations

from trustweave.engine import (
    _default_severity,
    decision_for_scenario,
    evaluate_flow,
    explain_policy_decision,
    matching_rule,
)
from trustweave.models import Flow, Source, Tool, parse_policy


def _policy():
    return parse_policy(
        {
            "schema_version": "trustweave.dev/policy/v1alpha2",
            "name": "engine-mutation-contract",
            "default_decision": "deny",
            "classification_taxonomy": ["public", "internal", "confidential", "restricted"],
            "rules": [
                {
                    "id": "TW-ENGINE-FIRST",
                    "description": "Allow declared trusted reads.",
                    "source_trust": ["trusted"],
                    "tool_action_classes": ["read"],
                    "decision": "allow",
                    "rationale": "The first declared trusted-read rule applies.",
                },
                {
                    "id": "TW-ENGINE-LATER",
                    "description": "A later broad rule must not replace the first match.",
                    "source_trust": ["trusted"],
                    "tool_action_classes": ["read"],
                    "decision": "deny",
                    "rationale": "This rule is intentionally shadowed for first-match testing.",
                },
                {
                    "id": "TW-ENGINE-APPROVAL",
                    "description": "Conditional external actions require review.",
                    "source_trust": ["conditional"],
                    "tool_action_classes": ["external"],
                    "decision": "require_approval",
                    "rationale": "The declared conditional external path requires review.",
                },
            ],
        }
    )


def test_default_severity_is_exact_for_every_supported_decision() -> None:
    assert _default_severity("deny") == "high"
    assert _default_severity("require_approval") == "medium"
    assert _default_severity("allow") == "info"


def test_synthetic_matching_preserves_first_match_and_declared_inputs() -> None:
    policy = _policy()

    matched = matching_rule(
        policy,
        "trusted",
        "read",
        source_data_classification="confidential",
        tool_capabilities=("records.read",),
        source_identifier="customer-inbox",
        tool_identifier="records-api",
        purpose="case_lookup",
    )
    decision = decision_for_scenario(
        policy,
        "trusted",
        "read",
        source_data_classification="confidential",
        tool_capabilities=("records.read",),
        source_identifier="customer-inbox",
        tool_identifier="records-api",
        purpose="case_lookup",
    )

    assert matched is not None
    assert matched.id == "TW-ENGINE-FIRST"
    assert decision == ("allow", "TW-ENGINE-FIRST")


def test_synthetic_default_has_no_rule_and_exact_default_decision() -> None:
    policy = _policy()

    assert matching_rule(policy, "untrusted", "sensitive") is None
    assert decision_for_scenario(policy, "untrusted", "sensitive") == ("deny", None)


def test_explanation_contains_exact_input_rule_order_and_default_behavior() -> None:
    policy = _policy()

    matched = explain_policy_decision(
        policy,
        "conditional",
        "external",
        source_data_classification="restricted",
        tool_capabilities=("notifications.send",),
        source_identifier="review-queue",
        tool_identifier="notification-api",
        purpose="notify_customer",
    )
    defaulted = explain_policy_decision(policy, "untrusted", "sensitive")

    assert matched["schema_version"] == "trustweave.dev/policy-explanation/v1alpha1"
    assert matched["policy"] == "engine-mutation-contract"
    assert matched["input"] == {
        "source_trust": "conditional",
        "source_data_classification": "restricted",
        "source_identifier": "review-queue",
        "tool_action_class": "external",
        "tool_capabilities": ["notifications.send"],
        "tool_identifier": "notification-api",
        "purpose_tag": "notify_customer",
    }
    assert [(item["id"], item["matched"]) for item in matched["checked_rules"]] == [
        ("TW-ENGINE-FIRST", False),
        ("TW-ENGINE-LATER", False),
        ("TW-ENGINE-APPROVAL", True),
    ]
    assert matched["decision"] == "require_approval"
    assert matched["rule_id"] == "TW-ENGINE-APPROVAL"
    assert matched["rationale"] == "The declared conditional external path requires review."
    assert defaulted["schema_version"] == "trustweave.dev/policy-explanation/v1alpha1"
    assert defaulted["policy"] == "engine-mutation-contract"
    assert defaulted["decision"] == "deny"
    assert defaulted["rule_id"] is None
    assert defaulted["rationale"] == (
        "No policy rule matched this supplied local input; the default decision was applied."
    )


def test_synthetic_defaults_are_stable_in_matching_and_explanations() -> None:
    policy = _policy()

    matched = matching_rule(policy, "trusted", "read")
    decision = decision_for_scenario(policy, "trusted", "read")
    explanation = explain_policy_decision(policy, "trusted", "read")

    assert matched is not None
    assert matched.id == "TW-ENGINE-FIRST"
    assert decision == ("allow", "TW-ENGINE-FIRST")
    assert explanation["input"] == {
        "source_trust": "trusted",
        "source_data_classification": "unspecified",
        "source_identifier": "synthetic-source",
        "tool_action_class": "read",
        "tool_capabilities": [],
        "tool_identifier": "synthetic-tool",
        "purpose_tag": "synthetic",
    }


def test_unmatched_declared_flow_retains_default_severity_and_rationale() -> None:
    policy = _policy()
    flow = Flow(source="untrusted-inbox", tool="sensitive-api", purpose="fallback")
    source = Source(
        name="untrusted-inbox",
        trust="untrusted",
        data_classification="confidential",
        description="Declared test source.",
    )
    tool = Tool(
        name="sensitive-api",
        action_class="sensitive",
        capabilities=("records.read",),
        description="Declared test tool.",
    )

    finding = evaluate_flow(flow, source, tool, policy)

    assert finding.decision == "deny"
    assert finding.severity == "high"
    assert finding.rule_id is None
    assert finding.rationale == (
        "No policy rule matched this declared path; the default decision was applied."
    )


def test_synthetic_defaults_participate_in_identifier_and_purpose_predicates() -> None:
    policy = parse_policy(
        {
            "schema_version": "trustweave.dev/policy/v1alpha2",
            "name": "synthetic-default-predicate-contract",
            "default_decision": "deny",
            "classification_taxonomy": ["public", "internal", "confidential", "restricted"],
            "rules": [
                {
                    "id": "TW-ENGINE-SYNTHETIC",
                    "description": "Match the documented synthetic defaults exactly.",
                    "source_trust": ["trusted"],
                    "tool_action_classes": ["read"],
                    "source_identifiers": ["synthetic-source"],
                    "tool_identifiers": ["synthetic-tool"],
                    "purpose_tags": ["synthetic"],
                    "decision": "allow",
                    "rationale": "The exact synthetic defaults form a deterministic subject.",
                }
            ],
        }
    )

    assert matching_rule(policy, "trusted", "read") is not None
    assert decision_for_scenario(policy, "trusted", "read") == (
        "allow",
        "TW-ENGINE-SYNTHETIC",
    )
    assert decision_for_scenario(
        policy,
        "trusted",
        "read",
        source_identifier="other-source",
    ) == ("deny", None)
    assert decision_for_scenario(
        policy,
        "trusted",
        "read",
        tool_identifier="other-tool",
    ) == ("deny", None)
    assert decision_for_scenario(policy, "trusted", "read", purpose="other-purpose") == (
        "deny",
        None,
    )
