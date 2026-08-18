from __future__ import annotations

import pytest

import trustweave.engine as engine_module
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
    assert matched["checked_rules"][2]["checks"] == {
        "source_trust": {
            "matched": True,
            "actual": "conditional",
            "expected_any_of": ["conditional"],
        },
        "tool_action_class": {
            "matched": True,
            "actual": "external",
            "expected_any_of": ["external"],
        },
        "source_data_classification": {
            "matched": True,
            "actual": "restricted",
            "expected_any_of": [],
        },
        "source_identifier": {"matched": True, "actual": "review-queue", "expected_any_of": []},
        "tool_identifier": {
            "matched": True,
            "actual": "notification-api",
            "expected_any_of": [],
        },
        "purpose_tags": {"matched": True, "actual": ["notify_customer"], "expected_any_of": []},
        "source_data_classification_bounds": {
            "matched": True,
            "actual": "restricted",
            "at_least": None,
            "at_most": None,
        },
        "required_controls": {"matched": True, "actual": [], "expected_all_of": []},
        "tool_capabilities": {
            "matched": True,
            "actual": ["notifications.send"],
            "expected_any_of": [],
        },
    }
    assert matched["decision"] == "require_approval"
    assert matched["rule_id"] == "TW-ENGINE-APPROVAL"
    assert matched["rationale"] == "The declared conditional external path requires review."
    assert matched["limits"] == [
        (
            "The explanation applies only to supplied synthetic labels and declared local "
            "policy metadata; it does not inspect or enforce a deployed runtime."
        )
    ]
    assert defaulted["schema_version"] == "trustweave.dev/policy-explanation/v1alpha1"
    assert defaulted["policy"] == "engine-mutation-contract"
    assert defaulted["decision"] == "deny"
    assert defaulted["rule_id"] is None
    assert defaulted["rationale"] == (
        "No policy rule matched this supplied local input; the default decision was applied."
    )
    assert defaulted["limits"] == matched["limits"]
    assert [(item["id"], item["matched"]) for item in defaulted["checked_rules"]] == [
        ("TW-ENGINE-FIRST", False),
        ("TW-ENGINE-LATER", False),
        ("TW-ENGINE-APPROVAL", False),
    ]


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


def test_synthetic_matching_binds_complete_predicate_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The synthetic matching API forwards the exact constructed declared subject to predicates."""

    observed: list[tuple[object, object, object, object]] = []

    def capture(_rule: object, source: object, tool: object, _policy: object, flow: object) -> bool:
        observed.append((source, tool, _policy, flow))
        return False

    monkeypatch.setattr(engine_module, "_rule_matches", capture)
    assert (
        matching_rule(
            _policy(),
            "conditional",
            "external",
            source_data_classification=None,
            tool_capabilities=("notifications.send",),
            source_identifier="inbox",
            tool_identifier="notifier",
            purpose="notify_customer",
        )
        is None
    )

    source, tool, _, flow = observed[0]
    assert source.name == "inbox"
    assert source.trust == "conditional"
    assert source.data_classification == "unspecified"
    assert source.description == "Synthetic policy scenario input."
    assert tool.name == "notifier"
    assert tool.action_class == "external"
    assert tool.capabilities == ("notifications.send",)
    assert tool.description == "Synthetic policy scenario input."
    assert flow.source == "inbox"
    assert flow.tool == "notifier"
    assert flow.purpose == "notify_customer"
    assert flow.purpose_tags == ("notify_customer",)


def test_synthetic_explanation_binds_complete_predicate_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explanation checks receive the same declared synthetic identity that it reports."""

    observed: list[tuple[object, object, object]] = []

    def capture_match(
        _rule: object, source: object, tool: object, _policy: object, flow: object
    ) -> bool:
        observed.append((source, tool, flow))
        return False

    monkeypatch.setattr(engine_module, "_rule_matches", capture_match)
    monkeypatch.setattr(engine_module, "_rule_match_checks", lambda *_arguments: {})
    explanation = explain_policy_decision(
        _policy(),
        "trusted",
        "read",
        source_data_classification="internal",
        tool_capabilities=("records.read",),
        source_identifier="case-inbox",
        tool_identifier="records-api",
        purpose="case_lookup",
    )

    assert explanation["decision"] == "deny"
    source, tool, flow = observed[0]
    assert source.description == "Synthetic explanation input."
    assert source.data_classification == "internal"
    assert tool.description == "Synthetic explanation input."
    assert tool.capabilities == ("records.read",)
    assert flow.source == "case-inbox"
    assert flow.tool == "records-api"
    assert flow.purpose == "case_lookup"
    assert flow.purpose_tags == ("case_lookup",)
