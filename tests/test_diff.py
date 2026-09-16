from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.diff import diff_bundles
from trustweave.engine import build_bundle, decision_for_scenario
from trustweave.io import load_document, write_json
from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.policy_weakening import policy_review_signals
from trustweave.report import render_diff_report

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
HISTORICAL_V011_BUNDLE = (
    ROOT / "tests" / "fixtures" / "historical-v011" / "authentic-v0.1.1-bundle.json"
)


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

    with pytest.raises(ValidationError, match="base bundle.schema_version"):
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


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda bundle: bundle.pop("manifest"), "manifest"),
        (
            lambda bundle: bundle["manifest"].update({"sources": [{"trust": "trusted"}]}),
            "sources",
        ),
        (
            lambda bundle: bundle["manifest"].update(
                {"tools": [bundle["manifest"]["tools"][0], bundle["manifest"]["tools"][0]]}
            ),
            "tools",
        ),
        (
            lambda bundle: bundle.update({"findings": [{"flow": {"source": "source"}}]}),
            "findings",
        ),
        (
            lambda bundle: bundle["manifest"]["tools"][0].update({"capabilities": [""]}),
            "capabilities",
        ),
    ],
)
def test_bundle_diff_rejects_malformed_declared_artifact_components(
    mutate: object, message: str
) -> None:
    bundle = build_bundle(
        parse_manifest(_copy_document(MANIFEST)), parse_policy(_copy_document(POLICY))
    )
    head = json.loads(json.dumps(bundle))
    assert callable(mutate)
    mutate(head)

    with pytest.raises(ValidationError, match=message):
        diff_bundles(bundle, head)


def test_bundle_diff_supports_historical_and_current_bundle_versions() -> None:
    """A v1alpha3 diff explicitly records a compatible v1alpha1-to-v1alpha2 comparison."""

    manifest = parse_manifest(_copy_document(MANIFEST))
    policy = parse_policy(_copy_document(POLICY))
    current = build_bundle(manifest, policy, generated_at="2026-08-15T00:00:00+00:00")
    historical = _copy_document(HISTORICAL_V011_BUNDLE)

    diff = diff_bundles(historical, current, generated_at="2026-08-15T00:00:00+00:00")

    assert diff["schema_version"] == "trustweave.dev/bundle-diff/v1alpha3"
    assert diff["base"]["bundle_schema_version"] == "trustweave.dev/bundle/v1alpha1"
    assert diff["head"]["bundle_schema_version"] == "trustweave.dev/bundle/v1alpha2"


def test_bundle_diff_reports_policy_only_fail_closed_weakening() -> None:
    """A security-relevant approval control change is visible without an outcome change."""

    base_policy_document = _copy_document(POLICY)
    head_policy_document = _copy_document(POLICY)
    approval_control = head_policy_document["approval_control"]
    assert isinstance(approval_control, dict)
    approval_control["fail_closed"] = False
    manifest = parse_manifest(_copy_document(MANIFEST))

    diff = diff_bundles(
        build_bundle(manifest, parse_policy(base_policy_document)),
        build_bundle(manifest, parse_policy(head_policy_document)),
    )

    assert diff["schema_version"] == "trustweave.dev/bundle-diff/v1alpha3"
    assert diff["changes"]["paths"] == {
        "added": [],
        "removed": [],
        "decision_changed": [],
    }
    assert diff["changes"]["policy"] == {
        "changed": [
            {
                "path": "policy.approval_control.fail_closed",
                "before": True,
                "after": False,
                "security_relevant": True,
            }
        ]
    }
    assert diff["summary"]["policy_changes"] == 1
    assert {signal["id"] for signal in diff["signals"]} == {"TW-DIFF-004"}
    _policy_signal(
        diff,
        "TW-DIFF-004",
        "The declared approval control changed from fail-closed to fail-open; review "
        "approval-boundary enforcement before accepting this policy change.",
        {"policy_field": "approval_control.fail_closed"},
    )


def test_bundle_diff_reports_default_allow_policy_weakening() -> None:
    """Default-decision weakening receives a deterministic policy delta and review signal."""

    base_policy_document = _copy_document(POLICY)
    head_policy_document = _copy_document(POLICY)
    head_policy_document["default_decision"] = "allow"
    manifest = parse_manifest(_copy_document(MANIFEST))

    diff = diff_bundles(
        build_bundle(manifest, parse_policy(base_policy_document)),
        build_bundle(manifest, parse_policy(head_policy_document)),
    )

    assert diff["changes"]["policy"]["changed"] == [
        {
            "path": "policy.default_decision",
            "before": "deny",
            "after": "allow",
            "security_relevant": True,
        }
    ]
    assert {signal["id"] for signal in diff["signals"]} == {"TW-DIFF-005"}
    _policy_signal(
        diff,
        "TW-DIFF-005",
        "The policy default decision changed to allow; unmatched declared paths now require "
        "explicit human review.",
        {"policy_field": "default_decision"},
    )


def _policy_only_diff(
    base_policy_document: dict[str, object], head_policy_document: dict[str, object]
) -> dict[str, object]:
    manifest = parse_manifest(_copy_document(MANIFEST))
    return diff_bundles(
        build_bundle(manifest, parse_policy(base_policy_document)),
        build_bundle(manifest, parse_policy(head_policy_document)),
        generated_at="2026-08-20T00:00:00+00:00",
    )


def _signal_ids(diff: dict[str, object]) -> set[str]:
    signals = diff["signals"]
    assert isinstance(signals, list)
    return {str(signal["id"]) for signal in signals if isinstance(signal, dict)}


def _policy_signal(
    diff: dict[str, object], identifier: str, message: str, subject: dict[str, object]
) -> None:
    """Assert the full stable public finding emitted for one policy weakening category."""

    signals = diff["signals"]
    assert isinstance(signals, list)
    matching = [
        signal for signal in signals if isinstance(signal, dict) and signal.get("id") == identifier
    ]
    assert matching == [
        {
            "id": identifier,
            "severity": "review",
            "message": message,
            "evidence_kind": "declared_bundle_difference",
            "subject": subject,
        }
    ]


def test_bundle_diff_reports_removed_approval_control_once() -> None:
    """Removing a declared approval control remains review-visible without flow changes."""

    base = _copy_document(POLICY)
    head = _copy_document(POLICY)
    head.pop("approval_control")

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["decision_changes"] == 0
    assert _signal_ids(diff) == {"TW-DIFF-006"}
    _policy_signal(
        diff,
        "TW-DIFF-006",
        "The declared approval control was removed; review every require-approval boundary "
        "before accepting this policy change.",
        {"policy_field": "approval_control"},
    )


def test_bundle_diff_reports_removed_approval_binding_once() -> None:
    """A narrower approval binding contract is a policy-only weakening signal."""

    base = _copy_document(POLICY)
    head = _copy_document(POLICY)
    control = head["approval_control"]
    assert isinstance(control, dict)
    control["binds_to"] = ["actor", "tool", "target", "parameters", "issued_at"]

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["decision_changes"] == 0
    assert _signal_ids(diff) == {"TW-DIFF-007"}
    _policy_signal(
        diff,
        "TW-DIFF-007",
        "The declared approval control lost one or more binding fields; review whether "
        "approval remains scoped to the actor, tool, target, parameters, and time.",
        {
            "policy_field": "approval_control.binds_to",
            "removed_bindings": ["expires_at"],
        },
    )


@pytest.mark.parametrize(
    ("before_decision", "after_decision"),
    [
        ("deny", "require_approval"),
        ("deny", "allow"),
        ("require_approval", "allow"),
    ],
)
def test_bundle_diff_reports_unexercised_rule_decision_weakening(
    before_decision: str, after_decision: str
) -> None:
    """Rule weakenings are visible even when no current manifest flow matches the rule."""

    base = _copy_document(POLICY)
    rules = base["rules"]
    assert isinstance(rules, list)
    rules.append(
        {
            "id": "TW-AUDIT-UNEXERCISED",
            "description": "Keep a deliberately unexercised declared boundary restricted.",
            "source_trust": ["conditional"],
            "tool_action_classes": ["write"],
            "decision": before_decision,
            "rationale": "This test-only rule must remain independently reviewable.",
        }
    )
    head = _copy_document(POLICY)
    head_rules = head["rules"]
    assert isinstance(head_rules, list)
    head_rules.append(
        {
            "id": "TW-AUDIT-UNEXERCISED",
            "description": "Keep a deliberately unexercised declared boundary restricted.",
            "source_trust": ["conditional"],
            "tool_action_classes": ["write"],
            "decision": after_decision,
            "rationale": "This test-only rule must remain independently reviewable.",
        }
    )

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["decision_changes"] == 0
    assert _signal_ids(diff) == {"TW-DIFF-008"}
    _policy_signal(
        diff,
        "TW-DIFF-008",
        "One or more declared policy rules became less restrictive; review the changed "
        "decision boundaries even when no current manifest flow exercises them.",
        {"rule_ids": ["TW-AUDIT-UNEXERCISED"]},
    )


def test_bundle_diff_reports_removed_required_controls() -> None:
    """Removing a declared rule control is visible independently of its rule decision."""

    base = _copy_document(POLICY)
    base["schema_version"] = "trustweave.dev/policy/v1alpha2"
    rules = base["rules"]
    assert isinstance(rules, list)
    rules.append(
        {
            "id": "TW-AUDIT-CONTROLS",
            "description": "Keep a test-only approval boundary explicitly controlled.",
            "source_trust": ["conditional"],
            "tool_action_classes": ["write"],
            "decision": "require_approval",
            "rationale": "This declared rule is intentionally unexercised by the manifest.",
            "required_controls": ["approval", "approval.fail_closed"],
        }
    )
    head = json.loads(json.dumps(base))
    head_rules = head["rules"]
    assert isinstance(head_rules, list)
    head_rules[-1]["required_controls"] = []

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["decision_changes"] == 0
    assert _signal_ids(diff) == {"TW-DIFF-009"}
    _policy_signal(
        diff,
        "TW-DIFF-009",
        "One or more declared policy rules lost required controls; review the affected "
        "approval and fail-closed obligations.",
        {"rule_ids": ["TW-AUDIT-CONTROLS"]},
    )


def test_bundle_diff_reports_classification_taxonomy_change() -> None:
    """Taxonomy changes always require explicit classification-boundary review."""

    base = _copy_document(POLICY)
    base["schema_version"] = "trustweave.dev/policy/v1alpha2"
    base["classification_taxonomy"] = ["public", "internal", "confidential", "restricted"]
    head = json.loads(json.dumps(base))
    head["classification_taxonomy"] = ["public", "internal", "confidential"]

    diff = _policy_only_diff(base, head)

    assert _signal_ids(diff) == {"TW-DIFF-010"}
    _policy_signal(
        diff,
        "TW-DIFF-010",
        "The declared classification taxonomy changed; review classification ordering, "
        "coverage, and every policy bound that depends on it.",
        {"policy_field": "classification_taxonomy"},
    )


def test_policy_weakening_classifier_retains_each_category_in_a_combined_delta() -> None:
    """Independent categories remain distinct stable signals for combined policy weakenings."""

    signals = policy_review_signals(
        [
            {
                "path": "policy.default_decision",
                "before": "deny",
                "after": "allow",
            },
            {
                "path": "policy.classification_taxonomy",
                "before": ["public", "restricted"],
                "after": ["public"],
            },
            {
                "path": "policy.approval_control.fail_closed",
                "before": True,
                "after": False,
            },
            {
                "path": "policy.approval_control.binds_to",
                "before": ["actor", "tool"],
                "after": ["actor"],
            },
            {
                "path": "policy.rules",
                "before": [
                    {
                        "id": "TW-AUDIT-COMBINED",
                        "decision": "deny",
                        "required_controls": ["approval"],
                    }
                ],
                "after": [
                    {
                        "id": "TW-AUDIT-COMBINED",
                        "decision": "allow",
                        "required_controls": [],
                    }
                ],
            },
        ]
    )

    assert [signal["id"] for signal in signals] == [
        "TW-DIFF-004",
        "TW-DIFF-005",
        "TW-DIFF-007",
        "TW-DIFF-008",
        "TW-DIFF-009",
        "TW-DIFF-010",
    ]


def test_policy_weakening_classifier_ignores_neutral_default_and_control_deltas() -> None:
    """Guard conditions remain fail-closed for neutral policy deltas."""

    signals = policy_review_signals(
        [
            {
                "path": "policy.default_decision",
                "before": "allow",
                "after": "allow",
            },
            {
                "path": "policy.rules",
                "before": [
                    {
                        "id": "TW-AUDIT-UNCHANGED",
                        "decision": "require_approval",
                        "required_controls": ["approval"],
                    }
                ],
                "after": [
                    {
                        "id": "TW-AUDIT-UNCHANGED",
                        "decision": "require_approval",
                        "required_controls": ["approval"],
                    }
                ],
            },
        ]
    )

    assert signals == []


def test_bundle_diff_reports_added_unexercised_rule_for_structural_review() -> None:
    """A new unexercised rule remains review-visible without a current path decision change."""

    base = _copy_document(POLICY)
    head = _copy_document(POLICY)
    rules = head["rules"]
    assert isinstance(rules, list)
    rules.append(
        {
            "id": "TW-AUDIT-ADDED",
            "description": (
                "A test-only trusted external boundary added for policy inventory coverage."
            ),
            "source_trust": ["trusted"],
            "tool_action_classes": ["external"],
            "decision": "deny",
            "rationale": "This addition must not be incorrectly compared with a missing base rule.",
        }
    )

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["policy_changes"] == 1
    assert diff["summary"]["decision_changes"] == 0
    _policy_signal(
        diff,
        "TW-DIFF-011",
        "Declared policy rule structure changed in a way that can alter first-match "
        "coverage; review the listed rule boundaries. This review signal does not prove "
        "that every listed change is insecure.",
        {
            "added_rule_ids": ["TW-AUDIT-ADDED"],
            "removed_rule_ids": [],
            "matching_predicate_changed_rule_ids": [],
            "reordered_rule_ids": [],
        },
    )


def test_bundle_diff_does_not_signal_neutral_rule_reordering() -> None:
    """Reordering semantically independent rules is recorded but not classified as weakening."""

    base = _copy_document(POLICY)
    head = _copy_document(POLICY)
    rules = head["rules"]
    assert isinstance(rules, list)
    head["rules"] = list(reversed(rules))

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["policy_changes"] == 1
    assert _signal_ids(diff) == set()


def _structural_rule(identifier: str, decision: str = "allow") -> dict[str, object]:
    """Return a valid v1alpha2 rule deliberately unmatched by the support-agent manifest."""

    return {
        "id": identifier,
        "description": "A deliberately unexercised structural-policy audit boundary.",
        "source_trust": ["conditional"],
        "tool_action_classes": ["write"],
        "source_identifiers": ["audit_unexercised_source"],
        "tool_identifiers": ["audit_unexercised_tool"],
        "purpose_tags": ["audit_structural"],
        "source_data_classifications": ["confidential"],
        "source_data_classification_at_least": "internal",
        "source_data_classification_at_most": "restricted",
        "tool_capabilities": ["record.write"],
        "decision": decision,
        "rationale": "This local test rule is intentionally not exercised by current flows.",
    }


def _v2_policy_with_structural_rule(identifier: str, decision: str = "allow") -> dict[str, object]:
    """Return a current policy with one unmatched v1alpha2 structural rule."""

    policy = _copy_document(POLICY)
    policy["schema_version"] = "trustweave.dev/policy/v1alpha2"
    rules = policy["rules"]
    assert isinstance(rules, list)
    rules.append(_structural_rule(identifier, decision))
    return policy


def _structural_signal(diff: dict[str, object]) -> dict[str, object]:
    """Return the canonical single structural-policy review signal from a bundle diff."""

    matching = [signal for signal in diff["signals"] if signal["id"] == "TW-DIFF-011"]
    assert matching == [
        {
            "id": "TW-DIFF-011",
            "severity": "review",
            "message": (
                "Declared policy rule structure changed in a way that can alter first-match "
                "coverage; review the listed rule boundaries. This review signal does not prove "
                "that every listed change is insecure."
            ),
            "evidence_kind": "declared_bundle_difference",
            "subject": matching[0]["subject"],
        }
    ]
    return matching[0]


def test_bundle_diff_reports_removed_unexercised_deny_for_structural_review() -> None:
    """Removing an unmatched deny rule remains visible even when its fallback is unexercised."""

    base = _v2_policy_with_structural_rule("TW-AUDIT-STRUCTURAL-REMOVE", "deny")
    head = _copy_document(POLICY)
    head["schema_version"] = "trustweave.dev/policy/v1alpha2"

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["policy_changes"] == 1
    assert diff["summary"]["decision_changes"] == 0
    assert _structural_signal(diff)["subject"] == {
        "added_rule_ids": [],
        "removed_rule_ids": ["TW-AUDIT-STRUCTURAL-REMOVE"],
        "matching_predicate_changed_rule_ids": [],
        "reordered_rule_ids": [],
    }


@pytest.mark.parametrize(
    "field, after_value",
    [
        ("source_trust", ["conditional", "untrusted"]),
        ("tool_action_classes", ["write", "external"]),
        ("source_identifiers", ["audit_unexercised_source", "second_source"]),
        ("tool_identifiers", ["audit_unexercised_tool", "second_tool"]),
        ("purpose_tags", ["audit_structural", "second_purpose"]),
        ("source_data_classifications", ["confidential", "restricted"]),
        ("source_data_classification_at_least", "public"),
        ("source_data_classification_at_most", "confidential"),
        ("tool_capabilities", ["record.write", "record.update"]),
    ],
)
def test_bundle_diff_reports_changed_unexercised_matching_predicate_for_structural_review(
    field: str, after_value: object
) -> None:
    """Every declared matching predicate is independently reviewer-visible when it changes."""

    identifier = "TW-AUDIT-STRUCTURAL-PREDICATE"
    base = _v2_policy_with_structural_rule(identifier)
    head = json.loads(json.dumps(base))
    rules = head["rules"]
    assert isinstance(rules, list)
    rules[-1][field] = after_value

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["decision_changes"] == 0
    assert _structural_signal(diff)["subject"] == {
        "added_rule_ids": [],
        "removed_rule_ids": [],
        "matching_predicate_changed_rule_ids": [identifier],
        "reordered_rule_ids": [],
    }


def test_bundle_diff_reports_potentially_overlapping_rule_reordering_for_structural_review() -> (
    None
):
    """First-match order changes are visible when two unexercised rule boundaries can overlap."""

    base = _copy_document(POLICY)
    base["schema_version"] = "trustweave.dev/policy/v1alpha2"
    base_rules = base["rules"]
    assert isinstance(base_rules, list)
    first = _structural_rule("TW-AUDIT-STRUCTURAL-ORDER-A", "deny")
    second = _structural_rule("TW-AUDIT-STRUCTURAL-ORDER-B", "allow")
    base_rules.extend((first, second))
    head = json.loads(json.dumps(base))
    head_rules = head["rules"]
    assert isinstance(head_rules, list)
    head["rules"] = [*head_rules[:-2], head_rules[-1], head_rules[-2]]

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["decision_changes"] == 0
    assert _structural_signal(diff)["subject"] == {
        "added_rule_ids": [],
        "removed_rule_ids": [],
        "matching_predicate_changed_rule_ids": [],
        "reordered_rule_ids": ["TW-AUDIT-STRUCTURAL-ORDER-A", "TW-AUDIT-STRUCTURAL-ORDER-B"],
    }


def test_bundle_diff_does_not_report_description_or_rationale_only_rule_edit() -> None:
    """Text-only changes do not masquerade as a matching-boundary structural review signal."""

    base = _v2_policy_with_structural_rule("TW-AUDIT-STRUCTURAL-TEXT")
    head = json.loads(json.dumps(base))
    rules = head["rules"]
    assert isinstance(rules, list)
    rules[-1]["description"] = "Updated local prose only."
    rules[-1]["rationale"] = "Updated local rationale only."

    diff = _policy_only_diff(base, head)

    assert diff["summary"]["policy_changes"] == 1
    assert _signal_ids(diff) == set()


def test_policy_weakening_classifier_combines_specific_and_structural_review_once() -> None:
    """Specific weakening evidence and broad structural review remain distinct and de-duplicated."""

    before_rule = _structural_rule("TW-AUDIT-STRUCTURAL-COMBINED", "deny")
    after_rule = json.loads(json.dumps(before_rule))
    after_rule["decision"] = "allow"
    after_rule["source_trust"] = ["conditional", "untrusted"]
    signals = policy_review_signals(
        [{"path": "policy.rules", "before": [before_rule], "after": [after_rule]}]
    )

    assert [signal["id"] for signal in signals] == ["TW-DIFF-008", "TW-DIFF-011"]
    structural = next(signal for signal in signals if signal["id"] == "TW-DIFF-011")
    assert structural["subject"] == {
        "added_rule_ids": [],
        "removed_rule_ids": [],
        "matching_predicate_changed_rule_ids": ["TW-AUDIT-STRUCTURAL-COMBINED"],
        "reordered_rule_ids": [],
    }


def test_policy_weakening_classifier_sorts_and_deduplicates_structural_rule_identifiers() -> None:
    """One structural signal exposes stable sorted identifiers even across compound changes."""

    before = [
        _structural_rule("TW-AUDIT-STRUCTURAL-B", "deny"),
        _structural_rule("TW-AUDIT-STRUCTURAL-A", "allow"),
    ]
    after = [
        _structural_rule("TW-AUDIT-STRUCTURAL-A", "allow"),
        _structural_rule("TW-AUDIT-STRUCTURAL-C", "deny"),
    ]
    signals = policy_review_signals([{"path": "policy.rules", "before": before, "after": after}])

    assert [signal["id"] for signal in signals] == ["TW-DIFF-011"]
    assert signals[0]["subject"] == {
        "added_rule_ids": ["TW-AUDIT-STRUCTURAL-C"],
        "removed_rule_ids": ["TW-AUDIT-STRUCTURAL-B"],
        "matching_predicate_changed_rule_ids": [],
        "reordered_rule_ids": [],
    }


def test_policy_weakening_classifier_ignores_exact_canonical_rule_equivalence() -> None:
    """A canonical-equivalent rules delta cannot create a structural review signal."""

    rule = _structural_rule("TW-AUDIT-STRUCTURAL-UNCHANGED")
    signals = policy_review_signals([{"path": "policy.rules", "before": [rule], "after": [rule]}])

    assert signals == []


def test_policy_weakening_classifier_ignores_unchanged_order_of_overlapping_rules() -> None:
    """Overlapping rules require a changed relative order before structural review is emitted."""

    first = _structural_rule("TW-AUDIT-STRUCTURAL-STABLE-A", "deny")
    second = _structural_rule("TW-AUDIT-STRUCTURAL-STABLE-B", "allow")
    signals = policy_review_signals(
        [{"path": "policy.rules", "before": [first, second], "after": [first, second]}]
    )

    assert signals == []


def test_reordering_a_wildcard_deny_below_an_exact_allow_is_a_review_signal() -> None:
    """`deny net.*` above `allow net.http` denies net.http; swapped, it allows it.

    The overlap helper compared capability patterns as strings, so the two were disjoint
    and the swap produced an empty signals list. A flow's capabilities are a set matched
    by any pattern, so no capability constraint can prove two rules apart.
    """

    deny = _structural_rule("TW-NET-DENY", "deny")
    deny["tool_capabilities"] = ["net.*"]
    allow = _structural_rule("TW-NET-HTTP-ALLOW", "allow")
    allow["tool_capabilities"] = ["net.http"]

    signals = policy_review_signals(
        [{"path": "policy.rules", "before": [deny, allow], "after": [allow, deny]}]
    )

    assert [signal["id"] for signal in signals] == ["TW-DIFF-011"]
    assert signals[0]["subject"]["reordered_rule_ids"] == ["TW-NET-DENY", "TW-NET-HTTP-ALLOW"]


def test_reordering_rules_that_differ_only_by_purpose_tag_is_a_review_signal() -> None:
    """A flow tagged with both purposes matches both rules, so their order matters."""

    first = _structural_rule("TW-PURPOSE-A", "deny")
    first["purpose_tags"] = ["billing"]
    second = _structural_rule("TW-PURPOSE-B", "allow")
    second["purpose_tags"] = ["support"]

    signals = policy_review_signals(
        [{"path": "policy.rules", "before": [first, second], "after": [second, first]}]
    )

    assert [signal["id"] for signal in signals] == ["TW-DIFF-011"]
    assert signals[0]["subject"]["reordered_rule_ids"] == ["TW-PURPOSE-A", "TW-PURPOSE-B"]


def test_reordering_rules_with_disjoint_trust_labels_is_still_neutral() -> None:
    """A single-valued subject field with disjoint values keeps proving two rules apart."""

    first = _structural_rule("TW-TRUST-A", "deny")
    first["source_trust"] = ["trusted"]
    second = _structural_rule("TW-TRUST-B", "allow")
    second["source_trust"] = ["untrusted"]

    signals = policy_review_signals(
        [{"path": "policy.rules", "before": [first, second], "after": [second, first]}]
    )

    assert signals == []


# ---------------------------------------------------------------------------------------
# Flows that differ only in their purpose tags (audit E-14a)
# ---------------------------------------------------------------------------------------


def _tagged_manifest(*tag_sets: list[str]) -> dict[str, object]:
    """Return a manifest whose flows share a source, tool and purpose but not their tags."""

    return {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "audit-tagged-flows",
        "description": "Two declared paths that differ only in why the data is used.",
        "sources": [
            {
                "name": "crm",
                "trust": "untrusted",
                "data_classification": "internal",
                "description": "Customer records supplied by an untrusted integration.",
            }
        ],
        "tools": [
            {
                "name": "reader",
                "action_class": "read",
                "capabilities": ["record.read"],
                "description": "Reads customer records.",
            }
        ],
        "flows": [
            {"source": "crm", "tool": "reader", "purpose": "lookup", "purpose_tags": tags}
            for tags in tag_sets
        ],
    }


def _tagged_policy() -> dict[str, object]:
    """Return a v1alpha2 policy that decides the two flows apart on their purpose tags."""

    return {
        "schema_version": "trustweave.dev/policy/v1alpha2",
        "name": "audit-purpose-tag-policy",
        "default_decision": "deny",
        "rules": [
            {
                "id": "TW-BILLING-READ",
                "description": "Billing lookups of customer records are reviewed and allowed.",
                "source_trust": ["untrusted"],
                "tool_action_classes": ["read"],
                "purpose_tags": ["billing"],
                "decision": "allow",
                "rationale": "Billing lookups are covered by the reviewed billing boundary.",
            }
        ],
    }


def _tagged_bundle(*tag_sets: list[str]) -> dict[str, object]:
    return build_bundle(parse_manifest(_tagged_manifest(*tag_sets)), parse_policy(_tagged_policy()))


def test_two_flows_differing_only_in_purpose_tags_can_be_diffed() -> None:
    """The diff refused a bundle scan had just written, naming ('crm', 'reader', 'lookup').

    Auditor's probe: scan a manifest with flows
    {'source':'crm','tool':'reader','purpose':'lookup','purpose_tags':['billing']} and
    {...'purpose_tags':['marketing']}, then diff the resulting bundle against itself.
    validate_bundle accepted the bundle (findings are compared as a multiset) while
    _findings_by_key keyed on (source, tool, purpose) alone and raised
    "bundle contains duplicate finding for ('crm', 'reader', 'lookup')" at exit 2.
    """

    bundle = _tagged_bundle(["billing"], ["marketing"])

    assert [
        (finding["flow"]["purpose_tags"], finding["decision"]) for finding in bundle["findings"]
    ] == [
        (["billing"], "allow"),
        (["marketing"], "deny"),
    ]

    diff = diff_bundles(bundle, bundle)

    assert diff["summary"]["added_paths"] == 0
    assert diff["summary"]["removed_paths"] == 0
    assert diff["summary"]["decision_changes"] == 0
    assert diff["signals"] == []


def test_two_byte_identical_flows_are_still_refused_and_the_message_names_the_flow() -> None:
    """Pins the refusal direction: only genuinely repeated flows remain a diff error.

    The old message called two distinct findings "duplicate" and printed a bare tuple.
    Folding purpose tags into the key leaves exactly one collision -- a flow declared
    twice, byte for byte -- and the message now names the bundle, the finding index and
    every field of the flow it repeats.
    """

    bundle = _tagged_bundle(["billing"], ["billing"])

    with pytest.raises(ValidationError) as error:
        diff_bundles(bundle, bundle)

    assert str(error.value) == (
        "base bundle findings[1] repeats a declared flow already indexed by this diff: "
        "source crm, tool reader, purpose lookup, purpose_tags ['billing']"
    )


def test_retagging_a_flow_reads_as_one_removed_and_one_added_declared_path() -> None:
    """Retagging is an add plus a remove, because the tags are part of the flow identity.

    This is the cost of the fix and it is deliberate: a flow whose purpose tags changed
    may match a different policy rule, so it is a different declared path, not the same
    path with a new decision.
    """

    base = _tagged_bundle(["billing"])
    head = _tagged_bundle(["marketing"])

    diff = diff_bundles(base, head)

    assert diff["summary"]["added_paths"] == 1
    assert diff["summary"]["removed_paths"] == 1
    assert diff["summary"]["decision_changes"] == 0
    assert diff["changes"]["paths"]["added"][0]["flow"]["purpose_tags"] == ["marketing"]
    assert diff["changes"]["paths"]["removed"][0]["flow"]["purpose_tags"] == ["billing"]


def test_the_published_decision_change_key_stays_three_elements() -> None:
    """bundle-diff v1alpha3 pins the key to source, tool and purpose; the fix must not widen it."""

    base = _tagged_bundle(["billing"])
    head_policy = _tagged_policy()
    rules = head_policy["rules"]
    assert isinstance(rules, list)
    rules[0]["decision"] = "require_approval"
    rules[0]["rationale"] = "Billing lookups now require a human approval."
    head = build_bundle(parse_manifest(_tagged_manifest(["billing"])), parse_policy(head_policy))

    diff = diff_bundles(base, head)

    changed = diff["changes"]["paths"]["decision_changed"]
    assert [entry["key"] for entry in changed] == [["crm", "reader", "lookup"]]
    assert changed[0]["after"]["flow"]["purpose_tags"] == ["billing"]


_REQUIRED_CONTROLS_PROBE_MANIFEST: dict[str, object] = {
    "schema_version": "trustweave.dev/v1alpha1",
    "name": "required-controls-probe",
    "description": "One benign declared flow, so only policy deltas produce signals.",
    "sources": [
        {
            "name": "operator",
            "trust": "trusted",
            "data_classification": "public",
            "description": "The authenticated operator.",
        }
    ],
    "tools": [
        {
            "name": "reader",
            "action_class": "read",
            "capabilities": ["doc.read"],
            "description": "A read-only tool.",
        }
    ],
    "flows": [{"source": "operator", "tool": "reader", "purpose": "read"}],
}


def _probe_policy_diff(
    base_policy_document: dict[str, object], head_policy_document: dict[str, object]
) -> dict[str, object]:
    """Diff two policies over a manifest whose only flow is benign under both."""

    manifest = parse_manifest(json.loads(json.dumps(_REQUIRED_CONTROLS_PROBE_MANIFEST)))
    return diff_bundles(
        build_bundle(manifest, parse_policy(base_policy_document)),
        build_bundle(manifest, parse_policy(head_policy_document)),
        generated_at="2026-08-20T00:00:00+00:00",
    )


def _required_controls_probe_policy() -> dict[str, object]:
    """The auditor's probe: a deny rule in front of a broad allow, and no declared control."""

    return {
        "schema_version": "trustweave.dev/policy/v1alpha2",
        "name": "required-controls-probe",
        "default_decision": "allow",
        "classification_taxonomy": ["public", "internal", "confidential", "restricted"],
        "rules": [
            {
                "id": "TW-DENYEXT",
                "description": "Deny untrusted input to external actions.",
                "source_trust": ["untrusted"],
                "tool_action_classes": ["external"],
                "decision": "deny",
                "rationale": "Untrusted text must not leave the declared boundary.",
            },
            {
                "id": "TW-ALLOWEXT",
                "description": "Every other declared path may act externally.",
                "source_trust": ["trusted", "conditional", "untrusted"],
                "tool_action_classes": ["read", "write", "sensitive", "external"],
                "decision": "allow",
                "rationale": "Broad allow rule behind the deny rule.",
            },
        ],
    }


def test_a_rule_that_gains_a_required_control_the_policy_does_not_declare_is_reported() -> None:
    """Turning a deny rule off by adding an unsatisfiable control emitted no signal at all.

    `required_controls` is a policy-global satisfiability gate, so naming a control the policy
    does not declare switches the whole rule off. The probe: `TW-DENYEXT` gains
    `required_controls: ["approval"]` while the policy declares no approval control, so
    `decision_for_scenario(policy, "untrusted", "external")` goes from
    `("deny", "TW-DENYEXT")` to `("allow", "TW-ALLOWEXT")` and `trustweave diff` emitted
    nothing: no signal, no decision change, exit 0.
    """

    base = _required_controls_probe_policy()
    head = json.loads(json.dumps(base))
    head_rules = head["rules"]
    assert isinstance(head_rules, list)
    head_rules[0]["required_controls"] = ["approval"]

    assert decision_for_scenario(parse_policy(base), "untrusted", "external") == (
        "deny",
        "TW-DENYEXT",
    )
    assert decision_for_scenario(parse_policy(head), "untrusted", "external") == (
        "allow",
        "TW-ALLOWEXT",
    )

    diff = _probe_policy_diff(base, head)

    assert _signal_ids(diff) == {"TW-DIFF-012"}
    _policy_signal(
        diff,
        "TW-DIFF-012",
        "One or more declared policy rules gained a required control this policy does not "
        "declare; the rule can no longer match any declared flow and those paths now take a "
        "later rule or the default decision.",
        {"rule_ids": ["TW-DENYEXT"]},
    )


def test_a_rule_that_gains_a_required_control_the_policy_declares_is_not_a_weakening() -> None:
    """Pins the refusal direction that keeps `required_controls` out of the matching fields.

    Adding a control the policy does declare narrows the rule without switching it off, so it
    must not co-fire. Treating `required_controls` as a symmetric matching predicate instead
    would report this harmless addition.
    """

    base = _required_controls_probe_policy()
    base["approval_control"] = {
        "mechanism": "human-review-queue",
        "binds_to": ["actor", "tool", "target", "parameters", "issued_at", "expires_at"],
        "fail_closed": True,
    }
    head = json.loads(json.dumps(base))
    head_rules = head["rules"]
    assert isinstance(head_rules, list)
    head_rules[0]["required_controls"] = ["approval"]

    diff = _probe_policy_diff(base, head)

    assert _signal_ids(diff) == set()
    assert diff["summary"]["decision_changes"] == 0


def test_removing_the_approval_control_under_a_rule_that_requires_it_stays_one_signal() -> None:
    """The rule is unchanged, so only the approval-control removal is reported.

    The new signal is directional on the rule's own declaration; a policy-level control
    removal is already `TW-DIFF-006` and must not be reported twice.
    """

    base = _required_controls_probe_policy()
    base["approval_control"] = {
        "mechanism": "human-review-queue",
        "binds_to": ["actor", "tool", "target", "parameters", "issued_at", "expires_at"],
        "fail_closed": True,
    }
    base_rules = base["rules"]
    assert isinstance(base_rules, list)
    base_rules[0]["required_controls"] = ["approval"]
    head = json.loads(json.dumps(base))
    head.pop("approval_control")

    diff = _probe_policy_diff(base, head)

    assert _signal_ids(diff) == {"TW-DIFF-006"}
