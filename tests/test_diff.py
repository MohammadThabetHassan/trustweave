from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.diff import diff_bundles
from trustweave.engine import build_bundle
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


def test_bundle_diff_does_not_compare_unmatched_rule_inventory_items() -> None:
    """Rule additions and removals are policy deltas, not direct before/after rule comparisons."""

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
    assert _signal_ids(diff) == set()


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
