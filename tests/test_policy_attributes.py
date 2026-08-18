from __future__ import annotations

import json
from pathlib import Path

import pytest

import trustweave.policy_predicates as predicates_module
from trustweave.engine import evaluate_manifest
from trustweave.io import load_document
from trustweave.models import Policy, PolicyRule, ValidationError, parse_manifest, parse_policy
from trustweave.policy_predicates import (
    PolicySubject,
    capability_matches,
    capability_pattern_covers,
    classification_matches,
    rule_covers,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"


def _policy_document() -> dict[str, object]:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def test_classification_and_capability_glob_change_declared_flow_decision() -> None:
    document = _policy_document()
    rules = document["rules"]
    assert isinstance(rules, list)
    rules.insert(
        0,
        {
            "id": "TW-ATTRIBUTE-001",
            "description": "Deny confidential external email capability paths.",
            "source_trust": ["conditional"],
            "source_data_classifications": ["confidential"],
            "tool_action_classes": ["external"],
            "tool_capabilities": ["email.*"],
            "decision": "deny",
            "severity": "critical",
            "rationale": "The declared confidential-to-email path requires a stricter review rule.",
        },
    )

    findings = evaluate_manifest(parse_manifest(load_document(MANIFEST)), parse_policy(document))
    confidential_email = next(
        finding
        for finding in findings
        if finding.flow.tool == "send_mock_email" and finding.flow.source == "customer_record"
    )
    assert confidential_email.decision == "deny"
    assert confidential_email.severity == "critical"
    assert confidential_email.rule_id == "TW-ATTRIBUTE-001"

    document["rules"][0]["source_data_classifications"] = ["public-content"]
    findings = evaluate_manifest(parse_manifest(load_document(MANIFEST)), parse_policy(document))
    confidential_email = next(
        finding
        for finding in findings
        if finding.flow.tool == "send_mock_email" and finding.flow.source == "customer_record"
    )
    assert confidential_email.decision == "require_approval"
    assert confidential_email.severity == "medium"


def test_policy_predicate_boundaries_and_rule_coverage_are_exact() -> None:
    """Bounded policy predicates preserve namespace, taxonomy, and subsumption semantics."""

    policy = Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="predicate-contract",
        default_decision="deny",
        rules=(),
        approval_control=None,
    )
    broad = PolicyRule(
        id="TW-PREDICATE-BROAD",
        description="Broad bounded rule.",
        source_trust=("trusted", "conditional"),
        tool_action_classes=("read", "external"),
        decision="deny",
        rationale="Broad predicate contract.",
        tool_capabilities=("records.*",),
        source_data_classification_at_least="internal",
        source_data_classification_at_most="restricted",
    )
    narrow = PolicyRule(
        id="TW-PREDICATE-NARROW",
        description="Narrow bounded rule.",
        source_trust=("trusted",),
        tool_action_classes=("read",),
        decision="deny",
        rationale="Narrow predicate contract.",
        tool_capabilities=("records.lookup",),
        source_data_classification_at_least="confidential",
        source_data_classification_at_most="restricted",
    )
    subject = PolicySubject(
        source_trust="trusted",
        tool_action_class="read",
        source_data_classification="confidential",
        source_identifier="customer-inbox",
        tool_identifier="records-api",
        purpose_tags=("case_lookup",),
        tool_capabilities=("records.lookup",),
        declared_controls=frozenset(),
    )

    assert capability_matches("records.*", "records.lookup")
    assert not capability_matches("records.*", "record.lookup")
    assert capability_matches("records.lookup", "records.lookup")
    assert not capability_matches("records.lookup", "records.read")
    assert capability_pattern_covers("records.*", "records.lookup")
    assert capability_pattern_covers("records.lookup", "records.lookup")
    assert not capability_pattern_covers("records.lookup", "records.*")
    assert not capability_pattern_covers("ab.*", "ax.b")
    assert not capability_pattern_covers("ns.*", "nsfoo")

    assert classification_matches(broad, subject, policy)
    assert not classification_matches(
        broad,
        PolicySubject(**{**subject.__dict__, "source_data_classification": "public"}),
        policy,
    )
    assert not classification_matches(
        broad,
        PolicySubject(**{**subject.__dict__, "source_data_classification": "unknown"}),
        policy,
    )
    assert rule_covers(broad, narrow, policy)
    assert not rule_covers(narrow, broad, policy)


def test_policy_attribute_constraints_remain_declarative_and_validate_severity() -> None:
    document = _policy_document()
    rules = document["rules"]
    assert isinstance(rules, list)
    assert isinstance(rules[0], dict)
    rules[0]["tool_capabilities"] = ["email.*"]
    rules[0]["severity"] = "urgent"

    with pytest.raises(ValidationError, match="severity must be one of"):
        parse_policy(document)


def test_policy_rule_coverage_handles_open_and_closed_taxonomy_bounds_exactly() -> None:
    """Rule subsumption accepts only taxonomy intervals and optional dimensions that truly cover."""

    policy = Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="coverage-bounds-contract",
        default_decision="deny",
        rules=(),
        approval_control=None,
    )

    def rule(
        identifier: str,
        *,
        minimum: str | None = None,
        maximum: str | None = None,
        classifications: tuple[str, ...] = (),
        source_ids: tuple[str, ...] = (),
        tool_ids: tuple[str, ...] = (),
        purposes: tuple[str, ...] = (),
        capabilities: tuple[str, ...] = (),
    ) -> PolicyRule:
        return PolicyRule(
            id=identifier,
            description="Coverage boundary fixture.",
            source_trust=("trusted",),
            tool_action_classes=("read",),
            decision="deny",
            rationale="Coverage boundary fixture.",
            source_data_classifications=classifications,
            source_identifiers=source_ids,
            tool_identifiers=tool_ids,
            purpose_tags=purposes,
            tool_capabilities=capabilities,
            source_data_classification_at_least=minimum,
            source_data_classification_at_most=maximum,
        )

    unbounded = rule("TW-COVER-UNBOUNDED")
    confidential_only = rule(
        "TW-COVER-CONFIDENTIAL", minimum="confidential", maximum="confidential"
    )
    internal_to_confidential = rule(
        "TW-COVER-INTERNAL-CONFIDENTIAL", minimum="internal", maximum="confidential"
    )
    public_to_restricted = rule("TW-COVER-ALL", minimum="public", maximum="restricted")

    assert rule_covers(unbounded, confidential_only, policy)
    assert rule_covers(public_to_restricted, confidential_only, policy)
    assert not rule_covers(confidential_only, unbounded, policy)
    assert not rule_covers(internal_to_confidential, public_to_restricted, policy)

    unrestricted = rule("TW-COVER-OPTIONAL")
    constrained = rule(
        "TW-COVER-CONSTRAINED",
        classifications=("confidential",),
        source_ids=("customer",),
        tool_ids=("records",),
        purposes=("lookup",),
        capabilities=("records.read",),
    )
    assert rule_covers(unrestricted, constrained, policy)
    assert not rule_covers(constrained, unrestricted, policy)

    taxonomy_free = Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="empty-taxonomy-coverage",
        default_decision="deny",
        rules=(),
        approval_control=None,
        classification_taxonomy=(),
    )
    assert rule_covers(unbounded, unrestricted, taxonomy_free)
    assert not rule_covers(confidential_only, unrestricted, taxonomy_free)


def test_policy_interval_coverage_preserves_empty_taxonomy_and_open_lower_bound_semantics() -> None:
    """Coverage never treats one-sided classifications as an unconstrained range."""

    def rule(
        identifier: str, *, minimum: str | None = None, maximum: str | None = None
    ) -> PolicyRule:
        return PolicyRule(
            id=identifier,
            description="Interval coverage fixture.",
            source_trust=("trusted",),
            tool_action_classes=("read",),
            decision="deny",
            rationale="Interval coverage fixture.",
            source_data_classification_at_least=minimum,
            source_data_classification_at_most=maximum,
        )

    taxonomy_free = Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="taxonomy-free-boundary",
        default_decision="deny",
        rules=(),
        approval_control=None,
        classification_taxonomy=(),
    )
    constrained_lower_only = rule("TW-BOUNDS-LOWER", minimum="low")
    unbounded = rule("TW-BOUNDS-UNBOUNDED")
    assert not predicates_module._bounds_cover(constrained_lower_only, unbounded, taxonomy_free)

    taxonomy = Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="taxonomy-boundary",
        default_decision="deny",
        rules=(),
        approval_control=None,
        classification_taxonomy=("low", "medium", "high"),
    )
    medium_to_high = rule("TW-BOUNDS-MEDIUM-HIGH", minimum="medium", maximum="high")
    at_most_high = rule("TW-BOUNDS-AT-MOST-HIGH", maximum="high")
    assert not predicates_module._bounds_cover(medium_to_high, at_most_high, taxonomy)


def test_policy_rule_coverage_preserves_equal_nonempty_optional_constraint_sets() -> None:
    """Equal non-empty classification, tool, and purpose constraints remain fully covered."""

    policy = Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="equal-constraint-coverage",
        default_decision="deny",
        rules=(),
        approval_control=None,
    )
    first = PolicyRule(
        id="TW-COVER-EQUAL-FIRST",
        description="Equal optional constraints must be covered.",
        source_trust=("trusted",),
        tool_action_classes=("read",),
        decision="deny",
        rationale="Equal optional constraints must be covered.",
        source_data_classifications=("internal",),
        tool_identifiers=("records",),
        purpose_tags=("case_lookup",),
    )
    later = PolicyRule(
        id="TW-COVER-EQUAL-LATER",
        description="Equal optional constraints must be covered.",
        source_trust=("trusted",),
        tool_action_classes=("read",),
        decision="deny",
        rationale="Equal optional constraints must be covered.",
        source_data_classifications=("internal",),
        tool_identifiers=("records",),
        purpose_tags=("case_lookup",),
    )

    assert rule_covers(first, later, policy)


def test_policy_predicate_optional_capability_and_upper_bound_boundaries() -> None:
    """Capability coverage and taxonomy bounds preserve their strict directional endpoints."""

    assert not predicates_module._capabilities_cover(("records.read",), ())
    assert not capability_matches("ns.*", "nsfoo")

    policy = Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="classification-upper-boundary",
        default_decision="deny",
        rules=(),
        approval_control=None,
        classification_taxonomy=("low", "medium", "high"),
    )
    rule = PolicyRule(
        id="TW-UPPER-BOUNDARY",
        description="Inclusive upper-bound fixture.",
        source_trust=("trusted",),
        tool_action_classes=("read",),
        decision="deny",
        rationale="Inclusive upper-bound fixture.",
        source_data_classification_at_most="medium",
    )
    subject = PolicySubject(
        source_trust="trusted",
        tool_action_class="read",
        source_data_classification="medium",
        source_identifier="source",
        tool_identifier="tool",
        purpose_tags=(),
        tool_capabilities=(),
        declared_controls=frozenset(),
    )
    assert classification_matches(rule, subject, policy)


def test_policy_rule_coverage_rejects_missing_later_tool_and_purpose_constraints() -> None:
    """A constrained earlier rule cannot cover an unconstrained later tool or purpose domain."""

    policy = Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="missing-later-optional-constraint",
        default_decision="deny",
        rules=(),
        approval_control=None,
    )

    def rule(
        identifier: str, *, tools: tuple[str, ...] = (), purposes: tuple[str, ...] = ()
    ) -> PolicyRule:
        return PolicyRule(
            id=identifier,
            description="Directional coverage fixture.",
            source_trust=("trusted",),
            tool_action_classes=("read",),
            decision="deny",
            rationale="Directional coverage fixture.",
            tool_identifiers=tools,
            purpose_tags=purposes,
        )

    assert not rule_covers(rule("TW-TOOL-FIRST", tools=("records",)), rule("TW-TOOL-LATER"), policy)
    assert not rule_covers(
        rule("TW-PURPOSE-FIRST", purposes=("case_lookup",)),
        rule("TW-PURPOSE-LATER"),
        policy,
    )
