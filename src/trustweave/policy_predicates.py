"""Shared deterministic predicates for declared policy matching and coverage analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from trustweave.models import Policy, PolicyRule


@dataclass(frozen=True)
class PolicySubject:
    """The bounded declared labels evaluated against one policy rule."""

    source_trust: str
    tool_action_class: str
    source_data_classification: str
    source_identifier: str
    tool_identifier: str
    purpose_tags: tuple[str, ...]
    tool_capabilities: tuple[str, ...]
    declared_controls: frozenset[str]


def capability_matches(pattern: str, capability: str) -> bool:
    """Match an exact capability or one validated final namespace wildcard."""

    if pattern.endswith(".*"):
        return capability.startswith(pattern[:-1])
    return capability == pattern


def capability_pattern_covers(first: str, later: str) -> bool:
    """Return only proven capability-pattern subsumption relationships."""

    if first == later:
        return True
    if not first.endswith(".*"):
        return False
    return later.startswith(first[:-1])


def classification_matches(rule: PolicyRule, subject: PolicySubject, policy: Policy) -> bool:
    """Evaluate taxonomy bounds; unrecognized supplied classifications never match a bound."""

    if (
        rule.source_data_classification_at_least is None
        and rule.source_data_classification_at_most is None
    ):
        return True
    if subject.source_data_classification not in policy.classification_taxonomy:
        return False
    rank = policy.classification_taxonomy.index(subject.source_data_classification)
    if (
        rule.source_data_classification_at_least is not None
        and rank < policy.classification_taxonomy.index(rule.source_data_classification_at_least)
    ):
        return False
    return (
        rule.source_data_classification_at_most is None
        or rank <= policy.classification_taxonomy.index(rule.source_data_classification_at_most)
    )


def checks_for_rule(
    rule: PolicyRule, subject: PolicySubject, policy: Policy
) -> dict[str, dict[str, Any]]:
    """Return one deterministic matching record for all declared predicate dimensions."""

    declared_controls = sorted(subject.declared_controls)
    purpose_tags = sorted(subject.purpose_tags)
    return {
        "source_trust": {
            "matched": subject.source_trust in rule.source_trust,
            "actual": subject.source_trust,
            "expected_any_of": list(rule.source_trust),
        },
        "tool_action_class": {
            "matched": subject.tool_action_class in rule.tool_action_classes,
            "actual": subject.tool_action_class,
            "expected_any_of": list(rule.tool_action_classes),
        },
        "source_data_classification": {
            "matched": not rule.source_data_classifications
            or subject.source_data_classification in rule.source_data_classifications,
            "actual": subject.source_data_classification,
            "expected_any_of": list(rule.source_data_classifications),
        },
        "source_identifier": {
            "matched": not rule.source_identifiers
            or subject.source_identifier in rule.source_identifiers,
            "actual": subject.source_identifier,
            "expected_any_of": list(rule.source_identifiers),
        },
        "tool_identifier": {
            "matched": not rule.tool_identifiers
            or subject.tool_identifier in rule.tool_identifiers,
            "actual": subject.tool_identifier,
            "expected_any_of": list(rule.tool_identifiers),
        },
        "purpose_tags": {
            "matched": not rule.purpose_tags
            or bool(set(rule.purpose_tags).intersection(purpose_tags)),
            "actual": purpose_tags,
            "expected_any_of": list(rule.purpose_tags),
        },
        "source_data_classification_bounds": {
            "matched": classification_matches(rule, subject, policy),
            "actual": subject.source_data_classification,
            "at_least": rule.source_data_classification_at_least,
            "at_most": rule.source_data_classification_at_most,
        },
        "required_controls": {
            "matched": set(rule.required_controls).issubset(subject.declared_controls),
            "actual": declared_controls,
            "expected_all_of": list(rule.required_controls),
        },
        "tool_capabilities": {
            "matched": not rule.tool_capabilities
            or any(
                capability_matches(pattern, capability)
                for pattern in rule.tool_capabilities
                for capability in subject.tool_capabilities
            ),
            "actual": list(subject.tool_capabilities),
            "expected_any_of": list(rule.tool_capabilities),
        },
    }


def rule_matches(rule: PolicyRule, subject: PolicySubject, policy: Policy) -> bool:
    """Return whether every declared predicate matches one supplied local subject.

    Evaluates the same predicates as :func:`checks_for_rule` in the same order without
    building reviewer-facing evidence records, so flow evaluation stays linear.
    """

    if subject.source_trust not in rule.source_trust:
        return False
    if subject.tool_action_class not in rule.tool_action_classes:
        return False
    if (
        rule.source_data_classifications
        and subject.source_data_classification not in rule.source_data_classifications
    ):
        return False
    if rule.source_identifiers and subject.source_identifier not in rule.source_identifiers:
        return False
    if rule.tool_identifiers and subject.tool_identifier not in rule.tool_identifiers:
        return False
    if rule.purpose_tags and not set(rule.purpose_tags).intersection(subject.purpose_tags):
        return False
    if not classification_matches(rule, subject, policy):
        return False
    if not set(rule.required_controls).issubset(subject.declared_controls):
        return False
    if rule.tool_capabilities:
        return any(
            capability_matches(pattern, capability)
            for pattern in rule.tool_capabilities
            for capability in subject.tool_capabilities
        )
    return True


def declared_controls(policy: Policy) -> frozenset[str]:
    """Expose design-time control declarations, never runtime enforcement state."""

    controls: set[str] = set()
    if policy.approval_control is not None:
        controls.add("approval")
        if policy.approval_control.fail_closed:
            controls.add("approval.fail_closed")
    return frozenset(controls)


def rule_is_possible(rule: PolicyRule, policy: Policy) -> bool:
    """Return whether static policy declarations permit a rule to match any local subject."""

    return set(rule.required_controls).issubset(declared_controls(policy))


def _set_covers(first: tuple[str, ...], later: tuple[str, ...]) -> bool:
    """Return whether an optional exact-set constraint covers another constraint."""

    if not first:
        return True
    if not later:
        return False
    return set(later).issubset(first)


def _capabilities_cover(first: tuple[str, ...], later: tuple[str, ...]) -> bool:
    """Return only capability coverage relationships provable from bounded patterns."""

    if not first:
        return True
    if not later:
        return False
    return all(
        any(capability_pattern_covers(first_pattern, later_pattern) for first_pattern in first)
        for later_pattern in later
    )


def _bounds_cover(first: PolicyRule, later: PolicyRule, policy: Policy) -> bool:
    """Return whether first's declared classification interval contains later's interval."""

    if not policy.classification_taxonomy:
        return (
            first.source_data_classification_at_least is None
            and first.source_data_classification_at_most is None
            and later.source_data_classification_at_least is None
            and later.source_data_classification_at_most is None
        )
    ranks = {value: index for index, value in enumerate(policy.classification_taxonomy)}
    first_lower = (
        ranks[first.source_data_classification_at_least]
        if first.source_data_classification_at_least is not None
        else 0
    )
    later_lower = (
        ranks[later.source_data_classification_at_least]
        if later.source_data_classification_at_least is not None
        else 0
    )
    first_upper = (
        ranks[first.source_data_classification_at_most]
        if first.source_data_classification_at_most is not None
        else len(ranks) - 1
    )
    later_upper = (
        ranks[later.source_data_classification_at_most]
        if later.source_data_classification_at_most is not None
        else len(ranks) - 1
    )
    return first_lower <= later_lower and first_upper >= later_upper


def rule_covers(first: PolicyRule, later: PolicyRule, policy: Policy) -> bool:
    """Return whether an earlier rule covers every possible subject of a later rule.

    Required controls are intentionally excluded from the subject predicate because they are
    static declarations of the policy itself. Their possibility is evaluated once by
    :func:`rule_is_possible`, exactly as flow evaluation does.
    """

    return (
        set(later.source_trust).issubset(first.source_trust)
        and set(later.tool_action_classes).issubset(first.tool_action_classes)
        and _set_covers(first.source_data_classifications, later.source_data_classifications)
        and _set_covers(first.source_identifiers, later.source_identifiers)
        and _set_covers(first.tool_identifiers, later.tool_identifiers)
        and _set_covers(first.purpose_tags, later.purpose_tags)
        and _bounds_cover(first, later, policy)
        and _capabilities_cover(first.tool_capabilities, later.tool_capabilities)
    )
