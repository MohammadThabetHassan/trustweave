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
    """Return whether every declared predicate matches one supplied local subject."""

    return all(bool(check["matched"]) for check in checks_for_rule(rule, subject, policy).values())


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
    """Return whether first's classification bound admits everything later's bound admits.

    Comparing the two intervals was not enough, because the two rules do not range over the
    same set of values. A rule that states no bound matches *any* classification string:
    :func:`classification_matches` returns True before it consults the taxonomy at all, and
    the engine deliberately admits a plainly different vocabulary — ``engine`` refuses only a
    near miss of a declared taxonomy value, so ``customer-provided`` reaches evaluation. A
    rule that states a bound, even the full interval, matches only values *inside* the
    taxonomy. Treating an unbounded rule as the full interval therefore made a bounded rule
    cover a live ``require_approval`` catch-all, which the review published as unreachable
    and told the reviewer to delete — turning that path into the default decision.

    So a bounded earlier rule covers a later rule only when the later rule is itself
    confined to taxonomy values that the earlier interval admits, either by naming an exact
    set or by stating its own bound.
    """

    if (
        first.source_data_classification_at_least is None
        and first.source_data_classification_at_most is None
    ):
        return True
    ranks = {value: index for index, value in enumerate(policy.classification_taxonomy)}
    if (
        not ranks
        or first.source_data_classification_at_least not in {None, *ranks}
        or first.source_data_classification_at_most not in {None, *ranks}
    ):
        # A bound naming a value outside the taxonomy matches nothing, so it proves no
        # coverage. The parser rejects such a policy; this predicate does not rely on that.
        return False
    first_lower = (
        ranks[first.source_data_classification_at_least]
        if first.source_data_classification_at_least is not None
        else 0
    )
    first_upper = (
        ranks[first.source_data_classification_at_most]
        if first.source_data_classification_at_most is not None
        else len(ranks) - 1
    )
    if later.source_data_classifications:
        # The later rule pins its classification to an exact set; any bound it also states
        # only narrows that set, so admitting every named value admits everything it matches.
        return all(
            value in ranks and first_lower <= ranks[value] <= first_upper
            for value in later.source_data_classifications
        )
    if (
        later.source_data_classification_at_least is None
        and later.source_data_classification_at_most is None
    ):
        # The later rule states no bound and names no set, so it matches classifications the
        # taxonomy does not contain and the bounded earlier rule matches none of those.
        return False
    later_lower = (
        ranks[later.source_data_classification_at_least]
        if later.source_data_classification_at_least is not None
        else 0
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
