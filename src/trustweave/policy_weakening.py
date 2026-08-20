"""Deterministic classification of security-relevant policy-delta review signals."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from itertools import combinations
from typing import Any

from trustweave.rules import finding_for_rule

_DECISION_RESTRICTION = {"allow": 0, "require_approval": 1, "deny": 2}
_MATCHING_FIELDS = (
    "source_trust",
    "tool_action_classes",
    "source_identifiers",
    "tool_identifiers",
    "purpose_tags",
    "source_data_classifications",
    "source_data_classification_at_least",
    "source_data_classification_at_most",
    "tool_capabilities",
)
_SET_LIKE_MATCHING_FIELDS = frozenset(
    {
        "source_trust",
        "tool_action_classes",
        "source_identifiers",
        "tool_identifiers",
        "purpose_tags",
        "source_data_classifications",
        "tool_capabilities",
    }
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []


def _rules_by_identifier(value: Any) -> dict[str, Mapping[str, Any]]:
    """Index a normalized policy-rule collection without trusting rule ordering."""

    indexed: dict[str, Mapping[str, Any]] = {}
    for item in _sequence(value):
        rule = _mapping(item)
        identifier = rule.get("id")
        if isinstance(identifier, str) and identifier:
            indexed[identifier] = rule
    return indexed


def _rule_identifiers(value: Any) -> list[str]:
    """Return normalized rule identifiers in declaration order without malformed values."""

    return [
        identifier
        for rule in _sequence(value)
        if isinstance((identifier := _mapping(rule).get("id")), str) and identifier
    ]


def _matching_values(rule: Mapping[str, Any], field: str) -> tuple[str, ...]:
    """Return a canonical set-like matching predicate without malformed values."""

    return tuple(
        sorted(item for item in _sequence(rule.get(field)) if isinstance(item, str) and item)
    )


def _matching_value(rule: Mapping[str, Any], field: str) -> object:
    """Normalize a matching predicate so semantically unordered values stay neutral."""

    if field in _SET_LIKE_MATCHING_FIELDS:
        return _matching_values(rule, field)
    return rule.get(field)


def _matching_predicate_changed(
    before_rule: Mapping[str, Any], after_rule: Mapping[str, Any]
) -> bool:
    """Identify declared matching-boundary changes without treating text metadata as structural."""

    return any(
        _matching_value(before_rule, field) != _matching_value(after_rule, field)
        for field in _MATCHING_FIELDS
    )


def _rules_could_overlap(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    """Conservatively identify whether two rules may match the same declared flow."""

    for field in _SET_LIKE_MATCHING_FIELDS:
        first_values = set(_matching_values(first, field))
        second_values = set(_matching_values(second, field))
        if first_values and second_values and first_values.isdisjoint(second_values):
            return False
    return True


def _reordered_overlapping_rule_ids(before: Any, after: Any) -> list[str]:
    """Return sorted identifiers whose changed relative order can affect first-match behavior."""

    before_rules = _rules_by_identifier(before)
    before_positions = {
        identifier: index for index, identifier in enumerate(_rule_identifiers(before))
    }
    after_positions = {
        identifier: index for index, identifier in enumerate(_rule_identifiers(after))
    }
    reordered: set[str] = set()
    common = sorted(set(before_positions) & set(after_positions))
    for first_id, second_id in combinations(common, 2):
        before_order = before_positions[first_id] < before_positions[second_id]
        after_order = after_positions[first_id] < after_positions[second_id]
        if before_order != after_order and _rules_could_overlap(
            before_rules[first_id], before_rules[second_id]
        ):
            reordered.update((first_id, second_id))
    return sorted(reordered)


def policy_review_signals(policy_changes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Classify deterministic policy weakenings and structural review obligations."""

    signals: dict[str, dict[str, Any]] = {}

    def add(identifier: str, message: str, subject: Mapping[str, str | Sequence[str]]) -> None:
        """Retain one stable finding per category without duplicate signals."""

        signals.setdefault(
            identifier, finding_for_rule(identifier, "review", message, subject=subject)
        )

    changes_by_path = {
        path: change for change in policy_changes if isinstance((path := change.get("path")), str)
    }
    default_change = changes_by_path.get("policy.default_decision")
    if (
        default_change
        and default_change.get("after") == "allow"
        and default_change.get("before") != "allow"
    ):
        add(
            "TW-DIFF-005",
            "The policy default decision changed to allow; unmatched declared paths now require "
            "explicit human review.",
            {"policy_field": "default_decision"},
        )

    taxonomy_change = changes_by_path.get("policy.classification_taxonomy")
    if taxonomy_change:
        add(
            "TW-DIFF-010",
            "The declared classification taxonomy changed; review classification ordering, "
            "coverage, and every policy bound that depends on it.",
            {"policy_field": "classification_taxonomy"},
        )

    approval_changes = {
        path.rsplit(".", maxsplit=1)[-1]: change
        for path, change in changes_by_path.items()
        if path.startswith("policy.approval_control.")
    }
    approval_removed = bool(approval_changes) and all(
        change.get("after") is None for change in approval_changes.values()
    )
    if approval_removed:
        add(
            "TW-DIFF-006",
            "The declared approval control was removed; review every require-approval boundary "
            "before accepting this policy change.",
            {"policy_field": "approval_control"},
        )
    else:
        fail_closed_change = approval_changes.get("fail_closed")
        if (
            fail_closed_change
            and fail_closed_change.get("before") is True
            and fail_closed_change.get("after") is False
        ):
            add(
                "TW-DIFF-004",
                "The declared approval control changed from fail-closed to fail-open; review "
                "approval-boundary enforcement before accepting this policy change.",
                {"policy_field": "approval_control.fail_closed"},
            )
        bindings_change = approval_changes.get("binds_to")
        if bindings_change:
            before_bindings = set(_sequence(bindings_change.get("before")))
            after_bindings = set(_sequence(bindings_change.get("after")))
            removed_bindings = sorted(
                binding
                for binding in before_bindings - after_bindings
                if isinstance(binding, str) and binding
            )
            if removed_bindings:
                add(
                    "TW-DIFF-007",
                    "The declared approval control lost one or more binding fields; review whether "
                    "approval remains scoped to the actor, tool, target, parameters, and time.",
                    {
                        "policy_field": "approval_control.binds_to",
                        "removed_bindings": removed_bindings,
                    },
                )

    rules_change = changes_by_path.get("policy.rules")
    if rules_change:
        before_rules = _rules_by_identifier(rules_change.get("before"))
        after_rules = _rules_by_identifier(rules_change.get("after"))
        weakened_decisions: list[str] = []
        removed_controls: list[str] = []
        matching_predicate_changed: list[str] = []
        for identifier in sorted(set(before_rules) & set(after_rules)):
            before_rule = before_rules[identifier]
            after_rule = after_rules[identifier]
            before_decision = before_rule.get("decision")
            after_decision = after_rule.get("decision")
            if (
                isinstance(before_decision, str)
                and isinstance(after_decision, str)
                and _DECISION_RESTRICTION.get(after_decision, -1)
                < _DECISION_RESTRICTION.get(before_decision, -1)
            ):
                weakened_decisions.append(identifier)
            before_controls = {
                control
                for control in _sequence(before_rule.get("required_controls"))
                if isinstance(control, str) and control
            }
            after_controls = {
                control
                for control in _sequence(after_rule.get("required_controls"))
                if isinstance(control, str) and control
            }
            if before_controls - after_controls:
                removed_controls.append(identifier)
            if _matching_predicate_changed(before_rule, after_rule):
                matching_predicate_changed.append(identifier)
        if weakened_decisions:
            add(
                "TW-DIFF-008",
                "One or more declared policy rules became less restrictive; review the changed "
                "decision boundaries even when no current manifest flow exercises them.",
                {"rule_ids": weakened_decisions},
            )
        if removed_controls:
            add(
                "TW-DIFF-009",
                "One or more declared policy rules lost required controls; review the affected "
                "approval and fail-closed obligations.",
                {"rule_ids": removed_controls},
            )

        added_rule_ids = sorted(set(after_rules) - set(before_rules))
        removed_rule_ids = sorted(set(before_rules) - set(after_rules))
        reordered_rule_ids = _reordered_overlapping_rule_ids(
            rules_change.get("before"), rules_change.get("after")
        )
        if added_rule_ids or removed_rule_ids or matching_predicate_changed or reordered_rule_ids:
            add(
                "TW-DIFF-011",
                "Declared policy rule structure changed in a way that can alter first-match "
                "coverage; review the listed rule boundaries. This review signal does not prove "
                "that every listed change is insecure.",
                {
                    "added_rule_ids": added_rule_ids,
                    "removed_rule_ids": removed_rule_ids,
                    "matching_predicate_changed_rule_ids": matching_predicate_changed,
                    "reordered_rule_ids": reordered_rule_ids,
                },
            )

    return [signals[identifier] for identifier in sorted(signals)]
