"""Deterministic classification of security-weakening policy deltas."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from trustweave.rules import finding_for_rule

_DECISION_RESTRICTION = {"allow": 0, "require_approval": 1, "deny": 2}


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


def policy_review_signals(policy_changes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Classify deterministic policy weakenings independently of exercised manifest flows."""

    signals: dict[str, dict[str, Any]] = {}

    def add(identifier: str, message: str, subject: Mapping[str, str | Sequence[str]]) -> None:
        """Retain one stable finding per weakening category without duplicate signals."""

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

    return [signals[identifier] for identifier in sorted(signals)]
