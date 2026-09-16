"""The edges of the weakening classifier: unnamed decisions, blank entries, exact sets.

`policy_review_signals` decides whether a policy change is a weakening a reviewer must
look at. Three of its comparisons had no test standing on their boundary.

A decision string the policy vocabulary does not name is ranked by a default, and that
default is what orders an unrecognised decision against a known one. Nothing exercised
it, so the rank could be moved -- or replaced with None, which makes the comparison raise
-- without a test noticing.

The control sets are filtered to non-empty strings. Nothing supplied a blank entry, so
the filter could be weakened to admit one, which invents a removed or an unsatisfiable
control out of a policy that declared neither.

And the satisfiability test asks whether the new controls are a subset of what the policy
declares. Nothing supplied a rule whose controls were exactly the declared set, so `<=`
could become `<` and report the one policy that names every control it declares as having
switched its own rule off.
"""

from __future__ import annotations

from typing import Any

from trustweave.policy_weakening import policy_review_signals


def _rule(identifier: str, decision: str, controls: list[Any] | None = None) -> dict[str, Any]:
    rule: dict[str, Any] = {"id": identifier, "decision": decision}
    if controls is not None:
        rule["required_controls"] = controls
    return rule


def _rules_change(before: list[Any], after: list[Any]) -> list[dict[str, Any]]:
    return [{"path": "policy.rules", "before": before, "after": after}]


def _ids(signals: list[dict[str, Any]]) -> set[str]:
    return {signal["id"] for signal in signals}


# ---------------------------------------------------------------------------------------
# A decision the vocabulary does not name ranks below every decision it does
# ---------------------------------------------------------------------------------------


def test_a_decision_changed_from_deny_to_an_unnamed_value_is_a_weakening() -> None:
    """The unnamed rank is compared against a named one, so it must be a number."""

    signals = policy_review_signals(
        _rules_change([_rule("R-1", "deny")], [_rule("R-1", "escalate-to-human")])
    )

    assert "TW-DIFF-008" in _ids(signals)


def test_an_unnamed_decision_ranks_below_require_approval_too() -> None:
    """Pins where the unnamed rank sits: under require_approval, not level with it."""

    signals = policy_review_signals(
        _rules_change([_rule("R-1", "require_approval")], [_rule("R-1", "escalate-to-human")])
    )

    assert "TW-DIFF-008" in _ids(signals)


def test_moving_from_an_unnamed_decision_to_allow_is_not_reported_as_a_weakening() -> None:
    """The other direction: an unnamed decision is already the least restrictive rank,
    so replacing it with `allow` does not lower the rule's restriction."""

    signals = policy_review_signals(
        _rules_change([_rule("R-1", "escalate-to-human")], [_rule("R-1", "allow")])
    )

    assert "TW-DIFF-008" not in _ids(signals)


def test_an_unchanged_decision_is_not_a_weakening() -> None:
    signals = policy_review_signals(_rules_change([_rule("R-1", "deny")], [_rule("R-1", "deny")]))

    assert "TW-DIFF-008" not in _ids(signals)


def test_deny_to_allow_is_a_weakening() -> None:
    signals = policy_review_signals(_rules_change([_rule("R-1", "deny")], [_rule("R-1", "allow")]))

    assert "TW-DIFF-008" in _ids(signals)


# ---------------------------------------------------------------------------------------
# A blank control is not a control
# ---------------------------------------------------------------------------------------


def test_a_blank_required_control_dropped_is_not_a_removed_control() -> None:
    """Admitting the empty string would report a removal the policy never had."""

    signals = policy_review_signals(
        _rules_change(
            [_rule("R-1", "deny", ["approval", ""])],
            [_rule("R-1", "deny", ["approval"])],
        )
    )

    assert "TW-DIFF-009" not in _ids(signals)


def test_a_blank_required_control_added_is_not_an_unsatisfiable_control() -> None:
    """The same filter on the other side: a blank entry must not switch a rule off."""

    signals = policy_review_signals(
        _rules_change(
            [_rule("R-1", "deny", ["approval"])],
            [_rule("R-1", "deny", ["approval", ""])],
        ),
        base_policy={"approval_control": {}},
        head_policy={"approval_control": {}},
    )

    assert "TW-DIFF-012" not in _ids(signals)


def test_a_genuinely_removed_control_is_still_reported() -> None:
    signals = policy_review_signals(
        _rules_change(
            [_rule("R-1", "deny", ["approval", "approval.fail_closed"])],
            [_rule("R-1", "deny", ["approval"])],
        )
    )

    assert "TW-DIFF-009" in _ids(signals)


# ---------------------------------------------------------------------------------------
# Naming exactly the declared controls is satisfiable, not impossible
# ---------------------------------------------------------------------------------------


def test_a_rule_naming_exactly_the_declared_controls_is_still_satisfiable() -> None:
    """`<=`, not `<`: a rule may name every control its policy declares.

    Reporting this rule as switched off would tell a reviewer that the strictest policy
    in the repository had disabled its own rule.
    """

    signals = policy_review_signals(
        _rules_change(
            [_rule("R-1", "deny", ["approval"])],
            [_rule("R-1", "deny", ["approval", "approval.fail_closed"])],
        ),
        base_policy={"approval_control": {}},
        head_policy={"approval_control": {"fail_closed": True}},
    )

    assert "TW-DIFF-012" not in _ids(signals)


def test_a_rule_gaining_a_control_the_policy_does_not_declare_is_reported() -> None:
    """The finding this boundary exists for still fires."""

    signals = policy_review_signals(
        _rules_change(
            [_rule("R-1", "deny", ["approval"])],
            [_rule("R-1", "deny", ["approval", "approval.fail_closed"])],
        ),
        base_policy={"approval_control": {}},
        head_policy={"approval_control": {}},
    )

    assert "TW-DIFF-012" in _ids(signals)


# ---------------------------------------------------------------------------------------
# A blank approval binding is not a removed binding
# ---------------------------------------------------------------------------------------


def test_a_blank_approval_binding_dropped_is_not_a_removed_binding() -> None:
    signals = policy_review_signals(
        [
            {
                "path": "policy.approval_control.binds_to",
                "before": ["ops-oncall", ""],
                "after": ["ops-oncall"],
            }
        ]
    )

    assert "TW-DIFF-006" not in _ids(signals)


def test_a_genuinely_removed_approval_binding_is_reported() -> None:
    signals = policy_review_signals(
        [
            {
                "path": "policy.approval_control.binds_to",
                "before": ["ops-oncall", "security"],
                "after": ["ops-oncall"],
            }
        ]
    )

    assert _ids(signals), "removing a real binding must produce a signal"
