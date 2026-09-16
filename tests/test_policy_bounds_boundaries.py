"""The exact boundaries of `_bounds_cover`, which decides whether a rule is shadowed.

Calling a rule covered publishes it as unreachable and tells the reviewer to delete it.
When the shadowed rule is a `require_approval` catch-all, deleting it turns that path
into the default decision, so every endpoint of this comparison is load-bearing.

`tests/test_policy_attributes.py` covers the semantics. This covers the arithmetic:
the inclusive ends of the interval, the open bounds' defaults, and the refusal to
index the taxonomy with a value that is not in it. Mutation testing showed all three
unasserted -- `<=` could become `<` at either end, the open lower bound could start at
1, and the guard that returns before a missing key is indexed could be weakened to
`and`, which turns a clean False into a KeyError.
"""

from __future__ import annotations

import pytest

from trustweave import policy_predicates as predicates_module
from trustweave.models import Policy, PolicyRule

TAXONOMY = ("low", "medium", "high")


def _rule(
    identifier: str,
    *,
    minimum: str | None = None,
    maximum: str | None = None,
    exact: tuple[str, ...] = (),
) -> PolicyRule:
    return PolicyRule(
        id=identifier,
        description="Bounds boundary fixture.",
        source_trust=("trusted",),
        tool_action_classes=("read",),
        decision="deny",
        rationale="Bounds boundary fixture.",
        source_data_classifications=exact,
        source_data_classification_at_least=minimum,
        source_data_classification_at_most=maximum,
    )


def _policy(taxonomy: tuple[str, ...] = TAXONOMY) -> Policy:
    return Policy(
        schema_version="trustweave.dev/policy/v1alpha2",
        name="bounds-boundaries",
        default_decision="deny",
        rules=(),
        approval_control=None,
        classification_taxonomy=taxonomy,
    )


# ---------------------------------------------------------------------------------------
# Both ends of the interval are inclusive
# ---------------------------------------------------------------------------------------


def test_a_later_rule_naming_exactly_the_lower_bound_is_covered() -> None:
    """`first_lower <= rank`: the lower endpoint is inside the interval."""

    first = _rule("TW-FIRST", minimum="low", maximum="high")
    later = _rule("TW-LATER", exact=("low",))

    assert predicates_module._bounds_cover(first, later, _policy()) is True


def test_a_later_rule_naming_exactly_the_upper_bound_is_covered() -> None:
    """`rank <= first_upper`: the upper endpoint is inside the interval."""

    first = _rule("TW-FIRST", minimum="low", maximum="high")
    later = _rule("TW-LATER", exact=("high",))

    assert predicates_module._bounds_cover(first, later, _policy()) is True


def test_a_later_rule_naming_a_value_below_the_lower_bound_is_not_covered() -> None:
    first = _rule("TW-FIRST", minimum="medium", maximum="high")
    later = _rule("TW-LATER", exact=("low",))

    assert predicates_module._bounds_cover(first, later, _policy()) is False


# ---------------------------------------------------------------------------------------
# An unstated bound opens to the end of the taxonomy, not to one step inside it
# ---------------------------------------------------------------------------------------


def test_an_unstated_lower_bound_starts_at_the_first_taxonomy_value() -> None:
    """`else 0`, not `else 1`: a rule stating only an upper bound still admits the lowest."""

    first = _rule("TW-FIRST", maximum="high")
    later = _rule("TW-LATER", exact=("low",))

    assert predicates_module._bounds_cover(first, later, _policy()) is True


def test_an_unstated_upper_bound_reaches_the_last_taxonomy_value() -> None:
    first = _rule("TW-FIRST", minimum="low")
    later = _rule("TW-LATER", exact=("high",))

    assert predicates_module._bounds_cover(first, later, _policy()) is True


# ---------------------------------------------------------------------------------------
# A bound outside the taxonomy proves no coverage, and is never used as an index
# ---------------------------------------------------------------------------------------


def test_a_lower_bound_outside_the_taxonomy_proves_no_coverage() -> None:
    """Returning False here is what keeps `ranks[...]` from being indexed with a missing key."""

    first = _rule("TW-FIRST", minimum="nonexistent")
    later = _rule("TW-LATER", exact=("low",))

    assert predicates_module._bounds_cover(first, later, _policy()) is False


def test_an_upper_bound_outside_the_taxonomy_proves_no_coverage() -> None:
    first = _rule("TW-FIRST", maximum="nonexistent")
    later = _rule("TW-LATER", exact=("low",))

    assert predicates_module._bounds_cover(first, later, _policy()) is False


def test_a_later_rule_naming_a_value_outside_the_taxonomy_is_not_covered() -> None:
    """The membership test guards the index; weakening it to `or` raises KeyError instead."""

    first = _rule("TW-FIRST", minimum="low", maximum="high")
    later = _rule("TW-LATER", exact=("customer-provided",))

    assert predicates_module._bounds_cover(first, later, _policy()) is False


def test_an_empty_taxonomy_proves_no_coverage_for_any_bounded_rule() -> None:
    first = _rule("TW-FIRST", minimum="low")
    later = _rule("TW-LATER", exact=("low",))

    assert predicates_module._bounds_cover(first, later, _policy(())) is False


# ---------------------------------------------------------------------------------------
# An unbounded earlier rule covers everything; an unbounded later rule is covered by nothing
# ---------------------------------------------------------------------------------------


def test_an_unbounded_earlier_rule_covers_any_later_rule() -> None:
    first = _rule("TW-FIRST")
    later = _rule("TW-LATER", minimum="medium", maximum="high")

    assert predicates_module._bounds_cover(first, later, _policy()) is True


def test_a_bounded_rule_does_not_cover_an_unbounded_later_rule() -> None:
    """The regression this predicate was rewritten for: an unbounded rule matches
    classification strings the taxonomy does not contain, so a bounded rule matches
    none of those and must not be allowed to call the catch-all unreachable."""

    first = _rule("TW-FIRST", minimum="low", maximum="high")
    later = _rule("TW-LATER")

    assert predicates_module._bounds_cover(first, later, _policy()) is False


@pytest.mark.parametrize("value", ["low", "medium", "high"])
def test_the_full_interval_covers_every_taxonomy_value(value: str) -> None:
    first = _rule("TW-FIRST", minimum="low", maximum="high")
    later = _rule("TW-LATER", exact=(value,))

    assert predicates_module._bounds_cover(first, later, _policy()) is True
