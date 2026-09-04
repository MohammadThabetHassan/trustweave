"""Extraction logic for the Rego suite adapter, exercised without the opa binary.

The adapter shells out to `opa parse` to obtain an AST, so an end-to-end test would need
opa installed in CI. The part worth pinning is the reading of that AST, which is pure, so
these tests hand it the shapes opa actually emits. Every fixture here was transcribed from
real `opa parse --format json` output against the public Gatekeeper library.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from rego_suite_coverage import _assertions  # noqa: E402


def _var(name: str) -> dict[str, Any]:
    return {"type": "var", "value": name}


def _ref(head: str, *rest: str) -> dict[str, Any]:
    return {"type": "ref", "value": [_var(head), *({"type": "string", "value": r} for r in rest)]}


def _call(function: str, argument: dict[str, Any]) -> dict[str, Any]:
    return {"type": "call", "value": [_ref(function), argument]}


def _expression(terms: Any, negated: bool = False) -> dict[str, Any]:
    return {"terms": terms, "negated": negated}


def _suite(*body: dict[str, Any]) -> dict[str, Any]:
    return {"rules": [{"head": {"name": "test_case"}, "body": list(body)}]}


BIND = _expression([_ref("assign"), _var("results"), _var("violation")])


def _values(ast: dict[str, Any]) -> list[str]:
    return [assertion["value"] for assertion in _assertions(ast)]


def test_iterating_a_bound_violation_set_pins_a_denial() -> None:
    """`results[result]` succeeds only when the set has a member."""

    assert _values(_suite(BIND, _expression(_ref("results", "result")))) == ["nonempty"]


def test_negating_that_iteration_pins_a_permit() -> None:
    assert _values(_suite(BIND, _expression(_ref("results", "_"), negated=True))) == ["empty"]


@pytest.mark.parametrize(
    ("operator", "count", "expected"),
    [
        ("equal", 0, "empty"),
        ("equal", 1, "nonempty"),
        ("gt", 0, "nonempty"),
        ("gte", 1, "nonempty"),
        ("lt", 1, "empty"),
        ("lte", 0, "empty"),
        ("neq", 0, "nonempty"),
    ],
)
def test_count_comparisons_resolve_to_the_decision_they_assert(
    operator: str, count: int, expected: str
) -> None:
    body = _expression(
        [_ref(operator), _call("count", _var("results")), {"type": "number", "value": count}]
    )

    assert _values(_suite(BIND, body)) == [expected]


def test_a_reversed_comparison_reads_the_same_as_the_direct_one() -> None:
    """`0 < count(results)` asserts exactly what `count(results) > 0` asserts."""

    body = _expression(
        [_ref("lt"), {"type": "number", "value": 0}, _call("count", _var("results"))]
    )

    assert _values(_suite(BIND, body)) == ["nonempty"]


def test_a_count_comparison_that_does_not_settle_emptiness_is_refused() -> None:
    """`count(results) != 2` is a real assertion that says nothing about denial."""

    body = _expression(
        [_ref("neq"), _call("count", _var("results")), {"type": "number", "value": 2}]
    )

    assert _assertions(_suite(BIND, body)) == []


def test_an_unbound_local_is_not_read_as_a_decision() -> None:
    """Without the binding, `results` is just a name; claiming otherwise invents a subject."""

    assert _assertions(_suite(_expression(_ref("results", "result")))) == []


def test_the_binding_records_the_rule_under_test_as_the_subject() -> None:
    assertion = _assertions(_suite(BIND, _expression(_ref("results", "result"))))[0]

    assert assertion["subject"] == "violation"
    assert assertion["domain"] == "violation_set"


def test_a_labelled_decision_is_pinned_in_its_own_domain() -> None:
    body = _expression(
        [_ref("equal"), _ref("authz", "decision"), {"type": "string", "value": "allow"}]
    )

    assertions = _assertions(_suite(body))

    assert assertions[0]["domain"] == "labelled"
    assert assertions[0]["value"] == "allow"


def test_a_neq_against_a_label_excludes_rather_than_pins() -> None:
    body = _expression(
        [_ref("neq"), _ref("authz", "decision"), {"type": "string", "value": "deny"}]
    )

    assert _assertions(_suite(body))[0]["operator"] == "excludes"


def test_a_directly_invoked_helper_is_measured_in_the_boolean_domain() -> None:
    assertions = _assertions(_suite(_expression([_ref("is_exempt"), _var("input")])))

    assert assertions[0]["domain"] == "boolean"
    assert assertions[0]["value"] == "holds"


def test_only_test_rules_are_measured() -> None:
    ast = {"rules": [{"head": {"name": "violation"}, "body": [BIND]}]}

    assert _assertions(ast) == []
