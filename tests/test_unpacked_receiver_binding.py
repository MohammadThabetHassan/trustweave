"""Binding receivers that arrive through a tuple assignment.

`client, other = Client(), Other()` binds two receivers in one statement. Reading the
whole tuple as a single value loses both, so a later `client.run(argv)` resolves to
nothing and an arbitrary process launch is published as no effect at all.

`_bind_unpacked` takes the two collaborators it needs as callables, so it can be exercised
directly rather than through a discovery fixture whose tools are found by other means.
That matters here: the end-to-end tests pass whatever this returns, which is why a mutant
that skipped every element, or bound the wrong one, survived.
"""

from __future__ import annotations

import ast

import pytest

from trustweave.code_analysis import _bind_unpacked


def _assign(source: str) -> ast.Assign:
    statement = ast.parse(source).body[0]
    assert isinstance(statement, ast.Assign)
    return statement


def _run(source: str, origins: dict[str, str] | None = None) -> tuple[bool, list[tuple[str, str]]]:
    """Return (was an unpacking, the (name, origin) pairs bound)."""

    table = origins if origins is not None else {"Client": "client", "Other": "other"}
    bound: list[tuple[str, str]] = []

    def receiver_of(value: ast.expr) -> str | None:
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            return table.get(value.func.id)
        return None

    def bind(name: str, origin: str, call: ast.Call) -> None:
        assert isinstance(call, ast.Call)
        bound.append((name, origin))

    return _bind_unpacked(_assign(source), receiver_of, bind), bound


def test_each_element_of_a_tuple_assignment_is_bound_to_its_own_receiver() -> None:
    unpacked, bound = _run("client, other = Client(), Other()")

    assert unpacked is True
    assert bound == [("client", "client"), ("other", "other")]


def test_a_list_assignment_is_unpacked_the_same_way() -> None:
    unpacked, bound = _run("[client, other] = [Client(), Other()]")

    assert unpacked is True
    assert bound == [("client", "client"), ("other", "other")]


def test_a_plain_assignment_is_not_an_unpacking() -> None:
    """The caller reads the whole value itself when this returns False."""

    unpacked, bound = _run("client = Client()")

    assert unpacked is False
    assert bound == []


def test_a_tuple_target_with_a_single_value_is_not_an_unpacking() -> None:
    unpacked, bound = _run("client, other = make_pair()")

    assert unpacked is False
    assert bound == []


def test_an_unpacking_of_unequal_length_binds_nothing_but_is_still_an_unpacking() -> None:
    """Returning False here would make the caller read the tuple as one value."""

    unpacked, bound = _run("client, other = Client(),")

    assert unpacked is True
    assert bound == []


def test_an_element_with_no_receiver_is_skipped_and_the_rest_are_bound() -> None:
    unpacked, bound = _run("plain, client = compute(), Client()")

    assert unpacked is True
    assert bound == [("client", "client")]


def test_an_element_that_is_not_a_name_is_skipped_and_the_rest_are_bound() -> None:
    """`holder.attr` is not a local binding, but the sibling still is."""

    unpacked, bound = _run("holder.attr, client = Other(), Client()")

    assert unpacked is True
    assert bound == [("client", "client")]


def test_a_statement_with_no_receivers_at_all_is_still_reported_as_an_unpacking() -> None:
    unpacked, bound = _run("first, second = compute(), compute()")

    assert unpacked is True
    assert bound == []


@pytest.mark.parametrize("source", ["a, b = Client(), Other()", "[a, b] = (Client(), Other())"])
def test_both_bracket_spellings_bind_in_source_order(source: str) -> None:
    _unpacked, bound = _run(source)

    assert [name for name, _origin in bound] == ["a", "b"]
