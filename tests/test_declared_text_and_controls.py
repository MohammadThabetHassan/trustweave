"""Assertion strength for two small predicates that decide what a report may contain.

Both are one boolean expression, both are read by something that then renders or gates,
and mutation testing showed each had a disjunct or a branch nothing asserted.

`contains_control_characters` is the guard that stops a declared field from closing the
Markdown row it was written into. Its DEL and Unicode-line-separator terms were carried
only by tests that pass a newline, so a mutant deleting either term survived.

`_declared_controls` mirrors the engine's design-time controls. The suite declared
`fail_closed: True` and asserted the control appears; nothing declared it false, so a
mutant reading `is False` -- which reports the control on exactly the policies that
switched it off -- survived.
"""

from __future__ import annotations

import pytest

from trustweave.models import contains_control_characters
from trustweave.policy_weakening import _declared_controls

# ---------------------------------------------------------------------------------------
# contains_control_characters: each disjunct carries its own character class
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("a\nb", "a newline closes the table row"),
        ("a\rb", "a carriage return closes the table row"),
        ("a\tb", "a tab breaks column alignment"),
        ("a\x00b", "NUL truncates in a C consumer"),
        ("a\x1bb", "an escape sequence repaints the terminal"),
        ("a\x7fb", "DEL is a control character above the space comparison"),
        ("a b", "U+2028 is a line separator to a JavaScript consumer"),
        ("a b", "U+2029 is a paragraph separator to a JavaScript consumer"),
    ],
)
def test_control_characters_are_detected(text: str, why: str) -> None:
    assert contains_control_characters(text) is True, why


@pytest.mark.parametrize(
    "text",
    ["", "plain", "spaces between words", "punctuation!?;:", "café", "日本語", "~\x7e"],
)
def test_ordinary_text_is_not_reported_as_control_characters(text: str) -> None:
    assert contains_control_characters(text) is False


def test_del_is_detected_on_its_own_rather_than_only_beside_a_line_separator() -> None:
    """The DEL term is a separate disjunct, not a condition on the line-separator term.

    Folding the two together with `and` leaves every ordinary DEL undetected, which is
    the mutation the suite accepted: DEL never appeared in a test without a newline
    beside it.
    """

    assert contains_control_characters("\x7f") is True
    assert contains_control_characters(" ") is True


def test_the_space_boundary_is_exclusive() -> None:
    """`< " "` admits the space itself; a mutant moving to `<=` would reject ordinary text."""

    assert contains_control_characters(" ") is False
    assert contains_control_characters("\x1f") is True


# ---------------------------------------------------------------------------------------
# _declared_controls: fail_closed is reported when declared true, and only then
# ---------------------------------------------------------------------------------------


def test_no_approval_control_declares_nothing() -> None:
    assert _declared_controls({}) == frozenset()


def test_a_non_mapping_approval_control_declares_nothing() -> None:
    assert _declared_controls({"approval_control": "yes"}) == frozenset()


def test_an_approval_control_declares_approval() -> None:
    assert _declared_controls({"approval_control": {}}) == frozenset({"approval"})


def test_fail_closed_true_adds_the_fail_closed_control_under_its_exact_name() -> None:
    declared = _declared_controls({"approval_control": {"fail_closed": True}})

    assert declared == frozenset({"approval", "approval.fail_closed"})


@pytest.mark.parametrize("value", [False, None, 0, "true", "yes"])
def test_fail_closed_that_is_not_true_does_not_add_the_control(value: object) -> None:
    """`is True`, not truthiness and not `is False`.

    A policy that switched fail-closed off must not be reported as declaring it; a
    mutant reading `is False` reports the control on exactly those policies, and a
    mutant reading `is not True` reports it on every policy that omits the flag.
    """

    declared = _declared_controls({"approval_control": {"fail_closed": value}})

    assert declared == frozenset({"approval"})
