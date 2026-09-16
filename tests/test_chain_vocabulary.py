"""Assertion strength for the declared classification vocabulary.

`tests/test_chain.py` covers what these helpers do. These cover what they *say* and
where their boundaries sit: the refusal each raises, the text a reviewer reads, and
the exact point at which a near miss stops being refused and becomes a warning.

Mutation testing showed those unasserted. The vocabulary arrived with the change that
let a graph declare its own taxonomy, and the suite that came with it accepted a
mutant that inverted `if match is None`, one that dropped the similarity cutoff, and
one that moved the taxonomy size limit by one entry. The distinction between refusing
and warning is the whole point of `_check_declared_classification` -- a refused near
miss is a typo the reviewer must fix, a warning is a term the graph simply does not
treat as sensitive -- so it is asserted here rather than left to line coverage.
"""

from __future__ import annotations

from typing import Any

import pytest

from trustweave.chain import (
    MAX_CLASSIFICATION_TAXONOMY,
    ChainVocabulary,
    _check_declared_classification,
    _declared_list,
    _parse_vocabulary,
)
from trustweave.models import ValidationError

# ---------------------------------------------------------------------------------------
# _declared_list: every refusal names the field, and the size limit is inclusive
# ---------------------------------------------------------------------------------------


def test_an_absent_field_is_not_a_declaration() -> None:
    assert _declared_list({}, "classification_taxonomy") is None


def test_an_empty_list_is_refused_and_names_the_field() -> None:
    with pytest.raises(ValidationError, match="chain_manifest.classification_taxonomy"):
        _declared_list({"classification_taxonomy": []}, "classification_taxonomy")


def test_an_empty_list_says_that_emptiness_is_the_problem() -> None:
    with pytest.raises(ValidationError, match="must not be empty"):
        _declared_list({"classification_taxonomy": []}, "classification_taxonomy")


def test_a_taxonomy_of_exactly_the_limit_is_accepted() -> None:
    """`>` not `>=`: the limit is inclusive, and only a boundary test says so."""

    values = [f"c{index}" for index in range(MAX_CLASSIFICATION_TAXONOMY)]

    declared = _declared_list({"classification_taxonomy": values}, "classification_taxonomy")

    assert declared is not None
    assert len(declared) == MAX_CLASSIFICATION_TAXONOMY


def test_one_over_the_limit_is_refused_and_names_the_limit() -> None:
    values = [f"c{index}" for index in range(MAX_CLASSIFICATION_TAXONOMY + 1)]

    with pytest.raises(ValidationError, match=f"at most {MAX_CLASSIFICATION_TAXONOMY} entries"):
        _declared_list({"classification_taxonomy": values}, "classification_taxonomy")


def test_a_value_that_is_not_a_sequence_is_refused_under_the_field_name() -> None:
    """The path label reaches the message `_sequence` raises."""

    with pytest.raises(ValidationError, match="chain_manifest.classification_taxonomy"):
        _declared_list({"classification_taxonomy": "restricted"}, "classification_taxonomy")


def test_an_entry_that_is_not_text_is_refused_under_the_field_name() -> None:
    """The path label reaches the message `_text` raises."""

    with pytest.raises(ValidationError, match="chain_manifest.classification_taxonomy"):
        _declared_list({"classification_taxonomy": [1]}, "classification_taxonomy")


def test_duplicate_classifications_are_refused_and_say_so() -> None:
    values = ["restricted", "restricted"]

    with pytest.raises(ValidationError, match="must not contain duplicate classifications"):
        _declared_list({"classification_taxonomy": values}, "classification_taxonomy")


# ---------------------------------------------------------------------------------------
# _parse_vocabulary: the two refusals a site configuring its own taxonomy will meet
# ---------------------------------------------------------------------------------------


def test_a_taxonomy_with_nothing_sensitive_asks_rather_than_guessing() -> None:
    """Guessing which unfamiliar term is the sensitive one invents a finding or a silence."""

    root: dict[str, Any] = {"classification_taxonomy": ["alpha", "beta"]}

    with pytest.raises(ValidationError) as raised:
        _parse_vocabulary(root)

    message = str(raised.value)
    assert "declares no classification this review treats as sensitive" in message
    assert "declare chain_manifest.sensitive_classifications" in message


def test_sensitive_terms_outside_the_taxonomy_are_refused_and_listed() -> None:
    root: dict[str, Any] = {
        "classification_taxonomy": ["alpha", "beta"],
        "sensitive_classifications": ["gamma", "delta"],
    }

    with pytest.raises(ValidationError) as raised:
        _parse_vocabulary(root)

    message = str(raised.value)
    assert "must name classifications from" in message
    # Sorted and comma-joined: the reviewer is told every unknown term, not just one.
    assert "delta, gamma" in message


def test_a_declared_vocabulary_is_returned_as_declared() -> None:
    root: dict[str, Any] = {
        "classification_taxonomy": ["alpha", "beta"],
        "sensitive_classifications": ["beta"],
    }

    vocabulary = _parse_vocabulary(root)

    assert vocabulary == ChainVocabulary(("alpha", "beta"), frozenset({"beta"}))


# ---------------------------------------------------------------------------------------
# _check_declared_classification: refuse a near miss, warn about a different term
# ---------------------------------------------------------------------------------------


def _vocabulary() -> ChainVocabulary:
    return ChainVocabulary(("restricted",), frozenset({"restricted"}))


def test_a_declared_classification_passes_silently() -> None:
    warnings: list[str] = []

    _check_declared_classification("restricted", "node.classification", _vocabulary(), warnings)

    assert warnings == []


def test_a_case_only_difference_is_refused_because_propagation_compares_exact_strings() -> None:
    warnings: list[str] = []

    with pytest.raises(ValidationError) as raised:
        _check_declared_classification("Restricted", "node.classification", _vocabulary(), warnings)

    message = str(raised.value)
    assert "'Restricted'" in message and "'restricted'" in message
    assert "would silently propagate nothing" in message
    assert "Correct the declaration, or name the value" in message
    assert "in chain_manifest.classification_taxonomy." in message


def test_a_typo_near_a_declared_classification_is_refused_not_warned_about() -> None:
    """The near-miss path: close enough to be a mistake, so refusing beats propagating nothing."""

    warnings: list[str] = []

    with pytest.raises(ValidationError) as raised:
        _check_declared_classification("restrcted", "node.classification", _vocabulary(), warnings)

    assert "'restrcted'" in str(raised.value)
    assert "looks like 'restricted'" in str(raised.value)
    assert warnings == [], "a refused near miss must not also be reported as a warning"


def test_a_plainly_different_term_is_warned_about_rather_than_refused() -> None:
    """The cutoff is load-bearing: at difflib's default it would refuse this instead.

    'restr' scores about 0.67 against 'restricted', under the 0.85 the guard states and
    over difflib's own 0.6 default. A mutant that drops the cutoff turns this warning
    into a refusal, which would reject a site's descriptive metadata outright.
    """

    warnings: list[str] = []

    _check_declared_classification("restr", "node.classification", _vocabulary(), warnings)

    assert len(warnings) == 1
    assert "'restr' is not named" in warnings[0]
    assert "classification_taxonomy" in warnings[0]
