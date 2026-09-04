"""Mutant generation for the Rego predictive-validity experiment.

Running `opa test` needs the binary, so the tested part is the generation of mutants: that
each edit is a single syntax-preserving change, that comments and string literals are left
alone, and that nothing silently produces a mutant identical to the original.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import rego_mutation  # noqa: E402


def _names(source: str) -> list[str]:
    return [mutant.name for mutant in rego_mutation._mutate(source)]


def _sources(source: str) -> list[str]:
    return [mutant.source for mutant in rego_mutation._mutate(source)]


def test_a_comparison_is_flipped() -> None:
    assert "L1:==->!=" in _names("x == 1\n")


def test_a_negation_is_dropped() -> None:
    assert "L1:drop-not" in _names("not is_exempt(input)\n")


def test_every_mutant_differs_from_the_original() -> None:
    """A mutant equal to the source would be counted as survived and mean nothing."""

    source = "x == 1\ny != 2\nnot z\ncount(r) > 0\n"

    for mutated in _sources(source):
        assert mutated != source


def test_each_mutant_changes_exactly_one_line() -> None:
    source = "x == 1\ny == 2\n"

    for mutated in _sources(source):
        differing = [
            index
            for index, (before, after) in enumerate(
                zip(source.splitlines(), mutated.splitlines(), strict=True)
            )
            if before != after
        ]
        assert len(differing) == 1


def test_a_comment_is_not_mutated() -> None:
    assert rego_mutation._mutate("# x == 1\n") == []


def test_an_inline_comment_is_not_mutated() -> None:
    """Only the code before a `#` is a candidate site."""

    names = _names("y := 2  # x == 1\n")

    assert not any(name.endswith("==->!=") for name in names)


def test_a_line_with_an_odd_number_of_quotes_is_skipped() -> None:
    """A comparison inside a string is not a decision site, and editing it changes data."""

    assert rego_mutation._mutate('msg := "value == 1\n') == []


def test_a_line_without_a_mutable_site_yields_nothing() -> None:
    assert rego_mutation._mutate("package example\n") == []


def test_boolean_literals_are_flipped() -> None:
    assert "L1:true->false" in _names("allowed := true\n")


def test_mutants_are_generated_for_every_line_that_has_a_site() -> None:
    lines = {name.split(":")[0] for name in _names("x == 1\ny == 2\nz == 3\n")}

    assert lines == {"L1", "L2", "L3"}


# ---------------------------------------------------------------------------------------
# Joining mutation score against the decision-coverage verdict
# ---------------------------------------------------------------------------------------


def _report(scores: dict[str, float | None]) -> dict:
    return {
        "detail": [
            {"policy": name, "mutation_score": score} for name, score in sorted(scores.items())
        ]
    }


def _coverage(verdicts: dict[str, bool]) -> dict:
    return {
        "subjects": [
            {
                "domain": "violation_set",
                "subject": f"lib/src/general/{name}/src_test.rego::violation",
                "blind": blind,
            }
            for name, blind in sorted(verdicts.items())
        ]
    }


def test_a_flagged_suite_scoring_lowest_is_reported_with_its_chance_probability() -> None:
    joined = rego_mutation.predictive_validity(
        _report({"a": 0.0, "b": 0.7, "c": 0.9}), _coverage({"a": True, "b": False, "c": False})
    )

    assert joined["flagged_suites_rank_lowest"] is True
    assert joined["probability_by_chance"] == round(1 / 3, 4)
    assert joined["blind"]["mutation_scores"] == [0.0]
    assert joined["covered"]["min_mutation_score"] == 0.7


def test_a_flagged_suite_that_is_not_worst_is_not_reported_as_predictive() -> None:
    """The claim must be falsifiable, so the negative case has to come out negative."""

    joined = rego_mutation.predictive_validity(
        _report({"a": 0.9, "b": 0.1, "c": 0.5}), _coverage({"a": True, "b": False, "c": False})
    )

    assert joined["flagged_suites_rank_lowest"] is False
    assert joined["probability_by_chance"] is None


def test_policies_without_a_coverage_verdict_are_left_out_of_the_join() -> None:
    joined = rego_mutation.predictive_validity(
        _report({"a": 0.0, "unmeasured": 0.4}), _coverage({"a": True})
    )

    assert joined["policies_joined"] == 1


def test_a_policy_with_no_score_is_left_out_of_the_join() -> None:
    joined = rego_mutation.predictive_validity(
        _report({"a": 0.0, "b": None}), _coverage({"a": True, "b": False})
    )

    assert joined["policies_joined"] == 1


def test_a_domain_other_than_violation_set_is_not_joined() -> None:
    """Boolean-helper subjects are not the policy's decision and would pollute the join."""

    coverage = {
        "subjects": [
            {"domain": "boolean", "subject": "x/general/a/src_test.rego::is_exempt", "blind": True}
        ]
    }

    assert rego_mutation.predictive_validity(_report({"a": 0.0}), coverage)["policies_joined"] == 0
