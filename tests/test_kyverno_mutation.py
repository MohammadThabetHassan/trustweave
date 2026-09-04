"""Mutant generation and the statistics for the Kyverno replication.

Running `kyverno test` needs the CLI, so what is tested here is everything around it: that
each mutant is a single valid edit, that the two arms are split by the coverage verdict, and
that the permutation test reports what it claims to.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import kyverno_mutation  # noqa: E402


def _names(source: str) -> list[str]:
    return [mutant.name for mutant in kyverno_mutation._mutate(source)]


def test_a_condition_operator_is_negated() -> None:
    assert "L1:AnyIn->AnyNotIn" in _names("      operator: AnyIn\n")


def test_a_longer_operator_does_not_also_fire_the_shorter_one() -> None:
    """`AnyNotIn` contains `AnyIn`; editing both at one site would double-count it."""

    names = _names("      operator: AnyNotIn\n")

    assert names == ["L1:AnyNotIn->AnyIn"]


def test_a_threshold_comparison_is_flipped() -> None:
    assert 'L1:">->"<' in _names('        replicas: ">0"\n')


def test_a_required_value_pattern_is_weakened() -> None:
    """`"?*"` requires a value; `"*"` accepts anything."""

    assert 'L1:"?*"->"*"' in _names('        image: "?*"\n')


def test_a_conditional_anchor_becomes_required() -> None:
    assert "L1:=(->(" in _names("        =(securityContext):\n")


def test_a_comment_is_not_mutated() -> None:
    assert kyverno_mutation._mutate("# operator: AnyIn\n") == []


def test_every_mutant_changes_exactly_one_line() -> None:
    source = "      operator: AnyIn\n      operator: Equals\n"

    for mutant in kyverno_mutation._mutate(source):
        differing = [
            index
            for index, (before, after) in enumerate(
                zip(source.splitlines(), mutant.source.splitlines(), strict=True)
            )
            if before != after
        ]
        assert len(differing) == 1


def test_a_manifest_with_no_mutable_site_yields_nothing() -> None:
    assert kyverno_mutation._mutate("apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n") == []


# ---------------------------------------------------------------------------------------
# Splitting the arms
# ---------------------------------------------------------------------------------------


def _coverage(subjects: list[tuple[str, str, bool]]) -> dict:
    return {
        "subjects": [
            {"domain": domain, "subject": subject, "blind": blind}
            for domain, subject, blind in subjects
        ]
    }


def test_policies_are_split_by_their_validate_verdict() -> None:
    blind, covered = kyverno_mutation.blind_validate_rules(
        _coverage(
            [
                ("kyverno_validate", "alpha/rule", True),
                ("kyverno_validate", "beta/rule", False),
            ]
        )
    )

    assert blind == {"alpha"} and covered == {"beta"}


def test_a_policy_with_any_blind_rule_counts_as_blind() -> None:
    """One untested outcome in a multi-rule policy is what the measure flags."""

    blind, covered = kyverno_mutation.blind_validate_rules(
        _coverage(
            [
                ("kyverno_validate", "alpha/one", False),
                ("kyverno_validate", "alpha/two", True),
            ]
        )
    )

    assert blind == {"alpha"} and covered == set()


def test_mutate_and_generate_rules_are_not_split_into_either_arm() -> None:
    """A mutate rule has no failure outcome, so its verdict means something else."""

    blind, covered = kyverno_mutation.blind_validate_rules(
        _coverage([("kyverno_mutate", "alpha/rule", True)])
    )

    assert blind == set() and covered == set()


# ---------------------------------------------------------------------------------------
# The statistic
# ---------------------------------------------------------------------------------------


def test_perfect_separation_is_reported_as_unlikely_by_chance() -> None:
    result = kyverno_mutation.permutation_test([0.0, 0.1], [0.8, 0.9, 1.0])

    assert result["p_value"] == 0.1
    assert result["observed_difference"] > 0
    assert "exact" in result["method"]


def test_identical_groups_are_reported_as_entirely_unremarkable() -> None:
    result = kyverno_mutation.permutation_test([0.5, 0.5], [0.5, 0.5])

    assert result["p_value"] == 1.0
    assert result["observed_difference"] == 0.0


def test_a_group_ordered_against_the_hypothesis_is_not_reported_as_evidence() -> None:
    """Blind policies scoring higher must not come out looking like a positive result."""

    result = kyverno_mutation.permutation_test([0.9, 1.0], [0.0, 0.1])

    assert result["observed_difference"] < 0
    assert result["p_value"] > 0.5


def test_an_empty_arm_yields_no_statistic_rather_than_a_misleading_one() -> None:
    assert kyverno_mutation.permutation_test([], [0.5])["p_value"] is None


# ---------------------------------------------------------------------------------------
# CEL expression sites
# ---------------------------------------------------------------------------------------


def test_a_universal_quantifier_becomes_existential() -> None:
    """`all` and `exists` differ on exactly the resources a suite should distinguish."""

    source = '        - expression: "object.spec.containers.all(c, has(c.image))"\n'

    assert "L1:.all(->.exists(" in _names(source)


def test_a_conjunction_becomes_a_disjunction() -> None:
    source = '        - expression: "a == 1 && b == 2"\n'

    assert "L1:&&->||" in _names(source)


def test_a_cel_equality_is_negated() -> None:
    source = '        - expression: "object.kind == Pod"\n'

    assert "L1:==->!=" in _names(source)


def test_a_cel_comparison_is_loosened() -> None:
    source = '        - expression: "size(object.spec.containers) >= 1"\n'

    assert "L1:>=->>" in _names(source)


def test_a_cel_expression_yields_enough_sites_to_score() -> None:
    """One or two sites is not a score; this is what the floor was rejecting."""

    source = (
        "        - expression: >-\n"
        "            object.spec.containers.all(c, has(c.securityContext) &&\n"
        "            c.securityContext.runAsNonRoot == true)\n"
    )

    assert len(kyverno_mutation._mutate(source)) >= 3


def test_a_pascal_case_condition_operator_is_untouched_by_the_cel_table() -> None:
    """`Equals` is a Kyverno condition operator, not a CEL one; it must edit once."""

    assert _names("      operator: Equals\n") == ["L1:Equals->NotEquals"]
