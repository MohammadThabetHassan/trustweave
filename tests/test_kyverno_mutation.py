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


# ---------------------------------------------------------------------------------------
# Provenance of the join. The score and the decision-blindness flag used to come from two
# different files: the score from whichever sibling directory a last-wins dict left behind,
# and the flag from a coverage artifact pooled over every variant of the policy.
# ---------------------------------------------------------------------------------------


def _suite(
    directory: Path,
    policy: str,
    *,
    rule: str = "r",
    results: tuple[str, ...] = ("pass", "fail"),
) -> Path:
    """A Kyverno policy and the CLI test manifest that exercises it, on disk."""

    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{policy}.yaml").write_text(
        "apiVersion: kyverno.io/v1\n"
        "kind: ClusterPolicy\n"
        f"metadata:\n  name: {policy}\n"
        "spec:\n"
        "  background: false\n"
        "  rules:\n"
        f"  - name: {rule}\n"
        "    match:\n      any:\n      - resources:\n          kinds:\n          - Pod\n"
        "    validate:\n      pattern:\n        spec:\n"
        "          hostNetwork: false\n",
        encoding="utf-8",
    )
    tests = directory / ".kyverno-test"
    tests.mkdir(exist_ok=True)
    entries = "".join(
        f"- kind: Pod\n  policy: {policy}\n  rule: {rule}\n  resources:\n  - r{index}\n"
        f"  result: {decision}\n"
        for index, decision in enumerate(results)
    )
    (tests / "kyverno-test.yaml").write_text(
        "apiVersion: cli.kyverno.io/v1alpha1\n"
        "kind: Test\n"
        f"metadata:\n  name: {policy}\n"
        f"policies:\n- ../{policy}.yaml\n"
        "resources:\n- resource.yaml\n"
        f"results:\n{entries}",
        encoding="utf-8",
    )
    return tests


def test_a_policy_is_keyed_by_the_name_its_manifest_states(tmp_path: Path) -> None:
    """The key was `path.parent.parent.name`, which is a directory rather than an identity.

    The pinned corpus publishes `-cel` and `-vpol` variants of a policy as sibling top-level
    directories, all naming the same policy. A last-wins dict over the sorted manifests
    collapsed 495 of them into 235 entries and kept the variant, so 36 of the 49 scored
    policies were mutated in a sibling of the directory whose coverage verdict labelled them.
    """

    _suite(tmp_path / "other" / "block-updates-deletes", "block-updates-deletes")
    _suite(tmp_path / "other-vpol" / "block-updates-deletes", "block-updates-deletes")

    manifests = kyverno_mutation.policy_manifests(tmp_path)

    assert list(manifests) == ["block-updates-deletes"]
    chosen, *rest = manifests["block-updates-deletes"]
    # Path order compares part-wise, so the base directory sorts before its suffixed
    # variants and is the one measured; the variants stay visible.
    assert chosen.parts[-3] == "other"
    assert [path.parts[-3] for path in rest] == ["other-vpol"]


def test_a_manifest_naming_a_policy_from_another_directory_is_still_keyed_by_the_name(
    tmp_path: Path,
) -> None:
    """The identity is what the `results[].policy` block says, not where the file lives."""

    _suite(tmp_path / "library" / "some-directory", "disallow-host-network")

    manifests = kyverno_mutation.policy_manifests(tmp_path)

    assert list(manifests) == ["disallow-host-network"]
    assert kyverno_mutation.manifest_cases(
        manifests["disallow-host-network"][0] / "kyverno-test.yaml"
    ) == {"disallow-host-network": 2}


def test_blindness_is_read_from_the_manifest_that_would_be_measured(tmp_path: Path) -> None:
    """One decision witnessed is blind; the pooled artifact rolled variants together.

    A policy whose base suite witnesses only `fail` is blind in that suite even when a
    variant's suite witnesses both, and it is the base suite that gets mutated.
    """

    blind = _suite(tmp_path / "other" / "p", "p", results=("fail",))
    covered = _suite(tmp_path / "other-vpol" / "p", "p", results=("fail", "pass"))

    assert kyverno_mutation.manifest_blindness(blind / "kyverno-test.yaml") == {"p": True}
    assert kyverno_mutation.manifest_blindness(covered / "kyverno-test.yaml") == {"p": False}


def _pooled_coverage(*blind_policies: str, covered: tuple[str, ...] = ()) -> dict:
    subjects = [
        {"domain": "kyverno_validate", "subject": f"{name}/r", "blind": True}
        for name in blind_policies
    ] + [{"domain": "kyverno_validate", "subject": f"{name}/r", "blind": False} for name in covered]
    return {"subjects": subjects}


def test_a_policy_no_manifest_names_is_recorded_as_skipped(tmp_path: Path) -> None:
    """The join dropped 3 of 18 blind and 29 of 101 covered policies with no trace at all."""

    report = kyverno_mutation.analyze(
        tmp_path, _pooled_coverage("ghost-policy", covered=("also-absent",)), 25, 8
    )

    assert report["policies_scored"] == 0
    reasons = {entry["policy"]: entry["reason"] for entry in report["skipped"]}
    assert set(reasons) == {"ghost-policy", "also-absent"}
    assert all("no kyverno-test.yaml names this policy" in reason for reason in reasons.values())


def test_a_manifest_stating_no_validate_expectation_is_recorded_not_labelled(
    tmp_path: Path,
) -> None:
    """The grouping variable has to come from the same file as the score, or it is guesswork."""

    directory = tmp_path / "other" / "p"
    directory.mkdir(parents=True)
    tests = directory / ".kyverno-test"
    tests.mkdir()
    (tests / "kyverno-test.yaml").write_text(
        "apiVersion: cli.kyverno.io/v1alpha1\nkind: Test\nmetadata:\n  name: p\n"
        "policies:\n- ../absent.yaml\nresults:\n"
        "- kind: Pod\n  policy: p\n  rule: r\n  resources:\n  - r0\n  result: pass\n",
        encoding="utf-8",
    )

    report = kyverno_mutation.analyze(tmp_path, _pooled_coverage("p"), 25, 8)

    assert report["policies_scored"] == 0
    ((skipped,),) = (report["skipped"],)
    assert skipped["policy"] == "p"
    assert "states no validate expectation" in skipped["reason"]


def test_the_report_records_what_was_run_and_over_what(tmp_path: Path) -> None:
    """Neither mutation artifact recorded its invocation or its corpus, so neither could be
    re-derived from itself."""

    report = kyverno_mutation.analyze(
        tmp_path,
        _pooled_coverage("ghost"),
        25,
        8,
        invocation=["kyverno_mutation.py", "--limit", "8"],
    )

    assert report["invocation"] == ["kyverno_mutation.py", "--limit", "8"]
    assert report["corpus"] == []
    assert "labelled_by_pooled_coverage" in report


def test_a_boolean_that_configures_the_run_is_not_a_mutable_guard() -> None:
    """`BOOLEANS` fired on any `true`/`false` token anywhere on a line.

    48 of the 248 scored Kyverno mutants sat on `background:`, `enabled:` or `message:`,
    which configure the run or the text it prints rather than what the policy matches.
    """

    assert _names("  background: false\n") == []
    assert _names("  enabled: true\n") == []
    assert _names('    message: "the value must be true"\n') == []
    assert _names("  policies.kyverno.io/description: this is true anyway\n") == []


def test_a_boolean_the_guard_reads_is_still_flipped() -> None:
    """The refusal direction: tightening must not stop mutating the pattern itself."""

    assert "L1:true->false" in _names("          readOnlyRootFilesystem: true\n")
    assert "L1:false->true" in _names("        - allowPrivilegeEscalation: false\n")
    # A Kyverno anchor is part of the pattern key, not a reason to decline it.
    assert "L1:false->true" in _names("        =(hostNetwork): false\n")
    assert "L1:true->false" in _names("    X(privileged): true\n")
