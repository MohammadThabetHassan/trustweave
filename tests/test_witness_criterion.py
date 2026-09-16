"""The witness construction has a closed-form criterion, and it needs no solver to check.

The paper's lemma on existential set guards says when a signature over named patterns or
named purpose sets is achievable: exactly when no guard marked false dominates one marked
true. `scripts/verify_witness_space.py` decides the same question three ways -- by that
criterion, by what the harness enumerates, and by asking Z3 -- and records all three. These
tests hold the first two to each other without the solver, so the lemma is load-bearing in
CI even where z3 is not installed, and hold both to the counts the solver last recorded.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "witness-space-verification-v1.json"

sys.path.insert(0, str(ROOT / "src"))

from trustweave.policy_predicates import capability_matches  # noqa: E402


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


verifier = _load("verify_witness_space")
harness = _load("policy_mutation")


def _signatures(patterns: tuple[str, ...]) -> tuple[set[tuple[bool, ...]], set[tuple[bool, ...]]]:
    """(what the criterion admits, what the construction enumerates) for one pattern set."""

    by_criterion = {
        signature
        for signature in itertools.product((False, True), repeat=len(patterns))
        if verifier.capability_signature_achievable_by_criterion(patterns, signature)
    }
    document = {"rules": [{"tool_capabilities": list(patterns)}]}
    constructed = {
        tuple(any(capability_matches(pattern, held) for held in witness) for pattern in patterns)
        for witness in harness.witness_space(document)["tool_capabilities"]
    }
    return by_criterion, constructed


class TestTheFreshTail:
    def test_the_outsider_stem_carries_no_namespace_separator(self) -> None:
        """The lemma's witness for a wildcard is its stem plus a tail that no wildcard stem can
        reach into, which the construction guarantees only by the shape of the stem it uses."""

        assert "." not in harness.OUTSIDER_STEM
        assert "." not in harness._fresh_outsider(({"rules": [{"tool_capabilities": ["net.*"]}]},))

    def test_no_named_literal_ends_with_the_tail(self) -> None:
        document = {"rules": [{"tool_capabilities": ["net.*", f"net.{harness.OUTSIDER_STEM}"]}]}
        tail = harness._fresh_outsider((document,))

        assert not any(
            literal.endswith(tail) for literal in ["net.*", f"net.{harness.OUTSIDER_STEM}"]
        )


class TestDominance:
    def test_a_wildcard_dominates_the_literals_and_wildcards_under_its_stem(self) -> None:
        assert verifier.dominates("net.*", "net.http")
        assert verifier.dominates("net.*", "net.http.*")
        assert verifier.dominates("net.*", "net.*")

    def test_a_literal_dominates_only_itself(self) -> None:
        assert verifier.dominates("net.http", "net.http")
        assert not verifier.dominates("net.http", "net.http.get")
        assert not verifier.dominates("net.http", "net.*")

    def test_disjoint_stems_dominate_nothing(self) -> None:
        assert not verifier.dominates("net.*", "fs.*")
        assert not verifier.dominates("fs.*", "net.http")


class TestTheCriterionAgainstTheConstruction:
    def test_the_nested_pair_admits_three_of_four(self) -> None:
        by_criterion, constructed = _signatures(("net.*", "net.http"))

        assert by_criterion == constructed
        assert len(by_criterion) == 3
        assert (False, True) not in by_criterion, "matches net.http but not net.*"

    def test_the_chain_of_three_admits_five_of_eight(self) -> None:
        """net.* dominates both literals; the literal net.http does not dominate net.http.get."""

        by_criterion, constructed = _signatures(("net.*", "net.http", "net.http.get"))

        assert by_criterion == constructed
        assert len(by_criterion) == 5
        assert (True, False, True) in by_criterion

    def test_every_recorded_case_agrees(self) -> None:
        for patterns in verifier.CAPABILITY_CASES:
            by_criterion, constructed = _signatures(patterns)
            assert by_criterion == constructed, patterns


class TestThePurposeCriterion:
    def test_one_intersection_test_over_two_tags_admits_two(self) -> None:
        rule_sets = (("a", "b"),)
        admitted = [
            signature
            for signature in itertools.product((False, True), repeat=1)
            if verifier.purpose_signature_achievable_by_criterion(rule_sets, signature)
        ]
        assert admitted == [(False,), (True,)]

    def test_a_set_covered_by_the_false_sets_cannot_be_true(self) -> None:
        rule_sets = (("a", "b"), ("a",), ("b",))
        assert not verifier.purpose_signature_achievable_by_criterion(
            rule_sets, (True, False, False)
        )
        assert verifier.purpose_signature_achievable_by_criterion(rule_sets, (True, True, False))


def test_the_certificate_records_the_criterion_agreeing_with_the_solver_everywhere() -> None:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))

    assert artifact["cases_where_the_criterion_agrees_with_the_solver"] == artifact["cases"] == 14
    for entry in (*artifact["capabilities"], *artifact["purposes"]):
        assert entry["criterion_agrees"], entry
        assert entry["achievable_by_criterion"] == entry["achievable_by_solver"], entry


def test_the_certificate_counts_match_a_fresh_run_of_the_criterion() -> None:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))

    for entry in artifact["capabilities"]:
        patterns = tuple(entry["patterns"])
        by_criterion, _ = _signatures(patterns)
        assert len(by_criterion) == entry["achievable_by_criterion"], patterns
    for entry in artifact["purposes"]:
        rule_sets = tuple(tuple(held) for held in entry["rule_sets"])
        admitted = sum(
            1
            for signature in itertools.product((False, True), repeat=len(rule_sets))
            if verifier.purpose_signature_achievable_by_criterion(rule_sets, signature)
        )
        assert admitted == entry["achievable_by_criterion"], rule_sets
