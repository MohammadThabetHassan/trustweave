"""The witness construction, certified by a solver rather than by its own argument.

Theorem 1's proof claimed that each of the `2^|K_P|` capability subsets is occupied by some
subject. It is not: everything matching `net.http` matches `net.*`, so one of the four
subsets a policy naming both induces is occupied by nothing, and two of the others coincide.
The claim survived review because nothing checked it.

These tests check it. The solver decides, for every candidate signature, whether any
capability set realises it, and the construction must produce exactly the achievable ones --
no more, or it invents classes no subject occupies, and no fewer, or the quotient is
incomplete and Corollary 4's premise is unreachable.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "witness-space-verification-v1.json"

z3 = pytest.importorskip("z3", reason="z3-solver is required to certify the construction")


def _checker() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "verify_witness_space", ROOT / "scripts" / "verify_witness_space.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["verify_witness_space"] = module
    specification.loader.exec_module(module)
    return module


checker = _checker()


class TestCapabilityAchievability:
    def test_a_nested_pattern_makes_one_signature_unachievable(self) -> None:
        """Nothing matches `net.http` without matching `net.*`, so that signature is empty."""

        patterns = ("net.*", "net.http")

        assert not checker.capability_signature_achievable(patterns, (False, True))
        assert checker.capability_signature_achievable(patterns, (True, True))
        assert checker.capability_signature_achievable(patterns, (True, False))
        assert checker.capability_signature_achievable(patterns, (False, False))

    def test_disjoint_patterns_leave_every_signature_achievable(self) -> None:
        patterns = ("net.*", "fs.*")

        for signature in ((False, False), (False, True), (True, False), (True, True)):
            assert checker.capability_signature_achievable(patterns, signature), signature

    def test_two_exact_patterns_are_independent(self) -> None:
        patterns = ("net.http", "net.https")

        assert checker.capability_signature_achievable(patterns, (True, False))
        assert checker.capability_signature_achievable(patterns, (False, True))

    def test_a_chain_of_three_patterns_collapses_to_five_of_eight(self) -> None:
        """`net.http.get` implies `net.http` implies `net.*`, so only the prefixes survive."""

        patterns = ("net.*", "net.http", "net.http.get")
        achievable = [
            signature
            for signature in [
                (a, b, c) for a in (False, True) for b in (False, True) for c in (False, True)
            ]
            if checker.capability_signature_achievable(patterns, signature)
        ]

        assert len(achievable) == 5

    def test_the_empty_capability_set_realises_the_all_false_signature(self) -> None:
        assert checker.capability_signature_achievable(("net.*", "fs.*"), (False, False))


class TestPurposeAchievability:
    def test_one_intersection_predicate_cannot_tell_the_subsets_apart(self) -> None:
        """`{a}`, `{b}` and `{a, b}` all intersect `{a, b}`, so four subsets give two answers."""

        achievable = [
            signature
            for signature in ((False,), (True,))
            if checker.purpose_signature_achievable(("a", "b"), (("a", "b"),), signature)
        ]

        assert len(achievable) == 2

    def test_two_predicates_over_disjoint_sets_are_independent(self) -> None:
        achievable = [
            signature
            for signature in ((False, False), (False, True), (True, False), (True, True))
            if checker.purpose_signature_achievable(("a", "b"), (("a",), ("b",)), signature)
        ]

        assert len(achievable) == 4

    def test_overlapping_predicates_stay_independent_when_a_shared_tag_exists(self) -> None:
        """`{a, b}` and `{b, c}` share `b`, and every combination is still reachable."""

        achievable = [
            signature
            for signature in ((False, False), (False, True), (True, False), (True, True))
            if checker.purpose_signature_achievable(
                ("a", "b", "c"), (("a", "b"), ("b", "c")), signature
            )
        ]

        assert len(achievable) == 4


def test_the_construction_agrees_with_the_solver_on_every_case() -> None:
    """The whole point: what is enumerated is exactly what a subject can occupy."""

    findings = checker.check()

    assert findings["capability_cases"] == findings["capability_cases_agreeing"]
    for entry in findings["capabilities"]:
        assert entry["unachievable_but_produced"] == [], entry["patterns"]
        assert entry["achievable_but_missing"] == [], entry["patterns"]


def test_the_committed_certificate_matches_a_fresh_check() -> None:
    committed = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    fresh = checker.check()

    assert committed["capabilities"] == fresh["capabilities"]
    assert committed["purposes"] == fresh["purposes"]


def test_the_certificate_records_the_nested_case_that_was_wrong() -> None:
    """If this case ever left the suite, the correction would stop being checked."""

    committed = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    nested = next(
        entry for entry in committed["capabilities"] if entry["patterns"] == ["net.*", "net.http"]
    )

    assert nested["candidate_signatures"] == 4
    assert nested["achievable_by_solver"] == 3
    assert nested["agree"] is True
