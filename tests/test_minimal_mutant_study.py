"""The payoff over subsumption-minimal mutants: the definition and the scoring."""

from __future__ import annotations

import importlib.util
import json
import sys
from fractions import Fraction
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


study = _load("minimal_mutant_study")
ccs = _load("combination_criteria_study")


def test_the_protocol_is_the_one_fixed_before_the_study() -> None:
    assert study.protocol_digest() == study.PROTOCOL_SHA256


def test_minimal_keeps_one_of_each_set_and_drops_every_superset() -> None:
    live = [{1, 2}, {1}, {1, 2, 3}, {4}, {1}, {4, 5}, {6, 7}, {7, 6}]
    found = sorted(sorted(s) for s in study.minimal(live))
    assert found == [[1], [4], [6, 7]]


def test_minimal_does_not_mistake_overlap_for_inclusion() -> None:
    live = [{1, 2}, {2, 3}, {3, 1}]
    assert len(study.minimal(live)) == 3


def test_the_payoff_strategies_over_a_small_space() -> None:
    # Four cells in two classes, decided permit, permit, deny, deny.
    space = ccs.Space(4, {(True,): [0, 1], (False,): [2, 3]}, [{0}, {0, 2}])
    decisions = [[0, 1], [2, 3]]
    scores = study.payoff(space, decisions, space.live)
    # One witness per class: {0} is hit with probability 1/2; {0, 2} with 1 - (1/2)(1/2).
    assert scores["quotient"] == (Fraction(1, 2) + Fraction(3, 4)) / 2
    # Two random cells of four: {0} with 1/2, {0, 2} with 1 - C(2,2)/C(4,2) = 5/6.
    assert scores["random_quotient"] == (Fraction(1, 2) + Fraction(5, 6)) / 2
    # The decision groups coincide with the classes here.
    assert scores["decision"] == scores["quotient"]
    least = study.minimal(space.live)
    assert least == [{0}]
    assert study.payoff(space, decisions, least)["quotient"] == Fraction(1, 2)


def test_the_reference_policy_scores_over_all_and_minimal_mutants() -> None:
    document = json.loads(ccs.REFERENCE_POLICY.read_text("utf-8"))
    space, decisions = study.generated_space(document)
    record = study.analyse(space, decisions, "reference")
    assert record["minimal_mutants"] <= record["live_mutants"]
    # The suites are the criteria study's: over every live mutant the scores are its own.
    assert (
        record["all"]["scores"]
        == ccs.score_space(*_criteria_space(document), "reference")["scores"]
    )
    # Every minimal mutant is live, so every expected score lies between zero and one.
    for value in record["minimal"]["payoff"].values():
        assert 0 <= Fraction(value) <= 1


def _criteria_space(document: dict) -> tuple:
    return (ccs.generated_space(document),)
