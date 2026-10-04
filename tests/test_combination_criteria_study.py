"""Established selection criteria against the quotient: the instrument, on synthetic inputs."""

from __future__ import annotations

import importlib.util
import json
import random
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


study = _load("combination_criteria_study")


def test_the_protocol_is_the_one_fixed_before_the_run() -> None:
    assert study.protocol_digest() == study.PROTOCOL_SHA256


def test_fixed_and_duplicate_positions_are_not_factors() -> None:
    keys = [(True, True, True, False), (True, False, False, False), (True, True, True, True)]
    # Position 0 never varies; position 2 repeats position 1.
    assert study.factor_positions(keys) == [1, 3]


def test_coverage_bits_count_t_wise_requirements() -> None:
    keys = [(0, 0), (0, 1), (1, 0)]
    each = study.coverage_bits(keys, [0, 1], 1)
    pairs = study.coverage_bits(keys, [0, 1], 2)
    universe_each = 0
    for mask in each:
        universe_each |= mask
    universe_pairs = 0
    for mask in pairs:
        universe_pairs |= mask
    assert universe_each.bit_count() == 4  # two values of each of two factors
    assert universe_pairs.bit_count() == 3  # only the three combinations some class takes
    # Fewer factors than t: every combination of the factors there are.
    assert study.coverage_bits(keys, [0, 1], 3) == pairs


def test_the_greedy_cover_covers_everything_and_is_seeded() -> None:
    bits = [0b011, 0b110, 0b100, 0b001]
    chosen = study.greedy_cover(bits, random.Random(1))
    covered = 0
    for index in chosen:
        covered |= bits[index]
    assert covered == 0b111
    assert chosen == study.greedy_cover(bits, random.Random(1))
    # Nothing to cover still yields a test.
    assert len(study.greedy_cover([0, 0], random.Random(1))) == 1


def test_base_choice_varies_one_factor_at_a_time_from_the_largest_class() -> None:
    keys = [(0, 0), (1, 0), (0, 1), (1, 1)]
    sizes = [5, 1, 1, 1]
    chosen = study.base_choice(keys, sizes, [0, 1], random.Random(3))
    assert chosen == [0, 1, 2]  # the base, and the nearest class with each other value


def test_detection_matches_the_earlier_studies() -> None:
    ees = _load("exact_evaluation_study")
    groups = [[0, 1, 2], [3, 4], [5]]
    for hits in ({0}, {0, 3}, {5}, {1, 2, 4}, set()):
        assert study.detection(groups, hits) == ees._detection(groups, hits)
    for cells in range(1, 9):
        for hits in range(cells + 1):
            for size in range(cells + 1):
                assert study.random_detection(cells, hits, size) == ees._random_detection(
                    cells, hits, size
                )


def test_certain_detection_needs_a_whole_class() -> None:
    space = study.Space(5, {(0,): [0, 1], (1,): [2, 3, 4]}, [{0, 1}, {0, 2}, {2, 3, 4, 1}])
    assert study.certain_share(space) == Fraction(2, 3)


def test_the_reference_policy_scores_as_the_earlier_study_scored_it() -> None:
    document = json.loads(study.REFERENCE_POLICY.read_text("utf-8"))
    space = study.generated_space(document)
    scored = study.score_space(space, "reference")
    assert scored["scores"]["quotient"] == 1.0
    assert scored["classes"] == 12 and scored["live_mutants"] == 22
    # Rule coverage: the four rules and the default each decide somewhere.
    assert scored["sizes"]["rule"] == 5.0
    assert scored["infeasible_requirements"] == {"rule": 0, "decision": 0, "mcdc": 0}
    for name in ("each_choice", "base_choice", "pairwise", "three_wise", "rule", "mcdc"):
        assert 0.0 < scored["scores"][name] <= scored["scores"]["quotient"]
