"""What deciding equivalence buys, pinned so the claim keeps its number.

The theory's practical claim is that a score inside the fragment is exact. The comparison
this file guards is what the alternative costs, and the figure that matters is not the
average: a suite with provably complete detection is reported at 57.9% by a pipeline that
cannot decide equivalence, because 42.1% of the generated mutants are equivalent and it has
no way to remove them from the denominator.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "estimator-comparison-v1.json"


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "estimator_comparison", ROOT / "scripts" / "estimator_comparison.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["estimator_comparison"] = module
    specification.loader.exec_module(module)
    return module


comparison = _module()


@pytest.fixture(scope="module")
def findings() -> dict:
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


class TestSamplingError:
    def test_a_sample_of_everything_has_no_error(self) -> None:
        killed = [True] * 14 + [False] * 8

        assert comparison.sampling_error(killed, len(killed))["mean_absolute_error"] == 0.0

    def test_a_suite_that_kills_everything_is_estimated_exactly(self) -> None:
        """There is nothing to be unlucky about, so sampling costs nothing."""

        result = comparison.sampling_error([True] * 22, 8)

        assert result["mean_absolute_error"] == 0.0
        assert result["worst_absolute_error"] == 0.0

    def test_error_falls_as_the_sample_grows(self) -> None:
        killed = [True] * 14 + [False] * 8
        errors = [
            comparison.sampling_error(killed, size)["mean_absolute_error"] for size in (4, 8, 16)
        ]

        assert errors == sorted(errors, reverse=True), errors

    def test_a_small_sample_is_usually_off_by_more_than_ten_points(self) -> None:
        killed = [True] * 14 + [False] * 8

        assert comparison.sampling_error(killed, 4)["share_off_by_over_10_points"] > 0.9


class TestRecordedComparison:
    def test_the_equivalent_share_is_the_one_the_theory_quotes(self, findings: dict) -> None:
        assert findings["equivalent_share"] == 0.4211

    def test_a_complete_suite_is_understated_by_the_equivalent_share(self, findings: dict) -> None:
        """The sharpest case: 100% detection reported as 57.9%."""

        complete = next(
            entry for entry in findings["suites"] if entry["suite"].startswith("coverage-matrix")
        )

        assert complete["exact_score"] == 1.0
        assert complete["score_without_equivalence_detection"] == pytest.approx(0.5789, abs=1e-4)
        assert complete["understatement_points"] == pytest.approx(42.11, abs=0.05)

    def test_every_suite_is_understated_never_overstated(self, findings: dict) -> None:
        """Undetected equivalents inflate the denominator, so the error has one sign."""

        for entry in findings["suites"]:
            assert entry["understatement_points"] > 0, entry["suite"]
            assert entry["exact_score"] >= entry["score_without_equivalence_detection"]

    def test_the_recorded_figures_match_a_fresh_run(self, findings: dict) -> None:
        fresh = comparison.analyse(
            ROOT / "policies" / "default-policy.json",
            [
                ROOT / "scenarios" / "default-scenarios.json",
                ROOT / "scenarios" / "adversarial-scenarios.json",
                ROOT / "scenarios" / "coverage-matrix-scenarios.json",
            ],
        )

        assert [entry["exact_score"] for entry in fresh["suites"]] == [
            entry["exact_score"] for entry in findings["suites"]
        ]
        assert fresh["equivalent_share"] == findings["equivalent_share"]
