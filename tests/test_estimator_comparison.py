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
from fractions import Fraction
from itertools import combinations
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

    @pytest.mark.parametrize("hits", range(11))
    def test_the_hypergeometric_rows_agree_with_enumerating_every_sample(self, hits: int) -> None:
        """The closed form is checked against the definition it replaces, sample by sample.

        An earlier version enumerated samples up to a cap and simulated above it. The
        hypergeometric sum must give what enumerating every sample gives, at every size.
        """

        killed = [True] * hits + [False] * (10 - hits)
        exact = Fraction(hits, 10)
        for size in range(1, 10):
            # Exact arithmetic on both sides: in floating point 0.4 - 0.3 exceeds 0.10, so a
            # sample exactly ten points off would be counted as more than ten points off.
            errors = [
                abs(Fraction(sum(sample), size) - exact) for sample in combinations(killed, size)
            ]
            row = comparison.sampling_error(killed, size)

            assert row["method"] == f"exact over {len(errors)} samples"
            assert row["mean_absolute_error"] == round(float(sum(errors) / len(errors)), 4)
            assert row["worst_absolute_error"] == round(float(max(errors)), 4)
            assert row["share_off_by_over_10_points"] == round(
                sum(1 for error in errors if error > Fraction(1, 10)) / len(errors), 4
            )

    def test_mirror_image_kill_sets_have_identical_errors(self) -> None:
        """Fourteen kills of 22 and eight of 22 are the same distribution reflected.

        The simulated rows reported them differently in the fourth decimal, which is the
        noise a closed form does not have.
        """

        for size in comparison.SAMPLE_SIZES:
            assert comparison.sampling_error(
                [True] * 14 + [False] * 8, size
            ) == comparison.sampling_error([True] * 8 + [False] * 14, size)


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
        assert [entry["sampling"] for entry in fresh["suites"]] == [
            entry["sampling"] for entry in findings["suites"]
        ]

    def test_no_recorded_row_is_simulated(self, findings: dict) -> None:
        """Every row smaller than the whole set is exact; none carries a seed or a draw count."""

        for entry in findings["suites"]:
            for row in entry["sampling"]:
                if row["sample_size"] < entry["mutants_live"]:
                    assert row["method"].startswith("exact over "), row

    def test_the_worst_sample_of_eight_is_the_one_that_kills_nothing(self, findings: dict) -> None:
        """The figure the simulation missed: probability 1 in 319,770, error 14/22."""

        default = next(
            entry for entry in findings["suites"] if entry["suite"].startswith("default")
        )
        row = next(row for row in default["sampling"] if row["sample_size"] == 8)

        assert row["method"] == "exact over 319770 samples"
        assert row["worst_absolute_error"] == round(14 / 22, 4)


def test_an_inconsistent_suite_is_refused_by_the_estimator_too(tmp_path: Path) -> None:
    """`kill_vector()` had the same hole as `analyze()`, and the same consequence.

    Its kill set is "the suite's cases that now fail", so a case that already failed against
    the original counts as a kill against every mutant that does not happen to fix it, and
    the exact score it reports as the baseline for every sampling error below is wrong.
    """

    suite = dict(json.loads((ROOT / "scenarios" / "default-scenarios.json").read_text("utf-8")))
    suite["scenarios"] = [
        {
            "id": "TW-SC-BAD",
            "description": "An untrusted write the policy denies, asserted to be allowed.",
            "source_trust": "untrusted",
            "tool_action_class": "write",
            "expected_decision": "allow",
        }
    ]
    path = tmp_path / "inconsistent-scenarios.json"
    path.write_text(json.dumps(suite), encoding="utf-8")

    with pytest.raises(SystemExit, match="TW-SC-BAD"):
        comparison.analyse(ROOT / "policies" / "default-policy.json", [path])
