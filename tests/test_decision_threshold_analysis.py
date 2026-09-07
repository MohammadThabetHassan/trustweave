"""Tests for the decision-threshold information analysis and the graded-trend test.

Both scripts read the committed suite-coverage and mutation artifacts, so their outputs
are facts about data in the repository rather than about a run. The findings the study
quotes are pinned here: an unpinned entropy figure could drift with an artifact
regeneration and nothing would say so.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from math import isclose
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str) -> ModuleType:
    """Load a script by path; scripts is not a package under a bare pytest run."""
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def threshold() -> ModuleType:
    return _load("decision_threshold_analysis")


@pytest.fixture(scope="module")
def trend() -> ModuleType:
    return _load("decision_trend_test")


class TestBinaryEntropy:
    def test_a_partition_that_flags_nothing_carries_no_information(
        self, threshold: ModuleType
    ) -> None:
        assert threshold.binary_entropy(0.0) == 0.0

    def test_a_partition_that_flags_everything_carries_no_information(
        self, threshold: ModuleType
    ) -> None:
        assert threshold.binary_entropy(1.0) == 0.0

    def test_an_even_split_carries_one_bit(self, threshold: ModuleType) -> None:
        assert isclose(threshold.binary_entropy(0.5), 1.0)

    def test_information_is_symmetric_about_an_even_split(self, threshold: ModuleType) -> None:
        assert isclose(threshold.binary_entropy(0.2), threshold.binary_entropy(0.8))

    @pytest.mark.parametrize("share", [0.01, 0.1, 0.3, 0.45])
    def test_information_rises_towards_an_even_split(
        self, threshold: ModuleType, share: float
    ) -> None:
        assert threshold.binary_entropy(share) < threshold.binary_entropy(share + 0.05)


class TestSatisfactionCurve:
    def test_the_curve_starts_at_one_and_never_rises(self, threshold: ModuleType) -> None:
        """Every subject witnesses at least one decision, and the curve is a survival."""

        for entry in threshold.analyse()["domains"]:
            curve = [share for _, share in sorted(entry["satisfaction_curve"].items())]
            assert curve[0] == 1.0
            pairs = zip(curve, curve[1:], strict=False)
            assert all(later <= earlier for earlier, later in pairs)

    def test_a_hand_computed_group_matches(self, threshold: ModuleType) -> None:
        # Four subjects over a three-valued domain: two witness one decision, two witness all.
        result = threshold.analyse_group([1, 1, 3, 3], domain_size=3)
        assert result["satisfaction_curve"] == {"1": 1.0, "2": 0.5, "3": 0.5}
        assert result["thresholds"][0] == {"k": 2, "share_flagged": 0.5, "bits": 1.0}
        assert result["most_informative_threshold"] == 2

    def test_a_threshold_every_subject_fails_carries_no_information(
        self, threshold: ModuleType
    ) -> None:
        result = threshold.analyse_group([1, 1, 1], domain_size=2)
        assert result["published_threshold_share_flagged"] == 1.0
        assert result["published_threshold_bits"] == 0.0


@pytest.fixture(scope="module")
def domains(threshold: ModuleType) -> dict[str, dict[str, object]]:
    return {
        f"{entry['ecosystem']}/{entry['domain']}": entry for entry in threshold.analyse()["domains"]
    }


class TestMeasuredFindings:
    """The figures docs/SUITE_COVERAGE_STUDY.md quotes, pinned to the artifacts."""

    def test_five_domains_carry_enough_subjects_to_measure(
        self, domains: dict[str, dict[str, object]]
    ) -> None:
        assert len(domains) == 5

    def test_the_kyverno_mutate_full_domain_threshold_carries_no_information(
        self, domains: dict[str, dict[str, object]]
    ) -> None:
        """It flags every subject, so it cannot distinguish any of them."""

        entry = domains["kyverno/kyverno_mutate"]
        assert entry["published_threshold_share_flagged"] == 1.0
        assert entry["published_threshold_bits"] == 0.0

    def test_the_xacml_informative_threshold_is_interior(
        self, domains: dict[str, dict[str, object]]
    ) -> None:
        """Three of four decisions splits the corpus; all four flags almost all of it."""

        entry = domains["xacml/xacml_decision"]
        assert entry["domain_size"] == 4
        assert entry["most_informative_threshold"] == 3
        assert entry["most_informative_bits"] > 0.9
        assert entry["published_threshold_bits"] < 0.3

    def test_binary_domains_flag_almost_nothing(
        self, domains: dict[str, dict[str, object]]
    ) -> None:
        for key in ("rego/violation_set", "cedar/cedar_decision"):
            assert domains[key]["published_threshold_share_flagged"] < 0.1

    def test_the_published_threshold_is_rarely_the_informative_one(
        self, threshold: ModuleType
    ) -> None:
        findings = threshold.analyse()
        assert findings["domains_where_published_threshold_is_most_informative"] == 2
        assert findings["domains_where_published_threshold_carries_under_0_3_bits"] == 4


class TestGradedTrend:
    def test_every_scored_policy_joins_to_a_coverage_verdict(self, trend: ModuleType) -> None:
        assert len(trend.joined_rows()) == 49

    def test_jonckheere_is_maximal_when_every_higher_group_scores_higher(
        self, trend: ModuleType
    ) -> None:
        assert trend.jonckheere([1, 1, 2, 2], [0.0, 0.1, 0.9, 1.0]) == 4.0

    def test_jonckheere_is_zero_when_the_order_is_reversed(self, trend: ModuleType) -> None:
        assert trend.jonckheere([1, 1, 2, 2], [0.9, 1.0, 0.0, 0.1]) == 0.0

    def test_ties_count_half(self, trend: ModuleType) -> None:
        assert trend.jonckheere([1, 2], [0.5, 0.5]) == 0.5

    def test_the_graded_trend_is_not_supported(self, trend: ModuleType) -> None:
        """Reported because it is negative: the signal is blindness, not a gradient."""

        findings = trend.run(permutations=2000, seed=0)
        assert findings["ordered_trend_supported_at_0_05"] is False
        assert findings["p_value_one_sided"] > 0.05

    def test_the_published_blindness_contrast_is_reproduced(self, trend: ModuleType) -> None:
        findings = trend.run(permutations=100, seed=0)
        published = findings["blindness_contrast_as_published"]
        assert published["blind_policies"] == 9
        assert published["covered_policies"] == 40
        assert published["blind_median"] == 0.5
        assert published["covered_median"] == 0.625


def test_the_committed_artifacts_match_a_fresh_computation(threshold: ModuleType) -> None:
    """A regenerated artifact must not silently disagree with the script that writes it."""

    committed = json.loads(
        (ROOT / "docs" / "decision-threshold-analysis-v1.json").read_text(encoding="utf-8")
    )
    assert committed == threshold.analyse()
