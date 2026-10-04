"""The second review round's re-analyses and the unranked exclusion cross-tabulation."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def _load(name: str) -> ModuleType:
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    specification = importlib.util.spec_from_file_location(name, scripts / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


analyses = _load("review_round_analyses")
taxonomy = _load("exclusion_taxonomy")


def test_kendall_tau_b_on_orderings_and_ties() -> None:
    assert analyses.kendall_tau_b([1, 2, 3, 4], [1, 2, 3, 4]) == pytest.approx(1.0)
    assert analyses.kendall_tau_b([1, 2, 3, 4], [4, 3, 2, 1]) == pytest.approx(-1.0)
    # Four concordant pairs, one tied only in x and one only in y: 4 / sqrt(5 * 5).
    assert analyses.kendall_tau_b([1, 2, 2, 3], [1, 2, 3, 3]) == pytest.approx(0.8)


def test_the_cluster_sign_flip_enumerates_every_pattern() -> None:
    # Two clusters of one unit each: only the all-positive pattern reaches the observed mean.
    assert analyses.cluster_sign_flip_p([[1.0], [1.0]]) == pytest.approx(0.25)
    # A cluster flips as a whole, so a large cluster dominates.
    assert analyses.cluster_sign_flip_p([[1.0, 1.0, 1.0], [-0.5]]) == pytest.approx(0.5)


def test_the_cluster_bootstrap_is_seeded_and_brackets_the_mean() -> None:
    clusters = [[0.1, 0.2], [0.3], [0.05, 0.05, 0.1], [0.2]]
    first = analyses.cluster_bootstrap(clusters)
    assert first == analyses.cluster_bootstrap(clusters)
    low, high = first
    mean = sum(v for c in clusters for v in c) / sum(len(c) for c in clusters)
    assert low <= mean <= high


def test_shares_sum_to_exactly_one_hundred() -> None:
    shares = taxonomy.shares_summing_to_100({"a": 1, "b": 1, "c": 1})
    assert round(sum(shares.values()), 1) == 100.0
    assert all(abs(value - 100 / 3) < 0.1 for value in shares.values())


def test_the_crosstab_counts_every_exclusion_once() -> None:
    crossed = taxonomy.crosstab(DOCS)
    ranked = taxonomy.measure(DOCS)
    assert crossed["exclusions"] == ranked["exclusions"]
    assert crossed["schemas"] == ranked["exclusions_by_kind"]["not a policy"]
    assert (
        crossed["guard_not_a_function_of_the_request"] + crossed["schema_only"]
        == crossed["exclusions"]
    )
    for row in crossed["rows"]:
        assert sum(row["bands"].values()) == row["artifacts"]
        assert round(sum(row["band_shares"].values()), 1) == 100.0


def test_the_committed_crosstab_reproduces() -> None:
    committed = json.loads((DOCS / "exclusion-crosstab-v1.json").read_text(encoding="utf-8"))
    assert taxonomy.crosstab(DOCS) == committed


def test_the_families_partition_the_inside_verdicts() -> None:
    found = analyses.families(DOCS)
    rows = found["by_language"]
    inside = sum(
        sum(value for key, value in row.items() if key != "families") for row in rows.values()
    )
    assert inside == found["recorded_inside"]
    total = inside + found["rego_and_kyverno_inside_unrecorded"] + found["cedar_inside_by_design"]
    assert total == taxonomy.measure(DOCS)["artifacts_inside"]


def test_the_committed_analyses_reproduce() -> None:
    committed = json.loads((DOCS / "review-round-analyses-v1.json").read_text(encoding="utf-8"))
    assert analyses.analyse(DOCS) == committed
