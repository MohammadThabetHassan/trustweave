"""Decision-class coverage: what a scenario suite can and cannot detect."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "policy_mutation", ROOT / "scripts" / "policy_mutation.py"
)
assert _spec and _spec.loader
policy_mutation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy_mutation)

POLICY = ROOT / "policies" / "default-policy.json"
DEFAULT_SUITE = ROOT / "scenarios" / "default-scenarios.json"
ADVERSARIAL_SUITE = ROOT / "scenarios" / "adversarial-scenarios.json"
MATRIX_SUITE = ROOT / "scenarios" / "coverage-matrix-scenarios.json"


def _report():
    return policy_mutation.analyze(POLICY, [DEFAULT_SUITE, ADVERSARIAL_SUITE, MATRIX_SUITE])


def test_equivalent_mutants_are_decided_not_estimated() -> None:
    """The partition is finite, so equivalence is computed rather than approximated."""

    report = _report()

    assert report["mutants_generated"] == report["mutants_equivalent"] + report["mutants_live"]
    assert report["mutants_equivalent"] > 0, "some single edits must be unobservable"


def test_a_suite_missing_a_decision_class_cannot_be_complete() -> None:
    """The adversarial suite expects no `allow`, so it cannot pin the permitted cell."""

    suites = _report()["suites"]

    assert suites["adversarial-scenarios.json"]["decision_classes_missing"] == ["allow"]
    assert suites["default-scenarios.json"]["decision_classes_missing"] == []
    assert suites["coverage-matrix-scenarios.json"]["decision_classes_missing"] == []


def test_case_count_does_not_predict_detection_power() -> None:
    """Five cases catch more policy changes than twenty-five. This is the whole finding."""

    suites = _report()["suites"]
    small = suites["default-scenarios.json"]
    large = suites["adversarial-scenarios.json"]

    assert large["cases"] > small["cases"]
    assert large["mutants_killed"] < small["mutants_killed"]


def test_total_cell_coverage_detects_every_observable_mutant() -> None:
    """Witnessing every cell of the partition is sufficient to pin the policy down."""

    report = _report()
    matrix = report["suites"]["coverage-matrix-scenarios.json"]

    assert matrix["cells_covered"] == f"{report['partition_cells']}/{report['partition_cells']}"
    assert matrix["mutants_killed"] == report["mutants_live"]
    assert matrix["survivors"] == []


def test_a_permit_by_default_policy_survives_the_adversarial_suite() -> None:
    """The dangerous direction: a policy permitting everything undeclared goes unnoticed."""

    suites = _report()["suites"]
    survivors = suites["adversarial-scenarios.json"]["survivors"]

    assert any(name == "default_decision[->allow]" for name in survivors)
    assert "default_decision[->allow]" not in suites["default-scenarios.json"]["survivors"]


def test_a_survivor_differs_only_where_the_suite_never_looks() -> None:
    """The exact reason a mutant survives, stated as a property rather than a count.

    The reference policy satisfies every expectation in the suite. A mutant that changed
    a cell the suite witnesses would therefore break that expectation and be killed. So
    every survivor must agree with the reference on all witnessed cells, and differ only
    on cells no case exercises. Detection power is bounded by cell coverage, not by how
    many cases the suite holds.
    """

    document = dict(policy_mutation.load_document(POLICY))
    reference = policy_mutation.decision_map(document)
    generated = dict(policy_mutation._mutants(document))
    report = _report()

    for suite_name, suite_path in (
        ("adversarial-scenarios.json", ADVERSARIAL_SUITE),
        ("default-scenarios.json", DEFAULT_SUITE),
    ):
        witnessed = {
            (trust, action) for trust, action, _ in policy_mutation._suite_expectations(suite_path)
        }
        for name in report["suites"][suite_name]["survivors"]:
            resolved = policy_mutation.decision_map(generated[name])
            differing = {cell for cell in reference if resolved[cell] != reference[cell]}
            assert differing, f"{name} is observably identical and should not be live"
            assert not (differing & witnessed), (
                f"{suite_name} survivor {name} differs on a cell the suite witnesses"
            )
