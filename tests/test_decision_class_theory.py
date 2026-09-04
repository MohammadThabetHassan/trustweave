"""Machine-checked verification of the results in docs/DECISION_CLASS_COVERAGE.md.

The exactness claims that document makes -- decidable equivalence, an exact kill criterion,
cell coverage deciding the mutation score -- are proved there over a restricted policy
fragment. A proof about a fragment is only useful if the shipped policy is in it and the
implementation agrees with the semantics, so these tests check both by exhaustive
enumeration over the real policy and the real mutant set rather than restating the theorems.
"""

from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "policy_mutation_theory", ROOT / "scripts" / "policy_mutation.py"
)
assert _spec and _spec.loader
policy_mutation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy_mutation)

POLICY = ROOT / "policies" / "default-policy.json"
SUITES = [
    ROOT / "scenarios" / "default-scenarios.json",
    ROOT / "scenarios" / "adversarial-scenarios.json",
    ROOT / "scenarios" / "coverage-matrix-scenarios.json",
]

CELLS = policy_mutation.CELLS
DECISIONS = policy_mutation.DECISIONS

Cell = tuple[str, str]
Expectation = tuple[str, str, str]


def _document() -> dict:
    return dict(policy_mutation.load_document(POLICY))


def _reference() -> dict[Cell, str]:
    return policy_mutation.decision_map(_document())


def _partition() -> tuple[dict[str, dict], dict[str, dict]]:
    """Split the generated mutants into equivalent and live, by decision vector."""

    reference = _reference()
    equivalent: dict[str, dict] = {}
    live: dict[str, dict] = {}
    for name, mutant in policy_mutation._mutants(_document()):
        try:
            resolved = policy_mutation.decision_map(mutant)
        except Exception:  # noqa: BLE001 - an unparseable mutant is not a policy
            continue
        (equivalent if resolved == reference else live)[name] = mutant
    return equivalent, live


def _kills_map(expectations: list[Expectation], resolved: dict[Cell, str]) -> bool:
    """The kill relation stated over a decision vector rather than a policy document."""

    return any(resolved[(trust, action)] != expected for trust, action, expected in expectations)


def _exhaustive_suite(reference: dict[Cell, str]) -> list[Expectation]:
    return [(trust, action, reference[(trust, action)]) for trust, action in CELLS]


# ---------------------------------------------------------------------------------------
# Theorem 1: the fragment's behaviour is a total function over a finite subject space
# ---------------------------------------------------------------------------------------


def test_the_subject_space_is_the_product_of_the_label_domains() -> None:
    expected = set(itertools.product(policy_mutation.TRUST_LEVELS, policy_mutation.ACTION_CLASSES))

    assert set(CELLS) == expected
    assert len(CELLS) == 12


def test_the_decision_vector_is_total_and_lands_in_the_decision_domain() -> None:
    """Totality is what the mandatory fail-closed default buys."""

    reference = _reference()

    assert set(reference) == set(CELLS)
    assert set(reference.values()) <= set(DECISIONS)


# ---------------------------------------------------------------------------------------
# Theorem 2: equivalence is decidable, and "equivalent" really means undetectable
# ---------------------------------------------------------------------------------------


def test_every_mutant_called_equivalent_survives_the_strongest_possible_suite() -> None:
    """The suite witnessing every cell is the most that any suite in these labels can do.

    This is the claim that matters. Calling a mutant equivalent because its decision vector
    matches is only sound if no suite could ever have caught it.
    """

    reference = _reference()
    equivalent, _ = _partition()
    exhaustive = _exhaustive_suite(reference)

    assert equivalent, "the operator set must produce equivalent mutants for this to test"
    for name, mutant in equivalent.items():
        assert not policy_mutation._kills(exhaustive, mutant), f"{name} was detectable"


def test_no_live_mutant_agrees_with_the_reference_everywhere() -> None:
    reference = _reference()
    _, live = _partition()

    for name, mutant in live.items():
        assert policy_mutation.decision_map(mutant) != reference, name


# ---------------------------------------------------------------------------------------
# Theorem 3: a suite kills a mutant exactly when it witnesses a cell the mutant changed
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("suite_path", SUITES, ids=lambda path: path.stem)
def test_the_kill_criterion_is_exactly_the_intersection_of_delta_and_witnessed(
    suite_path: Path,
) -> None:
    reference = _reference()
    expectations = policy_mutation._suite_expectations(suite_path)
    witnessed = {(trust, action) for trust, action, _ in expectations}
    _, live = _partition()

    for name, mutant in live.items():
        resolved = policy_mutation.decision_map(mutant)
        delta = {cell for cell in CELLS if resolved[cell] != reference[cell]}

        assert policy_mutation._kills(expectations, mutant) == bool(delta & witnessed), name


@pytest.mark.parametrize("suite_path", SUITES, ids=lambda path: path.stem)
def test_the_suites_are_consistent_with_the_policy_they_test(suite_path: Path) -> None:
    """Theorem 3 assumes consistency; a suite contradicting its own policy fails first."""

    reference = _reference()

    for trust, action, expected in policy_mutation._suite_expectations(suite_path):
        assert reference[(trust, action)] == expected, f"{trust}/{action}"


# ---------------------------------------------------------------------------------------
# Corollary 4: cell coverage decides the score
# ---------------------------------------------------------------------------------------


def test_witnessing_every_cell_kills_every_non_equivalent_mutant() -> None:
    reference = _reference()
    _, live = _partition()
    exhaustive = _exhaustive_suite(reference)

    assert live, "the operator set must produce live mutants for this to test"
    for name, mutant in live.items():
        assert policy_mutation._kills(exhaustive, mutant), name


def test_every_unwitnessed_cell_admits_a_surviving_mutant() -> None:
    """The converse, over the family of single-cell perturbations.

    For any cell a suite does not witness, a policy that differs from the reference only
    there is non-equivalent and undetectable. Incomplete cell coverage therefore cannot
    yield a sound 100% score, whatever the syntactic operator set happens to generate.
    """

    reference = _reference()
    expectations = policy_mutation._suite_expectations(SUITES[1])
    witnessed = {(trust, action) for trust, action, _ in expectations}
    unwitnessed = [cell for cell in CELLS if cell not in witnessed]

    assert unwitnessed, "this suite is expected to leave cells unwitnessed"
    for cell in unwitnessed:
        for decision in DECISIONS:
            if decision == reference[cell]:
                continue
            perturbed = dict(reference)
            perturbed[cell] = decision

            assert perturbed != reference
            assert not _kills_map(expectations, perturbed), f"{cell} -> {decision}"


def test_the_decision_vector_kill_relation_agrees_with_the_harness() -> None:
    """Validates the helper the previous test relies on against the real implementation."""

    expectations = policy_mutation._suite_expectations(SUITES[0])
    _, live = _partition()

    for name, mutant in live.items():
        resolved = policy_mutation.decision_map(mutant)

        assert _kills_map(expectations, resolved) == policy_mutation._kills(expectations, mutant), (
            name
        )


# ---------------------------------------------------------------------------------------
# Corollary 5: expecting every decision class is necessary, not sufficient
# ---------------------------------------------------------------------------------------


def test_a_suite_can_expect_every_decision_class_and_still_be_blind() -> None:
    """This is the orthogonality witness stated arithmetically."""

    reference = _reference()
    by_decision: dict[str, Cell] = {}
    for cell in CELLS:
        by_decision.setdefault(reference[cell], cell)

    assert set(by_decision) == set(DECISIONS), "the policy must reach every decision"

    expectations = [(cell[0], cell[1], reference[cell]) for cell in by_decision.values()]
    witnessed = set(by_decision.values())
    unwitnessed = [cell for cell in CELLS if cell not in witnessed]

    assert {expected for _, _, expected in expectations} == set(DECISIONS)
    survivors = 0
    for cell in unwitnessed:
        for decision in DECISIONS:
            if decision == reference[cell]:
                continue
            perturbed = dict(reference)
            perturbed[cell] = decision
            if not _kills_map(expectations, perturbed):
                survivors += 1

    assert survivors > 0, "full decision-class coverage must not imply full detection"


# ---------------------------------------------------------------------------------------
# The fragment guard: the shipped policy is inside, and the harness refuses what is not
# ---------------------------------------------------------------------------------------


def test_the_shipped_policy_is_inside_the_fragment() -> None:
    assert policy_mutation.fragment_violations(_document()) == []


def test_a_guard_outside_the_enumerated_space_is_refused_rather_than_measured() -> None:
    """Exactness is a property of the fragment; outside it the score would be unsound."""

    document = _document()
    document["rules"][0]["source_data_classification_at_least"] = "confidential"

    assert policy_mutation.fragment_violations(document) == [
        "TW-001.source_data_classification_at_least"
    ]


def test_analyze_refuses_an_out_of_fragment_policy(tmp_path: Path) -> None:
    import json

    document = _document()
    document["rules"][0]["tool_capabilities"] = ["network"]
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SystemExit, match="outside the enumerated"):
        policy_mutation.analyze(path, [SUITES[0]])
