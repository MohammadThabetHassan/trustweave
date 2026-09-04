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
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "policy_mutation_theory", ROOT / "scripts" / "policy_mutation.py"
)
assert _spec and _spec.loader
policy_mutation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy_mutation)

from trustweave.models import parse_policy  # noqa: E402

POLICY = ROOT / "policies" / "default-policy.json"
SUITES = [
    ROOT / "scenarios" / "default-scenarios.json",
    ROOT / "scenarios" / "adversarial-scenarios.json",
    ROOT / "scenarios" / "coverage-matrix-scenarios.json",
]

DECISIONS = policy_mutation.DECISIONS


def _cells() -> tuple:
    return policy_mutation.cells(_document())


def _space() -> dict:
    return policy_mutation.witness_space(_document())


Expectation = tuple[tuple, str]


def _document() -> dict:
    return dict(policy_mutation.load_document(POLICY))


def _reference() -> dict[tuple, str]:
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


def _kills_map(expectations: list[Expectation], resolved: dict[tuple, str]) -> bool:
    """The kill relation stated over a decision vector rather than a policy document."""

    return any(resolved[cell] != expected for cell, expected in expectations)


def _exhaustive_suite(reference: dict[tuple, str]) -> list[Expectation]:
    return [(cell, reference[cell]) for cell in reference]


# ---------------------------------------------------------------------------------------
# Theorem 1: the fragment's behaviour is a total function over a finite subject space
# ---------------------------------------------------------------------------------------


def test_the_subject_space_is_the_product_of_the_label_domains() -> None:
    expected = set(itertools.product(policy_mutation.TRUST_LEVELS, policy_mutation.ACTION_CLASSES))
    partition = _cells()

    assert {(cell[0], cell[1]) for cell in partition} == expected
    assert len(partition) == 12, "this policy constrains nothing beyond trust and action"


def test_the_decision_vector_is_total_and_lands_in_the_decision_domain() -> None:
    """Totality is what the mandatory fail-closed default buys."""

    reference = _reference()

    assert set(reference) == set(_cells())
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
    expectations = policy_mutation._suite_expectations(suite_path, _space())
    witnessed = {cell for cell, _ in expectations}
    _, live = _partition()

    for name, mutant in live.items():
        resolved = policy_mutation.decision_map(mutant)
        delta = {cell for cell in reference if resolved[cell] != reference[cell]}

        assert policy_mutation._kills(expectations, mutant) == bool(delta & witnessed), name


@pytest.mark.parametrize("suite_path", SUITES, ids=lambda path: path.stem)
def test_the_suites_are_consistent_with_the_policy_they_test(suite_path: Path) -> None:
    """Theorem 3 assumes consistency; a suite contradicting its own policy fails first."""

    reference = _reference()

    for cell, expected in policy_mutation._suite_expectations(suite_path, _space()):
        assert reference[cell] == expected, str(cell)


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
    expectations = policy_mutation._suite_expectations(SUITES[1], _space())
    witnessed = {cell for cell, _ in expectations}
    unwitnessed = [cell for cell in reference if cell not in witnessed]

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

    expectations = policy_mutation._suite_expectations(SUITES[0], _space())
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
    by_decision: dict[str, tuple] = {}
    for cell in _cells():
        by_decision.setdefault(reference[cell], cell)

    assert set(by_decision) == set(DECISIONS), "the policy must reach every decision"

    expectations = [(cell, reference[cell]) for cell in by_decision.values()]
    witnessed = set(by_decision.values())
    unwitnessed = [cell for cell in _cells() if cell not in witnessed]

    assert {expected for _, expected in expectations} == set(DECISIONS)
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
# The quotient: an open subject space enumerated relative to the policy
# ---------------------------------------------------------------------------------------


def test_the_shipped_policy_constrains_nothing_beyond_trust_and_action() -> None:
    """Its 12 cells are the whole space, not a projection of a larger one."""

    space = _space()

    assert len(space["source_data_classification"]) == 1
    assert len(space["purpose_tags"]) == 1
    assert len(space["tool_capabilities"]) == 1
    assert len(_cells()) == 12


def _richer_policy() -> dict:
    document = _document()
    document["schema_version"] = "trustweave.dev/policy/v1alpha2"
    document["rules"][0]["source_data_classification_at_least"] = "confidential"
    document["rules"][1]["tool_capabilities"] = ["net.*", "fs.read"]
    document["rules"][2]["purpose_tags"] = ["support", "billing"]
    return document


def test_a_richer_guard_enlarges_the_quotient_rather_than_being_refused() -> None:
    """The point of T2: enumerate the attribute space instead of projecting it away."""

    space = policy_mutation.witness_space(_richer_policy())

    assert len(space["source_data_classification"]) == 5
    assert len(space["purpose_tags"]) == 4, "every subset of the two named tags"
    assert len(space["tool_capabilities"]) == 4, "every subset of the two named patterns"
    assert len(policy_mutation.cells(_richer_policy())) == 960


def test_a_wildcard_capability_pattern_gets_a_witness_that_matches_it() -> None:
    from trustweave.policy_predicates import capability_matches

    witnesses = {
        witness
        for subset in policy_mutation.witness_space(_richer_policy())["tool_capabilities"]
        for witness in subset
    }

    assert any(capability_matches("net.*", witness) for witness in witnesses)
    assert "fs.read" in witnesses


def test_the_decision_map_covers_every_class_of_a_richer_policy() -> None:
    document = _richer_policy()

    resolved = policy_mutation.decision_map(document)

    assert set(resolved) == set(policy_mutation.cells(document))
    assert set(resolved.values()) <= set(DECISIONS)


def test_a_quotient_too_large_to_enumerate_is_refused_not_sampled() -> None:
    """An exact score over a sampled subspace would not be exact."""

    document = _document()
    document["schema_version"] = "trustweave.dev/policy/v1alpha2"
    document["rules"][0]["purpose_tags"] = [f"tag{index}" for index in range(20)]

    with pytest.raises(SystemExit, match="above the"):
        policy_mutation.cells(document)


def test_a_scenario_attribute_is_placed_in_its_class_rather_than_ignored(tmp_path: Path) -> None:
    """A case declaring a classification is located in the space the policy is measured over."""

    import json

    document = _richer_policy()
    space = policy_mutation.witness_space(document)
    suite = dict(policy_mutation.load_document(SUITES[0]))
    scenario = dict(suite["scenarios"][0])
    scenario["source_data_classification"] = "restricted"
    suite["scenarios"] = [scenario]
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(suite), encoding="utf-8")

    ((cell, _expected),) = policy_mutation._suite_expectations(path, space)

    assert cell[2] == "restricted"


def test_two_cases_differing_only_in_classification_no_longer_collapse(tmp_path: Path) -> None:
    """Under the old projection both mapped to one cell and one was scored wrongly."""

    import json

    document = _richer_policy()
    space = policy_mutation.witness_space(document)
    suite = dict(policy_mutation.load_document(SUITES[0]))
    base = dict(suite["scenarios"][0])
    first = {**base, "id": "A", "source_data_classification": "public"}
    second = {**base, "id": "B", "source_data_classification": "restricted"}
    suite["scenarios"] = [first, second]
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(suite), encoding="utf-8")

    cells_used = {cell for cell, _ in policy_mutation._suite_expectations(path, space)}

    assert len(cells_used) == 2


# ---------------------------------------------------------------------------------------
# The worked example in the document must not go stale
# ---------------------------------------------------------------------------------------


def test_the_documented_worked_example_matches_a_fresh_run() -> None:
    """A hand-copied table in a proof document is a claim, and claims here are checked."""

    document = (ROOT / "docs" / "DECISION_CLASS_COVERAGE.md").read_text(encoding="utf-8")
    report = policy_mutation.analyze(POLICY, SUITES)
    live = report["mutants_live"]

    rows = {}
    for line in document.splitlines():
        if not line.startswith("| `") or "scenarios" not in line:
            continue
        cells = [part.strip().strip("`") for part in line.strip("|").split("|")]
        rows[f"{cells[0]}.json"] = cells[1:]

    assert set(rows) == {path.name for path in SUITES}, "documented suites drifted"
    for name, (cases, witnessed, killed, score, _missing) in rows.items():
        measured = report["suites"][name]

        assert cases == str(measured["cases"]), name
        assert witnessed == measured["cells_covered"], name
        assert killed == f"{measured['mutants_killed']}/{live}", name
        assert score == measured["mutation_score"], name


def test_the_documented_mutant_counts_match_a_fresh_run() -> None:
    report = policy_mutation.analyze(POLICY, SUITES)
    document = (ROOT / "docs" / "DECISION_CLASS_COVERAGE.md").read_text(encoding="utf-8")

    sentence = (
        f"{report['mutants_generated']} mutants are generated and "
        f"{report['mutants_equivalent']} are discarded as\nequivalent by Theorem 2, leaving "
        f"{report['mutants_live']} live."
    )

    assert sentence in document


def test_expected_decision_classes_are_the_image_of_the_witnessed_cells() -> None:
    """Corollary 5's premise: a consistent suite cannot expect a class the policy never gives.

    This is why a missing decision class is evidence of a gap only against a policy whose
    range includes that decision.
    """

    reference = _reference()
    for suite_path in SUITES:
        expectations = policy_mutation._suite_expectations(suite_path, _space())
        witnessed = {cell for cell, _ in expectations}
        expected = {decision for _, decision in expectations}

        assert expected == {reference[cell] for cell in witnessed}, suite_path.name


def test_a_policy_that_never_returns_a_decision_needs_no_case_expecting_it() -> None:
    """The range caveat, made concrete: full cell coverage of a two-valued policy.

    Such a suite detects every non-equivalent mutant while expecting only two of the three
    decision classes, so a bare 'missing decision class' report would flag it wrongly.
    """

    document = _document()
    for rule in document["rules"]:
        if rule["decision"] == "require_approval":
            rule["decision"] = "deny"
    if document["default_decision"] == "require_approval":
        document["default_decision"] = "deny"

    reference = policy_mutation.decision_map(document)
    exhaustive = _exhaustive_suite(reference)
    expected = {decision for _, decision in exhaustive}

    assert "require_approval" not in expected
    assert set(reference) == set(policy_mutation.cells(document))
    for name, mutant in policy_mutation._mutants(document):
        resolved = policy_mutation.decision_map(mutant)
        if resolved != reference:
            assert policy_mutation._kills(exhaustive, mutant), name


def test_section_cross_references_in_the_document_resolve() -> None:
    """Renumbering a proof document silently breaks its internal pointers."""

    import re

    document = (ROOT / "docs" / "DECISION_CLASS_COVERAGE.md").read_text(encoding="utf-8")
    headings = {int(match) for match in re.findall(r"^## (\d+)\.", document, re.MULTILINE)}
    referenced = {int(match) for match in re.findall(r"\bsection (\d+)\b", document, re.IGNORECASE)}

    assert headings, "the document must have numbered sections"
    assert referenced <= headings, f"dangling: {sorted(referenced - headings)}"


# ---------------------------------------------------------------------------------------
# Soundness of the quotient: a class witness decides exactly as its members do
# ---------------------------------------------------------------------------------------

TAXONOMY = ("public", "internal", "confidential", "restricted")
_NAMED_PURPOSES = ("support", "billing")
_NAMED_CAPABILITIES = ("fs.read", "net.egress", "net.deep.thing", "unrelated.capability")


def _decide_concretely(policy: Any, subject: tuple) -> str:
    """The engine's own first-match evaluation over an unabstracted subject."""

    return policy_mutation._decide(policy, subject)


@given(
    trust=st.sampled_from(policy_mutation.TRUST_LEVELS),
    action=st.sampled_from(policy_mutation.ACTION_CLASSES),
    classification=st.sampled_from((*TAXONOMY, "unspecified", "not-in-taxonomy")),
    source_identifier=st.sampled_from(("synthetic-source", "alice", "bob")),
    tool_identifier=st.sampled_from(("synthetic-tool", "mailer", "search")),
    purposes=st.lists(
        st.sampled_from((*_NAMED_PURPOSES, "unnamed-purpose")), max_size=3, unique=True
    ),
    capabilities=st.lists(st.sampled_from(_NAMED_CAPABILITIES), max_size=3, unique=True),
)
@settings(max_examples=250, deadline=None)
def test_a_subject_decides_exactly_as_its_class_witness_does(
    trust: str,
    action: str,
    classification: str,
    source_identifier: str,
    tool_identifier: str,
    purposes: list[str],
    capabilities: list[str],
) -> None:
    """The abstraction theorem, checked rather than asserted.

    The subject space is open: identifiers, purposes and capabilities are arbitrary strings.
    Every exactness claim rests on the quotient being *complete* -- that any subject decides
    the same as the single witness standing for its class. If that fails for even one
    subject, two policies could differ on a subject the enumeration never visits and be
    reported equivalent.
    """

    document = _richer_policy()
    policy = parse_policy(document)
    space = policy_mutation.witness_space(document)

    concrete = (
        trust,
        action,
        classification,
        source_identifier,
        tool_identifier,
        tuple(purposes),
        tuple(capabilities),
    )
    witness = policy_mutation.abstract_cell(
        space,
        trust,
        action,
        classification,
        source_identifier,
        tool_identifier,
        tuple(purposes),
        tuple(capabilities),
    )

    assert witness in policy_mutation.decision_map(document)
    assert _decide_concretely(policy, concrete) == policy_mutation._decide(policy, witness)


@given(
    capabilities=st.lists(
        st.sampled_from(("net.a", "net.b.c", "net.", "netx", "fs.read", "fs.readx")),
        max_size=3,
        unique=True,
    )
)
@settings(max_examples=120, deadline=None)
def test_capability_witnesses_reproduce_wildcard_matching(capabilities: list[str]) -> None:
    """`net.*` covers a namespace, so a single witness must stand for all of it."""

    document = _richer_policy()
    policy = parse_policy(document)
    space = policy_mutation.witness_space(document)
    concrete = (
        "trusted",
        "read",
        "unspecified",
        "synthetic-source",
        "synthetic-tool",
        (),
        tuple(capabilities),
    )
    witness = policy_mutation.abstract_cell(
        space,
        "trusted",
        "read",
        "unspecified",
        "synthetic-source",
        "synthetic-tool",
        (),
        tuple(capabilities),
    )

    assert policy_mutation._decide(policy, concrete) == policy_mutation._decide(policy, witness)
