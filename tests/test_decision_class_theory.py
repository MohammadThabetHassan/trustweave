"""Machine-checked verification of the results in the decision-class coverage write-up.

The exactness claims that document makes -- decidable equivalence, an exact kill criterion,
cell coverage deciding the mutation score -- are proved there over a restricted policy
fragment. A proof about a fragment is only useful if the shipped policy is in it and the
implementation agrees with the semantics, so these tests check both by exhaustive
enumeration over the real policy and the real mutant set rather than restating the theorems.
"""

from __future__ import annotations

import copy
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


def _research_document() -> Path:
    """The long-form theory write-up, which is deliberately not in this repository.

    It is the article in long form, and a public repository counts as prior dissemination
    for a journal submission, so it lives beside the manuscript instead. These checks are
    worth keeping -- a hand-copied table in a proof document is a claim like any other --
    so they follow it via TRUSTWEAVE_RESEARCH_DIR and skip when it is not set.
    """

    from os import environ

    directory = environ.get("TRUSTWEAVE_RESEARCH_DIR", "").strip()
    if directory:
        candidate = Path(directory) / "DECISION_CLASS_COVERAGE.md"
        if candidate.is_file():
            return candidate
    in_tree = ROOT / "docs" / "DECISION_CLASS_COVERAGE.md"
    if in_tree.is_file():
        return in_tree
    pytest.skip("set TRUSTWEAVE_RESEARCH_DIR to the directory holding DECISION_CLASS_COVERAGE.md")


def test_the_documented_worked_example_matches_a_fresh_run() -> None:
    """A hand-copied table in a proof document is a claim, and claims here are checked."""

    document = _research_document().read_text(encoding="utf-8")
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
    document = _research_document().read_text(encoding="utf-8")

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

    document = _research_document().read_text(encoding="utf-8")
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


# ---------------------------------------------------------------------------------------
# What the enumerated object is, and what it is not
# ---------------------------------------------------------------------------------------


def _policy_with(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """The shipped policy with its rule set replaced, on the schema that allows every field."""

    document = _document()
    document["schema_version"] = "trustweave.dev/policy/v1alpha2"
    document["rules"] = rules
    return document


def _rule(index: int, decision: str, **extra: Any) -> dict[str, Any]:
    rule = copy.deepcopy(_document()["rules"][0])
    rule.update(
        {
            "id": f"R-{index}",
            "decision": decision,
            "source_trust": ["trusted"],
            "tool_action_classes": ["read"],
        }
    )
    rule.update(extra)
    return rule


def _capability_signatures(document: dict[str, Any]) -> set[tuple[bool, ...]]:
    space = policy_mutation.witness_space(document)
    patterns = tuple(
        pattern for rule in document["rules"] for pattern in rule.get("tool_capabilities") or []
    )
    return {
        tuple(
            any(policy_mutation.capability_matches(pattern, capability) for capability in witness)
            for pattern in patterns
        )
        for witness in space["tool_capabilities"]
    }


def test_nested_capability_patterns_do_not_give_a_class_each() -> None:
    """Anything matching `net.http` matches `net.*`, so one of the four subsets cannot exist.

    Theorem 1's bound of `2^|K_P|` is an upper bound and stays true. The proof's claim that
    each subset "is witnessed" does not: the signature "matches `net.http` but not `net.*`"
    is occupied by no subject, and the subset `{net.http}` realises the same signature as
    `{net.*, net.http}`.
    """

    document = _policy_with(
        [
            _rule(1, "allow", tool_capabilities=["net.*"]),
            _rule(2, "deny", tool_capabilities=["net.http"]),
        ]
    )
    space = policy_mutation.witness_space(document)

    assert len(space["tool_capabilities"]) == 3
    assert (False, True) not in _capability_signatures(document)


def test_disjoint_capability_patterns_still_give_a_class_each() -> None:
    """The collapse must come from subsumption, not from deduplicating indiscriminately."""

    document = _policy_with(
        [
            _rule(1, "allow", tool_capabilities=["net.*"]),
            _rule(2, "deny", tool_capabilities=["fs.*"]),
        ]
    )

    assert len(policy_mutation.witness_space(document)["tool_capabilities"]) == 4
    assert len(_capability_signatures(document)) == 4


def test_every_enumerated_capability_class_has_a_distinct_signature() -> None:
    """One witness per signature, so no class is counted twice."""

    for patterns in (
        ["net.*", "net.http"],
        ["net.*", "net.http", "net.http.get"],
        ["net.*", "fs.*", "net.http"],
    ):
        document = _policy_with(
            [_rule(index, "allow", tool_capabilities=[p]) for index, p in enumerate(patterns)]
        )
        space = policy_mutation.witness_space(document)

        assert len(_capability_signatures(document)) == len(space["tool_capabilities"]), patterns


def test_the_enumerated_cells_are_a_refinement_of_the_quotient_not_the_quotient() -> None:
    """Distinct cells can answer every predicate identically, and then they are one class.

    A policy whose only purpose predicate is "intersects {a, b}" cannot tell `{a}` from
    `{a, b}`, so the enumeration splits one class of `~P` into several. Soundness holds over
    a refinement -- the decision is still constant on each cell, so Theorem 3 and Corollary
    4 carry over. What the refinement costs is the policy-level reading of necessity: no
    policy the language can express differs at one copy and not another.
    """

    document = _policy_with([_rule(1, "allow", purpose_tags=["a", "b"])])
    policy = parse_policy(document)
    enumerated = policy_mutation.cells(document)
    signatures = {policy_mutation.predicate_signature(policy, cell) for cell in enumerated}

    assert len(signatures) < len(enumerated), "expected the enumeration to refine ~P here"
    # The refinement is sound: cells sharing a signature share a decision.
    by_signature: dict[tuple[bool, ...], set[str]] = {}
    for cell in enumerated:
        signature = policy_mutation.predicate_signature(policy, cell)
        by_signature.setdefault(signature, set()).add(policy_mutation._decide(policy, cell))
    assert all(len(decisions) == 1 for decisions in by_signature.values())


def test_a_cell_decides_the_same_as_every_other_cell_of_its_class() -> None:
    """The property that makes the refinement usable, checked on the shipped policy."""

    policy = parse_policy(_document())
    grouped: dict[tuple[bool, ...], set[str]] = {}
    for cell in _cells():
        signature = policy_mutation.predicate_signature(policy, cell)
        grouped.setdefault(signature, set()).add(policy_mutation._decide(policy, cell))

    assert grouped
    assert all(len(decisions) == 1 for decisions in grouped.values())


def test_the_quotient_bound_charges_only_for_components_a_guard_reads() -> None:
    """Theorem 1's bound is a product of per-component counts, and this is why.

    The bound was first written with a term per component of the subject regardless of
    whether the policy mentioned it -- `(|I_P| + 2)` for source identifiers, and the
    classification taxonomy's size for classifications. On this policy, which constrains
    only trust and action, that reports 240 cells where there are 12. A bound off by a
    factor of twenty on the paper's own running example is not a bound worth stating, and
    the corrected form charges a factor of one for a component no guard reads.
    """

    document = _document()
    named = {
        "classifications": {
            value for rule in document["rules"] for value in rule.get("data_classifications") or []
        },
        "sources": {value for rule in document["rules"] for value in rule.get("source_ids") or []},
        "tools": {value for rule in document["rules"] for value in rule.get("tool_ids") or []},
        "purposes": {value for rule in document["rules"] for value in rule.get("purposes") or []},
        "capabilities": {
            value for rule in document["rules"] for value in rule.get("required_capabilities") or []
        },
    }
    assert all(not values for values in named.values()), named

    trust = {value for rule in document["rules"] for value in rule["source_trust"]}
    actions = {value for rule in document["rules"] for value in rule["tool_action_classes"]}

    # Both halves of the minimum are load-bearing on this policy: it names every trust
    # level, so that component is capped by its domain, and three of the four action
    # classes, so that one is capped by the distinctions it draws plus one for the rest.
    trust_domain, action_domain = 3, 4
    assert len(trust) == trust_domain and len(actions) == action_domain - 1

    corrected = min(trust_domain, len(trust) + 1) * min(action_domain, len(actions) + 1)
    for values in named.values():
        corrected *= 1 if not values else len(values) + 1

    assert corrected == len(_cells()) == 12

    # The shape that over-charged, kept here so the regression is named and not merely
    # avoided: a term for every component of the subject rather than every component the
    # policy reads -- a taxonomy factor and a "+2" on each identifier component.
    taxonomy_size = 4
    over_charged = trust_domain * action_domain * (taxonomy_size + 1) * 2 * 2
    assert over_charged == 240
    assert over_charged == 20 * corrected


def test_two_equivalent_widenings_turn_on_rule_order_not_on_the_default() -> None:
    """The paper's explanation of the equivalence rate, checked rather than asserted.

    Eleven of the sixteen equivalent mutants are equivalent because TW-003 and TW-004
    decide what the default already decides. Two are not, and the first version of that
    explanation missed them: they widen a rule onto the one cell that decides
    `require_approval`, and survive only because TW-002 precedes them and first-match
    prefers it. Separating the two mechanisms matters, because the second is a property of
    first-match and does not carry to an arbitrary combining function.
    """

    document = _document()
    default = document["default_decision"]
    rules = [
        (
            rule["id"],
            set(rule["source_trust"]),
            set(rule["tool_action_classes"]),
            rule["decision"],
        )
        for rule in document["rules"]
    ]
    trust_levels = sorted({level for _, levels, _, _ in rules for level in levels})
    actions = sorted({action for _, _, classes, _ in rules for action in classes})
    actions = sorted(set(actions) | {"write"})

    def decide(trust: str, action: str) -> str:
        for _, levels, classes, decision in rules:
            if trust in levels and action in classes:
                return decision
        return default

    base = {(t, a): decide(t, a) for t in trust_levels for a in actions}
    assert sorted(cell for cell, value in base.items() if value != default) == [
        ("conditional", "external"),
        ("trusted", "read"),
    ]

    # Every widening of a default-deciding rule, and whether it newly reaches a cell whose
    # decision differs from that rule's own.
    turns_on_order = []
    for identifier, levels, classes, decision in rules:
        if decision != default:
            continue
        widenings = [[(t, a) for t in levels] for a in actions if a not in classes]
        widenings += [[(t, a) for a in classes] for t in trust_levels if t not in levels]
        for newly in widenings:
            if any(base[cell] != decision for cell in newly):
                turns_on_order.append(identifier)

    assert sorted(turns_on_order) == ["TW-003", "TW-004"], turns_on_order
    assert len(turns_on_order) == 2

    # And both are equivalent anyway, because an earlier rule claims that cell.
    claiming = next(
        index
        for index, (_, levels, classes, _) in enumerate(rules)
        if "conditional" in levels and "external" in classes
    )
    for identifier in turns_on_order:
        position = next(i for i, rule in enumerate(rules) if rule[0] == identifier)
        assert claiming < position, (identifier, claiming, position)


def test_the_rules_are_pairwise_disjoint_which_is_what_makes_swaps_equivalent() -> None:
    """Under first-match, and only under first-match: an arbitrary combiner is not immune."""

    rules = [
        (rule["id"], set(rule["source_trust"]), set(rule["tool_action_classes"]))
        for rule in _document()["rules"]
    ]

    for (left, left_trust, left_actions), (right, right_trust, right_actions) in (
        (a, b) for i, a in enumerate(rules) for b in rules[i + 1 :]
    ):
        overlapping = (left_trust & right_trust) and (left_actions & right_actions)
        assert not overlapping, f"{left} and {right} can both match a subject"


# ---------------------------------------------------------------------------------------
# Tightness: equivalence is decidable exactly when occupancy is
# ---------------------------------------------------------------------------------------


def test_equivalence_can_be_decided_from_occupancy_without_any_witness() -> None:
    """The constructive half of the tightness theorem, run as an algorithm.

    The theorem's forward direction says deciding equivalence needs only *occupancy* --
    for each candidate outcome vector, whether any subject realises it -- and never needs a
    witness, because the decision on an occupied vector is computed from the syntax. If
    that is right, a procedure comparing decisions on occupied cells alone must agree with
    the harness's own equivalence verdicts on every mutant. It does, on all 38.

    This matters beyond tidiness. The results about *suites* do need witnesses, since a
    suite is a set of subjects and not a set of cells, and separating the two is what
    Theorem 23 and its remark are for.
    """

    document = _document()
    reference = policy_mutation.decision_map(document)

    def equivalent_by_occupancy(mutant: dict) -> bool:
        # `decision_map` is keyed on the occupied cells only, so iterating it is exactly
        # "compare where some subject exists" -- and no witness is read.
        other = policy_mutation.decision_map(mutant)
        return all(reference[cell] == other[cell] for cell in reference)

    equivalent, live = _partition()
    disagreements = []
    for name, mutant in policy_mutation._mutants(document):
        by_occupancy = equivalent_by_occupancy(mutant)
        by_harness = name in equivalent
        if by_occupancy != by_harness:
            disagreements.append((name, by_occupancy, by_harness))

    assert equivalent and live, "the operator set must produce both for this to test"
    assert disagreements == [], disagreements


def test_the_finite_image_clause_is_free_for_finitely_many_outcomes() -> None:
    """Lemma 20: the first clause of the definition does no work in any real language.

    A guard reporting values in a finite V gives an outcome map into V^n, which is finite
    whatever the guards are -- including the halting guard of the undecidability theorem.
    So the definition's content is entirely its second clause, about witnesses, and a
    reading that treats finiteness as the substance has the theorem backwards.
    """

    import itertools

    for outcomes in (2, 3, 4):
        for arity in (1, 2, 3):
            values = list(range(outcomes))
            image = set(itertools.product(values, repeat=arity))
            assert len(image) == outcomes**arity < float("inf")

    # The halting guard: finite image, and the definition still excludes it, which is only
    # possible because the exclusion comes from the second clause.
    def halting_guard(steps_before_halt: int | None, subject_length: int) -> int:
        if steps_before_halt is None:
            return 0
        return 1 if steps_before_halt <= subject_length else 0

    realised = {halting_guard(None, n) for n in range(50)}
    assert realised == {0}, "a machine that never halts occupies only one class"
    realised = {halting_guard(7, n) for n in range(50)}
    assert realised == {0, 1}, "one that halts occupies both"
    # Which class a subject falls in is computable; *whether the true class is occupied at
    # all* is the halting question, and that is what the second clause asks for.
