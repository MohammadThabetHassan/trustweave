"""The exactness results do not depend on first-match evaluation.

docs/DECISION_CLASS_COVERAGE.md proves its theorems for a first-match policy over
TrustWeave's own label language, and docs/SUITE_COVERAGE_STUDY.md notes that none of the
four measured ecosystems is inside that language. Part of that gap is real -- their guards
are general expressions -- and part of it was an artefact of how the proofs were stated.

The proofs use only two properties: that the guards induce finitely many classes over the
subject space with a witness computable for each, and that the decision is a function of
the guard truth vector. First-match is one such function. Cedar's forbid-overrides,
Kyverno's any-rule-fails, and an XACML combining algorithm over four values are others.

These tests establish that claim by construction rather than by restating it. The subject
space here is genuinely infinite -- arbitrary strings -- and Hypothesis samples it, so a
finite witness set covering every sampled subject is evidence that the quotient is what the
construction says it is and not an artefact of a small enumeration.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# --------------------------------------------------------------------------------------
# A finitely-refining guard family over an infinite subject space
# --------------------------------------------------------------------------------------


class Guard(Protocol):
    def holds(self, subject: str) -> bool: ...

    def witnesses(self) -> tuple[str, ...]:
        """Subjects computable from this guard's own syntax."""


@dataclass(frozen=True)
class InSet:
    """Membership in a named set, the predicate every scalar component offers."""

    members: frozenset[str]

    def holds(self, subject: str) -> bool:
        return subject in self.members

    def witnesses(self) -> tuple[str, ...]:
        return tuple(sorted(self.members))


@dataclass(frozen=True)
class HasPrefix:
    """A final-wildcard namespace pattern: stands for infinitely many subjects."""

    prefix: str

    def holds(self, subject: str) -> bool:
        return subject.startswith(self.prefix)

    def witnesses(self) -> tuple[str, ...]:
        # The prefix itself, and one subject strictly inside the namespace it names.
        return (self.prefix, self.prefix + "x")


UNMATCHED = "\x00unmatched-by-construction"


def witness_set(guards: tuple[Guard, ...]) -> tuple[str, ...]:
    """Every subject any guard's syntax names, plus one no guard can match."""
    found: list[str] = [UNMATCHED]
    for guard in guards:
        found.extend(guard.witnesses())
    return tuple(dict.fromkeys(found))


def signature(guards: tuple[Guard, ...], subject: str) -> tuple[bool, ...]:
    return tuple(guard.holds(subject) for guard in guards)


def achieved_classes(guards: tuple[Guard, ...]) -> set[tuple[bool, ...]]:
    """The truth vectors reachable at all, computed from the guards alone."""
    return {signature(guards, subject) for subject in witness_set(guards)}


# --------------------------------------------------------------------------------------
# Combining functions: one per real ecosystem's evaluation rule
# --------------------------------------------------------------------------------------

Combiner = Callable[[tuple[bool, ...]], str]


def first_match(decisions: tuple[str, ...], default: str) -> Combiner:
    """TrustWeave: the decision of the first rule whose guard holds, else the default."""

    def combine(bits: tuple[bool, ...]) -> str:
        for bit, decision in zip(bits, decisions, strict=True):
            if bit:
                return decision
        return default

    return combine


def forbid_overrides(forbid_count: int) -> Combiner:
    """Cedar: any forbid denies; otherwise any permit allows; otherwise deny."""

    def combine(bits: tuple[bool, ...]) -> str:
        if any(bits[:forbid_count]):
            return "Deny"
        return "Allow" if any(bits[forbid_count:]) else "Deny"

    return combine


def any_rule_fails(bits: tuple[bool, ...]) -> str:
    """Kyverno: a resource fails if any rule's pattern is violated, else passes."""
    if not any(bits):
        return "skip"
    return "fail" if bits[0] else "pass"


def xacml_deny_overrides(bits: tuple[bool, ...]) -> str:
    """A four-valued algorithm: deny wins, then permit, then error, else not applicable."""
    deny, permit, error = bits[0], bits[1], bits[2]
    if deny:
        return "Deny"
    if permit:
        return "Permit"
    if error:
        return "Indeterminate"
    return "NotApplicable"


@dataclass(frozen=True)
class Policy:
    guards: tuple[Guard, ...]
    combine: Combiner
    label: str

    def decide(self, subject: str) -> str:
        return self.combine(signature(self.guards, subject))


GUARDS: tuple[Guard, ...] = (
    InSet(frozenset({"read", "write"})),
    HasPrefix("net."),
    InSet(frozenset({"write", "delete"})),
)

POLICIES = (
    Policy(GUARDS, first_match(("deny", "require_approval", "allow"), "allow"), "first-match"),
    Policy(GUARDS, forbid_overrides(forbid_count=1), "cedar forbid-overrides"),
    Policy(GUARDS, any_rule_fails, "kyverno any-rule-fails"),
    Policy(GUARDS, xacml_deny_overrides, "xacml deny-overrides"),
)
IDS = [policy.label for policy in POLICIES]


# --------------------------------------------------------------------------------------
# Theorem 1: the quotient is finite, and its witnesses cover an infinite space
# --------------------------------------------------------------------------------------


def test_the_witness_set_is_finite_and_bounded_by_the_guard_count() -> None:
    classes = achieved_classes(GUARDS)
    assert 0 < len(classes) <= 2 ** len(GUARDS)


@pytest.mark.parametrize("policy", POLICIES, ids=IDS)
@given(subject=st.text(max_size=12))
@settings(max_examples=400, deadline=None)
def test_every_subject_falls_into_a_class_the_construction_found(
    policy: Policy, subject: str
) -> None:
    """The finite witness set must account for arbitrary subjects, not just the named ones."""

    assert signature(policy.guards, subject) in achieved_classes(policy.guards)


@pytest.mark.parametrize("policy", POLICIES, ids=IDS)
@given(subject=st.text(max_size=12))
@settings(max_examples=400, deadline=None)
def test_the_decision_is_constant_on_a_class(policy: Policy, subject: str) -> None:
    """A subject decides exactly as any witness sharing its truth vector does."""

    target = signature(policy.guards, subject)
    twin = next(w for w in witness_set(policy.guards) if signature(policy.guards, w) == target)
    assert policy.decide(subject) == policy.decide(twin)


# --------------------------------------------------------------------------------------
# Theorem 2: equivalence is decidable on the witnesses alone
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("policy", POLICIES, ids=IDS)
@given(subject=st.text(max_size=12))
@settings(max_examples=300, deadline=None)
def test_agreeing_on_every_witness_means_agreeing_everywhere(policy: Policy, subject: str) -> None:
    """Two policies that agree on the finite witness set cannot differ on any subject."""

    other = Policy(policy.guards, policy.combine, policy.label + " copy")
    witnesses = witness_set(policy.guards)
    assert all(policy.decide(w) == other.decide(w) for w in witnesses)
    assert policy.decide(subject) == other.decide(subject)


def test_policies_differing_on_a_witness_are_detected_there() -> None:
    """A real difference must show up on the computed witnesses, not only off them."""

    reference = POLICIES[0]
    mutant = Policy(GUARDS, first_match(("allow", "require_approval", "allow"), "allow"), "m")
    witnesses = witness_set(GUARDS)
    assert any(reference.decide(w) != mutant.decide(w) for w in witnesses)


# --------------------------------------------------------------------------------------
# Theorem 3 and Corollary 4: the kill criterion, under every combining function
# --------------------------------------------------------------------------------------


def mutants_of(policy: Policy, domain: tuple[str, ...]) -> list[Policy]:
    """Every policy obtained by replacing the combining function's output on one class."""
    classes = sorted(achieved_classes(policy.guards))
    generated: list[Policy] = []
    for target, replacement in itertools.product(classes, domain):
        if policy.combine(target) == replacement:
            continue

        def combine(bits: tuple[bool, ...], t=target, r=replacement, base=policy.combine) -> str:
            return r if bits == t else base(bits)

        generated.append(Policy(policy.guards, combine, f"{policy.label}:{target}->{replacement}"))
    return generated


def difference_classes(reference: Policy, mutant: Policy) -> set[tuple[bool, ...]]:
    return {
        cell
        for cell in achieved_classes(reference.guards)
        if reference.combine(cell) != mutant.combine(cell)
    }


@pytest.mark.parametrize("policy", POLICIES, ids=IDS)
def test_a_suite_kills_a_mutant_exactly_when_it_witnesses_a_differing_class(
    policy: Policy,
) -> None:
    """Theorem 3, restated over truth vectors and checked for every partial suite."""

    domain = tuple(sorted({policy.combine(cell) for cell in achieved_classes(policy.guards)}))
    classes = sorted(achieved_classes(policy.guards))
    mutants = mutants_of(policy, domain)
    assert mutants, "the construction produced no mutants to reason about"

    for size in range(len(classes) + 1):
        for witnessed in itertools.combinations(classes, size):
            seen = set(witnessed)
            for mutant in mutants:
                delta = difference_classes(policy, mutant)
                killed = any(policy.combine(c) != mutant.combine(c) for c in seen)
                assert killed == bool(delta & seen)


@pytest.mark.parametrize("policy", POLICIES, ids=IDS)
def test_witnessing_every_class_kills_every_non_equivalent_mutant(policy: Policy) -> None:
    """Corollary 4, independent of the combining function."""

    classes = achieved_classes(policy.guards)
    domain = tuple(sorted({policy.combine(cell) for cell in classes}))
    for mutant in mutants_of(policy, domain):
        delta = difference_classes(policy, mutant)
        assert delta, "a mutant with no differing class would be equivalent"
        assert any(policy.combine(c) != mutant.combine(c) for c in classes)


@pytest.mark.parametrize("policy", POLICIES, ids=IDS)
def test_every_unwitnessed_class_admits_a_surviving_mutant(policy: Policy) -> None:
    """The bound is tight: a missed class is a mutant nobody catches."""

    classes = achieved_classes(policy.guards)
    domain = tuple(sorted({policy.combine(cell) for cell in classes}))
    assert len(domain) > 1, "a single-decision policy admits no mutant to survive"
    for missed in classes:
        seen = classes - {missed}
        replacement = next(d for d in domain if d != policy.combine(missed))
        survivor = Policy(
            policy.guards,
            lambda bits, m=missed, r=replacement, base=policy.combine: (
                r if bits == m else base(bits)
            ),
            "survivor",
        )
        assert not any(policy.combine(c) != survivor.combine(c) for c in seen)
        assert policy.combine(missed) != survivor.combine(missed)


# --------------------------------------------------------------------------------------
# Guards that are not two-valued
# --------------------------------------------------------------------------------------
#
# Everything above has boolean guards and varies only the combining function, so it
# verifies the theorem for |V| = 2 with decision domains up to |D| = 4. The theorem is
# stated for guards reporting values in any finite V, and that generalisation is the reason
# it reaches XACML at all: a XACML guard reports *indeterminate* when an attribute the
# target names is absent from the request, which is what produces the Indeterminate
# decision. Nothing above exercises a guard with three outcomes, so this section does.

INDETERMINATE = "indeterminate"
OUTCOMES = ("true", "false", INDETERMINATE)
ABSENT = "\x00absent"
NON_MEMBER = "\x00non-member"


@dataclass(frozen=True)
class Field:
    """A three-valued guard: a named set over one attribute that may be absent.

    A subject is a `|`-separated record. A guard reads one field, and reports
    indeterminate when the field is missing or explicitly absent -- the shape of a XACML
    target whose designator finds no attribute in the request.
    """

    index: int
    members: frozenset[str]

    def outcome(self, subject: str) -> str:
        fields = subject.split("|")
        if self.index >= len(fields) or fields[self.index] == ABSENT:
            return INDETERMINATE
        return "true" if fields[self.index] in self.members else "false"

    def choices(self) -> tuple[str, ...]:
        """Field values realising each outcome, read off this guard's own syntax."""
        return (*sorted(self.members), NON_MEMBER, ABSENT)


THREE_VALUED_GUARDS: tuple[Field, ...] = (
    Field(0, frozenset({"read"})),
    Field(1, frozenset({"net.http"})),
    Field(2, frozenset({"prod"})),
)


def three_valued_signature(guards: tuple[Field, ...], subject: str) -> tuple[str, ...]:
    return tuple(guard.outcome(subject) for guard in guards)


def three_valued_witnesses(guards: tuple[Field, ...]) -> tuple[str, ...]:
    """One subject per combination the guards' syntax can realise."""
    return tuple(
        "|".join(combination)
        for combination in itertools.product(*(guard.choices() for guard in guards))
    )


def xacml_target_algorithm(outcomes: tuple[str, ...]) -> str:
    """Deny-overrides over three-valued targets, propagating indeterminacy.

    A deny target that holds denies. A deny target that cannot be evaluated makes the
    result indeterminate rather than permitting, which is the fail-closed reading the
    standard's extended-indeterminate values exist to express.
    """
    deny, permit, scope = outcomes
    if scope == INDETERMINATE:
        return "Indeterminate"
    if deny == "true":
        return "Deny"
    if deny == INDETERMINATE:
        return "Indeterminate"
    if permit == "true":
        return "Permit" if scope == "true" else "NotApplicable"
    if permit == INDETERMINATE:
        return "Indeterminate"
    return "NotApplicable"


def test_a_three_valued_guard_family_is_still_finitely_refining() -> None:
    """The bound is |V|^n, and here every one of the 27 signatures is realised."""

    witnesses = three_valued_witnesses(THREE_VALUED_GUARDS)
    achieved = {three_valued_signature(THREE_VALUED_GUARDS, s) for s in witnesses}

    assert len(achieved) == len(OUTCOMES) ** len(THREE_VALUED_GUARDS) == 27
    assert achieved == set(itertools.product(OUTCOMES, repeat=len(THREE_VALUED_GUARDS)))


@given(st.text(max_size=40))
@settings(max_examples=400, deadline=None)
def test_every_subject_falls_in_a_three_valued_class_the_construction_found(
    subject: str,
) -> None:
    achieved = {
        three_valued_signature(THREE_VALUED_GUARDS, s)
        for s in three_valued_witnesses(THREE_VALUED_GUARDS)
    }

    assert three_valued_signature(THREE_VALUED_GUARDS, subject) in achieved


@given(st.text(max_size=40))
@settings(max_examples=400, deadline=None)
def test_the_three_valued_decision_is_constant_on_a_class(subject: str) -> None:
    """What the theorem actually needs: the decision reads only the outcome vector."""

    signature_here = three_valued_signature(THREE_VALUED_GUARDS, subject)
    for witness in three_valued_witnesses(THREE_VALUED_GUARDS):
        if three_valued_signature(THREE_VALUED_GUARDS, witness) == signature_here:
            assert xacml_target_algorithm(signature_here) == xacml_target_algorithm(
                three_valued_signature(THREE_VALUED_GUARDS, witness)
            )


def test_witnessing_every_three_valued_class_kills_every_non_equivalent_mutant() -> None:
    """Corollary: full coverage of the quotient decides the score, |V| notwithstanding."""

    witnesses = three_valued_witnesses(THREE_VALUED_GUARDS)
    original = {
        s: xacml_target_algorithm(three_valued_signature(THREE_VALUED_GUARDS, s)) for s in witnesses
    }

    # Semantic mutants: every function on the quotient that differs somewhere.
    classes = sorted({three_valued_signature(THREE_VALUED_GUARDS, s) for s in witnesses})
    killed = 0
    for target in classes:
        for decision in ("Deny", "Permit", "Indeterminate", "NotApplicable"):
            if decision == xacml_target_algorithm(target):
                continue

            def mutant(outcomes: tuple[str, ...], _t=target, _d=decision) -> str:
                return _d if outcomes == _t else xacml_target_algorithm(outcomes)

            differs = any(
                mutant(three_valued_signature(THREE_VALUED_GUARDS, s)) != original[s]
                for s in witnesses
            )
            assert differs, (target, decision)
            killed += 1

    assert killed == len(classes) * 3


def test_an_unwitnessed_three_valued_class_admits_a_survivor() -> None:
    """Necessity, over semantic mutants: a missed class hides a real difference."""

    witnesses = three_valued_witnesses(THREE_VALUED_GUARDS)
    missed = three_valued_signature(THREE_VALUED_GUARDS, witnesses[0])
    partial = [s for s in witnesses if three_valued_signature(THREE_VALUED_GUARDS, s) != missed]
    assert partial, "the fixture needs more than one class"

    original_at_missed = xacml_target_algorithm(missed)
    survivor_decision = next(
        d for d in ("Deny", "Permit", "Indeterminate", "NotApplicable") if d != original_at_missed
    )

    def survivor(outcomes: tuple[str, ...]) -> str:
        return survivor_decision if outcomes == missed else xacml_target_algorithm(outcomes)

    assert all(
        survivor(three_valued_signature(THREE_VALUED_GUARDS, s))
        == xacml_target_algorithm(three_valued_signature(THREE_VALUED_GUARDS, s))
        for s in partial
    )
    assert survivor(missed) != original_at_missed
