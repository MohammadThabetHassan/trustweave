"""Measure what a scenario suite can actually detect about a policy.

A scenario suite is usually judged by how many cases it holds. That number says nothing
about what the suite would notice if the policy changed. This script answers the useful
question directly: mutate the policy in every single-edit way that matters, discard the
mutants that are provably indistinguishable, and report how many of the rest each suite
catches.

Two properties make the answer exact rather than estimated.

A policy over a finite label domain induces a finite partition of its subject space -- here
the product of trust levels and action classes. Every mutant is therefore fully described
by the decision it returns for each cell, so two mutants that agree on every cell are
equivalent by construction. That removes the equivalent-mutant problem that otherwise
forces manual inspection or approximation.

Decision-class coverage follows from the same partition. A suite that never expects a given
decision cannot distinguish a policy that returns it from one that does not, no matter how
many cases the suite contains.

Run: python scripts/policy_mutation.py --policy policies/default-policy.json \\
         --scenarios scenarios/default-scenarios.json scenarios/adversarial-scenarios.json
"""

from __future__ import annotations

import argparse
import copy
import itertools
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trustweave.io import load_document  # noqa: E402
from trustweave.models import DEFAULT_CLASSIFICATION_TAXONOMY, parse_policy  # noqa: E402
from trustweave.policy_predicates import (  # noqa: E402
    PolicySubject,
    capability_matches,
    declared_controls,
    rule_matches,
)
from trustweave.scenarios import parse_scenarios  # noqa: E402

TRUST_LEVELS = ("trusted", "conditional", "untrusted")
ACTION_CLASSES = ("read", "write", "sensitive", "external")
DECISIONS = ("allow", "deny", "require_approval")

# One witness value for anything a policy does not name. Membership predicates compare
# exact strings, so every unnamed value behaves identically and one representative suffices.
OUTSIDER = "trustweave-witness-outsider"
UNSPECIFIED_CLASSIFICATION = "unspecified"
DEFAULT_SOURCE_IDENTIFIER = "synthetic-source"
DEFAULT_TOOL_IDENTIFIER = "synthetic-tool"

# The order a cell's components appear in. A cell is one class of the quotient below.
ATTRIBUTES = (
    "source_trust",
    "tool_action_class",
    "source_data_classification",
    "source_identifier",
    "tool_identifier",
    "purpose_tags",
    "tool_capabilities",
)

# The quotient is a product, so it grows multiplicatively in the number of distinct purpose
# tags and capability patterns a policy names. Refusing a policy too large to enumerate is
# honest; reporting an exact score over a sampled subspace would not be.
MAX_CELLS = 200_000

Cell = tuple[str, str, str, str, str, tuple[str, ...], tuple[str, ...]]


def _named_by_rules(rules: list[dict[str, Any]], field: str) -> tuple[str, ...]:
    values = {value for rule in rules for value in rule.get(field) or () if isinstance(value, str)}
    return tuple(sorted(values))


def _capability_witness(pattern: str) -> str:
    """A capability that matches this pattern and nothing narrower."""

    return pattern[:-1] + OUTSIDER if pattern.endswith(".*") else pattern


def _subsets(values: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return tuple(
        combination
        for size in range(len(values) + 1)
        for combination in itertools.combinations(values, size)
    )


def witness_space(document: dict[str, Any]) -> dict[str, tuple[Any, ...]]:
    """One representative per equivalence class of subjects, per attribute.

    The subject space is not finite: identifiers, purposes and capabilities are arbitrary
    strings. It is finite *relative to a policy*, because every predicate the language
    offers tests membership in a set the policy names, an ordering over a declared taxonomy,
    or a namespace pattern the policy names. Subjects agreeing on all of those match exactly
    the same rules, so one witness per class is enough to observe the policy completely.

    Returned per attribute:

    trust, action           the full label domains
    classification          the taxonomy plus any named value, but only when some rule
                            constrains classification at all; otherwise one value
    identifiers             each named value, the default, and one outsider
    purpose tags            every subset of the named tags, since matching is intersection
    capabilities            every subset of the named patterns, witnessed by a capability
                            matching each, since matching is existential over the pair
    """

    rules = [rule for rule in document.get("rules") or [] if isinstance(rule, dict)]
    taxonomy = tuple(document.get("classification_taxonomy") or DEFAULT_CLASSIFICATION_TAXONOMY)

    named_classifications = _named_by_rules(rules, "source_data_classifications")
    bounded = any(
        rule.get("source_data_classification_at_least")
        or rule.get("source_data_classification_at_most")
        for rule in rules
    )
    if named_classifications or bounded:
        classifications = tuple(
            dict.fromkeys((*taxonomy, *named_classifications, UNSPECIFIED_CLASSIFICATION))
        )
    else:
        classifications = (UNSPECIFIED_CLASSIFICATION,)

    def identifiers(field: str, default: str) -> tuple[str, ...]:
        named = _named_by_rules(rules, field)
        return tuple(dict.fromkeys((default, *named, OUTSIDER))) if named else (default,)

    patterns = _named_by_rules(rules, "tool_capabilities")
    return {
        "source_trust": TRUST_LEVELS,
        "tool_action_class": ACTION_CLASSES,
        "source_data_classification": classifications,
        "source_identifier": identifiers("source_identifiers", DEFAULT_SOURCE_IDENTIFIER),
        "tool_identifier": identifiers("tool_identifiers", DEFAULT_TOOL_IDENTIFIER),
        "purpose_tags": _subsets(_named_by_rules(rules, "purpose_tags")),
        "tool_capabilities": tuple(
            tuple(_capability_witness(pattern) for pattern in subset)
            for subset in _subsets(patterns)
        ),
    }


def cells(document: dict[str, Any]) -> tuple[Cell, ...]:
    """Every class of the quotient, in deterministic order."""

    space = witness_space(document)
    total = 1
    for attribute in ATTRIBUTES:
        total *= len(space[attribute])
    if total > MAX_CELLS:
        raise SystemExit(
            f"policy induces {total} subject classes, above the {MAX_CELLS} this harness will "
            "enumerate; an exact score cannot be computed without enumerating all of them"
        )
    return tuple(itertools.product(*(space[attribute] for attribute in ATTRIBUTES)))


def abstract_cell(
    space: dict[str, tuple[Any, ...]],
    source_trust: str,
    tool_action_class: str,
    source_data_classification: str | None = None,
    source_identifier: str | None = None,
    tool_identifier: str | None = None,
    purpose_tags: tuple[str, ...] = (),
    tool_capabilities: tuple[str, ...] = (),
) -> Cell:
    """Place one concrete subject in its class, so a test case can be located in the quotient."""

    def represent(attribute: str, value: str | None, default: str) -> str:
        witnesses = space[attribute]
        if value is None:
            return default if default in witnesses else witnesses[0]
        if value in witnesses:
            return value
        return OUTSIDER if OUTSIDER in witnesses else witnesses[0]

    named_purposes = {tag for subset in space["purpose_tags"] for tag in subset}
    purposes = tuple(sorted(set(purpose_tags) & named_purposes))

    witnessed_capabilities = {
        witness for subset in space["tool_capabilities"] for witness in subset
    }
    hit = {
        witness
        for witness in witnessed_capabilities
        for capability in tool_capabilities
        if capability_matches(_pattern_of(witness), capability)
    }
    return (
        source_trust,
        tool_action_class,
        represent(
            "source_data_classification", source_data_classification, UNSPECIFIED_CLASSIFICATION
        ),
        represent("source_identifier", source_identifier, DEFAULT_SOURCE_IDENTIFIER),
        represent("tool_identifier", tool_identifier, DEFAULT_TOOL_IDENTIFIER),
        purposes,
        tuple(sorted(hit)),
    )


def _pattern_of(witness: str) -> str:
    """Recover the pattern a capability witness stands for."""

    return witness[: -len(OUTSIDER)] + "*" if witness.endswith(OUTSIDER) else witness


def _decide(policy: Any, cell: Cell) -> str:
    """First-match evaluation over one class witness, using the engine's own predicates."""

    subject = PolicySubject(
        source_trust=cell[0],
        tool_action_class=cell[1],
        source_data_classification=cell[2],
        source_identifier=cell[3],
        tool_identifier=cell[4],
        purpose_tags=cell[5],
        tool_capabilities=cell[6],
        declared_controls=declared_controls(policy),
    )
    for rule in policy.rules:
        if rule_matches(rule, subject, policy):
            return str(rule.decision)
    return str(policy.default_decision)


def decision_map(document: dict[str, Any]) -> dict[Cell, str]:
    """The decision this policy gives for every class of its subject space.

    This is the policy's complete observable behaviour: two policies with the same map
    cannot be told apart by any subject the language can express, not merely by any subject
    the scenario format happens to supply.
    """

    policy = parse_policy(document)
    return {cell: _decide(policy, cell) for cell in cells(document)}


# ---------------------------------------------------------------------------------------
# Mutation operators. Each yields (name, mutated document).
# ---------------------------------------------------------------------------------------


def _mutants(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    generated: list[tuple[str, dict[str, Any]]] = []
    rules = document.get("rules", [])

    for index, rule in enumerate(rules):
        identifier = rule.get("id", f"rule{index}")

        removed = copy.deepcopy(document)
        del removed["rules"][index]
        generated.append((f"delete_rule[{identifier}]", removed))

        for decision in DECISIONS:
            if decision == rule.get("decision"):
                continue
            flipped = copy.deepcopy(document)
            flipped["rules"][index]["decision"] = decision
            generated.append((f"flip_decision[{identifier}->{decision}]", flipped))

        for trust in TRUST_LEVELS:
            if trust in rule.get("source_trust", []):
                continue
            widened = copy.deepcopy(document)
            widened["rules"][index]["source_trust"] = [*rule["source_trust"], trust]
            generated.append((f"widen_trust[{identifier}+{trust}]", widened))

        for trust in rule.get("source_trust", []):
            if len(rule["source_trust"]) == 1:
                continue
            narrowed = copy.deepcopy(document)
            narrowed["rules"][index]["source_trust"] = [
                value for value in rule["source_trust"] if value != trust
            ]
            generated.append((f"narrow_trust[{identifier}-{trust}]", narrowed))

        for action in ACTION_CLASSES:
            if action in rule.get("tool_action_classes", []):
                continue
            widened = copy.deepcopy(document)
            widened["rules"][index]["tool_action_classes"] = [
                *rule["tool_action_classes"],
                action,
            ]
            generated.append((f"widen_action[{identifier}+{action}]", widened))

        for action in rule.get("tool_action_classes", []):
            if len(rule["tool_action_classes"]) == 1:
                continue
            narrowed = copy.deepcopy(document)
            narrowed["rules"][index]["tool_action_classes"] = [
                value for value in rule["tool_action_classes"] if value != action
            ]
            generated.append((f"narrow_action[{identifier}-{action}]", narrowed))

    for decision in DECISIONS:
        if decision == document.get("default_decision"):
            continue
        changed = copy.deepcopy(document)
        changed["default_decision"] = decision
        generated.append((f"default_decision[->{decision}]", changed))

    # Rule order is load-bearing under first-match semantics.
    for index in range(len(rules) - 1):
        swapped = copy.deepcopy(document)
        swapped["rules"][index], swapped["rules"][index + 1] = (
            swapped["rules"][index + 1],
            swapped["rules"][index],
        )
        left = rules[index].get("id", index)
        right = rules[index + 1].get("id", index + 1)
        generated.append((f"swap_rules[{left}<->{right}]", swapped))

    return generated


# Scenario fields the enumerated subject space does not range over. `decision_map` evaluates
# every cell with no classification, no capabilities, and the default identifiers and
# purpose, so a scenario that sets any of them is evaluated as something other than what it
# declares -- and two scenarios differing only there collapse onto one cell.
def _suite_expectations(path: Path, space: dict[str, tuple[Any, ...]]) -> list[tuple[Cell, str]]:
    """Place each case of one suite in the quotient, with the decision it expects.

    A scenario may declare a classification, capabilities, identifiers and a purpose tag.
    Each is mapped to the class its value belongs to, so a case is located in the same
    space the policy is enumerated over rather than projected onto trust and action.
    """

    located = []
    for scenario in parse_scenarios(load_document(path)):
        cell = abstract_cell(
            space,
            scenario.source_trust,
            scenario.tool_action_class,
            scenario.source_data_classification,
            scenario.source_identifier,
            scenario.tool_identifier,
            (scenario.purpose_tag,) if scenario.purpose_tag else (),
            scenario.tool_capabilities,
        )
        located.append((cell, scenario.expected_decision))
    return located


def _kills(expectations: list[tuple[Cell, str]], mutant: dict[str, Any]) -> bool:
    """A suite kills a mutant when any of its cases would now fail."""

    resolved = decision_map(mutant)
    return any(resolved[cell] != expected for cell, expected in expectations)


def analyze(policy_path: Path, suite_paths: list[Path]) -> dict[str, Any]:
    document = dict(load_document(policy_path))
    space = witness_space(document)
    partition = cells(document)
    reference = decision_map(document)

    generated = _mutants(document)
    live: list[tuple[str, dict[str, Any]]] = []
    equivalent: list[str] = []
    for name, mutant in generated:
        # A mutant that named a value the reference does not would be observed over a
        # different quotient, so its map would not be comparable. The operator set only
        # edits rule order, decisions and the two closed label domains, so this holds; it
        # is checked rather than assumed.
        if witness_space(mutant) != space:
            raise SystemExit(f"mutant {name} changed the subject quotient")
        try:
            resolved = decision_map(mutant)
        except Exception:  # noqa: BLE001 - an unparseable mutant is not a policy
            equivalent.append(name)
            continue
        if resolved == reference:
            # Indistinguishable from the original for every subject in the domain.
            equivalent.append(name)
            continue
        live.append((name, mutant))

    suites: dict[str, Any] = {}
    for suite_path in suite_paths:
        expectations = _suite_expectations(suite_path, space)
        witnessed = {cell for cell, _ in expectations}
        expected_decisions = {expected for _, expected in expectations}
        killed = [name for name, mutant in live if _kills(expectations, mutant)]
        survivors = [name for name, _ in live if name not in set(killed)]
        suites[suite_path.name] = {
            "cases": len(expectations),
            "distinct_engine_inputs": len(witnessed),
            "cells_covered": f"{len(witnessed)}/{len(partition)}",
            "decision_classes_expected": sorted(expected_decisions),
            "decision_classes_missing": sorted(set(DECISIONS) - expected_decisions),
            "mutants_killed": len(killed),
            "mutation_score": (f"{100 * len(killed) / len(live):.1f}%" if live else "n/a"),
            "survivors": sorted(survivors),
        }

    return {
        "schema_version": "trustweave.dev/policy-mutation/v1alpha1",
        "policy": policy_path.name,
        "partition_cells": len(partition),
        "subject_quotient": {name: len(values) for name, values in space.items()},
        "mutants_generated": len(generated),
        "mutants_equivalent": len(equivalent),
        "mutants_live": len(live),
        "equivalent_share": f"{100 * len(equivalent) / len(generated):.1f}%",
        "equivalent_mutants": sorted(equivalent),
        "suites": suites,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--scenarios", type=Path, nargs="+", required=True)
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args()

    report = analyze(arguments.policy, list(arguments.scenarios))

    print(f"policy: {report['policy']}  partition: {report['partition_cells']} cells")
    print(
        f"mutants: {report['mutants_generated']} generated, "
        f"{report['mutants_equivalent']} provably equivalent ({report['equivalent_share']}), "
        f"{report['mutants_live']} live"
    )
    print()
    header = f"{'suite':40} {'cases':>5} {'cells':>7} {'killed':>8} {'score':>7}  missing decisions"
    print(header)
    print("-" * len(header))
    for name, scores in report["suites"].items():
        missing = ", ".join(scores["decision_classes_missing"]) or "none"
        print(
            f"{name:40} {scores['cases']:>5} {scores['cells_covered']:>7} "
            f"{scores['mutants_killed']:>3}/{report['mutants_live']:<4} "
            f"{scores['mutation_score']:>7}  {missing}"
        )

    if arguments.json:
        arguments.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
