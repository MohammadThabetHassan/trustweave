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

from trustweave.engine import decision_for_labels  # noqa: E402
from trustweave.io import load_document  # noqa: E402
from trustweave.models import parse_policy  # noqa: E402
from trustweave.scenarios import parse_scenarios  # noqa: E402

TRUST_LEVELS = ("trusted", "conditional", "untrusted")
ACTION_CLASSES = ("read", "write", "sensitive", "external")
DECISIONS = ("allow", "deny", "require_approval")

CELLS = tuple(itertools.product(TRUST_LEVELS, ACTION_CLASSES))

# Guard fields the enumerated subject space does not range over. `decision_map` evaluates
# each cell with no data classification, no capabilities, and fixed identifiers and purpose,
# so a rule constraining any of these decides over a space larger than CELLS enumerates.
# Two mutants differing only there would resolve to the same map and be discarded as
# equivalent when they are not, which would silently inflate the reported score.
OUT_OF_FRAGMENT_FIELDS = (
    "source_data_classifications",
    "source_data_classification_at_least",
    "source_data_classification_at_most",
    "tool_capabilities",
    "source_identifiers",
    "tool_identifiers",
    "purpose_tags",
    "required_controls",
)


def fragment_violations(document: dict[str, Any]) -> list[str]:
    """Rule guards that range outside the trust x action space this harness enumerates.

    Exactness here is a property of the fragment, not of the tool: equivalence is decidable
    because the subject space is finite and fully enumerated. A policy that steps outside it
    must be refused rather than measured approximately while still reporting an exact score.
    """

    found: list[str] = []
    for index, rule in enumerate(document.get("rules") or []):
        if not isinstance(rule, dict):
            continue
        identifier = rule.get("id", f"rule{index}")
        found.extend(f"{identifier}.{field}" for field in OUT_OF_FRAGMENT_FIELDS if rule.get(field))
    return found


def decision_map(document: dict[str, Any]) -> dict[tuple[str, str], str]:
    """Return the decision this policy gives for every cell of the partition.

    This is the policy's complete observable behaviour over the label domain. Two policies
    with the same map cannot be told apart by any scenario expressed in these labels.
    """

    policy = parse_policy(document)
    resolved: dict[tuple[str, str], str] = {}
    for trust, action in CELLS:
        decision, _ = decision_for_labels(policy, trust, action)
        resolved[(trust, action)] = decision
    return resolved


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
OUT_OF_FRAGMENT_SCENARIO_FIELDS = (
    "source_data_classification",
    "tool_capabilities",
    "source_identifier",
    "tool_identifier",
    "purpose_tag",
)


def scenario_fragment_violations(path: Path) -> list[str]:
    """Scenario attributes that the trust x action enumeration cannot represent."""

    found: list[str] = []
    for scenario in parse_scenarios(load_document(path)):
        for field in OUT_OF_FRAGMENT_SCENARIO_FIELDS:
            if getattr(scenario, field, None):
                found.append(f"{scenario.id}.{field}")
    return found


def _suite_expectations(path: Path) -> list[tuple[str, str, str]]:
    """Return (source_trust, tool_action_class, expected_decision) for one suite."""

    scenarios = parse_scenarios(load_document(path))
    return [
        (scenario.source_trust, scenario.tool_action_class, scenario.expected_decision)
        for scenario in scenarios
    ]


def _kills(expectations: list[tuple[str, str, str]], mutant: dict[str, Any]) -> bool:
    """A suite kills a mutant when any of its cases would now fail."""

    resolved = decision_map(mutant)
    return any(resolved[(trust, action)] != expected for trust, action, expected in expectations)


def analyze(policy_path: Path, suite_paths: list[Path]) -> dict[str, Any]:
    document = dict(load_document(policy_path))
    outside = fragment_violations(document)
    if outside:
        raise SystemExit(
            "policy uses guards outside the enumerated trust x action space, so equivalence "
            "cannot be decided by enumeration and the score would not be exact: "
            + ", ".join(outside)
        )
    reference = decision_map(document)

    generated = _mutants(document)
    live: list[tuple[str, dict[str, Any]]] = []
    equivalent: list[str] = []
    for name, mutant in generated:
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
        outside_suite = scenario_fragment_violations(suite_path)
        if outside_suite:
            raise SystemExit(
                f"{suite_path.name} declares scenario attributes outside the enumerated "
                "trust x action space, so its cases cannot be placed in the partition and a "
                "score over them would not be exact: " + ", ".join(outside_suite)
            )
        expectations = _suite_expectations(suite_path)
        witnessed = {(trust, action) for trust, action, _ in expectations}
        expected_decisions = {expected for _, _, expected in expectations}
        killed = [name for name, mutant in live if _kills(expectations, mutant)]
        survivors = [name for name, _ in live if name not in set(killed)]
        suites[suite_path.name] = {
            "cases": len(expectations),
            "distinct_engine_inputs": len(witnessed),
            "cells_covered": f"{len(witnessed)}/{len(CELLS)}",
            "decision_classes_expected": sorted(expected_decisions),
            "decision_classes_missing": sorted(set(DECISIONS) - expected_decisions),
            "mutants_killed": len(killed),
            "mutation_score": (f"{100 * len(killed) / len(live):.1f}%" if live else "n/a"),
            "survivors": sorted(survivors),
        }

    return {
        "schema_version": "trustweave.dev/policy-mutation/v1alpha1",
        "policy": policy_path.name,
        "partition_cells": len(CELLS),
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
