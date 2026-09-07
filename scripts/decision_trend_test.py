"""Is decision coverage graded, or only a blindness flag?

docs/SUITE_COVERAGE_STUDY.md tests one contrast: blind suites against covered ones, where
blind means the suite witnesses a single decision. On the Kyverno corpus that contrast
reaches p = 0.043 one-sided. A natural next claim is that the relation is graded -- that
witnessing more decisions predicts detecting more faults -- which would let the measure
report a quantity rather than a flag.

This script tests that claim on the recorded Kyverno data with a Jonckheere-Terpstra test
against the ordered alternative, and reports the answer whichever way it falls. The two
artifacts it joins are the ones already committed, so the test adds no new measurement and
carries no new researcher degrees of freedom.

Usage:
    python scripts/decision_trend_test.py [--permutations N] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from statistics import median
from typing import Any

DOCS = Path(__file__).resolve().parents[1] / "docs"
COVERAGE = DOCS / "suite-coverage-kyverno-v1.json"
MUTATION = DOCS / "kyverno-mutation-v1.json"
VALIDATE_DOMAIN = "kyverno_validate"


def witnessed_by_policy() -> dict[str, list[int]]:
    """Decisions witnessed by each validate rule, grouped under its policy."""
    reading = json.loads(COVERAGE.read_text(encoding="utf-8"))
    per_policy: dict[str, list[int]] = defaultdict(list)
    for subject in reading["subjects"]:
        if subject["domain"] != VALIDATE_DOMAIN:
            continue
        policy = subject["subject"].split("/", 1)[0]
        per_policy[policy].append(len(subject["decisions_witnessed"]))
    return dict(per_policy)


def joined_rows() -> list[tuple[str, int, float, bool]]:
    """(policy, decisions witnessed by its best-covered rule, score, recorded blind flag).

    A policy holds several validate rules, so a policy-level level has to aggregate them.
    The maximum is used, which is the generous reading: a policy counts as witnessing k
    decisions when any one of its rules does. The recorded per-policy ``decision_blind``
    flag from the mutation artifact is carried through unchanged so the published
    blind-against-covered contrast can be reproduced beside the graded one.
    """

    per_policy = witnessed_by_policy()
    mutation = json.loads(MUTATION.read_text(encoding="utf-8"))
    rows: list[tuple[str, int, float, bool]] = []
    missing: list[str] = []
    for entry in mutation["detail"]:
        counts = per_policy.get(entry["policy"])
        if not counts:
            missing.append(entry["policy"])
            continue
        rows.append(
            (entry["policy"], max(counts), entry["mutation_score"], entry["decision_blind"])
        )
    if missing:
        raise SystemExit(f"Could not join {len(missing)} scored policies: {missing[:5]}")
    return rows


def jonckheere(levels: list[int], scores: list[float]) -> float:
    """Concordant comparisons across ordered groups, ties counting half."""
    groups: dict[int, list[float]] = defaultdict(list)
    for level, score in zip(levels, scores, strict=True):
        groups[level].append(score)
    ordered = sorted(groups)
    statistic = 0.0
    for index, lower in enumerate(ordered):
        for higher in ordered[index + 1 :]:
            for small in groups[lower]:
                for large in groups[higher]:
                    if large > small:
                        statistic += 1.0
                    elif large == small:
                        statistic += 0.5
    return statistic


def run(permutations: int, seed: int) -> dict[str, Any]:
    rows = joined_rows()
    levels = [level for _, level, _, _ in rows]
    scores = [score for _, _, score, _ in rows]
    observed = jonckheere(levels, scores)

    generator = random.Random(seed)
    shuffled = scores[:]
    at_least_as_extreme = 0
    for _ in range(permutations):
        generator.shuffle(shuffled)
        if jonckheere(levels, shuffled) >= observed:
            at_least_as_extreme += 1
    p_value = (at_least_as_extreme + 1) / (permutations + 1)

    arms = []
    for level in sorted(set(levels)):
        values = [score for _, other, score, _ in rows if other == level]
        arms.append(
            {
                "decisions_witnessed": level,
                "policies": len(values),
                "median_mutation_score": round(median(values), 4),
                "mean_mutation_score": round(sum(values) / len(values), 4),
            }
        )

    blind = [score for _, level, score, _ in rows if level == 1]
    sighted = [score for _, level, score, _ in rows if level > 1]
    flagged = [score for _, _, score, recorded in rows if recorded]
    unflagged = [score for _, _, score, recorded in rows if not recorded]
    return {
        "schema_version": "v1",
        "policies_joined": len(rows),
        "arms": arms,
        "jonckheere_statistic": observed,
        "permutations": permutations,
        "seed": seed,
        "p_value_one_sided": round(p_value, 4),
        "ordered_trend_supported_at_0_05": p_value < 0.05,
        "blindness_contrast_by_max_rule": {
            "blind_policies": len(blind),
            "blind_median": round(median(blind), 4) if blind else None,
            "sighted_policies": len(sighted),
            "sighted_median": round(median(sighted), 4) if sighted else None,
        },
        "blindness_contrast_as_published": {
            "blind_policies": len(flagged),
            "blind_median": round(median(flagged), 4) if flagged else None,
            "covered_policies": len(unflagged),
            "covered_median": round(median(unflagged), 4) if unflagged else None,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--permutations", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    findings = run(args.permutations, args.seed)
    print(f"policies joined: {findings['policies_joined']}")
    for arm in findings["arms"]:
        print(
            f"  witnessed={arm['decisions_witnessed']}  n={arm['policies']:3d}  "
            f"median={arm['median_mutation_score']:.3f}  mean={arm['mean_mutation_score']:.3f}"
        )
    print(
        f"\nJonckheere-Terpstra J = {findings['jonckheere_statistic']:.1f}, "
        f"p = {findings['p_value_one_sided']:.4f} one-sided "
        f"({findings['permutations']} permutations, seed {findings['seed']})"
    )
    verdict = "supported" if findings["ordered_trend_supported_at_0_05"] else "NOT supported"
    print(f"ordered trend at 0.05: {verdict}")
    published = findings["blindness_contrast_as_published"]
    print(
        f"\nblindness contrast, recorded flag: {published['blind_policies']} blind "
        f"median {published['blind_median']} against {published['covered_policies']} "
        f"covered median {published['covered_median']}"
    )
    aggregated = findings["blindness_contrast_by_max_rule"]
    print(
        f"blindness contrast, best rule per policy: {aggregated['blind_policies']} blind "
        f"median {aggregated['blind_median']} against {aggregated['sighted_policies']} "
        f"sighted median {aggregated['sighted_median']}"
    )
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
