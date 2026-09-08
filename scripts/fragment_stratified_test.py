"""Does the decision-coverage flag predict detection inside the fragment, or outside it?

the suite-coverage study reports one contrast on the Kyverno corpus: policies whose
suite witnesses a single decision kill fewer mutants than policies whose suite witnesses
more, at p = 0.043 one-sided. That figure is the study's only evidence that the measure
tracks fault detection at all.

The exactness results it descends from hold only inside the fragment of
the decision-class coverage write-up, and scripts/fragment_membership.py can now say which
policies are inside. So the contrast can be stratified, which asks a sharper question than
the pooled figure does: is the association coming from the policies the theory covers?

The statistic is the one scripts/kyverno_mutation.py uses -- a difference in group means
under a one-sided permutation of the labels -- so the pooled arm here reproduces the
published number rather than reporting a differently-computed one beside it. Splits are
enumerated exactly when there are few enough.

Usage:
    python scripts/fragment_stratified_test.py [--json out.json]
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import random
from pathlib import Path
from statistics import mean, median
from typing import Any

DOCS = Path(__file__).resolve().parents[1] / "docs"
MEMBERSHIP = DOCS / "fragment-membership-kyverno-v1.json"
MUTATION = DOCS / "kyverno-mutation-v1.json"
MAX_EXACT_SPLITS = 200_000
SAMPLED_TRIALS = 100_000


def _difference(pool: list[float], indices: tuple[int, ...]) -> float:
    chosen = set(indices)
    left = [pool[index] for index in chosen]
    right = [pool[index] for index in range(len(pool)) if index not in chosen]
    return mean(right) - mean(left)


def permutation_test(blind: list[float], covered: list[float], seed: int) -> dict[str, Any]:
    """Difference in means, one-sided, exact where the split count allows."""

    pool = blind + covered
    size = len(blind)
    observed = mean(covered) - mean(blind)
    splits = math.comb(len(pool), size)

    if splits <= MAX_EXACT_SPLITS:
        extreme = sum(
            1
            for combination in itertools.combinations(range(len(pool)), size)
            if _difference(pool, combination) >= observed
        )
        return {
            "observed_difference": round(observed, 4),
            "p_value": round(extreme / splits, 4),
            "method": f"exact over {splits} splits, one-sided",
        }

    generator = random.Random(seed)
    indices = list(range(len(pool)))
    extreme = 0
    for _ in range(SAMPLED_TRIALS):
        generator.shuffle(indices)
        if _difference(pool, tuple(indices[:size])) >= observed:
            extreme += 1
    return {
        "observed_difference": round(observed, 4),
        "p_value": round(extreme / SAMPLED_TRIALS, 4),
        "method": f"sampled, {SAMPLED_TRIALS} permutations, seed {seed}, one-sided",
    }


def joined_rows() -> list[dict[str, Any]]:
    membership = json.loads(MEMBERSHIP.read_text(encoding="utf-8"))
    verdicts = {entry["subject"]: entry["verdict"] for entry in membership["policies"]}
    mutation = json.loads(MUTATION.read_text(encoding="utf-8"))

    rows: list[dict[str, Any]] = []
    unjudged: list[str] = []
    for entry in mutation["detail"]:
        verdict = verdicts.get(entry["policy"])
        if verdict is None:
            unjudged.append(entry["policy"])
            continue
        rows.append(
            {
                "policy": entry["policy"],
                "fragment": verdict,
                "decision_blind": entry["decision_blind"],
                "mutation_score": entry["mutation_score"],
            }
        )
    if unjudged:
        raise SystemExit(f"{len(unjudged)} scored policies have no verdict: {unjudged[:5]}")
    return rows


def stratum(rows: list[dict[str, Any]], label: str, seed: int) -> dict[str, Any]:
    blind = [row["mutation_score"] for row in rows if row["decision_blind"]]
    covered = [row["mutation_score"] for row in rows if not row["decision_blind"]]
    summary: dict[str, Any] = {
        "stratum": label,
        "policies": len(rows),
        "blind_policies": len(blind),
        "covered_policies": len(covered),
    }
    if not blind or not covered:
        summary["test"] = {"p_value": None, "method": "not applicable, an arm is empty"}
        return summary
    summary.update(
        {
            "blind_mean": round(mean(blind), 4),
            "blind_median": round(median(blind), 4),
            "covered_mean": round(mean(covered), 4),
            "covered_median": round(median(covered), 4),
            "test": permutation_test(blind, covered, seed),
        }
    )
    return summary


def run(seed: int = 0) -> dict[str, Any]:
    rows = joined_rows()
    strata = [
        stratum(rows, "all", seed),
        stratum([row for row in rows if row["fragment"] == "inside"], "inside", seed),
        stratum([row for row in rows if row["fragment"] == "outside"], "outside", seed),
    ]
    by_label = {entry["stratum"]: entry for entry in strata}
    inside = by_label["inside"]["test"].get("p_value")
    outside = by_label["outside"]["test"].get("p_value")
    return {
        "schema_version": "v1",
        "policies_joined": len(rows),
        "strata": strata,
        "association_significant_inside_the_fragment": bool(inside is not None and inside < 0.05),
        "association_significant_outside_the_fragment": bool(
            outside is not None and outside < 0.05
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    findings = run(args.seed)
    print(f"policies joined: {findings['policies_joined']}")
    for entry in findings["strata"]:
        print(f"\n{entry['stratum']}: {entry['policies']} policies")
        if entry["test"].get("p_value") is None:
            print(f"   {entry['test']['method']}")
            continue
        print(
            f"   blind   n={entry['blind_policies']:2d} "
            f"mean={entry['blind_mean']:.4f} median={entry['blind_median']:.3f}"
        )
        print(
            f"   covered n={entry['covered_policies']:2d} "
            f"mean={entry['covered_mean']:.4f} median={entry['covered_median']:.3f}"
        )
        print(
            f"   difference={entry['test']['observed_difference']:+.4f} "
            f"p={entry['test']['p_value']:.4f}  ({entry['test']['method']})"
        )
    print(
        f"\nsignificant inside the fragment: "
        f"{findings['association_significant_inside_the_fragment']}"
    )
    print(
        f"significant outside the fragment: "
        f"{findings['association_significant_outside_the_fragment']}"
    )
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
