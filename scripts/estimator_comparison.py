"""What deciding equivalence buys over estimating it, measured rather than asserted.

The practical claim in the decision-class coverage write-up is that inside the fragment a
mutation score is exact: equivalence is a table comparison rather than an undecidable
question, so no mutant has to be sampled and no survivor has to be inspected by hand. The
paper never said what the alternative costs, which leaves the claim's value to the reader's
imagination.

This measures it against the two approximations a tool without the fragment must use.

**Undetected equivalents.** Equivalence being undecidable in general, a tool either counts
every generated mutant in the denominator -- deflating the score by however many are
equivalent -- or asks a human to triage the survivors. The first is what an automated
pipeline does, and the error is the equivalent share.

**Sampling.** Where the mutant set is too large to run whole, a tool scores a random sample
and extrapolates. Here the true kill set is known, so the sampling error is not simulated
but computed: over every sample of size k, the mean absolute error and the worst case.

Usage:
    python scripts/estimator_comparison.py --policy P --scenarios S [S ...] [--json out]
"""

from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_SIZES = (4, 8, 12, 16, 20)
# Above this many combinations the exact sampling distribution is estimated instead, with a
# fixed seed, because enumerating every sample of every size is exponential.
MAX_EXACT_SAMPLES = 200_000
SAMPLED_DRAWS = 20_000


def _harness() -> Any:
    specification = importlib.util.spec_from_file_location(
        "policy_mutation", ROOT / "scripts" / "policy_mutation.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["policy_mutation"] = module
    specification.loader.exec_module(module)
    return module


def kill_vector(harness: Any, policy_path: Path, suite_path: Path) -> dict[str, Any]:
    """Which mutants are equivalent, and which of the rest this suite kills."""

    document = dict(harness.load_document(policy_path))
    space = harness.witness_space(document)
    reference = harness.decision_map(document)

    equivalent: list[str] = []
    live: list[tuple[str, dict[str, Any]]] = []
    for name, mutant in harness._mutants(document):
        try:
            resolved = harness.decision_map(mutant)
        except Exception:  # noqa: BLE001 - an unparseable mutant is not a policy
            equivalent.append(name)
            continue
        (equivalent.append(name) if resolved == reference else live.append((name, mutant)))

    expectations = harness._suite_expectations(suite_path, space)
    killed = {name for name, mutant in live if harness._kills(expectations, mutant)}
    return {
        "generated": len(equivalent) + len(live),
        "equivalent": len(equivalent),
        "live": [name for name, _ in live],
        "killed": sorted(killed),
    }


def sampling_error(killed: list[bool], size: int) -> dict[str, Any]:
    """Error of scoring a random sample of *size* mutants, against the exact score."""

    total = len(killed)
    if size >= total:
        return {"sample_size": size, "note": "sample is the whole set", "mean_absolute_error": 0.0}
    exact = sum(killed) / total
    combinations = 1
    for index in range(size):
        combinations = combinations * (total - index) // (index + 1)

    errors: list[float] = []
    if combinations <= MAX_EXACT_SAMPLES:
        method = f"exact over {combinations} samples"
        for sample in itertools.combinations(killed, size):
            errors.append(abs(sum(sample) / size - exact))
    else:
        import random

        method = f"sampled, {SAMPLED_DRAWS} draws, seed 0"
        generator = random.Random(0)
        indices = list(range(total))
        for _ in range(SAMPLED_DRAWS):
            generator.shuffle(indices)
            chosen = [killed[index] for index in indices[:size]]
            errors.append(abs(sum(chosen) / size - exact))
    return {
        "sample_size": size,
        "method": method,
        "mean_absolute_error": round(statistics.fmean(errors), 4),
        "worst_absolute_error": round(max(errors), 4),
        "share_off_by_over_10_points": round(
            sum(1 for error in errors if error > 0.10) / len(errors), 4
        ),
    }


def analyse(policy_path: Path, suite_paths: list[Path]) -> dict[str, Any]:
    harness = _harness()
    suites = []
    for suite_path in suite_paths:
        vector = kill_vector(harness, policy_path, suite_path)
        live, killed = vector["live"], set(vector["killed"])
        exact = len(killed) / len(live) if live else 0.0
        # What a tool that cannot decide equivalence reports: the same kills over every
        # generated mutant, because it has no way to remove the equivalent ones.
        undetected = len(killed) / vector["generated"] if vector["generated"] else 0.0
        flags = [name in killed for name in live]
        suites.append(
            {
                "suite": suite_path.name,
                "mutants_generated": vector["generated"],
                "mutants_equivalent": vector["equivalent"],
                "mutants_live": len(live),
                "exact_score": round(exact, 4),
                "score_without_equivalence_detection": round(undetected, 4),
                "understatement_points": round((exact - undetected) * 100, 2),
                "sampling": [sampling_error(flags, size) for size in SAMPLE_SIZES],
            }
        )
    return {
        "schema_version": "v1",
        "policy": policy_path.name,
        "suites": suites,
        "equivalent_share": round(
            suites[0]["mutants_equivalent"] / suites[0]["mutants_generated"], 4
        )
        if suites
        else None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--scenarios", type=Path, nargs="+", required=True)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    findings = analyse(args.policy, args.scenarios)
    print(f"policy: {findings['policy']}   equivalent share: {findings['equivalent_share']:.1%}\n")
    print(f"{'suite':40s} {'exact':>7s} {'no detection':>13s} {'understated by':>15s}")
    for entry in findings["suites"]:
        print(
            f"{entry['suite']:40s} {entry['exact_score']:7.1%} "
            f"{entry['score_without_equivalence_detection']:13.1%} "
            f"{entry['understatement_points']:14.1f}pt"
        )
    print("\nsampling error against the exact score:")
    for entry in findings["suites"]:
        print(f"  {entry['suite']}")
        for sample in entry["sampling"]:
            if "mean_absolute_error" not in sample or "method" not in sample:
                continue
            mean = sample["mean_absolute_error"]
            worst = sample["worst_absolute_error"]
            over = sample["share_off_by_over_10_points"]
            print(
                f"      k={sample['sample_size']:2d}  mean |error|={mean:.3f}"
                f"  worst={worst:.3f}  off by >10pt in {over:.1%}"
                f"   ({sample['method']})"
            )
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
