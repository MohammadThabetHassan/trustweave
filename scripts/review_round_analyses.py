"""Post hoc re-analyses, computed from artifacts the studies already wrote.

Nothing here runs a policy engine or draws a new sample. Each analysis reads JSON under `docs/`
and answers a question the original reports left open:

* **Does line coverage track adequacy?** The suite study reports that line coverage overstates
  the kill rate, and the exact study that it overstates exact adequacy by less. Neither says
  whether a module with higher coverage has a higher score. Kendall's tau-b between each
  module's line coverage and its score answers that, with a seeded permutation p-value.
* **Are the paired comparisons robust to clustering?** The Rego payoff study scores 34
  policies that are 13 modules under the settings their suites test, and the real-fault study
  20 fixes from 18 commits and 17 modules. Resampling and sign-flipping whole modules (or
  commits) rather than policies (or fixes) gives intervals and p-values that do not treat
  units sharing a source as independent. The sign-flip is exact over every pattern.
* **What do the two fixes with no decision change do to the real-fault means?** The protocol
  fixed in advance that a fix whose versions decide alike on every tested setting is reported,
  not scored; counting both as exposed by nothing is the pessimistic alternative.
* **How large is the equivalent share outside the reference policy?** Section 6 prices
  decidability on one four-rule policy whose 42% equivalent share is the largest measured; the
  real populations' shares are already in their artifacts.
* **Which guard families do the inside verdicts rest on?** Three adapters record, per artifact,
  the operators or functions its guards use. Some families are decidable whatever their
  operands; others only when an operand is a literal, which no adapter checks. The tally says
  how many inside verdicts use the second kind.

    python scripts/review_round_analyses.py --json docs/review-round-analyses-v1.json
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SEED = 20261004
RESAMPLES = 10_000

# --- guard families ----------------------------------------------------------------------------
#
# A family is *operand-free* when occupancy of any Boolean combination of its atoms is decidable,
# with a witness, whichever request fields or literals fill its operands: equality and order
# (equality logic and linear orders), Boolean connectives and presence tests, linear arithmetic
# (Presburger arithmetic and its real counterpart), bag extraction, cardinality, set relations
# and quantifiers over collections whose element guards are operand-free (Boolean algebra with
# Presburger arithmetic), and unary normalisations of one field, which are rational functions and
# so preserve regularity. A family is *literal-operand* when that argument needs an operand the
# policy writes down: a pattern (a regular language only when the pattern is a literal), a
# product, quotient or remainder (linear only when one factor is a literal), duration
# arithmetic, substring and concatenation, and a function applied to every member of a bag.
# The adapters accept both kinds by name and check no operand, so a verdict that uses a
# literal-operand family is inside on the strength of an argument the instrument did not check.

XACML_LITERAL_OPERAND_SUFFIXES = (
    "regexp-match",
    "starts-with",
    "ends-with",
    "contains",
    "match",
    "multiply",
    "divide",
    "mod",
    "dayTimeDuration",
    "yearMonthDuration",
    "substring",
    "concatenate",
)
XACML_LITERAL_OPERAND_NAMES = frozenset({"map"})

AZURE_LITERAL_OPERAND_OPERATORS = frozenset(
    {"like", "notlike", "match", "notmatch", "matchinsensitively", "notmatchinsensitively"}
)
# ARM template functions that read a value or compare, test or normalise one: operand-free.
AZURE_OPERAND_FREE_FUNCTIONS = frozenset(
    {
        "field",
        "current",
        "parameters",
        "requestContext",
        "subscription",
        "resourceGroup",
        "equals",
        "less",
        "lessOrEquals",
        "greater",
        "greaterOrEquals",
        "and",
        "or",
        "not",
        "if",
        "empty",
        "length",
        "tolower",
        "toLower",
        "toupper",
        "toUpper",
        "tryGet",
        "bool",
    }
)

IAM_LITERAL_OPERAND_MARKERS = ("Like",)


def xacml_literal_operand(function: str) -> bool:
    name = function.rsplit(":", 1)[-1]
    return name in XACML_LITERAL_OPERAND_NAMES or any(
        name == suffix or name.endswith(f"-{suffix}") for suffix in XACML_LITERAL_OPERAND_SUFFIXES
    )


def families(docs: Path) -> dict[str, Any]:
    """Inside verdicts by the kind of family their guards use, for the adapters that record it."""

    rows: dict[str, Any] = {}

    azure = json.loads((docs / "fragment-membership-azure-wide-v1.json").read_text("utf-8"))
    counted: Counter[str] = Counter()
    which: Counter[str] = Counter()
    for entry in azure["policies"]:
        if entry["verdict"] != "inside":
            continue
        operators = {op.lower() for op in entry.get("leaf_operators", [])}
        functions = set(entry.get("arm_functions", []))
        reasons = sorted(
            (operators & AZURE_LITERAL_OPERAND_OPERATORS)
            | (functions - AZURE_OPERAND_FREE_FUNCTIONS)
        )
        counted["literal-operand" if reasons else "operand-free"] += 1
        which.update(reasons)
    rows["Azure Policy"] = {**counted, "families": dict(sorted(which.items()))}

    xacml = json.loads((docs / "fragment-membership-xacml-wide-v1.json").read_text("utf-8"))
    counted = Counter()
    which = Counter()
    for entry in xacml["policies"]:
        if entry["verdict"] != "inside":
            continue
        reasons = sorted(
            {f.rsplit(":", 1)[-1] for f in entry.get("functions", []) if xacml_literal_operand(f)}
        )
        counted["literal-operand" if reasons else "operand-free"] += 1
        which.update(reasons)
    rows["XACML"] = {**counted, "families": dict(sorted(which.items()))}

    iam = json.loads((docs / "fragment-membership-iam-wide-v1.json").read_text("utf-8"))
    counted = Counter()
    which = Counter()
    for entry in iam["policies"]:
        if entry["verdict"] != "inside":
            continue
        reasons = sorted(
            {
                op
                for op in entry.get("condition_operators", [])
                if any(marker in op for marker in IAM_LITERAL_OPERAND_MARKERS)
            }
        )
        # An IAM condition value is always written in the policy, so a Like operator's
        # pattern is a literal by construction; it is counted apart because a policy variable
        # inside the pattern relates two request fields, which the adapter does not record.
        counted["pattern, literal by construction" if reasons else "operand-free"] += 1
        which.update(reasons)
    rows["AWS IAM"] = {**counted, "families": dict(sorted(which.items()))}

    unrecorded = 0
    for stem in (
        "fragment-membership-rego-wide-v1",
        "fragment-membership-rego-gcp-v1",
        "fragment-membership-kyverno-wide-v1",
        "fragment-membership-kyverno-thirdparty-v1",
    ):
        findings = json.loads((docs / f"{stem}.json").read_text("utf-8"))
        unrecorded += findings["counts"]["inside"]
    cedar = json.loads((docs / "fragment-membership-cedar-wide-v1.json").read_text("utf-8"))

    inside = sum(sum(v for k, v in row.items() if k != "families") for row in rows.values())
    literal = rows["Azure Policy"].get("literal-operand", 0) + rows["XACML"].get(
        "literal-operand", 0
    )
    return {
        "by_language": rows,
        "recorded_inside": inside,
        "literal_operand_where_recorded": literal,
        "iam_patterns_literal_by_construction": rows["AWS IAM"].get(
            "pattern, literal by construction", 0
        ),
        "rego_and_kyverno_inside_unrecorded": unrecorded,
        "cedar_inside_by_design": cedar["counts"]["inside"],
    }


# --- line coverage against adequacy -------------------------------------------------------------


def kendall_tau_b(x: Sequence[float], y: Sequence[float]) -> float:
    concordant = discordant = tied_x = tied_y = 0
    for i, j in itertools.combinations(range(len(x)), 2):
        dx = (x[i] > x[j]) - (x[i] < x[j])
        dy = (y[i] > y[j]) - (y[i] < y[j])
        if dx == 0 and dy == 0:
            continue
        if dx == 0:
            tied_x += 1
        elif dy == 0:
            tied_y += 1
        elif dx == dy:
            concordant += 1
        else:
            discordant += 1
    denominator = math.sqrt((concordant + discordant + tied_x) * (concordant + discordant + tied_y))
    return (concordant - discordant) / denominator if denominator else 0.0


def tau_permutation_p(x: Sequence[float], y: Sequence[float], seed: int = SEED) -> float:
    """Two-sided p of tau-b under random pairing, from RESAMPLES seeded permutations."""

    generator = random.Random(seed)
    observed = abs(kendall_tau_b(x, y))
    shuffled = list(y)
    extreme = 0
    for _ in range(RESAMPLES):
        generator.shuffle(shuffled)
        extreme += abs(kendall_tau_b(x, shuffled)) >= observed - 1e-12
    return (1 + extreme) / (1 + RESAMPLES)


def coverage_association(docs: Path) -> dict[str, Any]:
    suite = json.loads((docs / "rego-suite-adequacy-v1.json").read_text("utf-8"))
    exact = json.loads((docs / "rego-exact-adequacy-v1.json").read_text("utf-8"))
    development = suite["development_module"]

    measured = [
        m
        for subject, m in suite["modules"].items()
        if subject != development and m.get("status") == "measured"
    ]
    coverage = [m["coverage"] / 100 for m in measured]
    kill = [m["mutation_score"] for m in measured]

    decided = [
        (subject, m)
        for subject, m in exact["modules"].items()
        if not m.get("development") and m.get("status") == "measured"
    ]
    decided_coverage = [suite["modules"][subject]["coverage"] / 100 for subject, _ in decided]
    decided_exact = [m["exact_score"] for _, m in decided]
    decided_raw = [m["raw_score"] for _, m in decided]

    def summary(x: list[float], y: list[float]) -> dict[str, Any]:
        return {
            "modules": len(x),
            "kendall_tau_b": round(kendall_tau_b(x, y), 4),
            "permutation_p_two_sided": round(tau_permutation_p(x, y), 4),
        }

    return {
        "kill_rate": {
            **summary(coverage, kill),
            "mean_line_coverage": round(statistics.fmean(coverage), 4),
            "mean_kill_rate": round(statistics.fmean(kill), 4),
        },
        "exact_score": {
            **summary(decided_coverage, decided_exact),
            "mean_line_coverage": round(statistics.fmean(decided_coverage), 4),
            "mean_exact_score": round(statistics.fmean(decided_exact), 4),
            "mean_raw_score": round(statistics.fmean(decided_raw), 4),
            "coverage_minus_exact": round(
                statistics.fmean(decided_coverage) - statistics.fmean(decided_exact), 4
            ),
            "coverage_minus_raw": round(
                statistics.fmean(decided_coverage) - statistics.fmean(decided_raw), 4
            ),
            "range_of_exact_scores": [round(min(decided_exact), 4), round(max(decided_exact), 4)],
            "range_of_line_coverage": [
                round(min(decided_coverage), 4),
                round(max(decided_coverage), 4),
            ],
        },
    }


# --- clustered comparisons ----------------------------------------------------------------------


def cluster_bootstrap(clusters: Sequence[Sequence[float]], seed: int = SEED) -> tuple[float, float]:
    """95% interval of the unit-level mean, resampling whole clusters."""

    generator = random.Random(seed)
    count = len(clusters)
    means = []
    for _ in range(RESAMPLES):
        drawn = [clusters[generator.randrange(count)] for _ in range(count)]
        values = [value for cluster in drawn for value in cluster]
        means.append(statistics.fmean(values))
    means.sort()
    return means[int(0.025 * RESAMPLES)], means[int(0.975 * RESAMPLES) - 1]


def cluster_sign_flip_p(clusters: Sequence[Sequence[float]]) -> float:
    """Exact one-sided p of the unit-level mean when every cluster's sign may flip together."""

    sums = [sum(cluster) for cluster in clusters]
    units = sum(len(cluster) for cluster in clusters)
    observed = sum(sums) / units
    extreme = 0
    for signs in itertools.product((1, -1), repeat=len(sums)):
        extreme += sum(s * v for s, v in zip(signs, sums, strict=True)) / units >= observed - 1e-12
    return extreme / 2 ** len(sums)


def clustered(units: list[tuple[str, dict[str, float]]], pairs: dict[str, tuple[str, str]]) -> dict:
    groups: dict[str, list[dict[str, float]]] = defaultdict(list)
    for cluster, scores in units:
        groups[cluster].append(scores)
    results: dict[str, Any] = {"units": len(units), "clusters": len(groups)}
    for name, (left, right) in pairs.items():
        clusters = [[s[left] - s[right] for s in members] for members in groups.values()]
        low, high = cluster_bootstrap(clusters)
        results[name] = {
            "strategies": [left, right],
            "mean_difference": round(statistics.fmean(v for c in clusters for v in c), 6),
            "cluster_bootstrap_95": [round(low, 6), round(high, 6)],
            "cluster_sign_flip_p": round(cluster_sign_flip_p(clusters), 6),
            "clusters_higher": sum(1 for c in clusters if sum(c) > 0),
            "clusters_lower": sum(1 for c in clusters if sum(c) < 0),
        }
    return results


PAIRS = {"H1": ("quotient", "random_quotient"), "H2": ("quotient", "decision")}


def clustering(docs: Path) -> dict[str, Any]:
    payoff = json.loads((docs / "rego-suite-strategy-study-v1.json").read_text("utf-8"))
    policies = [
        (subject, policy["expected_score"])
        for subject, module in payoff["modules"].items()
        if not module["development"]
        for policy in module["policies"]
        if policy["status"] == "scored"
    ]
    faults_artifact = json.loads((docs / "rego-real-faults-v1.json").read_text("utf-8"))
    faults = [
        f
        for f in faults_artifact["faults"]
        if f.get("status") == "scored" and not f.get("development")
    ]
    return {
        "rego_payoff_by_module": clustered(policies, PAIRS),
        "real_faults_by_commit": clustered(
            [(f["fix_commit"], f["exposure"]) for f in faults], PAIRS
        ),
        "real_faults_by_module": clustered(
            [(f"{f['corpus']}:{f['module']}", f["exposure"]) for f in faults], PAIRS
        ),
    }


# --- the faults reported rather than scored -----------------------------------------------------


def no_change_sensitivity(docs: Path) -> dict[str, Any]:
    artifact = json.loads((docs / "rego-real-faults-v1.json").read_text("utf-8"))
    scored = [
        f["exposure"]
        for f in artifact["faults"]
        if f.get("status") == "scored" and not f.get("development")
    ]
    unchanged = [
        f["number"]
        for f in artifact["faults"]
        if f.get("status") == "no decision change under the tested settings"
    ]
    strategies = sorted(scored[0])
    padded = scored + [{s: 0.0 for s in strategies} for _ in unchanged]
    return {
        "reported_not_scored": unchanged,
        "faults": len(padded),
        "mean_exposure_counting_them_as_unexposed": {
            s: round(statistics.fmean(e[s] for e in padded), 6) for s in strategies
        },
        "H1_mean_difference": round(
            statistics.fmean(e["quotient"] - e["random_quotient"] for e in padded), 6
        ),
        "H2_mean_difference": round(
            statistics.fmean(e["quotient"] - e["decision"] for e in padded), 6
        ),
    }


# --- equivalent shares --------------------------------------------------------------------------


def equivalent_shares(docs: Path) -> dict[str, Any]:
    generated = json.loads((docs / "suite-strategy-study-v1.json").read_text("utf-8"))
    mutants = generated["operator_sets"]["A"]["mutants"]
    symcc = json.loads((docs / "cedar-symcc-crosscheck-v1.json").read_text("utf-8"))["summary"]
    rego = json.loads((docs / "rego-exact-adequacy-v1.json").read_text("utf-8"))
    xacml = json.loads((docs / "xacml-criteria-study-v1.json").read_text("utf-8"))["summary"]

    outright = sum(
        m["suite_equivalent"]
        for m in rego["modules"].values()
        if not m.get("development")
        and m.get("status") == "measured"
        and m["instantiations"] == ["absent"]
    )
    headline = rego["headline"]
    compiling = headline["mutants"] - headline["stillborn"]

    def share(equivalent: int, total: int) -> dict[str, Any]:
        return {"equivalent": equivalent, "mutants": total, "share": round(equivalent / total, 4)}

    rows = {
        "reference policy": share(16, 38),
        "generated (300)": share(mutants["equivalent"], mutants["equivalent"] + mutants["live"]),
        "Cedar with an author schema (71)": share(
            symcc["primary"]["equivalent_verdicts"],
            symcc["primary"]["equivalent_verdicts"] + symcc["secondary"]["live_verdicts"],
        ),
        "Gatekeeper, decided (13)": {
            **share(headline["suite_equivalent"], compiling),
            "outright": outright,
            "outright_share": round(outright / compiling, 4),
        },
        "XACML benchmark (11)": share(
            xacml["mutants"]["equivalent"],
            xacml["mutants"]["equivalent"] + xacml["mutants"]["live"],
        ),
    }
    return rows


def analyse(docs: Path) -> dict[str, Any]:
    return {
        "schema_version": "v1",
        "seed": SEED,
        "resamples": RESAMPLES,
        "guard_families": families(docs),
        "line_coverage": coverage_association(docs),
        "clustered": clustering(docs),
        "real_faults_no_change_sensitivity": no_change_sensitivity(docs),
        "equivalent_shares": equivalent_shares(docs),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docs", type=Path, default=DOCS)
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)
    findings = analyse(arguments.docs)
    text = json.dumps(findings, indent=2, sort_keys=True) + "\n"
    if arguments.json:
        arguments.json.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
