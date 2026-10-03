"""Two studies that use exact equivalence as ground truth.

Inside the fragment, whether a mutant is equivalent to its policy is decided rather than
estimated, so "how many faults does this suite detect" and "is this edit a real change" have
exact answers. This script measures two things against those answers, under the protocol in
`docs/EXACT_EVALUATION_PROTOCOL.md`:

- **Study 1** scores suite strategies -- one witness per class of the policy's quotient, one
  per decision, and random suites of the same sizes -- by their exact expected mutation
  score. No suite is sampled: each mutant's detection probability under each strategy has a
  closed form, computed in rational arithmetic.
- **Study 2** treats every mutant as a proposed change and asks which reviewers flag it:
  TrustWeave's own diff signals, a text diff, a suite run, and the exact table comparison.

The protocol was fixed before either study ran, and its hash is fixed here. The script
refuses to run against a protocol that has changed since.

Usage:
    python scripts/exact_evaluation_study.py sample --json docs/generated-policy-sample-v1.json
    python scripts/exact_evaluation_study.py suites \
        --sample docs/generated-policy-sample-v1.json --json docs/suite-strategy-study-v1.json
    python scripts/exact_evaluation_study.py review \
        --sample docs/generated-policy-sample-v1.json --json docs/review-signal-study-v1.json
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
sys.path.insert(0, str(ROOT / "src"))

from trustweave.diff import _policy_changes  # noqa: E402
from trustweave.models import DEFAULT_CLASSIFICATION_TAXONOMY, parse_policy  # noqa: E402
from trustweave.policy_weakening import policy_review_signals  # noqa: E402

PROTOCOL = DOCS / "EXACT_EVALUATION_PROTOCOL.md"
# Fixed when the protocol was written, before any study ran.
PROTOCOL_SHA256 = "e1baa3b2e529d5d8ba00771fa7f8807158d00281ce4c95217455d7f613c324c9"
REFERENCE_POLICY = ROOT / "policies" / "default-policy.json"
SEED = 20261003
POLICIES = 300
MAX_CELLS = 5_000
RESAMPLES = 10_000
PERMISSIVENESS = {"deny": 0, "require_approval": 1, "allow": 2}
# The signals `policy_weakening.policy_review_signals` itself classifies as weakenings.
WEAKENING_SIGNALS = frozenset(
    {"TW-DIFF-004", "TW-DIFF-005", "TW-DIFF-006", "TW-DIFF-007", "TW-DIFF-008", "TW-DIFF-009"}
)
OPTIONAL_LISTS = (
    "source_data_classifications",
    "tool_capabilities",
    "source_identifiers",
    "tool_identifiers",
    "purpose_tags",
)
BOUNDS = ("source_data_classification_at_least", "source_data_classification_at_most")
STRATEGIES = ("refinement", "quotient", "decision", "random_quotient", "random_decision")
HYPOTHESES = (
    ("H1", "quotient", "random_quotient", "greater"),
    ("H2", "quotient", "decision", "greater"),
    ("H3", "decision", "random_decision", "two-sided"),
)


def _load(name: str) -> Any:
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


oracle = _load("interpreter_oracle")
harness = oracle.harness


def protocol_digest(path: Path = PROTOCOL) -> str:
    """The protocol's hash, over LF line endings so a CRLF checkout hashes the same text."""

    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def require_protocol(path: Path = PROTOCOL) -> None:
    found = protocol_digest(path)
    if found != PROTOCOL_SHA256:
        raise SystemExit(
            f"{path.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the studies "
            "ran; a changed protocol is a different study, so this one refuses to run"
        )


# ---------------------------------------------------------------------------------------
# Faults
# ---------------------------------------------------------------------------------------


def operators_a(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The paper's operator set, unchanged."""

    return list(harness._mutants(document))


def _named(document: dict[str, Any], field: str) -> list[str]:
    return sorted({value for rule in document["rules"] for value in rule.get(field) or ()})


def operators_b(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Set A plus edits to every optional predicate, within the policy's own vocabulary."""

    generated = operators_a(document)
    taxonomy = list(document.get("classification_taxonomy") or DEFAULT_CLASSIFICATION_TAXONOMY)
    for index, rule in enumerate(document["rules"]):
        identifier = rule.get("id", f"rule{index}")
        for field in OPTIONAL_LISTS:
            if field not in rule:
                continue
            values = list(rule[field])
            dropped = copy.deepcopy(document)
            del dropped["rules"][index][field]
            generated.append((f"drop_{field}[{identifier}]", dropped))
            if len(values) > 1:
                for value in values:
                    narrowed = copy.deepcopy(document)
                    narrowed["rules"][index][field] = [kept for kept in values if kept != value]
                    generated.append((f"narrow_{field}[{identifier}-{value}]", narrowed))
            pool = taxonomy if field == "source_data_classifications" else _named(document, field)
            for value in pool:
                if value in values:
                    continue
                widened = copy.deepcopy(document)
                widened["rules"][index][field] = [*values, value]
                generated.append((f"widen_{field}[{identifier}+{value}]", widened))
        for bound in BOUNDS:
            if bound not in rule:
                continue
            dropped = copy.deepcopy(document)
            del dropped["rules"][index][bound]
            generated.append((f"drop_{bound}[{identifier}]", dropped))
            for level in taxonomy:
                if level == rule[bound]:
                    continue
                shifted = copy.deepcopy(document)
                shifted["rules"][index][bound] = level
                generated.append((f"shift_{bound}[{identifier}->{level}]", shifted))
    return generated


OPERATOR_SETS: dict[str, Callable[[dict[str, Any]], list[tuple[str, dict[str, Any]]]]] = {
    "A": operators_a,
    "B": operators_b,
}


def operator_of(name: str) -> str:
    return name.split("[", 1)[0]


# ---------------------------------------------------------------------------------------
# The sample
# ---------------------------------------------------------------------------------------


def space_size(space: dict[str, tuple[Any, ...]]) -> int:
    return math.prod(len(space[attribute]) for attribute in harness.ATTRIBUTES)


def draw_sample(policies: int = POLICIES, seed: int = SEED) -> dict[str, Any]:
    """Generated policies whose pooled witness space has at most MAX_CELLS cells."""

    generator = random.Random(seed)
    kept: list[dict[str, Any]] = []
    rejected = 0
    over_cap: list[int] = []
    while len(kept) < policies:
        document = oracle.generate_policy(generator)
        if document is None:
            rejected += 1
            continue
        space = harness.witness_space(document, *(m for _, m in operators_b(document)))
        size = space_size(space)
        if size > MAX_CELLS:
            over_cap.append(size)
            continue
        kept.append(document)
    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "seed": seed,
        "max_cells": MAX_CELLS,
        "candidates_drawn": len(kept) + rejected + len(over_cap),
        "rejected_by_parser": rejected,
        "over_cell_cap": len(over_cap),
        "over_cell_cap_smallest": min(over_cap) if over_cap else None,
        "policies": kept,
    }


# ---------------------------------------------------------------------------------------
# Exact analysis of one policy
# ---------------------------------------------------------------------------------------


def _detection(groups: Sequence[Sequence[int]], hits: set[int]) -> Fraction:
    """P(a suite with one uniformly chosen witness per group contains a cell in `hits`)."""

    missed = Fraction(1)
    for group in groups:
        inside = sum(1 for cell in group if cell in hits)
        if inside:
            missed *= Fraction(len(group) - inside, len(group))
    return 1 - missed


def _random_detection(cells: int, hits: int, size: int) -> Fraction:
    """P(`size` cells drawn uniformly without replacement include one of `hits` cells)."""

    if hits == 0:
        return Fraction(0)
    return 1 - Fraction(math.comb(cells - hits, size), math.comb(cells, size))


def analyse_policy(document: dict[str, Any], operator_set: str) -> dict[str, Any]:
    """Every mutant of one policy: its exact difference set and its detection probabilities."""

    mutants = OPERATOR_SETS[operator_set](document)
    space = harness.witness_space(document, *(m for _, m in mutants))
    cells = harness.cells_of(space)
    policy = parse_policy(document)
    decided = harness.decision_map(document, space)
    reference = [decided[cell] for cell in cells]

    by_class: dict[tuple[bool, ...], list[int]] = defaultdict(list)
    by_decision: dict[str, list[int]] = defaultdict(list)
    for position, cell in enumerate(cells):
        by_class[harness.predicate_signature(policy, cell)].append(position)
        by_decision[reference[position]].append(position)
    classes = list(by_class.values())
    decisions = list(by_decision.values())
    size = {"quotient": len(classes), "decision": len(decisions)}

    records: list[dict[str, Any]] = []
    for name, mutant in mutants:
        try:
            resolved = harness.decision_map(mutant, space)
        except Exception:  # noqa: BLE001 - a mutant the parser refuses is not a policy
            records.append({"mutant": name, "status": "unrunnable", "mutant_document": None})
            continue
        changed = {p for p, cell in enumerate(cells) if resolved[cell] != reference[p]}
        weakened = {
            p for p in changed if PERMISSIVENESS[resolved[cells[p]]] > PERMISSIVENESS[reference[p]]
        }
        record: dict[str, Any] = {
            "mutant": name,
            "status": "live" if changed else "equivalent",
            "cells_changed": len(changed),
            "cells_weakened": len(weakened),
            "mutant_document": mutant,
        }
        for target, hits in (("change", changed), ("weakening", weakened)):
            record[f"{target}_detection"] = {
                "refinement": Fraction(1 if hits else 0),
                "quotient": _detection(classes, hits),
                "decision": _detection(decisions, hits),
                "random_quotient": _random_detection(len(cells), len(hits), size["quotient"]),
                "random_decision": _random_detection(len(cells), len(hits), size["decision"]),
            }
        records.append(record)
    return {
        "cells": len(cells),
        "quotient_classes": size["quotient"],
        "decision_range": size["decision"],
        "mutants": records,
    }


# ---------------------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------------------


def _round(value: Fraction | float) -> float:
    return round(float(value), 6)


def bootstrap_interval(differences: Sequence[float], seed: int = SEED) -> tuple[float, float]:
    generator = random.Random(seed)
    count = len(differences)
    means = sorted(
        statistics.fmean(differences[generator.randrange(count)] for _ in range(count))
        for _ in range(RESAMPLES)
    )
    return means[int(0.025 * RESAMPLES)], means[int(0.975 * RESAMPLES) - 1]


def sign_flip_p(differences: Sequence[float], alternative: str, seed: int = SEED) -> float:
    generator = random.Random(seed)
    observed = statistics.fmean(differences)
    extreme = 0
    for _ in range(RESAMPLES):
        flipped = statistics.fmean(d if generator.random() < 0.5 else -d for d in differences)
        if alternative == "greater":
            extreme += flipped >= observed
        else:
            extreme += abs(flipped) >= abs(observed)
    return (1 + extreme) / (1 + RESAMPLES)


def holm(p_values: dict[str, float]) -> dict[str, float]:
    ordered = sorted(p_values.items(), key=lambda item: item[1])
    adjusted: dict[str, float] = {}
    running = 0.0
    for rank, (name, p) in enumerate(ordered):
        running = max(running, min(1.0, (len(ordered) - rank) * p))
        adjusted[name] = running
    return adjusted


def compare(scores: list[dict[str, Fraction]]) -> dict[str, Any]:
    """The three pre-registered paired comparisons, over policies that have live mutants."""

    results: dict[str, Any] = {}
    raw: dict[str, float] = {}
    for name, left, right, alternative in HYPOTHESES:
        exact = [score[left] - score[right] for score in scores]
        differences = [float(d) for d in exact]
        low, high = bootstrap_interval(differences)
        raw[name] = sign_flip_p(differences, alternative)
        results[name] = {
            "strategies": [left, right],
            "alternative": alternative,
            "policies": len(differences),
            "mean_difference": _round(statistics.fmean(differences)),
            "median_difference": _round(statistics.median(differences)),
            "bootstrap_95": [_round(low), _round(high)],
            "p_value": round(raw[name], 4),
            "wins": sum(1 for d in exact if d > 0),
            "ties": sum(1 for d in exact if d == 0),
            "losses": sum(1 for d in exact if d < 0),
        }
    for name, adjusted in holm(raw).items():
        results[name]["p_value_holm"] = round(adjusted, 4)
    return results


# ---------------------------------------------------------------------------------------
# Study 1
# ---------------------------------------------------------------------------------------


def expected_scores(analysis: dict[str, Any]) -> dict[str, Fraction] | None:
    live = [m for m in analysis["mutants"] if m["status"] == "live"]
    if not live:
        return None
    scores = {
        strategy: sum((m["change_detection"][strategy] for m in live), Fraction(0)) / len(live)
        for strategy in STRATEGIES
    }
    if scores["refinement"] != 1:
        raise SystemExit("a suite covering the common refinement missed a live mutant")
    return scores


def suite_study(sample: dict[str, Any]) -> dict[str, Any]:
    require_protocol()
    reference = json.loads(REFERENCE_POLICY.read_text(encoding="utf-8"))
    findings: dict[str, Any] = {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "seed": SEED,
        "resamples": RESAMPLES,
        "random_frame": "uniform over the cells of the pooled product space",
        "deviations": [],
        "operator_sets": {},
    }
    for operator_set in OPERATOR_SETS:
        per_policy: list[dict[str, Any]] = []
        scores: list[dict[str, Fraction]] = []
        strata: dict[int, list[dict[str, Fraction]]] = defaultdict(list)
        no_live = 0
        totals = Counter()
        for index, document in enumerate(sample["policies"]):
            analysis = analyse_policy(document, operator_set)
            totals.update(m["status"] for m in analysis["mutants"])
            score = expected_scores(analysis)
            if score is None:
                no_live += 1
                continue
            scores.append(score)
            strata[analysis["decision_range"]].append(score)
            per_policy.append(
                {
                    "policy": index,
                    "cells": analysis["cells"],
                    "quotient_classes": analysis["quotient_classes"],
                    "decision_range": analysis["decision_range"],
                    "expected_score": {s: _round(v) for s, v in score.items()},
                }
            )
        mean = {s: _round(statistics.fmean(float(x[s]) for x in scores)) for s in STRATEGIES}
        reference_analysis = analyse_policy(reference, operator_set)
        reference_score = expected_scores(reference_analysis)
        findings["operator_sets"][operator_set] = {
            "policies_scored": len(scores),
            "policies_without_live_mutants": no_live,
            "mutants": dict(sorted(totals.items())),
            "mean_expected_score": mean,
            "median_suite_size": {
                "refinement": statistics.median(p["cells"] for p in per_policy),
                "quotient": statistics.median(p["quotient_classes"] for p in per_policy),
                "decision": statistics.median(p["decision_range"] for p in per_policy),
            },
            "quotient_score_one": sum(1 for x in scores if x["quotient"] == 1),
            "hypotheses": compare(scores),
            "by_decision_range": {
                str(r): {
                    "policies": len(group),
                    "mean_expected_score": {
                        s: _round(statistics.fmean(float(x[s]) for x in group)) for s in STRATEGIES
                    },
                }
                for r, group in sorted(strata.items())
            },
            "reference_policy": {
                "cells": reference_analysis["cells"],
                "quotient_classes": reference_analysis["quotient_classes"],
                "decision_range": reference_analysis["decision_range"],
                "expected_score": (
                    {s: _round(v) for s, v in reference_score.items()} if reference_score else None
                ),
            },
            "per_policy": per_policy,
        }
    return findings


# ---------------------------------------------------------------------------------------
# Study 2
# ---------------------------------------------------------------------------------------


def tool_signals(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    changes = _policy_changes({"policy": before}, {"policy": after})["changed"]
    signals = policy_review_signals(changes, base_policy=before, head_policy=after)
    return sorted({str(signal.get("rule_id") or signal.get("id")) for signal in signals})


def _ratio(numerator: Fraction | int, denominator: Fraction | int) -> float | None:
    return _round(Fraction(numerator) / Fraction(denominator)) if denominator else None


RESTRICTION = {"allow": 0, "require_approval": 1, "deny": 2}


def direction(document: dict[str, Any], name: str) -> str | None:
    """Which way a decision edit points: the two edits whose direction decides a signal."""

    operator = operator_of(name)
    if operator == "flip_decision":
        rule, after = name[len("flip_decision[") : -1].rsplit("->", 1)
        before = next(r["decision"] for r in document["rules"] if r.get("id") == rule)
        return (
            "to a stricter decision"
            if RESTRICTION[after] > RESTRICTION[before]
            else ("to a more permissive decision")
        )
    if operator == "default_decision":
        after = name[len("default_decision[->") : -1]
        return "to allow" if after == "allow" else "to anything but allow"
    return None


def review_records(
    document: dict[str, Any], operator_set: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    analysis = analyse_policy(document, operator_set)
    records = []
    for mutant in analysis["mutants"]:
        if mutant["status"] == "unrunnable":
            continue
        signals = tool_signals(document, mutant["mutant_document"])
        records.append(
            {
                "direction": direction(document, mutant["mutant"]),
                "operator": operator_of(mutant["mutant"]),
                "change": mutant["status"] == "live",
                "weakening": mutant["cells_weakened"] > 0,
                "signals": signals,
                "change_detection": mutant["change_detection"],
                "weakening_detection": mutant["weakening_detection"],
            }
        )
    return records, analysis


def score_reviewers(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Precision and recall of each reviewer, for each target, pooled over the changes."""

    results: dict[str, Any] = {}
    for target in ("change", "weakening"):
        positives = [r for r in records if r[target]]
        negatives = [r for r in records if not r[target]]

        def tool_flags(record: dict[str, Any], target: str = target) -> bool:
            if target == "change":
                return bool(record["signals"])
            return bool(WEAKENING_SIGNALS.intersection(record["signals"]))

        reviewers: dict[str, Any] = {}
        hits = sum(1 for r in positives if tool_flags(r))
        false_alarms = sum(1 for r in negatives if tool_flags(r))
        reviewers["trustweave_diff"] = {
            "recall": _ratio(hits, len(positives)),
            "precision": _ratio(hits, hits + false_alarms),
            "false_alarms": false_alarms,
            "missed": len(positives) - hits,
        }
        reviewers["text_diff"] = {
            "recall": 1.0 if positives else None,
            "precision": _ratio(len(positives), len(records)),
            "false_alarms": len(negatives),
            "missed": 0,
        }
        for strategy in ("decision", "quotient"):
            expected = sum((r[f"{target}_detection"][strategy] for r in positives), Fraction(0))
            reviewers[f"suite_{strategy}"] = {
                "recall": _ratio(expected, len(positives)),
                "precision": 1.0 if expected else None,
                "false_alarms": 0,
                "missed": _round(len(positives) - expected),
            }
        reviewers["exact_table"] = {
            "recall": 1.0 if positives else None,
            "precision": 1.0 if positives else None,
            "false_alarms": 0,
            "missed": 0,
        }
        by_operator: dict[str, Any] = {}
        for operator in sorted({r["operator"] for r in positives}):
            group = [r for r in positives if r["operator"] == operator]
            by_operator[operator] = {
                "positives": len(group),
                "trustweave_diff_recall": _ratio(
                    sum(1 for r in group if tool_flags(r)), len(group)
                ),
                "suite_decision_recall": _ratio(
                    sum((r[f"{target}_detection"]["decision"] for r in group), Fraction(0)),
                    len(group),
                ),
            }
        results[target] = {
            "changes": len(records),
            "positives": len(positives),
            "reviewers": reviewers,
            "recall_by_operator": by_operator,
        }
    return results


def review_study(sample: dict[str, Any]) -> dict[str, Any]:
    require_protocol()
    reference = json.loads(REFERENCE_POLICY.read_text(encoding="utf-8"))
    findings: dict[str, Any] = {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "weakening_signals": sorted(WEAKENING_SIGNALS),
        "permissiveness": ["deny", "require_approval", "allow"],
        "deviations": [],
        "descriptive_additions": [
            "decision_edits_by_direction: added after the run, to check the two sentences of "
            "the paper that say which decision edits raise no signal; it is a count, not a test"
        ],
        "operator_sets": {},
    }
    for operator_set in OPERATOR_SETS:
        pooled: list[dict[str, Any]] = []
        cells_decided: list[int] = []
        cells_per_change: list[int] = []
        signal_counts: Counter[str] = Counter()
        by_direction: dict[str, Counter[str]] = defaultdict(Counter)
        for document in sample["policies"]:
            records, analysis = review_records(document, operator_set)
            pooled.extend(records)
            cells_decided.append(analysis["cells"])
            cells_per_change.extend(analysis["cells"] for _ in records)
            for record in records:
                signal_counts.update(record["signals"])
                if record["direction"]:
                    outcome = "signalled" if record["signals"] else "silent"
                    by_direction[f"{record['operator']} {record['direction']}"][outcome] += 1
        reference_records, reference_analysis = review_records(reference, operator_set)
        findings["operator_sets"][operator_set] = {
            "generated": score_reviewers(pooled),
            "signals_emitted": dict(sorted(signal_counts.items())),
            "decision_edits_by_direction": {
                key: {"signalled": counts["signalled"], "silent": counts["silent"]}
                for key, counts in sorted(by_direction.items())
            },
            "exact_table_cells_per_change_median": statistics.median(cells_per_change),
            "exact_table_cells_per_policy_median": statistics.median(cells_decided),
            "reference_policy": {
                "cells_per_change": reference_analysis["cells"],
                **score_reviewers(reference_records),
            },
        }
    return findings


# ---------------------------------------------------------------------------------------


def _write(findings: dict[str, Any], path: Path | None) -> None:
    text = json.dumps(findings, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(text)
    else:
        path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sample_command = commands.add_parser("sample", help="draw and record the generated policies")
    sample_command.add_argument("--json", type=Path)
    for name in ("suites", "review"):
        study = commands.add_parser(name)
        study.add_argument("--sample", type=Path, required=True)
        study.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)

    if arguments.command == "sample":
        require_protocol()
        _write(draw_sample(), arguments.json)
        return 0
    sample = json.loads(arguments.sample.read_text(encoding="utf-8"))
    if sample.get("protocol_sha256") != PROTOCOL_SHA256:
        raise SystemExit("the sample was drawn under a different protocol")
    runner = suite_study if arguments.command == "suites" else review_study
    _write(runner(sample), arguments.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
