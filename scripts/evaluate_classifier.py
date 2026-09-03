"""Measure the local source classifier against the labelled benchmark.

Reports per-class precision, recall and F1, the refusal rate, and a confusion matrix, so a
change to the symbol catalog or the refusal rules can be judged by what it costs as well as
by what it gains.

Refusal is scored, not ignored. A classifier that answers everything is not better than one
that abstains when the evidence is genuinely ambiguous, and treating abstention as a failure
would reward guessing. Cases labelled ``undecidable`` are correct precisely when the
classifier refuses them.

Run: python scripts/evaluate_classifier.py [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trustweave.code_analysis import analyze_sources  # noqa: E402
from trustweave.code_sources import collect_python_sources  # noqa: E402

BENCHMARK = ROOT / "benchmark" / "tool-classification"
CLASSES = ("read", "write", "sensitive", "external")
REFUSED = "undecidable"


def _predict(module: Path, tool_name: str) -> str:
    """Return the class the analyzer proposes for *tool_name*, or ``undecidable``."""

    tools, _ = analyze_sources(collect_python_sources(module))
    for tool in tools:
        if tool.name != tool_name:
            continue
        proposed = tool.proposed_action_class()
        return REFUSED if proposed == "unknown" else proposed
    # A tool the discoverer never found cannot be classified either.
    return "not_discovered"


def evaluate() -> dict[str, Any]:
    index = json.loads((BENCHMARK / "benchmark.json").read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for case in index["cases"]:
        predicted = _predict(BENCHMARK / case["module"], case["tool_name"])
        rows.append(
            {
                "id": case["id"],
                "family": case["family"],
                "difficulty": case["difficulty"],
                "expected": case["ground_truth"],
                "predicted": predicted,
                "correct": predicted == case["ground_truth"],
                "annotators_agree": case.get("annotators_agree"),
            }
        )

    labels = (*CLASSES, REFUSED, "not_discovered")
    matrix = {expected: Counter() for expected in (*CLASSES, REFUSED)}
    for row in rows:
        matrix[row["expected"]][row["predicted"]] += 1

    per_class: dict[str, dict[str, float | int]] = {}
    for label in (*CLASSES, REFUSED):
        true_positive = matrix[label][label]
        predicted_total = sum(matrix[other][label] for other in matrix)
        actual_total = sum(matrix[label].values())
        precision = true_positive / predicted_total if predicted_total else 0.0
        recall = true_positive / actual_total if actual_total else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {
            "support": actual_total,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    decidable = [row for row in rows if row["expected"] != REFUSED]
    answered = [row for row in decidable if row["predicted"] in CLASSES]
    correct_answered = [row for row in answered if row["correct"]]
    agreed = [row for row in rows if row["annotators_agree"] is True]

    return {
        "schema_version": "trustweave.dev/classification-evaluation/v1alpha1",
        "cases": len(rows),
        "overall": {
            "accuracy": round(sum(row["correct"] for row in rows) / len(rows), 4),
            "accuracy_on_agreed_labels_only": (
                round(sum(row["correct"] for row in agreed) / len(agreed), 4) if agreed else None
            ),
            # Of the cases a human could decide, how many did the analyzer attempt?
            "answer_rate_on_decidable": round(len(answered) / len(decidable), 4),
            # When it does answer, how often is it right? This is the number that matters:
            # a wrong confident answer is worse than a refusal.
            "precision_when_answering": (
                round(len(correct_answered) / len(answered), 4) if answered else None
            ),
            "refusal_rate": round(
                sum(1 for row in rows if row["predicted"] == REFUSED) / len(rows), 4
            ),
            "not_discovered": sum(1 for row in rows if row["predicted"] == "not_discovered"),
        },
        "per_class": per_class,
        "by_difficulty": {
            level: round(
                sum(row["correct"] for row in rows if row["difficulty"] == level)
                / max(1, sum(1 for row in rows if row["difficulty"] == level)),
                4,
            )
            for level in ("easy", "medium", "hard")
        },
        "confusion": {
            expected: {
                label: matrix[expected][label] for label in labels if matrix[expected][label]
            }
            for expected in matrix
        },
        "failures": [
            {k: row[k] for k in ("id", "family", "difficulty", "expected", "predicted")}
            for row in rows
            if not row["correct"]
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="Write the full report to this path.")
    arguments = parser.parse_args()

    report = evaluate()
    overall = report["overall"]
    print(f"cases: {report['cases']}")
    print(f"  accuracy                 {overall['accuracy']:.3f}")
    print(f"  accuracy (agreed labels) {overall['accuracy_on_agreed_labels_only']}")
    print(f"  answer rate (decidable)  {overall['answer_rate_on_decidable']:.3f}")
    print(f"  precision when answering {overall['precision_when_answering']}")
    print(f"  refusal rate             {overall['refusal_rate']:.3f}")
    print(f"  never discovered         {overall['not_discovered']}")
    print("\nper class:")
    for label, scores in report["per_class"].items():
        print(
            f"  {label:12} n={scores['support']:<3} "
            f"P={scores['precision']:.3f} R={scores['recall']:.3f} F1={scores['f1']:.3f}"
        )
    print("\nby difficulty:", report["by_difficulty"])
    print(f"\nfailures: {len(report['failures'])}")
    for failure in report["failures"]:
        print(f"  {failure['id']:9} {failure['expected']:12} -> {failure['predicted']}")

    if arguments.json:
        arguments.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
