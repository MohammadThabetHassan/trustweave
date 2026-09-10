"""Enforce the mutation quality threshold and the survivor-triage parity gate.

The gate lives here rather than inline in .github/workflows/mutation.yml so that the
checks CI runs are the checks a contributor can run locally, byte for byte, before
pushing. An inventory that satisfies this script satisfies the workflow.

Usage:
    python scripts/mutation_gate.py --run-log mutation-run.log \
        --results mutation-results.txt --evidence mutation-quality.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

THRESHOLD_PERCENT = 95
ALLOWED_CLASSIFICATIONS = {"equivalent", "defensive", "needs_regression"}
REQUIRED_TOP_LEVEL = {
    "schema_version",
    "mutation_run",
    "survivor_count",
    "untriaged_count",
    "classification_counts",
    "survivors",
}
TOTALS_PATTERN = r"(\d+)/(\d+).*?🎉\s+(\d+).*?🙁\s+(\d+)"
SURVIVOR_PATTERN = r"^\s*([A-Za-z0-9_.]+__mutmut_\d+): survived$"
RESULT_PATTERN = r"^\s*([A-Za-z0-9_.]+)__mutmut_\d+: (\w[\w ]*)$"
DEFAULT_TRIAGE = Path("docs/mutation-survivor-triage-v1.json")
DEFAULT_RATCHET = Path("docs/mutation-ratchet-v1.json")
# Modules mutated on every run and held to a floor, but not to the survivor-triage gate.
# The strict gate needs a recorded proof for every survivor; these have too many for that
# to be written honestly, and running them under no control at all is the worse option.
RATCHETED_MODULES = ("trustweave.code_analysis",)


def module_of(identifier: str) -> str:
    """`trustweave.chain.x_render__mutmut_4` -> `trustweave.chain`."""

    qualified = identifier.rsplit("__mutmut_", 1)[0]
    return qualified.rsplit(".", 1)[0]


def partition(results: str) -> tuple[dict[str, Counter[str]], dict[str, Counter[str]]]:
    """Per-module outcome counts, split into the gated modules and the ratcheted ones."""

    gated: dict[str, Counter[str]] = defaultdict(Counter)
    ratcheted: dict[str, Counter[str]] = defaultdict(Counter)
    for qualified, status in re.findall(RESULT_PATTERN, results, re.MULTILINE):
        module = qualified.rsplit(".", 1)[0]
        target = ratcheted if module in RATCHETED_MODULES else gated
        target[module][status.strip()] += 1
    return dict(gated), dict(ratcheted)


def check_ratchet(
    ratcheted: dict[str, Counter[str]], floors: dict[str, Any]
) -> tuple[list[str], dict[str, Any]]:
    """Every ratcheted module must hold the rate its record names, or better."""

    failures: list[str] = []
    measured: dict[str, Any] = {}
    for module in sorted(RATCHETED_MODULES):
        counts = ratcheted.get(module)
        recorded = floors.get(module)
        if recorded is None and not counts:
            # Nothing declared and nothing produced: there is no claim to check.
            continue
        if not counts:
            failures.append(
                f"Ratcheted module has a recorded floor but produced no mutants: {module}"
            )
            continue
        total = sum(counts.values())
        killed = counts.get("killed", 0)
        rate = killed / total
        measured[module] = {
            "generated": total,
            "killed": killed,
            "score_percent": round(rate * 100, 4),
        }
        if recorded is None:
            failures.append(f"Ratcheted module has no recorded floor: {module}")
            continue
        floor = recorded["score_percent"] / 100
        if rate < floor:
            failures.append(
                f"Mutation ratchet failed for {module}: "
                f"{killed}/{total} ({rate:.2%}) below the recorded {floor:.2%}"
            )
    return failures, measured


class GateFailure(Exception):
    """A gate condition was not met. The message is the operator-facing reason."""


def parse_totals(run_output: str) -> tuple[int, int, int]:
    """Return (generated, killed, survived) from the run's final progress line."""
    matches = re.findall(TOTALS_PATTERN, run_output.replace("\r", "\n"))
    if not matches:
        raise GateFailure(
            "Mutation run output did not contain final generated, killed, and survived totals"
        )
    completed, generated, killed, survived = (int(value) for value in matches[-1])
    if completed != generated:
        raise GateFailure(f"Mutation run did not complete: {completed}/{generated}")
    # killed + survived need not equal generated: a mutant can also be reported as having
    # no covering test. That is forbidden in the gated scope and checked per module below,
    # because a gated module with uncovered mutants is a gap the triage cannot describe.
    if killed + survived > generated:
        raise GateFailure(
            "Mutation totals are inconsistent: "
            f"generated={generated}, killed={killed}, survived={survived}"
        )
    return generated, killed, survived


def check_gated_threshold(gated: dict[str, Counter[str]]) -> dict[str, Any]:
    """The threshold is over the gated modules, not the whole run.

    A ratcheted module is mutated in the same run and held to a floor instead, so folding
    it into this total would let a large weak module drag the gated ones under the line, or
    be carried by them.
    """

    generated = sum(sum(counts.values()) for counts in gated.values())
    killed = sum(counts.get("killed", 0) for counts in gated.values())
    if not generated:
        raise GateFailure("No gated module produced any mutant")
    uncovered = {
        module: dict(counts)
        for module, counts in gated.items()
        if set(counts) - {"killed", "survived"}
    }
    if uncovered:
        raise GateFailure(
            "Gated modules have mutants with no covering test, which the survivor triage "
            f"cannot account for: {uncovered}"
        )
    if killed * 100 < generated * THRESHOLD_PERCENT:
        raise GateFailure(
            f"Mutation quality gate failed: {killed}/{generated} killed "
            f"({killed * 100 / generated:.2f}%) < {THRESHOLD_PERCENT}% over the gated scope"
        )
    return {
        "generated": generated,
        "killed": killed,
        "score_percent": round(killed * 100 / generated, 4),
    }


def parse_survivors(result_output: str, survived: int) -> list[str]:
    """Return the survivor identifiers, cross-checked against the run's own total."""
    survivors = re.findall(SURVIVOR_PATTERN, result_output, re.MULTILINE)
    if len(survivors) != survived:
        raise GateFailure(
            "Mutation result survivor count does not equal final run total: "
            f"results={len(survivors)}, run={survived}"
        )
    if len(set(survivors)) != len(survivors):
        raise GateFailure("Mutation results contain duplicate survivor identifiers")
    return survivors


def normalized_diff(text: str) -> str:
    """Drop mutmut's `# <id>: survived` banner so digests pin only the diff body."""
    lines = text.splitlines(keepends=True)
    if lines and lines[0].startswith("# ") and ": survived" in lines[0]:
        lines = lines[1:]
    return "".join(lines)


def diff_digest(text: str) -> str:
    return hashlib.sha256(normalized_diff(text).encode("utf-8")).hexdigest()


def load_inventory(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise GateFailure(f"Missing survivor triage inventory: {path}")
    inventory = json.loads(path.read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_TOP_LEVEL - set(inventory))
    if missing:
        raise GateFailure(f"Survivor triage inventory is missing fields: {missing}")
    if not isinstance(inventory["survivors"], list):
        raise GateFailure("Survivor triage inventory survivors must be a list")
    return inventory


def check_identifier_parity(inventory: dict[str, Any], survivors: Sequence[str]) -> list[str]:
    """Require the inventory to name exactly the survivors this run produced."""
    records = inventory["survivors"]
    triage_ids = [record.get("id") for record in records if isinstance(record, dict)]
    if len(triage_ids) != len(records) or any(not isinstance(item, str) for item in triage_ids):
        raise GateFailure("Every survivor triage record must have a string id")
    if len(set(triage_ids)) != len(triage_ids):
        raise GateFailure("Survivor triage inventory contains duplicate mutant ids")
    if set(triage_ids) != set(survivors):
        missing = sorted(set(survivors) - set(triage_ids))
        stale = sorted(set(triage_ids) - set(survivors))
        raise GateFailure(
            f"Survivor-triage exact identifier parity failed: missing={missing}; stale={stale}"
        )
    if inventory["survivor_count"] != len(records):
        raise GateFailure(
            "Survivor triage count is inconsistent: "
            f"declared={inventory['survivor_count']}, actual={len(records)}"
        )
    if inventory["untriaged_count"] != 0:
        raise GateFailure(
            f"Survivor triage inventory has unresolved entries: {inventory['untriaged_count']}"
        )
    return triage_ids


def check_records(inventory: dict[str, Any]) -> tuple[Counter[str], dict[str, int]]:
    """Validate every record's classification, rationale and diff; return their digests."""
    classifications: list[str] = []
    digests: Counter[str] = Counter()
    for record in inventory["survivors"]:
        identifier = record["id"]
        diff = record.get("diff")
        if not isinstance(diff, str) or not diff.strip():
            raise GateFailure(f"Survivor triage diff is empty for {identifier!r}")
        digests[diff_digest(diff)] += 1
        classification = record.get("classification")
        if classification not in ALLOWED_CLASSIFICATIONS:
            raise GateFailure(
                f"Invalid survivor classification for {identifier!r}: {classification!r}"
            )
        rationale = record.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise GateFailure(f"Survivor triage rationale is empty for {identifier!r}")
        classifications.append(classification)
    actual = Counter(classifications)
    expected = {label: actual.get(label, 0) for label in sorted(ALLOWED_CLASSIFICATIONS)}
    if inventory["classification_counts"] != expected:
        raise GateFailure(
            "Survivor triage classification counts are inconsistent: "
            f"declared={inventory['classification_counts']}, actual={expected}"
        )
    return digests, expected


def current_diff_digests(survivors: Sequence[str], mutmut: str) -> Counter[str]:
    """Ask mutmut to re-render every survivor so the pinned diffs cannot drift."""
    digests: Counter[str] = Counter()
    for identifier in survivors:
        shown = subprocess.run(
            [mutmut, "show", identifier], check=True, capture_output=True, text=True
        )
        digests[diff_digest(shown.stdout)] += 1
    return digests


def check_diff_parity(triage_digests: Counter[str], current: Counter[str]) -> None:
    if triage_digests != current:
        missing = sorted((current - triage_digests).elements())
        stale = sorted((triage_digests - current).elements())
        raise GateFailure(
            "Survivor-triage exact diff parity failed: "
            f"missing_diff_digests={missing}; stale_diff_digests={stale}"
        )


def run_gate(
    run_log: Path,
    results: Path,
    triage_path: Path,
    mutmut: str,
    ratchet_path: Path | None = None,
) -> dict[str, Any]:
    """Run every gate condition and return the evidence record on success."""
    generated, killed, survived = parse_totals(run_log.read_text(encoding="utf-8"))
    result_text = results.read_text(encoding="utf-8")
    all_survivors = parse_survivors(result_text, survived)
    gated, ratcheted = partition(result_text)
    gated_totals = check_gated_threshold(gated)
    # Only the gated modules are held to exact survivor parity. A ratcheted module's
    # survivors are counted, never excused, and no proof is claimed for any of them.
    survivors = [
        identifier for identifier in all_survivors if module_of(identifier) not in RATCHETED_MODULES
    ]
    inventory = load_inventory(triage_path)
    check_identifier_parity(inventory, survivors)
    triage_digests, counts = check_records(inventory)
    check_diff_parity(triage_digests, current_diff_digests(survivors, mutmut))
    unresolved = counts.get("needs_regression", 0)
    if unresolved:
        raise GateFailure(
            f"Mutation survivor gate failed: {unresolved} needs_regression classifications remain"
        )
    floors: dict[str, Any] = {}
    if ratchet_path is not None and ratchet_path.is_file():
        floors = json.loads(ratchet_path.read_text(encoding="utf-8"))["modules"]
    ratchet_failures, ratchet_measured = check_ratchet(ratcheted, floors)
    if ratchet_failures:
        raise GateFailure("; ".join(ratchet_failures))

    return {
        "generated": generated,
        "killed": killed,
        "survived": survived,
        "score_percent": round(killed * 100 / generated, 4),
        "gated_generated": gated_totals["generated"],
        "gated_killed": gated_totals["killed"],
        "gated_score_percent": gated_totals["score_percent"],
        "ratcheted_modules": ratchet_measured,
        "threshold_percent": THRESHOLD_PERCENT,
        "triage_survivor_count": len(inventory["survivors"]),
        "triage_untriaged_count": inventory["untriaged_count"],
        "triage_classification_counts": counts,
        "survivor_identifier_parity": "exact",
        "survivor_triage_parity": "exact_normalized_diff",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-log", type=Path, default=Path("mutation-run.log"))
    parser.add_argument("--results", type=Path, default=Path("mutation-results.txt"))
    parser.add_argument("--triage", type=Path, default=DEFAULT_TRIAGE)
    parser.add_argument("--evidence", type=Path, default=Path("mutation-quality.json"))
    parser.add_argument("--mutmut", default="mutmut", help="mutmut executable to re-render diffs")
    parser.add_argument("--ratchet", type=Path, default=DEFAULT_RATCHET)
    args = parser.parse_args(argv)

    try:
        evidence = run_gate(args.run_log, args.results, args.triage, args.mutmut, args.ratchet)
    except GateFailure as failure:
        print(str(failure), file=sys.stderr)
        return 1

    args.evidence.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
