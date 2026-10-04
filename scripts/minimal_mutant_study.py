"""The payoff over subsumption-minimal mutants.

Under `docs/MINIMAL_MUTANTS_PROTOCOL.md` (hashed below). Inside the fragment every mutant is
constant on each witness cell, so a live mutant's difference set over the cells is exact, and
one mutant subsumes another exactly when its difference set is a subset of the other's. This
rescores the payoff studies' suites and the criteria study's, unchanged, over each policy's
subsumption-minimal mutants, after reproducing all three studies over every live mutant.

CLI:
    python scripts/minimal_mutant_study.py study --cache DIR --workers 6 --json OUT
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import multiprocessing
import statistics
import sys
from collections import defaultdict
from collections.abc import Callable, Sequence
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "MINIMAL_MUTANTS_PROTOCOL.md"
# Fixed when the protocol was committed (5e66b1f), before the study ran on any policy.
PROTOCOL_SHA256 = "3e7404773b2461689c2f2a275f09fcbcea36b1f8f8824df09cb3ad0cb00711bf"
SEED = 20261004
PAYOFF = ("quotient", "random_quotient", "decision", "random_decision")

# Corrections after the first run, kept so the record is whole.
IMPLEMENTATION_NOTES = (
    "The first run looked the criteria study's decision coverage up among the payoff "
    'studies\' strategies, where "decision" names the decision proxy, so its Q_decision^m '
    "tested the quotient against the proxy a second time, and the per-policy record let the "
    "proxy's score overwrite decision coverage's. Each strategy is now named with the study it "
    "comes from, and a criterion is compared with the quotient's score from the same study, "
    "both at six decimals, so a tie is a tie: the first run took the quotient's exact score and "
    "counted rounding differences as wins and losses (8 of MC/DC's 300 comparisons as losses). "
    "Every mean, interval and p value other than Q_decision^m's is the same as in that run.",
)

if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))


def _load(name: str) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def protocol_digest(path: Path = PROTOCOL) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def require_protocol() -> None:
    found = protocol_digest()
    if found != PROTOCOL_SHA256:
        raise SystemExit(
            f"{PROTOCOL.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the "
            "study ran; a changed protocol is a different study, so this one refuses to run"
        )


# --- minimal mutants ---------------------------------------------------------------------------


def minimal(live: Sequence[set[int]]) -> list[set[int]]:
    """The subsumption-minimal difference sets: identical sets once, and none with a strict
    subset among the others.

    Taken smallest first, a set is minimal exactly when no minimal set already kept is inside
    it: a strict subset that is not minimal has a minimal one inside it, kept before.
    """

    representative: dict[int, set[int]] = {}
    for hits in live:
        mask = 0
        for cell in hits:
            mask |= 1 << cell
        representative.setdefault(mask, hits)
    kept: list[int] = []
    for mask in sorted(representative, key=lambda m: (bin(m).count("1"), m)):
        if not any(k & mask == k for k in kept):
            kept.append(mask)
    return [representative[mask] for mask in kept]


# --- the spaces, with the decision each cell gets ----------------------------------------------


def generated_space(document: dict[str, Any]) -> tuple[Any, list[list[int]]]:
    """The criteria study's space for a generated policy, and its cells grouped by decision."""

    ccs = _load("combination_criteria_study")
    ees = _load("exact_evaluation_study")
    harness = ees.harness
    mutants = ees.OPERATOR_SETS["A"](document)
    space = harness.witness_space(document, *(m for _, m in mutants))
    cells = harness.cells_of(space)
    policy = ees.parse_policy(document)
    decided = harness.decision_map(document, space)
    reference = [decided[cell] for cell in cells]
    classes: dict[tuple[Any, ...], list[int]] = defaultdict(list)
    by_decision: dict[Any, list[int]] = defaultdict(list)
    for position, cell in enumerate(cells):
        classes[harness.predicate_signature(policy, cell)].append(position)
        by_decision[reference[position]].append(position)
    live: list[set[int]] = []
    for _, mutant in mutants:
        try:
            resolved = harness.decision_map(mutant, space)
        except Exception:  # noqa: BLE001 - as the study: a mutant the parser refuses is no policy
            continue
        changed = {p for p, cell in enumerate(cells) if resolved[cell] != reference[p]}
        if changed:
            live.append(changed)
    width = len(next(iter(classes)))
    rules = len(policy.rules)
    assert rules and width % rules == 0, (width, rules)
    found = ccs.Space(len(cells), dict(classes), live, rules=rules, dimensions=width // rules)
    return found, list(by_decision.values())


def cedar_space(est: dict[str, Any]) -> tuple[Any, list[list[int]]]:
    """The criteria study's space for a Cedar file, and its requests grouped by decision."""

    ccs = _load("combination_criteria_study")
    ces = _load("cedar_exact_study")
    cedarpy, _ = ces._cedar()
    found = ces.observables_of(est)
    space = ces.WitnessSpace(found, cap=ces.MAX_CELLS)
    assert space.size() <= ces.MAX_CELLS
    original = cedarpy.PolicySet.from_json_str(json.dumps(est))
    made = [
        request
        for index, cell in enumerate(space.cells())
        if (request := ces.request_of(space, cell, str(index))) is not None
    ]
    batches = ces.batches_of(made)
    reference = [decision for decision, _ in ces.evaluate(original, batches, len(made))]
    atoms = [ces.parsed(text) for text in ces.atoms_of(est)]
    classes: dict[tuple[Any, ...], list[int]] = defaultdict(list)
    for position, signature in enumerate(ces._signatures(atoms, batches, len(made))):
        classes[signature].append(position)
    by_decision: dict[Any, list[int]] = defaultdict(list)
    for position, decision in enumerate(reference):
        by_decision[decision].append(position)
    live: list[set[int]] = []
    for _, mutated in ces.mutants_of(est, found):
        try:
            mutant = cedarpy.PolicySet.from_json_str(json.dumps(mutated))
        except Exception:  # noqa: BLE001 - as the study: an edit Cedar cannot read is no policy
            continue
        resolved = [decision for decision, _ in ces.evaluate(mutant, batches, len(made))]
        changed = {p for p, d in enumerate(resolved) if d != reference[p]}
        if changed:
            live.append(changed)
    return ccs.Space(len(made), dict(classes), live), list(by_decision.values())


# --- one policy --------------------------------------------------------------------------------


def payoff(space: Any, decisions: list[list[int]], live: Sequence[set[int]]) -> dict[str, Fraction]:
    """The payoff studies' four strategies, mean expected detection over the given mutants."""

    ccs = _load("combination_criteria_study")
    groups = list(space.classes.values())
    n = len(live)
    return {
        "quotient": sum((ccs.detection(groups, h) for h in live), Fraction(0)) / n,
        "random_quotient": sum(
            (ccs.random_detection(space.cells, len(h), len(groups)) for h in live), Fraction(0)
        )
        / n,
        "decision": sum((ccs.detection(decisions, h) for h in live), Fraction(0)) / n,
        "random_decision": sum(
            (ccs.random_detection(space.cells, len(h), len(decisions)) for h in live),
            Fraction(0),
        )
        / n,
    }


def analyse(space: Any, decisions: list[list[int]], label: str) -> dict[str, Any]:
    """Every strategy over all live mutants and over the minimal ones; the suites are the same."""

    ccs = _load("combination_criteria_study")
    every = ccs.score_space(space, label)
    reduced_live = minimal(space.live)
    reduced = ccs.Space(
        space.cells, space.classes, reduced_live, rules=space.rules, dimensions=space.dimensions
    )
    least = ccs.score_space(reduced, label)
    return {
        "status": "scored",
        "live_mutants": len(space.live),
        "minimal_mutants": len(reduced_live),
        "all": {
            **every,
            "payoff": {k: str(v) for k, v in payoff(space, decisions, space.live).items()},
        },
        "minimal": {
            **least,
            "payoff": {k: str(v) for k, v in payoff(space, decisions, reduced_live).items()},
        },
    }


def _generated_task(task: tuple[int, str]) -> tuple[int, dict[str, Any]]:
    index, document_json = task
    space, decisions = generated_space(json.loads(document_json))
    if not space.live:
        return index, {"status": "no live mutants"}
    return index, analyse(space, decisions, f"generated:{index}")


def _cedar_task(task: tuple[str, str]) -> tuple[str, dict[str, Any]]:
    subject, est_json = task
    space, decisions = cedar_space(json.loads(est_json))
    if not space.live:
        return subject, {"status": "no live mutants"}
    return subject, analyse(space, decisions, f"cedar:{subject}")


# --- the populations ---------------------------------------------------------------------------


def _run(function: Callable[[Any], Any], tasks: list[Any], workers: int) -> dict[Any, Any]:
    results: dict[Any, Any] = {}
    if workers <= 1:
        for task in tasks:
            key, value = function(task)
            results[key] = value
        return results
    context = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(workers, mp_context=context) as pool:
        for key, value in pool.map(function, tasks, chunksize=1):
            results[key] = value
            print(f"  {len(results)}/{len(tasks)}", file=sys.stderr, flush=True)
    return results


def _round(value: float) -> float:
    return round(value, 6)


def _payoff_means(records: list[dict[str, Any]], which: str) -> dict[str, float]:
    """As the payoff studies take them: the mean of each policy's exact score, rounded once."""

    return {
        s: _round(statistics.fmean(float(Fraction(r[which]["payoff"][s])) for r in records))
        for s in PAYOFF
    }


def _criteria_view(records: list[dict[str, Any]], which: str) -> dict[Any, dict[str, Any]]:
    return {i: {"status": "scored", **r[which]} for i, r in enumerate(records)}


def hypotheses(records: list[dict[str, Any]], criteria: Sequence[str]) -> dict[str, Any]:
    """H1m, H2m and every Q_s^m over minimal mutants, one Holm family per population."""

    ees = _load("exact_evaluation_study")

    # A strategy is named with the study it comes from: "decision" is the payoff studies'
    # proxy there and decision coverage in the criteria study.
    def value(record: dict[str, Any], strategy: tuple[str, str]) -> float:
        source, name = strategy
        minimal_record = record["minimal"]
        if source == "payoff":
            return float(Fraction(minimal_record["payoff"][name]))
        return float(minimal_record["scores"][name])

    pairs = {
        "H1m": (("payoff", "quotient"), ("payoff", "random_quotient")),
        "H2m": (("payoff", "quotient"), ("payoff", "decision")),
    }
    pairs.update({f"Q_{s}^m": (("criteria", "quotient"), ("criteria", s)) for s in criteria})
    raw: dict[str, float] = {}
    results: dict[str, Any] = {}
    for name, (left, right) in pairs.items():
        differences = [value(r, left) - value(r, right) for r in records]
        low, high = ees.bootstrap_interval(differences, seed=SEED)
        raw[name] = ees.sign_flip_p(differences, "greater", seed=SEED)
        results[name] = {
            "mean_difference": _round(statistics.fmean(differences)),
            "bootstrap_95": [_round(low), _round(high)],
            "p_value": round(raw[name], 4),
            "higher": sum(1 for d in differences if d > 0),
            "ties": sum(1 for d in differences if d == 0),
            "lower": sum(1 for d in differences if d < 0),
        }
    for name, adjusted in ees.holm(raw).items():
        results[name]["p_value_holm"] = round(adjusted, 4)
    return results


def summarise(
    records: dict[Any, dict[str, Any]],
    criteria: Sequence[str],
    payoff_reference: dict[str, Any],
    criteria_reference: dict[str, Any],
) -> dict[str, Any]:
    ccs = _load("combination_criteria_study")
    scored = [records[k] for k in sorted(records) if records[k]["status"] == "scored"]
    every_payoff = _payoff_means(scored, "all")
    every_criteria = ccs.summarise(_criteria_view(scored, "all"), criteria)
    keys = ("mean_score", "mean_random_score", "mean_size")
    reproduced = {
        "payoff": every_payoff == {s: payoff_reference[s] for s in PAYOFF},
        "criteria": all(every_criteria[k] == criteria_reference[k] for k in keys),
    }
    least_criteria = ccs.summarise(_criteria_view(scored, "minimal"), criteria)
    sizes = [r["minimal_mutants"] for r in scored]
    return {
        "policies_scored": len(scored),
        "reproduced": reproduced,
        "live_mutants": sum(r["live_mutants"] for r in scored),
        "minimal_mutants": sum(sizes),
        "minimal_set_size": {
            "min": min(sizes),
            "median": statistics.median(sizes),
            "max": max(sizes),
            "policies_with_one": sum(1 for s in sizes if s == 1),
            "policies_with_two": sum(1 for s in sizes if s == 2),
        },
        "all_mutants": {
            "payoff": every_payoff,
            "criteria_mean_score": every_criteria["mean_score"],
        },
        "minimal": {
            "payoff": _payoff_means(scored, "minimal"),
            "criteria_mean_score": least_criteria["mean_score"],
            "criteria_mean_random_score": least_criteria["mean_random_score"],
            "certain_detection_mean": least_criteria["certain_detection_mean"],
        },
        "hypotheses": hypotheses(scored, criteria) if all(reproduced.values()) else None,
    }


def study(cache: Path, workers: int) -> dict[str, Any]:
    require_protocol()
    ccs = _load("combination_criteria_study")
    sample = json.loads((DOCS / "generated-policy-sample-v1.json").read_text("utf-8"))
    payoff_artifact = json.loads((DOCS / "suite-strategy-study-v1.json").read_text("utf-8"))
    cedar_artifact = json.loads((DOCS / "cedar-suite-strategy-study-v1.json").read_text("utf-8"))
    criteria_artifact = json.loads((DOCS / "combination-criteria-study-v1.json").read_text("utf-8"))
    generated = _run(
        _generated_task, [(i, json.dumps(d)) for i, d in enumerate(sample["policies"])], workers
    )
    cedar = _run(_cedar_task, ccs.cedar_population(cache), workers)
    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "seed": SEED,
        "definition": (
            "a live mutant is minimal when no other live mutant's difference set is a strict "
            "subset of its own; identical difference sets count once"
        ),
        "deviations": [],
        "implementation_notes": list(IMPLEMENTATION_NOTES),
        "populations": {
            "generated": summarise(
                generated,
                (*ccs.COMBINATION, *ccs.STRUCTURAL),
                payoff_artifact["operator_sets"]["A"]["mean_expected_score"],
                criteria_artifact["populations"]["generated"],
            ),
            "cedar": summarise(
                cedar,
                ccs.COMBINATION,
                cedar_artifact["analyses"]["primary: files with a condition"][
                    "mean_expected_score"
                ],
                criteria_artifact["populations"]["cedar"],
            ),
        },
        "per_policy": {
            "generated": [{"policy": i, **_compact(generated[i])} for i in sorted(generated)],
            "cedar": {s: _compact(cedar[s]) for s in sorted(cedar)},
        },
    }


def _compact(record: dict[str, Any]) -> dict[str, Any]:
    if record["status"] != "scored":
        return record
    return {
        "live_mutants": record["live_mutants"],
        "minimal_mutants": record["minimal_mutants"],
        "minimal_criteria_scores": record["minimal"]["scores"],
        "minimal_payoff_scores": {
            k: _round(float(Fraction(v))) for k, v in record["minimal"]["payoff"].items()
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("study")
    run.add_argument("--cache", type=Path, required=True)
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--json", type=Path, required=True)
    arguments = parser.parse_args(argv)
    result = study(arguments.cache, arguments.workers)
    arguments.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, population in result["populations"].items():
        print(
            name, json.dumps(population["reproduced"]), json.dumps(population["minimal"]["payoff"])
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
