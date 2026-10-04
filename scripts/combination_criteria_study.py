"""Established selection criteria against the quotient, at matched size.

Under `docs/COMBINATION_CRITERIA_PROTOCOL.md`, fixed and hashed before any outcome was computed.
One witness per quotient class is all-combinations coverage over a policy's guard atoms; this
scores the cheaper combination strategies -- each choice, base choice, pairwise, three-wise -- and,
where rules are explicit, rule, decision and MC/DC coverage, on the paper's generated and Cedar
populations, with every mutant's detection computed in rational arithmetic as the earlier studies
compute it for the quotient.

    python scripts/combination_criteria_study.py reference --json OUT
    python scripts/combination_criteria_study.py study --cache DIR --workers 6 \
        --json docs/combination-criteria-study-v1.json

`reference` is the development run: the reference policy, reported apart. `study` runs both
populations; the Cedar files are read from `--cache`, fetched there at their pinned commits when
absent, and checked against their recorded digests.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import itertools
import json
import multiprocessing
import random
import statistics
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "COMBINATION_CRITERIA_PROTOCOL.md"
# Fixed when the protocol was committed (267c9c1), before any outcome was computed.
PROTOCOL_SHA256 = "34848d864ff5caf6a23412a26731f6b693ca3f303a3c306b5fb6bac9eca86750"
SEED = 20261004
CONSTRUCTIONS = 100
REFERENCE_POLICY = ROOT / "policies" / "default-policy.json"

COMBINATION = ("each_choice", "base_choice", "pairwise", "three_wise")
STRUCTURAL = ("rule", "decision", "mcdc")
# How each implementation choice the protocol leaves open was settled, before the run.
IMPLEMENTATION_NOTES = (
    "A t-wise strategy over fewer than t factors covers every combination of the factors there "
    "are, which is the quotient.",
    "A combination strategy whose cover needs no class (a policy with no factor) takes one "
    "class, the first in the seeded order, so that no suite is empty.",
    "A structural criterion's suite size is its number of feasible requirements; two "
    "requirements may draw the same cell.",
)


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
            f"{PROTOCOL.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the study "
            "ran; a changed protocol is a different study, so this one refuses to run"
        )


# --- one policy's space ------------------------------------------------------------------------


@dataclass
class Space:
    """Cells, the quotient's classes keyed by atom vector, and every live mutant's difference."""

    cells: int
    classes: dict[tuple[Any, ...], list[int]]
    live: list[set[int]]
    rules: int | None = None  # set when the rule structure is explicit
    dimensions: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def generated_space(document: dict[str, Any]) -> Space:
    """`exact_evaluation_study.analyse_policy`'s space, keeping what that function discards."""

    ees = _load("exact_evaluation_study")
    harness = ees.harness
    mutants = ees.OPERATOR_SETS["A"](document)
    space = harness.witness_space(document, *(m for _, m in mutants))
    cells = harness.cells_of(space)
    policy = ees.parse_policy(document)
    decided = harness.decision_map(document, space)
    reference = [decided[cell] for cell in cells]
    classes: dict[tuple[Any, ...], list[int]] = defaultdict(list)
    for position, cell in enumerate(cells):
        classes[harness.predicate_signature(policy, cell)].append(position)
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
    return Space(len(cells), dict(classes), live, rules=rules, dimensions=width // rules)


def cedar_space(est: dict[str, Any]) -> Space:
    """`cedar_exact_study.analyse_file`'s space, keeping what that function discards."""

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
    return Space(len(made), dict(classes), live)


# --- factors and strategies --------------------------------------------------------------------


def factor_positions(keys: Sequence[tuple[Any, ...]]) -> list[int]:
    """Positions that vary over the classes, a position identical to an earlier one dropped."""

    if not keys:
        return []
    seen: set[tuple[Any, ...]] = set()
    kept: list[int] = []
    for position in range(len(keys[0])):
        column = tuple(key[position] for key in keys)
        if len(set(column)) < 2 or column in seen:
            continue
        seen.add(column)
        kept.append(position)
    return kept


def coverage_bits(keys: Sequence[tuple[Any, ...]], factors: Sequence[int], t: int) -> list[int]:
    """For each class, the set of t-wise requirements it covers, as a bit set."""

    width = min(t, len(factors))
    ids: dict[tuple[Any, ...], int] = {}
    bits: list[int] = []
    for key in keys:
        mask = 0
        for chosen in itertools.combinations(factors, width):
            requirement = (chosen, tuple(key[p] for p in chosen))
            index = ids.setdefault(requirement, len(ids))
            mask |= 1 << index
        bits.append(mask)
    return bits


def greedy_cover(bits: Sequence[int], generator: random.Random) -> list[int]:
    """Classes chosen greedily until every requirement any class covers is covered."""

    order = list(range(len(bits)))
    generator.shuffle(order)
    uncovered = 0
    for mask in bits:
        uncovered |= mask
    chosen: list[int] = []
    while uncovered:
        best, gain = -1, 0
        for index in order:
            found = (bits[index] & uncovered).bit_count()
            if found > gain:
                best, gain = index, found
        chosen.append(best)
        uncovered &= ~bits[best]
    return chosen or order[:1]


def base_choice(
    keys: Sequence[tuple[Any, ...]],
    sizes: Sequence[int],
    factors: Sequence[int],
    generator: random.Random,
) -> list[int]:
    order = list(range(len(keys)))
    generator.shuffle(order)
    base = max(order, key=lambda index: sizes[index])
    chosen = {base}
    for position in factors:
        for value in sorted({key[position] for key in keys} - {keys[base][position]}, key=repr):
            best, distance = -1, len(factors) + 1
            for index in order:
                if keys[index][position] != value:
                    continue
                apart = sum(1 for p in factors if keys[index][p] != keys[base][p])
                if apart < distance:
                    best, distance = index, apart
            chosen.add(best)
    return sorted(chosen)


def structural_requirements(space: Space) -> dict[str, list[list[int]]]:
    """Each structural criterion's feasible requirements, each the cells satisfying it."""

    assert space.rules is not None and space.dimensions is not None
    keys = list(space.classes)
    width = space.dimensions
    fixed = {
        position
        for position in range(space.rules * width)
        if len({key[position] for key in keys}) < 2
    }

    def guard(key: tuple[Any, ...], rule: int) -> bool:
        return all(key[rule * width : (rule + 1) * width])

    def reached(key: tuple[Any, ...], rule: int) -> bool:
        return not any(guard(key, earlier) for earlier in range(rule))

    predicates: dict[str, list[Callable[[tuple[Any, ...]], bool]]] = {
        name: [] for name in STRUCTURAL
    }
    for rule in range(space.rules):
        decides = (lambda r: lambda k: reached(k, r) and guard(k, r))(rule)
        predicates["rule"].append(decides)
        predicates["decision"].append(decides)
        predicates["decision"].append((lambda r: lambda k: reached(k, r) and not guard(k, r))(rule))
        predicates["mcdc"].append(decides)
        for position in range(rule * width, (rule + 1) * width):
            if position in fixed:
                continue
            predicates["mcdc"].append(
                (
                    lambda r, p: (
                        lambda k: (
                            reached(k, r)
                            and not k[p]
                            and all(k[q] for q in range(r * width, (r + 1) * width) if q != p)
                        )
                    )
                )(rule, position)
            )
    predicates["rule"].append(lambda k: not any(guard(k, r) for r in range(space.rules)))

    requirements: dict[str, list[list[int]]] = {}
    infeasible: dict[str, int] = {}
    for name, tests in predicates.items():
        groups = []
        for test in tests:
            members = [cell for key in keys if test(key) for cell in space.classes[key]]
            if members:
                groups.append(members)
        requirements[name] = groups
        infeasible[name] = len(tests) - len(groups)
    space.extra["infeasible_requirements"] = infeasible
    return requirements


# --- detection ---------------------------------------------------------------------------------


def detection(groups: Sequence[Sequence[int]], hits: set[int]) -> Fraction:
    """P(one uniform cell from each group lands in `hits`), as the earlier studies compute it."""

    missed = Fraction(1)
    for group in groups:
        inside = sum(1 for cell in group if cell in hits)
        if inside:
            missed *= Fraction(len(group) - inside, len(group))
    return 1 - missed


def random_detection(cells: int, hits: int, size: int) -> Fraction:
    """1 - C(N - h, s) / C(N, s), by the shorter of its two product forms."""

    if hits == 0:
        return Fraction(0)
    if size >= cells:
        return Fraction(1)
    missed = Fraction(1)
    if hits <= size:
        for i in range(hits):
            missed *= Fraction(cells - size - i, cells - i)
    else:
        for j in range(size):
            missed *= Fraction(cells - hits - j, cells - j)
    return 1 - missed


def certain_share(space: Space) -> Fraction:
    """Live mutants whose difference set holds a whole class: every quotient suite finds them."""

    classes = [set(members) for members in space.classes.values()]
    certain = sum(1 for hits in space.live if any(group <= hits for group in classes))
    return Fraction(certain, len(space.live))


def score_space(space: Space, seed_label: str) -> dict[str, Any]:
    """Every strategy's mean score and size, and each one's random comparator, for one policy."""

    keys = list(space.classes)
    sizes = [len(space.classes[key]) for key in keys]
    groups_of = [space.classes[key] for key in keys]
    factors = factor_positions(keys)
    live = space.live
    n = len(live)

    def mean_detection(groups: Sequence[Sequence[int]]) -> Fraction:
        return sum((detection(groups, hits) for hits in live), Fraction(0)) / n

    def mean_random(size: int) -> Fraction:
        return sum((random_detection(space.cells, len(h), size) for h in live), Fraction(0)) / n

    scores: dict[str, Fraction] = {"quotient": mean_detection(groups_of)}
    suite_sizes: dict[str, Fraction] = {"quotient": Fraction(len(keys))}
    randoms: dict[str, Fraction] = {"quotient": mean_random(len(keys))}

    builders: dict[str, Callable[[random.Random], list[int]]] = {
        "base_choice": lambda g: base_choice(keys, sizes, factors, g),
    }
    for name, t in (("each_choice", 1), ("pairwise", 2), ("three_wise", 3)):
        bits = coverage_bits(keys, factors, t)
        builders[name] = (lambda b: lambda g: greedy_cover(b, g))(bits)

    for name in COMBINATION:
        total = Fraction(0)
        total_random = Fraction(0)
        total_size = 0
        cache: dict[int, Fraction] = {}
        for construction in range(CONSTRUCTIONS):
            generator = random.Random(f"{SEED}:{seed_label}:{name}:{construction}")
            chosen = builders[name](generator)
            total += mean_detection([groups_of[i] for i in chosen])
            if len(chosen) not in cache:
                cache[len(chosen)] = mean_random(len(chosen))
            total_random += cache[len(chosen)]
            total_size += len(chosen)
        scores[name] = total / CONSTRUCTIONS
        randoms[name] = total_random / CONSTRUCTIONS
        suite_sizes[name] = Fraction(total_size, CONSTRUCTIONS)

    if space.rules is not None:
        for name, groups in structural_requirements(space).items():
            scores[name] = mean_detection(groups)
            randoms[name] = mean_random(len(groups))
            suite_sizes[name] = Fraction(len(groups))

    return {
        "cells": space.cells,
        "classes": len(keys),
        "factors": len(factors),
        "live_mutants": n,
        "certain_detection": round(float(certain_share(space)), 6),
        "scores": {k: round(float(v), 6) for k, v in scores.items()},
        "random_scores": {k: round(float(v), 6) for k, v in randoms.items()},
        "sizes": {k: round(float(v), 4) for k, v in suite_sizes.items()},
        **(
            {"infeasible_requirements": space.extra["infeasible_requirements"]}
            if "infeasible_requirements" in space.extra
            else {}
        ),
    }


# --- the populations ---------------------------------------------------------------------------


def _generated_task(task: tuple[int, str]) -> tuple[int, dict[str, Any]]:
    index, document_json = task
    space = generated_space(json.loads(document_json))
    if not space.live:
        return index, {"status": "no live mutants"}
    return index, {"status": "scored", **score_space(space, f"generated:{index}")}


def _cedar_task(task: tuple[str, str]) -> tuple[str, dict[str, Any]]:
    subject, est_json = task
    space = cedar_space(json.loads(est_json))
    if not space.live:
        return subject, {"status": "no live mutants"}
    return subject, {"status": "scored", **score_space(space, f"cedar:{subject}")}


def cedar_population(cache: Path) -> list[tuple[str, str]]:
    """The 96 files of the Cedar study's primary analysis, as engine JSON."""

    ces = _load("cedar_exact_study")
    _, internal = ces._cedar()
    artifact = json.loads((DOCS / "cedar-suite-strategy-study-v1.json").read_text("utf-8"))
    primary = sorted(
        subject
        for subject, entry in artifact["files"].items()
        if entry.get("status") == "scored"
        and entry.get("with_condition")
        and entry.get("mutants", {}).get("live", 0) > 0
    )
    manifest = json.loads((DOCS / "third-party-sample-cedar-corpus-v1.json").read_text("utf-8"))
    wanted = {"files": [e for e in manifest["files"] if f"{e['repo']}/{e['path']}" in primary]}
    texts = ces._texts(wanted, cache)
    tasks = []
    for subject in primary:
        content = texts.get(subject)
        if content is None:
            raise SystemExit(f"{subject}: not fetchable at its pinned commit")
        tasks.append((subject, internal.policies_to_json_str(content.decode("utf-8"))))
    return tasks


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


def _hypotheses(records: list[dict[str, Any]], strategies: Sequence[str]) -> dict[str, Any]:
    ees = _load("exact_evaluation_study")
    raw: dict[str, float] = {}
    results: dict[str, Any] = {}
    for strategy in strategies:
        for name, left, right in (
            (f"Q_{strategy}", ("scores", "quotient"), ("scores", strategy)),
            (f"R_{strategy}", ("scores", strategy), ("random_scores", strategy)),
        ):
            differences = [r[left[0]][left[1]] - r[right[0]][right[1]] for r in records]
            low, high = ees.bootstrap_interval(differences, seed=SEED)
            raw[name] = ees.sign_flip_p(differences, "greater", seed=SEED)
            results[name] = {
                "mean_difference": round(statistics.fmean(differences), 6),
                "bootstrap_95": [round(low, 6), round(high, 6)],
                "p_value": round(raw[name], 4),
                "higher": sum(1 for d in differences if d > 0),
                "ties": sum(1 for d in differences if d == 0),
                "lower": sum(1 for d in differences if d < 0),
            }
    for name, adjusted in ees.holm(raw).items():
        results[name]["p_value_holm"] = round(adjusted, 4)
    return results


def summarise(records: dict[Any, dict[str, Any]], strategies: Sequence[str]) -> dict[str, Any]:
    scored = [r for r in records.values() if r["status"] == "scored"]
    names = ("quotient", *strategies)
    quotient_size = statistics.fmean(r["sizes"]["quotient"] for r in scored)
    summary: dict[str, Any] = {
        "policies_scored": len(scored),
        "statuses": dict(Counter(r["status"] for r in records.values())),
        "mean_score": {
            s: round(statistics.fmean(r["scores"][s] for r in scored), 6) for s in names
        },
        "mean_random_score": {
            s: round(statistics.fmean(r["random_scores"][s] for r in scored), 6) for s in names
        },
        "mean_size": {s: round(statistics.fmean(r["sizes"][s] for r in scored), 3) for s in names},
        "median_size": {s: statistics.median(r["sizes"][s] for r in scored) for s in names},
        "mean_size_share_of_quotient": {
            s: round(statistics.fmean(r["sizes"][s] for r in scored) / quotient_size, 4)
            for s in names
        },
        "certain_detection_mean": round(
            statistics.fmean(r["certain_detection"] for r in scored), 6
        ),
        "hypotheses": _hypotheses(scored, strategies),
    }
    if any("infeasible_requirements" in r for r in scored):
        summary["infeasible_requirements"] = dict(
            sum((Counter(r["infeasible_requirements"]) for r in scored), Counter())
        )
    return summary


def study(cache: Path, workers: int) -> dict[str, Any]:
    require_protocol()
    sample = json.loads((DOCS / "generated-policy-sample-v1.json").read_text("utf-8"))
    generated = _run(
        _generated_task,
        [(i, json.dumps(d)) for i, d in enumerate(sample["policies"])],
        workers,
    )
    cedar = _run(_cedar_task, cedar_population(cache), workers)
    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "seed": SEED,
        "constructions": CONSTRUCTIONS,
        "implementation_notes": list(IMPLEMENTATION_NOTES),
        "deviations": [],
        "populations": {
            "generated": {
                **summarise(generated, (*COMBINATION, *STRUCTURAL)),
                "per_policy": [generated[i] for i in sorted(generated)],
            },
            "cedar": {
                **summarise(cedar, COMBINATION),
                "per_file": {subject: cedar[subject] for subject in sorted(cedar)},
            },
        },
    }


def reference() -> dict[str, Any]:
    document = json.loads(REFERENCE_POLICY.read_text("utf-8"))
    space = generated_space(document)
    return {"reference policy": score_space(space, "reference")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("study")
    run.add_argument("--cache", type=Path, required=True)
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--json", type=Path, required=True)
    development = commands.add_parser("reference")
    development.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.command == "reference":
        findings = reference()
    else:
        findings = study(arguments.cache.resolve(), arguments.workers)
        findings["development"] = reference()
    text = json.dumps(findings, indent=2, sort_keys=True) + "\n"
    if arguments.json:
        arguments.json.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
