"""The suite-strategy study replicated on real Rego policy, decided by OPA.

The first suite-strategy study (`exact_evaluation_study.py`) scored five suite strategies on
generated policies, and the second (`cedar_exact_study.py`) on real Cedar policy decided by the
Cedar engine. Under `docs/EXACT_EVALUATION_PROTOCOL_REGO.md` (hashed below) this asks the same
questions of real Rego: the Gatekeeper modules whose witness spaces the exact-adequacy study
built and checked (`docs/rego-exact-adequacy-v1.json`), under every instantiation their own
suites test.

Every decision is OPA's. The quotient classes are the cells grouped by what OPA says each of the
module's own atoms is at the cell's values -- an atom is a comparison, call or condition of the
module's source, recorded with its operator and the order of its operands -- and a module whose
decision is not constant on every class is excluded rather than scored, because then the classes
are not its quotient. The detection probabilities are the first study's, in closed form.

CLI:
    python scripts/rego_payoff_study.py study --corpus <gatekeeper-library> \\
        --json docs/rego-suite-strategy-study-v1.json [--only SUBJECT ...] [--workers 6]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import math
import multiprocessing
import random
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Sequence
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "EXACT_EVALUATION_PROTOCOL_REGO.md"
PROTOCOL_SHA256 = "d0e1bdfc605905ee40e7caf29ab72f3dbeef8cc34e2c4bc33b209afd769f03df"
EXACT_ARTIFACT = DOCS / "rego-exact-adequacy-v1.json"
SEED = 20261004
RESAMPLES = 10_000
DEVELOPMENT = "src/general/httpsonly/src.rego"
STRATEGIES = ("refinement", "quotient", "decision", "random_quotient", "random_decision")
HYPOTHESES = (
    ("H1", "quotient", "random_quotient", "greater"),
    ("H2", "quotient", "decision", "greater"),
    ("H3", "decision", "random_decision", "two-sided"),
)
_OPS = {"equal": "==", "neq": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}


def require_protocol(development_only: bool) -> None:
    found = hashlib.sha256(PROTOCOL.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if found != PROTOCOL_SHA256 and not development_only:
        raise SystemExit(
            f"{PROTOCOL.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the "
            "study ran; a changed protocol is a different study, so this one refuses to run"
        )


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


# --- detection, as the first study computes it ----------------------------------------------


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


# --- statistics, as the first study computes them --------------------------------------------


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


def compare(scores: list[dict[str, float]]) -> dict[str, Any]:
    """The three pre-registered paired comparisons."""

    results: dict[str, Any] = {}
    raw: dict[str, float] = {}
    for name, left, right, alternative in HYPOTHESES:
        differences = [score[left] - score[right] for score in scores]
        low, high = bootstrap_interval(differences)
        raw[name] = sign_flip_p(differences, alternative)
        results[name] = {
            "strategies": [left, right],
            "alternative": alternative,
            "policies": len(differences),
            "mean_difference": round(statistics.fmean(differences), 6),
            "median_difference": round(statistics.median(differences), 6),
            "bootstrap_95": [round(low, 6), round(high, 6)],
            "p_value": round(raw[name], 4),
            "wins": sum(1 for d in differences if d > 0),
            "ties": sum(1 for d in differences if d == 0),
            "losses": sum(1 for d in differences if d < 0),
        }
    for name, adjusted in holm(raw).items():
        results[name]["p_value_holm"] = round(adjusted, 4)
    return results


# --- the quotient ----------------------------------------------------------------------------


def atom_expression(atom: tuple[Any, ...], operand: str) -> str | None:
    """The atom as a Rego expression over `operand`, a reference to the value it tests."""

    kind = atom[0]
    if kind == "cmp" and atom[1] in _OPS:
        return f"{operand} {_OPS[atom[1]]} {atom[2]}"
    if kind == "size" and atom[1] in _OPS:
        return f"count({operand}) {_OPS[atom[1]]} {atom[2]}"
    if kind == "case" and atom[2] in _OPS:
        return f"{atom[1]}({operand}) {_OPS[atom[2]]} {atom[3]}"
    if kind == "affix":
        return f"{atom[1]}({operand}, {atom[2]})"
    if kind == "regex":
        return f"regex.match({atom[1]}, {operand})"
    if kind == "glob":
        return f"glob.match({atom[1]}, [], {operand})"
    if kind == "type":
        return f"{atom[1]}({operand})"
    if kind == "truthy":
        return operand
    return None


def evaluate_atoms(opa: str, pairs: list[tuple[tuple[Any, ...], Any]]) -> dict[int, bool]:
    """Each (atom, value) pair decided by OPA. The value is read from data, so no operand is a
    literal the type checker could reject before evaluation."""

    lines = ["package tw_atoms", ""]
    values = []
    for index, (atom, value) in enumerate(pairs):
        expression = atom_expression(atom, f"data.tw_values[{index}]")
        assert expression is not None
        values.append(value)
        lines.append(f"r{index} := true {{ {expression} }} else := false")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "atoms.rego").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (root / "values.json").write_text(json.dumps({"tw_values": values}), encoding="utf-8")
        done = subprocess.run(
            [opa, "eval", "--v0-compatible", "--format", "json", "-d", str(root), "data.tw_atoms"],
            capture_output=True,
            text=True,
            timeout=900,
        )
    if done.returncode != 0:
        raise RuntimeError(done.stderr.strip()[:300])
    result = json.loads(done.stdout)["result"][0]["expressions"][0]["value"]
    return {int(key[1:]): bool(value) for key, value in result.items()}


class Quotient:
    """The module's atoms, per path, and the signature of a review under them."""

    def __init__(self, analyzer: Any, shapes: dict[tuple[Any, ...], str]) -> None:
        self.atoms = {
            path: sorted(atoms, key=repr)
            for path, atoms in analyzer.atoms.items()
            if path not in analyzer.unmerged and all(atom_expression(a, "x") for a in atoms)
        }
        self.unmerged = set(analyzer.unmerged) | {
            path
            for path, atoms in analyzer.atoms.items()
            if not all(atom_expression(a, "x") for a in atoms)
        }
        self.paths = set(analyzer.read) | set(analyzer.atoms) | self.unmerged
        self.shapes = shapes
        self.children: dict[tuple[Any, ...], set[Any]] = defaultdict(set)
        for path in self.paths:
            for depth in range(1, len(path)):
                self.children[path[:depth]].add(path[depth])
        self.outcomes: dict[tuple[str, str], bool] = {}

    def values_to_decide(self, cells: list[Any]) -> set[tuple[str, str]]:
        """The (path, value) pairs whose atoms the signatures of these cells need."""

        wanted: set[tuple[str, str]] = set()

        def walk(value: Any, at: tuple[Any, ...]) -> None:
            if value is ABSENT_MARK:
                return
            if at in self.atoms:
                wanted.add((json.dumps(at), json.dumps(value, sort_keys=True)))
            kids = self.children.get(at, set())
            if "*" in kids:
                # A scalar where a collection was expected has no elements, as in `signature`.
                for element in _elements(value) or []:
                    walk(element, at + ("*",))
            if isinstance(value, dict):
                for key in kids - {"*"}:
                    walk(value.get(key, ABSENT_MARK), at + (key,))

        for cell in cells:
            walk(cell, ("review",))
        return wanted

    def decide(self, opa: str, wanted: set[tuple[str, str]]) -> None:
        pairs: list[tuple[tuple[Any, ...], Any]] = []
        keys: list[tuple[str, str, int]] = []
        seen: set[tuple[str, str]] = set()
        for path_text, value_text in sorted(wanted):
            path = tuple(json.loads(path_text))
            for number, atom in enumerate(self.atoms[path]):
                key = (repr(atom), value_text)
                if key in seen:
                    continue
                seen.add(key)
                pairs.append((atom, json.loads(value_text)))
                keys.append((repr(atom), value_text, number))
        if not pairs:
            return
        decided = evaluate_atoms(opa, pairs)
        for index, (atom_text, value_text, _) in enumerate(keys):
            self.outcomes[(atom_text, value_text)] = decided[index]

    def _class(self, at: tuple[Any, ...], value: Any) -> Any:
        if at in self.unmerged:
            return ("raw", json.dumps(value, sort_keys=True))
        if at in self.atoms:
            text = json.dumps(value, sort_keys=True)
            return tuple(self.outcomes[(repr(atom), text)] for atom in self.atoms[at])
        return None

    def signature(self, value: Any, at: tuple[Any, ...] = ("review",)) -> Any:
        if value is ABSENT_MARK:
            return ("absent",)
        here = self._class(at, value)
        kids = self.children.get(at, set())
        parts: list[Any] = []
        if "*" in kids:
            elements = _elements(value)
            if elements is not None:
                parts.append(frozenset(self.signature(e, at + ("*",)) for e in elements))
        if isinstance(value, dict):
            for key in sorted(kids - {"*"}, key=str):
                parts.append((key, self.signature(value.get(key, ABSENT_MARK), at + (key,))))
        elif kids - {"*"} and "*" not in kids:
            parts.append(("not an object", type(value).__name__))
        return ("present", here, tuple(parts))


class _AbsentMark:
    __slots__ = ()


ABSENT_MARK = _AbsentMark()


def _elements(value: Any) -> list[Any] | None:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return None


# --- one module ------------------------------------------------------------------------------


def study_module(task: tuple[str, str, str, list[str], str]) -> dict[str, Any]:
    subject, source, test_path, lib_paths, opa = task
    exact = _load("rego_exact_study")
    space = _load("rego_witness_space")
    mutation = _load("rego_source_mutation")
    libs = [Path(p) for p in lib_paths]
    lib_sources = [
        f for p in libs for f in sorted(p.rglob("*.rego")) if not f.name.endswith("_test.rego")
    ]
    inputs = exact.authors_inputs(opa, source, Path(test_path), libs)
    absent = space.ABSENT
    instantiations: list[Any] = []
    seen: set[str] = set()
    for item in inputs:
        params = item.get("parameters", absent) if isinstance(item, dict) else absent
        key = "absent" if params is absent else json.dumps(params, sort_keys=True)
        if key not in seen:
            seen.add(key)
            instantiations.append(params)
    instantiations = instantiations or [absent]
    found = mutation.mutants(source)
    live_sources = {i: m for i, m in enumerate(found) if exact.compiles(opa, m.source, libs)}
    asts = [space.opa_parse(opa, f.read_text(encoding="utf-8")) for f in lib_sources]
    module_ast = space.opa_parse(opa, source)
    mutant_asts = {i: space.opa_parse(opa, m.source) for i, m in live_sources.items()}
    package = space.package_of(module_ast)
    shapes = space.shapes_from(inputs)

    record: dict[str, Any] = {"subject": subject, "development": subject == DEVELOPMENT}
    policies = []
    for params in instantiations:
        label = "absent" if params is absent else params
        cells = exact._witness_cells(space, module_ast, asts, mutant_asts, package, params, shapes)
        alone = space.Analyzer([module_ast, *asts], package, params)
        alone.run()
        quotient = Quotient(alone, shapes)
        quotient.decide(opa, quotient.values_to_decide(cells))
        signatures = [quotient.signature(cell) for cell in cells]
        everything = [exact._wrap(c, params, absent) for c in cells]
        reference = exact.decide(opa, source, libs, everything)

        by_class: dict[Any, list[int]] = defaultdict(list)
        by_decision: dict[Any, list[int]] = defaultdict(list)
        for position, signature in enumerate(signatures):
            by_class[signature].append(position)
            by_decision[json.dumps(reference[position])].append(position)
        not_constant = sum(
            1
            for members in by_class.values()
            if len({json.dumps(reference[p]) for p in members}) > 1
        )
        policy: dict[str, Any] = {
            "parameters": label,
            "cells": len(cells),
            "quotient_classes": len(by_class),
            "decision_classes": len(by_decision),
            "unmerged_paths": len(quotient.unmerged),
        }
        if not_constant:
            policy["status"] = f"excluded: the decision varies inside {not_constant} classes"
            policies.append(policy)
            continue
        classes = list(by_class.values())
        decisions = list(by_decision.values())
        live = 0
        totals = dict.fromkeys(STRATEGIES, Fraction(0))
        for mutant in live_sources.values():
            got = exact.decide(opa, mutant.source, libs, everything)
            hits = {p for p in range(len(cells)) if got[p] != reference[p]}
            if not hits:
                continue
            live += 1
            totals["refinement"] += 1
            totals["quotient"] += _detection(classes, hits)
            totals["decision"] += _detection(decisions, hits)
            totals["random_quotient"] += _random_detection(len(cells), len(hits), len(classes))
            totals["random_decision"] += _random_detection(len(cells), len(hits), len(decisions))
        policy["live_mutants"] = live
        if live:
            policy["status"] = "scored"
            policy["expected_score"] = {s: round(float(totals[s] / live), 6) for s in STRATEGIES}
        else:
            policy["status"] = "no live mutants"
        policies.append(policy)
    record["policies"] = policies
    return record


# --- the study ---------------------------------------------------------------------------------


def study(corpus: Path, workers: int, only: list[str] | None) -> dict[str, Any]:
    require_protocol(development_only=bool(only) and set(only) == {DEVELOPMENT})
    suite = _load("rego_suite_study")
    opa = suite._opa()
    libs = [str(p) for p in suite._lib_dirs(corpus)]
    exact_result = json.loads(EXACT_ARTIFACT.read_text(encoding="utf-8"))
    subjects = sorted(
        s for s, r in exact_result["modules"].items() if r.get("status") == "measured"
    )
    if only:
        subjects = [s for s in subjects if s in only]
    tasks = []
    for subject in subjects:
        module = corpus / subject
        test = module.with_name(module.name.replace(".rego", "_test.rego"))
        tasks.append((subject, module.read_text("utf-8"), str(test), libs, opa))
    records: dict[str, Any] = {}
    context = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(workers, mp_context=context) as pool:
        pending = {pool.submit(study_module, task): task[0] for task in tasks}
        for future in concurrent.futures.as_completed(pending):
            record = future.result()
            records[record["subject"]] = record
            print(f"{len(records)}/{len(tasks)} {record['subject']}", file=sys.stderr, flush=True)

    def scored(include_development: bool) -> list[dict[str, float]]:
        return [
            p["expected_score"]
            for s, r in sorted(records.items())
            if include_development or s != DEVELOPMENT
            for p in r["policies"]
            if p["status"] == "scored"
        ]

    def module_means() -> list[dict[str, float]]:
        out = []
        for s, r in sorted(records.items()):
            if s == DEVELOPMENT:
                continue
            rows = [p["expected_score"] for p in r["policies"] if p["status"] == "scored"]
            if rows:
                out.append({k: statistics.fmean(row[k] for row in rows) for k in STRATEGIES})
        return out

    headline = scored(include_development=False)

    def summary(rows: list[dict[str, float]]) -> dict[str, Any] | None:
        if not rows:
            return None
        return {
            "policies": len(rows),
            "mean_expected_score": {
                k: round(statistics.fmean(r[k] for r in rows), 6) for k in STRATEGIES
            },
            "comparisons": compare(rows) if len(rows) > 1 else None,
        }

    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "engine": suite._engine_version(),
        "seed": SEED,
        "resamples": RESAMPLES,
        "development_module": DEVELOPMENT,
        "witness_spaces": EXACT_ARTIFACT.name,
        "headline": summary(headline),
        "by_module": summary(module_means()),
        "with_development_module": summary(scored(include_development=True)),
        "modules": dict(sorted(records.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("study")
    run.add_argument("--corpus", type=Path, required=True)
    run.add_argument("--workers", type=int, default=6)
    run.add_argument("--only", nargs="*", default=None)
    run.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)
    findings = study(args.corpus, args.workers, args.only)
    text = json.dumps(findings, indent=1)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
