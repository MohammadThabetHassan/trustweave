"""The exact adequacy of real Rego suites, decided by the engine.

Under `docs/EXACT_ADEQUACY_PROTOCOL_REGO.md` (hashed below), on the OPA Gatekeeper library
modules that ship an author-written suite and that the membership measurement judged inside the
fragment, this decides which of the suite study's mutants are equivalent to their module, and so
each suite's exact mutation score, and records an input that kills every surviving mutant that is
not equivalent.

Every decision is the engine's: `opa eval` with `with input as` over the cells
(`scripts/rego_witness_space.py` builds them), and a kill is `opa test` failing exactly as in the
suite study (`scripts/rego_suite_study.py`), whose mutants (`scripts/rego_source_mutation.py`)
this study takes unchanged.

CLI:
    python scripts/rego_exact_study.py study --corpus <gatekeeper-library> \
        --json docs/rego-exact-adequacy-v1.json [--only SUBJECT ...] [--workers 6]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import multiprocessing
import random
import re
import statistics
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "EXACT_ADEQUACY_PROTOCOL_REGO.md"
PROTOCOL_SHA256 = "afe5723345f67b5d79506ac3543f8e8f495fc6101c5901611375212e32246a91"
# The second population, policy schemas instantiated by their suites, has its own protocol.
PROTOCOL_SCHEMAS = DOCS / "EXACT_ADEQUACY_PROTOCOL_REGO_SCHEMAS.md"
PROTOCOL_SCHEMAS_SHA256 = "f57aab7eb3961794f4fd8a94943074c669cec9ca5d0c422c98adafeafd5637c8"
SUITE_ARTIFACT = DOCS / "rego-suite-adequacy-v1.json"
MEMBERSHIP_ARTIFACT = DOCS / "fragment-membership-rego-wide-v1.json"

SEED = 20261004
RESAMPLES = 10_000
MAX_CELLS = 250_000
DRAWS = 200
DEVELOPMENT = "src/general/httpsonly/src.rego"
EVAL_TIMEOUT = 900


def require_protocol(development_only: bool, kind: str = "inside") -> str:
    """The hash of the protocol the population runs under; refuse if that protocol changed."""

    protocol, expected = (
        (PROTOCOL, PROTOCOL_SHA256)
        if kind == "inside"
        else (PROTOCOL_SCHEMAS, PROTOCOL_SCHEMAS_SHA256)
    )
    found = hashlib.sha256(protocol.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if found != expected and not development_only:
        raise SystemExit(
            f"{protocol.name} hashes to {found}, not the {expected} fixed before the "
            "study ran; a changed protocol is a different study, so this one refuses to run"
        )
    return expected


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


# --- the population --------------------------------------------------------------------------


def population(kind: str = "inside") -> list[str]:
    """The suite study's measured modules judged inside, or (second protocol) judged schemas."""

    suite = json.loads(SUITE_ARTIFACT.read_text(encoding="utf-8"))["modules"]
    membership = json.loads(MEMBERSHIP_ARTIFACT.read_text(encoding="utf-8"))["policies"]
    rows = {row["subject"]: row for row in membership}
    chosen = []
    for subject, record in sorted(suite.items()):
        if record.get("status") != "measured":
            continue
        row = rows.get(f"gatekeeper-library/{subject}", {})
        verdict, reason = row.get("verdict"), row.get("reason", "")
        wanted = (
            verdict == "inside"
            if kind == "inside"
            else verdict == "outside" and reason.startswith("is a policy schema")
        )
        if wanted:
            chosen.append(subject)
    return chosen


# --- the authors' inputs -----------------------------------------------------------------------


def _instrumented(opa: str, source: str) -> str:
    """The module with a print of its input at the start of every `violation` body."""

    done = subprocess.run(
        [
            opa,
            "parse",
            "--format",
            "json",
            "--json-include",
            "locations",
            "--v0-compatible",
            "/dev/stdin",
        ],
        input=source,
        capture_output=True,
        text=True,
        timeout=60,
    )
    ast = json.loads(done.stdout)
    lines = source.split("\n")
    spots = []
    for rule in ast.get("rules") or []:
        head = rule.get("head", {})
        name = head.get("name") or ".".join(
            str(p.get("value")) for p in head.get("ref", []) if p.get("type") in ("var", "string")
        )
        if name != "violation":
            continue
        current: dict[str, Any] | None = rule
        while current is not None:
            body = current.get("body") or []
            if body and body[0].get("location"):
                spots.append((body[0]["location"]["row"], body[0]["location"]["col"]))
            current = current.get("else")
    for row, col in sorted(set(spots), reverse=True):
        line = lines[row - 1]
        lines[row - 1] = (
            line[: col - 1]
            + 'print("TWINPUT", json.marshal(input))\n'
            + " " * (col - 1)
            + line[col - 1 :]
        )
    return "\n".join(lines)


def authors_inputs(opa: str, source: str, test: Path, libs: list[Path]) -> list[Any]:
    with tempfile.TemporaryDirectory() as directory:
        module = Path(directory) / "module.rego"
        module.write_text(_instrumented(opa, source), encoding="utf-8")
        done = subprocess.run(
            [opa, "test", str(module), str(test), *(str(p) for p in libs), "--v0-compatible", "-v"],
            capture_output=True,
            text=True,
            timeout=300,
        )
    found: list[Any] = []
    seen: set[str] = set()
    for line in done.stdout.splitlines():
        marker = line.find("TWINPUT ")
        if marker < 0:
            continue
        text = line[marker + len("TWINPUT ") :].strip()
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            continue
        key = json.dumps(value, sort_keys=True)
        if key not in seen:
            seen.add(key)
            found.append(value)
    return found


# --- the engine --------------------------------------------------------------------------------


def _package(source: str) -> str:
    match = re.search(r"^package\s+([\w.]+)", source, flags=re.M)
    if not match:
        raise ValueError("no package line")
    return match.group(1)


def decide(opa: str, source: str, libs: list[Path], inputs: list[Any]) -> list[Any]:
    """The decision on every input: True (denied), False (allowed) or "error"."""

    package = _package(source)
    harness = (
        "package tw_harness\n\n"
        "decisions := {i: d | some i; x := data.tw_inputs[i]; "
        f"d := count(data.{package}.violation) > 0 with input as x}}\n"
    )

    def run(batch: list[int]) -> dict[int, Any]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "module.rego").write_text(source, encoding="utf-8")
            (root / "harness.rego").write_text(harness, encoding="utf-8")
            (root / "inputs.json").write_text(
                json.dumps({"tw_inputs": [inputs[i] for i in batch]}), encoding="utf-8"
            )
            done = subprocess.run(
                [
                    opa,
                    "eval",
                    "--v0-compatible",
                    "--format",
                    "json",
                    "-d",
                    str(root),
                    *(arg for p in libs for arg in ("-d", str(p))),
                    "data.tw_harness.decisions",
                ],
                capture_output=True,
                text=True,
                timeout=EVAL_TIMEOUT,
            )
        if done.returncode != 0:
            raise RuntimeError(done.stderr.strip()[:300] or done.stdout.strip()[:300])
        result = json.loads(done.stdout)
        values = result["result"][0]["expressions"][0]["value"] if result.get("result") else {}
        return {batch[int(k)]: v for k, v in values.items()}

    out: dict[int, Any] = {}

    def settle(batch: list[int]) -> None:
        try:
            got = run(batch)
        except RuntimeError:
            if len(batch) == 1:
                out[batch[0]] = "error"
                return
            middle = len(batch) // 2
            settle(batch[:middle])
            settle(batch[middle:])
            return
        for i in batch:
            out[i] = got.get(i, "error")

    settle(list(range(len(inputs))))
    return [out[i] for i in range(len(inputs))]


def compiles(opa: str, source: str, libs: list[Path]) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        module = Path(directory) / "module.rego"
        module.write_text(source, encoding="utf-8")
        done = subprocess.run(
            [opa, "check", "--v0-compatible", str(module), *(str(p) for p in libs)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    return done.returncode == 0


# --- one module --------------------------------------------------------------------------------


def _wrap(review: Any, params: Any, absent: Any) -> dict[str, Any]:
    value: dict[str, Any] = {"review": review}
    if params is not absent:
        value["parameters"] = params
    return value


def study_module(task: tuple[str, str, str, list[str], str]) -> dict[str, Any]:
    subject, source, test_path, lib_paths, opa = task
    space = _load("rego_witness_space")
    suite = _load("rego_suite_study")
    mutation = _load("rego_source_mutation")
    test = Path(test_path)
    libs = [Path(p) for p in lib_paths]
    lib_sources = [
        f for p in libs for f in sorted(p.rglob("*.rego")) if not f.name.endswith("_test.rego")
    ]
    record: dict[str, Any] = {"subject": subject, "development": subject == DEVELOPMENT}

    inputs = authors_inputs(opa, source, test, libs)
    absent = space.ABSENT
    instantiations: list[Any] = []
    seen: set[str] = set()
    for item in inputs:
        params = item.get("parameters", absent) if isinstance(item, dict) else absent
        key = "absent" if params is absent else json.dumps(params, sort_keys=True)
        if key not in seen:
            seen.add(key)
            instantiations.append(params)
    if not instantiations:
        instantiations = [absent]
    record["authors_inputs"] = len(inputs)
    record["instantiations"] = ["absent" if p is absent else p for p in instantiations]

    found = mutation.mutants(source)
    record["mutants"] = len(found)

    # kills, exactly as the suite study judges them
    killed: list[bool] = []
    stillborn: list[bool] = []
    with tempfile.TemporaryDirectory() as directory:
        module = Path(directory) / Path(subject).name
        for mutant in found:
            module.write_text(mutant.source, encoding="utf-8")
            killed.append(not suite._passes(suite._run_test([module, test, *libs], coverage=False)))
    for mutant in found:
        stillborn.append(not compiles(opa, mutant.source, libs))
    record["killed"] = sum(killed)
    record["stillborn"] = sum(stillborn)
    reference = json.loads(SUITE_ARTIFACT.read_text(encoding="utf-8"))["modules"].get(subject, {})
    record["kills_reproduce_the_suite_study"] = (
        reference.get("killed") == record["killed"]
        and reference.get("mutants") == record["mutants"]
    )

    # the witness space, per instantiation, from the module and every mutant that compiles
    asts = [space.opa_parse(opa, f.read_text(encoding="utf-8")) for f in lib_sources]
    module_ast = space.opa_parse(opa, source)
    mutant_asts = {
        i: space.opa_parse(opa, m.source) for i, m in enumerate(found) if not stillborn[i]
    }
    package = space.package_of(module_ast)
    shapes = space.shapes_from(inputs)
    generator = random.Random(f"{SEED}:{subject}")

    distinguishable = [False] * len(found)
    kill_inputs: dict[int, Any] = {}
    per_instantiation = []
    for params in instantiations:
        label = "absent" if params is absent else params
        try:
            merged = space.Analyzer([module_ast, *asts], package, params)
            merged.run()
            for ast in mutant_asts.values():
                other = space.Analyzer([ast, *asts], package, params)
                try:
                    other.run()
                except space.Unsupported:
                    continue
                for segs, hints in other.hints.items():
                    merged.hints[segs] |= hints
                merged.read |= other.read
                merged.links |= other.links
            cells = space.build(merged, shapes, MAX_CELLS)
        except space.Unsupported as reason:
            record["status"] = f"excluded: {reason}"
            record["instantiation_failed"] = label
            return record

        pool = space.leaf_pool(cells)
        drawn = [space.perturb(generator.choice(cells), pool, generator) for _ in range(DRAWS)]
        wanted = "absent" if params is absent else json.dumps(params, sort_keys=True)
        authors = [
            item["review"]
            for item in inputs
            if isinstance(item, dict)
            and "review" in item
            and (
                "absent"
                if "parameters" not in item
                else json.dumps(item["parameters"], sort_keys=True)
            )
            == wanted
        ]
        authors_drawn = (
            [space.perturb(generator.choice(authors), pool, generator) for _ in range(DRAWS)]
            if authors
            else []
        )
        checks = drawn + authors + authors_drawn
        everything = [_wrap(r, params, absent) for r in cells + checks]

        base = decide(opa, source, libs, everything)
        missing: list[dict[str, Any]] = []
        for i, mutant in enumerate(found):
            if stillborn[i]:
                continue
            got = decide(opa, mutant.source, libs, everything)
            on_cells = next((c for c in range(len(cells)) if got[c] != base[c]), None)
            if on_cells is not None:
                distinguishable[i] = True
                kill_inputs.setdefault(i, (everything[on_cells], base[on_cells]))
                continue
            off = next((c for c in range(len(cells), len(everything)) if got[c] != base[c]), None)
            if off is not None:
                missing.append({"mutant": i, "operator": mutant.operator, "input": everything[off]})
        per_instantiation.append(
            {
                "parameters": label,
                "cells": len(cells),
                "cells_where_the_module_errors": sum(1 for d in base[: len(cells)] if d == "error"),
                "drawn": len(drawn),
                "authors_reviews": len(authors),
                "authors_drawn": len(authors_drawn),
            }
        )
        if missing:
            record["status"] = "excluded: missing cell"
            record["missing_cells"] = missing[:5]
            record["instantiations_checked"] = per_instantiation
            return record

    live = [i for i in range(len(found)) if not stillborn[i]]
    equivalent = [i for i in live if not distinguishable[i]]
    dist = [i for i in live if distinguishable[i]]
    killed_dist = [i for i in dist if killed[i]]
    survivors = [i for i in dist if not killed[i]]
    closing = close_the_gaps(
        subject, source, found, test, libs, [kill_inputs[i] for i in survivors]
    )
    extended_kills = closing["killed"]
    closing_summary = {
        "tests_added": closing["tests_added"],
        "kills_every_distinguishable_mutant": all(extended_kills[i] for i in dist),
        "suite_equivalent_kills_unchanged": all(extended_kills[i] == killed[i] for i in equivalent),
        "exceptions": [
            i
            for i in live
            if (distinguishable[i] and not extended_kills[i])
            or (not distinguishable[i] and extended_kills[i] != killed[i])
        ],
    }
    record.update(
        {
            "status": "measured",
            "instantiations_checked": per_instantiation,
            "live": len(live),
            "suite_equivalent": len(equivalent),
            "distinguishable": len(dist),
            "killed_through_decision": len(killed_dist),
            "killed_without_a_decision_change": sum(killed[i] for i in equivalent),
            "killed_stillborn": sum(killed[i] for i in range(len(found)) if stillborn[i]),
            "raw_score": round(sum(killed) / len(found), 4) if found else None,
            "exact_score": round(len(killed_dist) / len(dist), 4) if dist else None,
            "survivors": [
                {
                    "mutant": i,
                    "operator": found[i].operator,
                    "detail": found[i].detail,
                    "kill_input": kill_inputs[i][0],
                    "module_decision": kill_inputs[i][1],
                }
                for i in survivors
            ],
            "closing_the_gaps": closing_summary,
            "equivalent_by_operator": dict(Counter(found[i].operator for i in equivalent)),
            "survivors_suite_study": sum(1 for i in range(len(found)) if not killed[i]),
        }
    )
    return record


def close_the_gaps(
    subject: str,
    source: str,
    found: list[Any],
    test: Path,
    libs: list[Path],
    gaps: list[tuple[Any, Any]],
) -> dict[str, Any]:
    """Add one test per killing input, asserting the module's own decision there, and run the
    extended suite on every mutant as the suite study runs the shipped one."""

    suite = _load("rego_suite_study")
    lines = []
    for number, (value, decision) in enumerate(gaps):
        if decision == "error":
            continue
        assertion = "count(violation) > 0" if decision is True else "count(violation) == 0"
        lines.append(
            f"test_tw_gap_{number} {{\n  {assertion} with input as {json.dumps(value)}\n}}\n"
        )
    killed: list[bool] = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        module = root / Path(subject).name
        extra = root / "tw_gaps_test.rego"
        extra.write_text(f"package {_package(source)}\n\n" + "\n".join(lines), encoding="utf-8")
        files = [module, test, extra, *libs] if lines else [module, test, *libs]
        for mutant in found:
            module.write_text(mutant.source, encoding="utf-8")
            killed.append(not suite._passes(suite._run_test(files, coverage=False)))
    return {"tests_added": len(lines), "killed": killed}


# --- the study ---------------------------------------------------------------------------------


def _bootstrap_ci(values: list[float], seed: int) -> list[float]:
    generator = random.Random(seed)
    size = len(values)
    means = []
    for _ in range(RESAMPLES):
        sample = [values[generator.randrange(size)] for _ in range(size)]
        means.append(statistics.fmean(sample))
    means.sort()
    return [round(means[int(0.025 * RESAMPLES)], 4), round(means[int(0.975 * RESAMPLES)], 4)]


def study(
    corpus: Path, workers: int, only: list[str] | None, kind: str = "inside"
) -> dict[str, Any]:
    protocol_sha256 = require_protocol(
        development_only=bool(only) and set(only) == {DEVELOPMENT}, kind=kind
    )
    suite = _load("rego_suite_study")
    opa = suite._opa()
    libs = suite._lib_dirs(corpus)
    subjects = population(kind)
    if only:
        subjects = [s for s in subjects if s in only]
    tasks = []
    for subject in subjects:
        module = corpus / subject
        test = module.with_name(module.name.replace(".rego", "_test.rego"))
        tasks.append((subject, module.read_text("utf-8"), str(test), [str(p) for p in libs], opa))
    records: dict[str, dict[str, Any]] = {}
    # Spawned, not forked: a fork taken while the executor's own threads hold a lock leaves the
    # workers waiting on it for ever, which is what the first run of this study did.
    context = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(workers, mp_context=context) as pool:
        pending = {pool.submit(study_module, task): task[0] for task in tasks}
        for future in concurrent.futures.as_completed(pending):
            record = future.result()
            records[record["subject"]] = record
            print(
                f"{len(records)}/{len(tasks)} {record['subject']}: {record.get('status')}",
                file=sys.stderr,
                flush=True,
            )
    measured = {s: r for s, r in records.items() if r.get("status") == "measured"}
    headline = {s: r for s, r in measured.items() if s != DEVELOPMENT}
    statuses = Counter(r.get("status") for r in records.values())
    return {
        "schema_version": "v1",
        "population_kind": kind,
        "protocol_sha256": protocol_sha256,
        "engine": suite._engine_version(),
        "seed": SEED,
        "resamples": RESAMPLES,
        "max_cells": MAX_CELLS,
        "draws": DRAWS,
        "corpus": {"name": corpus.name, "commit": suite._git_commit(corpus)},
        "development_module": DEVELOPMENT,
        "population": {"modules": len(subjects), **dict(sorted(statuses.items()))},
        "headline": aggregate(headline),
        "with_development_module": aggregate(measured),
        "modules": dict(sorted(records.items())),
    }


def aggregate(group: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not group:
        return None
    total = lambda key: sum(r[key] for r in group.values())  # noqa: E731
    survivors_before = total("survivors_suite_study")
    survivors_after = sum(len(r["survivors"]) for r in group.values())
    equivalent_survivors = sum(
        r["suite_equivalent"] - r["killed_without_a_decision_change"] for r in group.values()
    )
    stillborn_survivors = sum(r["stillborn"] - r["killed_stillborn"] for r in group.values())
    raw = [r["raw_score"] for r in group.values()]
    exact = [r["exact_score"] for r in group.values() if r["exact_score"] is not None]
    gaps = [
        r["exact_score"] - r["raw_score"] for r in group.values() if r["exact_score"] is not None
    ]
    return {
        "modules": len(group),
        "mutants": total("mutants"),
        "stillborn": total("stillborn"),
        "killed": total("killed"),
        "killed_stillborn": total("killed_stillborn"),
        "suite_equivalent": total("suite_equivalent"),
        "distinguishable": total("distinguishable"),
        "killed_through_decision": total("killed_through_decision"),
        "killed_without_a_decision_change": total("killed_without_a_decision_change"),
        "survivors_suite_study": survivors_before,
        "survivors_equivalent": equivalent_survivors,
        "survivors_stillborn": stillborn_survivors,
        "survivors_real": survivors_after,
        "share_of_survivors_equivalent": round(equivalent_survivors / survivors_before, 4)
        if survivors_before
        else None,
        "pooled_raw_score": round(total("killed") / total("mutants"), 4),
        "pooled_exact_score": round(total("killed_through_decision") / total("distinguishable"), 4),
        "mean_raw_score": round(statistics.fmean(raw), 4),
        "mean_exact_score": round(statistics.fmean(exact), 4) if exact else None,
        "mean_difference": round(statistics.fmean(gaps), 4) if gaps else None,
        "difference_bootstrap_95": _bootstrap_ci(gaps, SEED) if len(gaps) > 1 else None,
        "closing_the_gaps_holds_everywhere": all(
            r["closing_the_gaps"]["kills_every_distinguishable_mutant"]
            and r["closing_the_gaps"]["suite_equivalent_kills_unchanged"]
            for r in group.values()
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("study")
    run.add_argument("--corpus", type=Path, required=True)
    run.add_argument("--workers", type=int, default=6)
    run.add_argument("--only", nargs="*", default=None)
    run.add_argument("--population", choices=("inside", "schemas"), default="inside")
    run.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)
    findings = study(args.corpus, args.workers, args.only, args.population)
    text = json.dumps(findings, indent=1)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
