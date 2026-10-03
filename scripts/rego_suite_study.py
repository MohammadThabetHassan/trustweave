"""What a real policy suite's coverage is worth, against the faults a mutation seeds.

Under `docs/SUITE_ADEQUACY_PROTOCOL_REGO.md` (hashed below), on the OPA Gatekeeper library's
modules that ship an author-written unit-test suite, this measures two numbers per module: the
line coverage the suite reports -- what a practitioner reads -- and the fraction of the
module's mutants the same suite kills. The gap between them is the point: how much the adequacy
signal in common use overstates what the suite pins down.

Every decision is the engine's: coverage is `opa test --coverage`, a kill is the suite no
longer passing under `opa test` when a mutant stands in for the module. The mutants come from
`scripts/rego_source_mutation.py` -- the located-span operator set the protocol describes,
distinct from the text-search set of `scripts/rego_mutation.py`. The script imports no engine;
it shells out to `opa`, found the way the membership adapter finds it.

CLI:
    python scripts/rego_suite_study.py study --corpus <gatekeeper-library> \
        --json docs/rego-suite-adequacy-v1.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import random
import shutil
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
PROTOCOL = DOCS / "SUITE_ADEQUACY_PROTOCOL_REGO.md"
PROTOCOL_SHA256 = "1b18d80285d07fa84970523801801eb6b19a0175dd1373deb56b095ded525675"

SEED = 20261003
RESAMPLES = 10_000
DEVELOPMENT = "src/general/httpsonly/src.rego"
TEST_TIMEOUT = 180


def require_protocol() -> None:
    found = hashlib.sha256(PROTOCOL.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if found != PROTOCOL_SHA256:
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


def _opa() -> str:
    found = shutil.which("opa")
    if found is None:
        raise SystemExit("opa is not on PATH; install it to run the rego suite study")
    return found


def _lib_dirs(corpus: Path) -> list[Path]:
    return sorted((corpus / "src" / "rego").glob("lib_*"))


def discover(corpus: Path) -> list[tuple[str, Path, Path]]:
    """Every module with a `violation` decision and an author-written suite beside it."""

    found: list[tuple[str, Path, Path]] = []
    for test in sorted(corpus.rglob("*_test.rego")):
        module = test.with_name(test.name.replace("_test.rego", ".rego"))
        if not module.exists():
            continue
        if "/rego/lib_" in str(module).replace("\\", "/"):
            continue
        text = module.read_text(encoding="utf-8", errors="ignore")
        if not any(line.lstrip().startswith("violation") for line in text.splitlines()):
            continue
        found.append((str(module.relative_to(corpus)), module, test))
    return found


def _run_test(paths: list[Path], coverage: bool) -> subprocess.CompletedProcess[str]:
    command = [_opa(), "test", *(str(p) for p in paths), "--v0-compatible", "-f", "json"]
    if coverage:
        command.append("--coverage")
    return subprocess.run(command, capture_output=True, text=True, timeout=TEST_TIMEOUT)


def _passes(result: subprocess.CompletedProcess[str]) -> bool:
    """True only if every test ran and passed. A mutant that fails, errors or will not load in
    context is not passing, which is what the suite is credited with catching."""

    try:
        results = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    if not isinstance(results, list) or not results:
        return False
    return all(not entry.get("fail") and not entry.get("error") for entry in results)


def _coverage(module: Path, test: Path, libs: list[Path]) -> float | None:
    result = _run_test([module, test, *libs], coverage=True)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    files = report.get("files", {})
    key = next((name for name in files if Path(name).name == module.name), None)
    if key is not None and isinstance(files[key].get("coverage"), (int, float)):
        return round(float(files[key]["coverage"]), 4)
    overall = report.get("coverage")
    return round(float(overall), 4) if isinstance(overall, (int, float)) else None


def _score_module(task: tuple[str, str, str, list[str]]) -> dict[str, Any]:
    subject, module_text, test_path, lib_paths = task
    mutation = _load("rego_source_mutation")
    test = Path(test_path)
    libs = [Path(p) for p in lib_paths]
    with tempfile.TemporaryDirectory() as directory:
        module = Path(directory) / Path(subject).name
        module.write_text(module_text, encoding="utf-8")
        baseline = _run_test([module, test, *libs], coverage=False)
        if not _passes(baseline):
            return {"subject": subject, "status": "suite does not pass as shipped"}
        coverage = _coverage(module, test, libs)
        found = mutation.mutants(module_text)
        if not found:
            return {"subject": subject, "status": "no mutants", "coverage": coverage}
        killed_by_operator: Counter[str] = Counter()
        total_by_operator: Counter[str] = Counter()
        killed = 0
        for mutant in found:
            module.write_text(mutant.source, encoding="utf-8")
            total_by_operator[mutant.operator] += 1
            if not _passes(_run_test([module, test, *libs], coverage=False)):
                killed += 1
                killed_by_operator[mutant.operator] += 1
    return {
        "subject": subject,
        "status": "measured",
        "coverage": coverage,
        "mutants": len(found),
        "killed": killed,
        "mutation_score": round(killed / len(found), 4),
        "killed_by_operator": dict(sorted(killed_by_operator.items())),
        "total_by_operator": dict(sorted(total_by_operator.items())),
    }


def _bootstrap_ci(values: list[float], seed: int) -> list[float]:
    generator = random.Random(seed)
    size = len(values)
    means = []
    for _ in range(RESAMPLES):
        sample = [values[generator.randrange(size)] for _ in range(size)]
        means.append(statistics.fmean(sample))
    means.sort()
    return [round(means[int(0.025 * RESAMPLES)], 4), round(means[int(0.975 * RESAMPLES)], 4)]


def _git_commit(corpus: Path) -> str | None:
    try:
        done = subprocess.run(
            ["git", "-C", str(corpus), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() or None if done.returncode == 0 else None


def _engine_version() -> str:
    try:
        done = subprocess.run([_opa(), "version"], capture_output=True, text=True, timeout=30)
        for line in done.stdout.splitlines():
            if line.startswith("Version:"):
                return "opa " + line.split(":", 1)[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "opa"


def study(corpus: Path, workers: int = 8) -> dict[str, Any]:
    require_protocol()
    libs = _lib_dirs(corpus)
    modules = discover(corpus)
    tasks = [
        (subject, module.read_text("utf-8"), str(test), [str(p) for p in libs])
        for subject, module, test in modules
    ]

    records: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ProcessPoolExecutor(workers) as pool:
        for record in pool.map(_score_module, tasks):
            records[record["subject"]] = record

    measured = {s: r for s, r in records.items() if r["status"] == "measured"}
    headline = {s: r for s, r in measured.items() if s != DEVELOPMENT}
    statuses = Counter(r["status"] for r in records.values())

    def aggregate(group: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
        if not group:
            return None
        coverage = [r["coverage"] for r in group.values() if r["coverage"] is not None]
        scores = [r["mutation_score"] for r in group.values()]
        gaps = [
            r["coverage"] / 100 - r["mutation_score"]
            for r in group.values()
            if r["coverage"] is not None
        ]
        killed = sum(r["killed"] for r in group.values())
        total = sum(r["mutants"] for r in group.values())
        return {
            "modules": len(group),
            "mutants": total,
            "killed": killed,
            "pooled_mutation_score": round(killed / total, 4) if total else None,
            "mean_coverage": round(statistics.fmean(coverage), 4) if coverage else None,
            "median_coverage": round(statistics.median(coverage), 4) if coverage else None,
            "mean_mutation_score": round(statistics.fmean(scores), 4),
            "median_mutation_score": round(statistics.median(scores), 4),
            "mean_gap": round(statistics.fmean(gaps), 4) if gaps else None,
            "gap_bootstrap_95": _bootstrap_ci(gaps, SEED) if gaps else None,
        }

    killed_by_operator: Counter[str] = Counter()
    total_by_operator: Counter[str] = Counter()
    for record in measured.values():
        killed_by_operator.update(record["killed_by_operator"])
        total_by_operator.update(record["total_by_operator"])

    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "engine": _engine_version(),
        "seed": SEED,
        "resamples": RESAMPLES,
        "corpus": {"name": corpus.name, "commit": _git_commit(corpus)},
        "development_module": DEVELOPMENT,
        "population": {
            "modules_with_a_suite_and_a_decision": len(modules),
            "measured": len(measured),
            **{status: count for status, count in sorted(statuses.items()) if status != "measured"},
        },
        "by_operator": {
            operator: {"killed": killed_by_operator[operator], "total": total_by_operator[operator]}
            for operator in sorted(total_by_operator)
        },
        "headline": aggregate(headline),
        "with_development_module": aggregate(measured),
        "modules": dict(sorted(records.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("study", help="measure coverage against mutation score")
    run.add_argument("--corpus", type=Path, required=True, help="the gatekeeper-library root")
    run.add_argument("--workers", type=int, default=8)
    run.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.command == "study":
        findings = study(args.corpus, args.workers)
        text = json.dumps(findings, indent=1, sort_keys=False)
        if args.json:
            args.json.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
