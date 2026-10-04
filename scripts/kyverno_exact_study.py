"""The exact adequacy of real Kyverno suites, decided by the engine.

Under `docs/EXACT_ADEQUACY_PROTOCOL_KYVERNO.md` (hashed below), on the Kyverno library policies
that ship an author-written suite and that the membership measurement judged inside the fragment,
this decides which of each policy's mutants are equivalent to it, and so each suite's exact
mutation score, and records a resource that kills every surviving mutant that is not equivalent.

Every decision is the engine's: `kyverno apply` over the cells `scripts/kyverno_witness_space.py`
builds, and a kill is `kyverno test` failing, run as `scripts/kyverno_mutation.py` runs it, on the
mutants that script generates.

CLI:
    python scripts/kyverno_exact_study.py study --corpus <kyverno/policies> \
        --json docs/kyverno-exact-adequacy-v1.json [--kyverno PATH] [--only NAME ...] [--workers 6]
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import copy
import hashlib
import json
import multiprocessing
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import kyverno_mutation as km  # noqa: E402
import kyverno_witness_space as ws  # noqa: E402

ROOT = SCRIPTS.parent
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "EXACT_ADEQUACY_PROTOCOL_KYVERNO.md"
# Fixed when the protocol was committed (c51346f), before the instrument existed.
PROTOCOL_SHA256 = "70ac8bd427979ccf9a701d6d5b7844d5998dd7937dbcc174ba53a619e8fac73f"
MEMBERSHIP = DOCS / "fragment-membership-kyverno-wide-v1.json"
CORPUS_COMMIT = "ef9843f08d25b3555fe69616f8612c9f915af5d4"
KYVERNO_VERSION = "1.19.1"
DEVELOPMENT = ("require-labels", "disallow-privileged-containers", "restrict-nodeport")
CELL_CAP = 20_000
DRAWS = 200
SEED = 20261004
RESAMPLES = 10_000
TIMEOUT = 900

# Condition 3, as the protocol states it for a policy's own text.
_NAME = r'(?:[A-Za-z0-9_\-]+|"[^"]+")'
POLICY_KEY = re.compile(
    r"^\{\{\s*(?:request\.operation|request\.object(?:\." + _NAME + r")+)"
    r"(?:\s*\|\|\s*'[^']*')?\s*\}\}$"
)
GUARDS = frozenset({"pattern", "anyPattern", "deny"})
EXCLUDED_GUARDS = frozenset({"foreach", "cel", "podSecurity", "manifests", "assert"})
SELECTORS = frozenset({"kinds", "names", "namespaces", "operations"})
UNLOADABLE = "unloadable"


def protocol_digest() -> str:
    return hashlib.sha256(PROTOCOL.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def require_protocol() -> None:
    if protocol_digest() != PROTOCOL_SHA256:
        raise SystemExit(f"{PROTOCOL.name} does not hash to the value fixed before the study ran")


# ---------------------------------------------------------------------------------------------
# The population
# ---------------------------------------------------------------------------------------------


def _literal(value: Any) -> bool:
    if isinstance(value, list):
        return all(_literal(item) for item in value)
    return not isinstance(value, dict) and "{{" not in str(value)


def _has_variable(node: Any) -> bool:
    if isinstance(node, dict):
        return any(_has_variable(k) or _has_variable(v) for k, v in node.items())
    if isinstance(node, list):
        return any(_has_variable(item) for item in node)
    return "{{" in str(node)


def _selectors_ok(block: Any) -> bool:
    if not block:
        return True
    if not isinstance(block, dict):
        return False
    groups = list(block.get("any") or []) + list(block.get("all") or [])
    if "resources" in block:
        groups.append({"resources": block["resources"]})
    for group in groups:
        if not isinstance(group, dict) or set(group) - {"resources"}:
            return False
        if set(group.get("resources") or {}) - SELECTORS:
            return False
    return True


def exclusion(documents: Sequence[Any]) -> str | None:
    """Why a policy file fails conditions 1 to 4, or None when it meets them."""

    if len(documents) != 1 or not isinstance(documents[0], dict):
        return "1: not one document"
    policy = documents[0]
    if policy.get("kind") != "ClusterPolicy":
        return "1: not a ClusterPolicy"
    rules = (policy.get("spec") or {}).get("rules") or []
    if not rules:
        return "2: no rules"
    for rule in rules:
        validate = rule.get("validate")
        if (
            not isinstance(validate, dict)
            or rule.get("context")
            or set(validate) & EXCLUDED_GUARDS
            or not set(validate) & GUARDS
        ):
            return "2: a rule that is not a pattern or deny validate rule"
    for rule in rules:
        validate = rule["validate"]
        conditions = ws._conditions(rule.get("preconditions")) + ws._conditions(
            (validate.get("deny") or {}).get("conditions")
        )
        for condition in conditions:
            if not POLICY_KEY.match(str(condition.get("key", "")).strip()):
                return "3: a condition the witness space does not model"
            if not _literal(condition.get("value")):
                return "3: a condition the witness space does not model"
        if _has_variable(validate.get("pattern")) or _has_variable(validate.get("anyPattern")):
            return "3: a variable in a pattern value"
        if not (_selectors_ok(rule.get("match")) and _selectors_ok(rule.get("exclude"))):
            return "4: a selector other than kinds, names, namespaces and operations"
    return None


def population(corpus: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """The policies meeting conditions 1 to 4, and the reason each other inside policy is out."""

    import fragment_membership_kyverno as fmk  # noqa: PLC0415 - needs scripts/ on the path

    verdicts = {
        p["subject"]: p["verdict"]
        for p in json.loads(MEMBERSHIP.read_text(encoding="utf-8"))["policies"]
    }
    files: dict[str, list[Path]] = collections.defaultdict(list)
    for name, path in fmk.discover(corpus):
        files[name].append(path)
    manifests = km.policy_manifests(corpus)
    eligible: list[dict[str, Any]] = []
    excluded: dict[str, str] = {}
    for name in sorted(files):
        if verdicts.get(name) != "inside":
            continue
        if len(files[name]) != 1:
            excluded[name] = "1: the manifest names several policy files"
            continue
        documents = [
            d
            for d in yaml.safe_load_all(files[name][0].read_text(encoding="utf-8"))
            if d is not None
        ]
        reason = exclusion(documents)
        if reason is not None:
            excluded[name] = reason
            continue
        eligible.append(
            {"name": name, "policy": str(files[name][0]), "tests": str(manifests[name][0])}
        )
    return eligible, excluded


# ---------------------------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------------------------


def _identity(resource: dict[str, Any]) -> tuple[str, str, str]:
    metadata = resource.get("metadata") or {}
    return (
        str(resource.get("kind")),
        str(metadata.get("namespace") or ""),
        str(metadata.get("name")),
    )


def _batches(resources: Sequence[dict[str, Any]]) -> list[list[int]]:
    """Resource indexes grouped so that no group holds two resources of one identity.

    A namespaced resource written without a namespace is in `default` to the engine, so the two
    spellings are one identity here.
    """

    groups: list[tuple[set[tuple[str, str, str]], list[int]]] = []
    for index, resource in enumerate(resources):
        kind, namespace, name = _identity(resource)
        identity = (kind, namespace or "default", name)
        for seen, members in groups:
            if identity not in seen:
                seen.add(identity)
                members.append(index)
                break
        else:
            groups.append(({identity}, [index]))
    return [members for _, members in groups]


class Engine:
    """`kyverno apply` with a policy report, over many resources per process."""

    def __init__(self, kyverno: str) -> None:
        self.kyverno = kyverno

    def _apply(
        self,
        workspace: Path,
        policy: Path,
        resources: Sequence[dict[str, Any]],
        operation: str | None,
    ) -> dict[tuple[str, str, str], dict[str, str]] | None:
        target = workspace / "resources.yaml"
        target.write_text(yaml.safe_dump_all(list(resources), sort_keys=False), encoding="utf-8")
        command = [
            self.kyverno,
            "apply",
            str(policy),
            "--resource",
            str(target),
            "--policy-report",
            "--output-format",
            "json",
            "--remove-color",
        ]
        if operation is not None:
            command += ["--set", f"request.operation={operation}"]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None
        start = re.search(r"^\{", completed.stdout, re.MULTILINE)
        if start is None:
            return None
        try:
            report = json.loads(completed.stdout[start.start() :])
        except json.JSONDecodeError:
            return None
        decided: dict[tuple[str, str, str], dict[str, str]] = collections.defaultdict(dict)
        for result in report.get("results") or []:
            for reference in result.get("resources") or []:
                key = (
                    str(reference.get("kind")),
                    str(reference.get("namespace") or ""),
                    str(reference.get("name")),
                )
                decided[key][str(result.get("rule"))] = str(result.get("result"))
        return decided

    def loads(self, policy_text: str, probe: dict[str, Any]) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            policy = workspace / "policy.yaml"
            policy.write_text(policy_text, encoding="utf-8")
            return self._apply(workspace, policy, [probe], None) is not None

    def decide(
        self, policy_text: str, resources: Sequence[dict[str, Any]], operation: str | None
    ) -> list[dict[str, str]]:
        """One decision per resource; a resource the engine cannot load decides `unloadable`."""

        decisions: list[dict[str, str]] = [{} for _ in resources]
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            policy = workspace / "policy.yaml"
            policy.write_text(policy_text, encoding="utf-8")
            pending = _batches(resources)
            while pending:
                batch = pending.pop()
                decided = self._apply(workspace, policy, [resources[i] for i in batch], operation)
                if decided is None:
                    if len(batch) == 1:
                        decisions[batch[0]] = {UNLOADABLE: UNLOADABLE}
                    else:
                        half = len(batch) // 2
                        pending += [batch[:half], batch[half:]]
                    continue
                for index in batch:
                    kind, namespace, name = _identity(resources[index])
                    found = decided.get((kind, namespace, name))
                    if found is None and not namespace:
                        # The engine reports a namespaced resource written without one in
                        # `default`, and a cluster-scoped one with no namespace at all.
                        found = decided.get((kind, "default", name))
                    decisions[index] = dict(found or {})
        return decisions


def decide_all(
    engine: Engine,
    policy_text: str,
    resources: Sequence[dict[str, Any]],
    operations: Sequence[str | None],
) -> list[dict[str, str]]:
    """Decisions over (resource, operation) pairs, operation-major within each resource."""

    by_operation = {op: engine.decide(policy_text, resources, op) for op in operations}
    return [by_operation[op][i] for i in range(len(resources)) for op in operations]


# ---------------------------------------------------------------------------------------------
# Kills, run as the mutation experiment runs them
# ---------------------------------------------------------------------------------------------


def _staged(policy_path: Path, tests: Path, workspace: Path) -> tuple[Path, Path, Path]:
    root = tests.resolve().parent
    staged_root = workspace / root.name
    shutil.copytree(root, staged_root)
    return (
        staged_root,
        staged_root / policy_path.resolve().relative_to(root),
        staged_root / tests.resolve().relative_to(root),
    )


def suite_outcomes(
    policy_path: Path, tests: Path, sources: Sequence[str], extra: Path | None = None
) -> list[bool | None]:
    """For each source: True when the suite passes with it, False when it fails, None when it
    produces no summary. `extra` names a directory of further test manifests to run as well."""

    outcomes: list[bool | None] = []
    with tempfile.TemporaryDirectory() as directory:
        staged_root, staged_policy, staged_tests = _staged(policy_path, tests, Path(directory))
        if extra is not None:
            shutil.copytree(extra, staged_root / extra.name)
        for source in sources:
            staged_policy.write_text(source, encoding="utf-8")
            shipped = km._run_test(staged_tests)
            if extra is None or shipped is not True:
                outcomes.append(shipped)
                continue
            outcomes.append(km._run_test(staged_root / extra.name))
    return outcomes


# ---------------------------------------------------------------------------------------------
# One policy
# ---------------------------------------------------------------------------------------------


def family(mutant: str) -> str:
    original = mutant.split(":", 1)[1].split("->", 1)[0]
    if original in {o for o, _ in km.OPERATOR_PAIRS}:
        return "condition operator"
    if original in {o for o, _ in km.CEL_OPERATORS}:
        return "expression operator"
    if original in {o for o, _ in km.THRESHOLDS}:
        return "threshold"
    if original in {o for o, _ in km.WEAKENINGS}:
        return "weakening"
    if original in {o for o, _ in km.ANCHORS}:
        return "anchor"
    return "boolean"


def suite_resources(tests: Path) -> list[dict[str, Any]]:
    manifest = yaml.safe_load((tests / "kyverno-test.yaml").read_text(encoding="utf-8")) or {}
    found: list[dict[str, Any]] = []
    for reference in manifest.get("resources") or []:
        path = (tests / str(reference)).resolve()
        if not path.is_file():
            continue
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(document, dict) and document.get("kind"):
                found.append(document)
    return found


def _renamed(resource: dict[str, Any], name: str, keep: bool) -> dict[str, Any]:
    if not keep:
        resource.setdefault("metadata", {})["name"] = name
    return resource


def _differs(a: dict[str, str], b: dict[str, str]) -> bool:
    if UNLOADABLE in a or UNLOADABLE in b:
        return False
    return a != b


def _gap_suite(
    workspace: Path, policy_file: Path, policy_name: str, gaps: list[dict[str, Any]]
) -> Path:
    """A directory of test manifests asserting the policy's own result on each kill resource."""

    directory = workspace / "tw-gaps"
    by_operation: dict[str | None, list[dict[str, Any]]] = collections.defaultdict(list)
    for gap in gaps:
        by_operation[gap["operation"]].append(gap)
    for position, (operation, members) in enumerate(sorted(by_operation.items(), key=str)):
        manifest_dir = directory / f"op-{position}"
        manifest_dir.mkdir(parents=True)
        resources = [gap["resource"] for gap in members]
        (manifest_dir / "resources.yaml").write_text(
            yaml.safe_dump_all(resources, sort_keys=False), encoding="utf-8"
        )
        results = []
        for gap in members:
            for rule, result in sorted(gap["asserted"].items()):
                results.append(
                    {
                        "policy": policy_name,
                        "rule": rule,
                        "resources": [gap["resource"]["metadata"]["name"]],
                        "kind": gap["resource"]["kind"],
                        "result": result,
                    }
                )
        manifest: dict[str, Any] = {
            "apiVersion": "cli.kyverno.io/v1alpha1",
            "kind": "Test",
            "metadata": {"name": f"tw-gaps-{position}"},
            "policies": [os.path.relpath(policy_file, manifest_dir).replace("\\", "/")],
            "resources": ["resources.yaml"],
            "results": results,
        }
        if operation is not None:
            (manifest_dir / "values.yaml").write_text(
                yaml.safe_dump(
                    {
                        "apiVersion": "cli.kyverno.io/v1alpha1",
                        "kind": "Values",
                        "globalValues": {"request.operation": operation},
                    }
                ),
                encoding="utf-8",
            )
            manifest["variables"] = "values.yaml"
        (manifest_dir / "kyverno-test.yaml").write_text(
            yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
        )
    return directory


def analyse_policy(task: dict[str, Any], kyverno: str) -> dict[str, Any]:
    name = task["name"]
    policy_path, tests = Path(task["policy"]), Path(task["tests"])
    engine = Engine(kyverno)
    text = policy_path.read_text(encoding="utf-8")
    policy = yaml.safe_load(text)
    mutants = km._mutate(text)
    record: dict[str, Any] = {"policy": name, "file": task.get("relative", policy_path.name)}
    if not mutants:
        return {**record, "excluded": "5: no mutants"}
    parsed: list[dict[str, Any] | None] = []
    for mutant in mutants:
        try:
            document = yaml.safe_load(mutant.source)
        except yaml.YAMLError:
            document = None
        parsed.append(document if isinstance(document, dict) else None)
    authors = suite_resources(tests)
    try:
        spaces = ws.rule_spaces(policy, [d for d in parsed if d is not None])
        cells = ws.cells(spaces, authors, CELL_CAP)
    except ws.Unsupported as reason:
        return {**record, "excluded": str(reason)}
    operations = ws.OPERATIONS if any(s.reads_operation for s in spaces) else (None,)

    # Condition 5, then the kills, exactly as the experiment runs the suite.
    sources = [text] + [m.source for m in mutants]
    outcomes = suite_outcomes(policy_path, tests, sources)
    if outcomes[0] is not True:
        return {**record, "excluded": "5: the suite does not pass with the unmodified policy"}
    kills = outcomes[1:]

    # Every decision on every cell is the engine's.
    unique_resources: list[dict[str, Any]] = []
    position: dict[int, int] = {}
    for cell in cells:
        if id(cell.resource) not in position:
            position[id(cell.resource)] = len(unique_resources)
            unique_resources.append(cell.resource)
    probe = unique_resources[0]
    if not engine.loads(text, probe):
        return {**record, "excluded": "the engine cannot load the policy"}

    def on_cells(source: str) -> list[dict[str, str]]:
        by_resource = decide_all(engine, source, unique_resources, operations)
        index = {op: k for k, op in enumerate(operations)}
        return [
            by_resource[position[id(cell.resource)] * len(operations) + index[cell.operation]]
            for cell in cells
        ]

    reference = on_cells(text)
    stillborn = [
        kills[i] is None or parsed[i] is None or not engine.loads(mutants[i].source, probe)
        for i in range(len(mutants))
    ]
    separating: list[int | None] = []
    mutant_cells: list[list[dict[str, str]] | None] = []
    for i, mutant in enumerate(mutants):
        if stillborn[i]:
            separating.append(None)
            mutant_cells.append(None)
            continue
        decided = on_cells(mutant.source)
        mutant_cells.append(decided)
        separating.append(
            next((k for k in range(len(cells)) if _differs(reference[k], decided[k])), None)
        )

    # Completeness, three ways.
    rng = random.Random(f"{SEED}:{name}")
    keeps_names = any(
        "name" in (space.root.children.get("metadata") or ws.Node()).children for space in spaces
    )
    perturb_cells = ws.Perturber(unique_resources, rng)
    drawn = [
        _renamed(perturb_cells.draw(rng.choice(unique_resources)), f"tw-d-{k}", keeps_names)
        for k in range(DRAWS)
    ]
    own = [copy.deepcopy(resource) for resource in authors]
    perturb_own = ws.Perturber(own + unique_resources, rng)
    drawn_own = (
        [
            _renamed(perturb_own.draw(rng.choice(own)), f"tw-a-{k}", keeps_names)
            for k in range(DRAWS)
        ]
        if own
        else []
    )
    checks = (
        [("drawn", r) for r in drawn]
        + [("authors", r) for r in own]
        + [("authors, perturbed", r) for r in drawn_own]
    )
    check_resources = [resource for _, resource in checks]
    check_reference = decide_all(engine, text, check_resources, operations)
    missing: dict[str, Any] | None = None
    for i, mutant in enumerate(mutants):
        if stillborn[i]:
            continue
        decided = decide_all(engine, mutant.source, check_resources, operations)
        separated_here = next(
            (k for k in range(len(decided)) if _differs(check_reference[k], decided[k])), None
        )
        if separated_here is not None and separating[i] is None and missing is None:
            which, resource = checks[separated_here // len(operations)]
            missing = {
                "mutant": mutant.name,
                "source": which,
                "operation": operations[separated_here % len(operations)],
                "resource": resource,
                "policy": check_reference[separated_here],
                "mutant_result": decided[separated_here],
            }
    unloadable_checks = sum(1 for d in check_reference if UNLOADABLE in d)
    unloadable_cells = sum(1 for d in reference if UNLOADABLE in d)

    entries = []
    gaps = []
    for i, mutant in enumerate(mutants):
        entry: dict[str, Any] = {"mutant": mutant.name, "family": family(mutant.name)}
        if stillborn[i]:
            entry["status"] = "stillborn"
        else:
            killed = kills[i] is False
            equivalent = separating[i] is None
            entry.update(
                {
                    "status": "killed" if killed else "survived",
                    "equivalent": equivalent,
                }
            )
            if not equivalent:
                k = separating[i]
                cell = cells[k]  # type: ignore[index]
                decided = mutant_cells[i][k]  # type: ignore[index]
                entry["separating_cell"] = {
                    "rule": spaces[cell.rule].name,
                    "operation": cell.operation,
                    "resource": cell.resource,
                    "policy": reference[k],  # type: ignore[index]
                    "mutant": decided,
                }
                if not killed:
                    asserted = {
                        rule: result
                        for rule, result in reference[k].items()  # type: ignore[index]
                        if decided.get(rule) != result
                    }
                    gaps.append(
                        {
                            "mutant": mutant.name,
                            "operation": cell.operation,
                            "resource": copy.deepcopy(cell.resource),
                            "asserted": asserted,
                        }
                    )
        entries.append(entry)

    record.update(
        {
            "rules": [space.name for space in spaces],
            "reads_operation": operations != (None,),
            "cells": len(cells),
            "cells_with_a_result": sum(1 for d in reference if d and UNLOADABLE not in d),
            "unloadable_cells": unloadable_cells,
            "check_inputs": len(checks) * len(operations),
            "unloadable_check_inputs": unloadable_checks,
            "authors_resources": len(own),
            "mutants": entries,
        }
    )
    if missing is not None:
        record["excluded"] = "a missing cell"
        record["missing_cell"] = missing
        return record

    # Closing the gaps: the kill resources become tests asserting the policy's own result.
    expressible = [gap for gap in gaps if gap["asserted"]]
    record["gaps_not_expressible"] = len(gaps) - len(expressible)
    if expressible:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            staged_root, staged_policy, _ = _staged(policy_path, tests, workspace / "stage")
            # The gap manifests point at the policy file by its place in the staged tree.
            gap_dir = _gap_suite(
                staged_root,
                staged_policy,
                str((policy.get("metadata") or {}).get("name")),
                expressible,
            )
            extended = suite_outcomes(policy_path, tests, sources, extra=gap_dir)
        exceptions = []
        if extended[0] is not True:
            exceptions.append("the extended suite does not pass with the unmodified policy")
        for i, entry in enumerate(entries):
            if entry["status"] == "stillborn":
                continue
            killed_extended = extended[i + 1] is False
            if not entry["equivalent"] and not killed_extended:
                exceptions.append(f"{entry['mutant']}: distinguishable and not killed")
            if entry["equivalent"] and killed_extended:
                exceptions.append(f"{entry['mutant']}: equivalent and killed")
        record["closing_the_gaps"] = {"tests_added": len(expressible), "exceptions": exceptions}
    return record


def _analyse(arguments: tuple[dict[str, Any], str]) -> dict[str, Any]:
    task, kyverno = arguments
    try:
        return analyse_policy(task, kyverno)
    except Exception as error:  # noqa: BLE001 - reported per policy, never silently dropped
        return {
            "policy": task["name"],
            "excluded": f"instrument error: {type(error).__name__}: {error}",
        }


# ---------------------------------------------------------------------------------------------
# Measures
# ---------------------------------------------------------------------------------------------


def tally(record: dict[str, Any]) -> dict[str, int]:
    counts = collections.Counter()
    for entry in record.get("mutants", []):
        counts["mutants"] += 1
        if entry["status"] == "stillborn":
            counts["stillborn"] += 1
            continue
        killed = entry["status"] == "killed"
        counts["killed"] += killed
        counts["survived"] += not killed
        if entry["equivalent"]:
            counts["equivalent"] += 1
            counts["killed_but_equivalent"] += killed
            counts["equivalent_survivors"] += not killed
        else:
            counts["distinguishable"] += 1
            counts["killed_distinguishable"] += killed
            counts["real"] += not killed
    return {
        key: counts[key]
        for key in (
            "mutants",
            "stillborn",
            "killed",
            "survived",
            "equivalent",
            "equivalent_survivors",
            "killed_but_equivalent",
            "distinguishable",
            "killed_distinguishable",
            "real",
        )
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def scores(counts: dict[str, int]) -> dict[str, float | None]:
    return {
        "raw": _ratio(counts["killed"], counts["killed"] + counts["survived"]),
        "exact": _ratio(counts["killed_distinguishable"], counts["distinguishable"]),
        "share_of_survivors_equivalent": _ratio(counts["equivalent_survivors"], counts["survived"]),
    }


def bootstrap_interval(values: Sequence[float], seed: int = SEED) -> list[float]:
    rng = random.Random(seed)
    means = sorted(statistics.fmean(rng.choices(values, k=len(values))) for _ in range(RESAMPLES))
    return [round(means[int(0.025 * RESAMPLES)], 6), round(means[int(0.975 * RESAMPLES) - 1], 6)]


def summarise(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    totals = collections.Counter()
    per_policy = []
    families: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for record in records:
        counts = tally(record)
        totals.update(counts)
        policy_scores = scores(counts)
        per_policy.append(policy_scores)
        for entry in record["mutants"]:
            bucket = families[entry["family"]]
            bucket["mutants"] += 1
            if entry["status"] == "stillborn":
                bucket["stillborn"] += 1
            elif entry["equivalent"]:
                bucket["equivalent"] += 1
            elif entry["status"] == "killed":
                bucket["killed_distinguishable"] += 1
            else:
                bucket["real"] += 1
    pooled = dict(totals)
    paired = [
        (s["exact"], s["raw"])
        for s in per_policy
        if s["exact"] is not None and s["raw"] is not None
    ]
    differences = [exact - raw for exact, raw in paired]
    return {
        "policies": len(records),
        "pooled": pooled,
        "pooled_scores": scores({k: totals[k] for k in tally({})}),
        "mean_over_policies": {
            "policies_with_both_scores": len(paired),
            "raw": round(statistics.fmean(r for _, r in paired), 6) if paired else None,
            "exact": round(statistics.fmean(e for e, _ in paired), 6) if paired else None,
            "difference": round(statistics.fmean(differences), 6) if differences else None,
            "bootstrap_95": bootstrap_interval(differences) if len(differences) > 1 else None,
        },
        "by_family": {name: dict(counts) for name, counts in sorted(families.items())},
    }


# ---------------------------------------------------------------------------------------------
# The study
# ---------------------------------------------------------------------------------------------


def kyverno_version(kyverno: str) -> str:
    completed = subprocess.run(
        [kyverno, "version"], capture_output=True, text=True, check=False, timeout=60
    )
    found = re.search(r"Version:\s*(\S+)", completed.stdout + completed.stderr)
    return found.group(1) if found else "unknown"


def corpus_commit(corpus: Path) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(corpus), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return completed.stdout.strip() or None


def study(arguments: argparse.Namespace) -> dict[str, Any]:
    require_protocol()
    kyverno = arguments.kyverno or shutil.which("kyverno")
    if not kyverno:
        raise SystemExit("kyverno is not on PATH; pass --kyverno")
    os.environ["PATH"] = str(Path(kyverno).resolve().parent) + os.pathsep + os.environ["PATH"]
    version = kyverno_version(kyverno)
    if version != KYVERNO_VERSION:
        raise SystemExit(f"the protocol fixes Kyverno {KYVERNO_VERSION}; found {version}")
    corpus = Path(arguments.corpus)
    commit = corpus_commit(corpus)
    if commit != CORPUS_COMMIT:
        raise SystemExit(f"the corpus is at {commit}, not {CORPUS_COMMIT}")
    eligible, excluded = population(corpus)
    if arguments.only:
        eligible = [task for task in eligible if task["name"] in set(arguments.only)]
    for task in eligible:
        task["relative"] = Path(task["policy"]).resolve().relative_to(corpus.resolve()).as_posix()
    records: list[dict[str, Any]] = []
    context = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(arguments.workers, mp_context=context) as pool:
        for done, record in enumerate(pool.map(_analyse, [(t, kyverno) for t in eligible]), 1):
            print(f"  {done}/{len(eligible)} {record['policy']}", flush=True)
            records.append(record)
    development = [r for r in records if r["policy"] in DEVELOPMENT]
    primary = [r for r in records if r["policy"] not in DEVELOPMENT]
    passing = [r for r in primary if "excluded" not in r]
    failing = collections.defaultdict(list)
    for name, reason in excluded.items():
        failing[reason].append(name)
    for record in primary:
        if "excluded" in record:
            failing[record["excluded"]].append(record["policy"])
    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "seed": SEED,
        "kyverno_version": version,
        "corpus": {"remote": "https://github.com/kyverno/policies.git", "commit": commit},
        "deviations": [],
        "population": {
            "inside_policies_considered": len(eligible) + len(excluded),
            "meeting_conditions_1_to_4": len(eligible),
            "development": sorted(r["policy"] for r in development),
            "scored": len(passing),
            "excluded_by_reason": {k: sorted(v) for k, v in sorted(failing.items())},
        },
        "results": summarise(passing),
        "development_results": summarise([r for r in development if "excluded" not in r]),
        "closing_the_gaps": {
            "policies_with_gaps": sum(1 for r in passing if "closing_the_gaps" in r),
            "tests_added": sum(
                r.get("closing_the_gaps", {}).get("tests_added", 0) for r in passing
            ),
            "gaps_not_expressible": sum(r.get("gaps_not_expressible", 0) for r in passing),
            "exceptions": {
                r["policy"]: r["closing_the_gaps"]["exceptions"]
                for r in passing
                if r.get("closing_the_gaps", {}).get("exceptions")
            },
        },
        "policies": {r["policy"]: r for r in records},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("study")
    run.add_argument("--corpus", required=True)
    run.add_argument("--json", required=True)
    run.add_argument("--kyverno")
    run.add_argument("--only", nargs="*")
    run.add_argument("--workers", type=int, default=6)
    arguments = parser.parse_args(argv)
    artifact = study(arguments)
    Path(arguments.json).write_text(
        json.dumps(artifact, indent=1, sort_keys=False) + "\n", encoding="utf-8", newline="\n"
    )
    pooled = artifact["results"]
    print(json.dumps({"scored": artifact["population"]["scored"], **pooled["pooled_scores"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
