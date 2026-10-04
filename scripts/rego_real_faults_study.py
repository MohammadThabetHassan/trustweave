"""Real faults in two Rego libraries' histories, and whether the suite strategies expose them.

Protocol: `docs/REAL_FAULTS_PROTOCOL_REGO.md`, whose hash is fixed below; the script refuses to
run on the protocol's population unless the file is the one that was committed before it ran.

Every payoff result in the paper scores suites against the authors' own mutants. Here the
"mutant" is a fix the maintainers of the Gatekeeper library or of Google's Config Validator
library made to one of their own policies: the policy in use, *P*, is the module at the fix's
parent commit, the fix, *F*, is the module at the commit, and the question is whether a suite
built from *P* would have contained an input on which the two decide differently.

The witness space, its completeness check and every decision are the exact study's
(`rego_exact_study.py`, `rego_witness_space.py`); *P*'s quotient and the strategies' closed
forms are the Rego payoff study's (`rego_payoff_study.py`); membership is the paper's procedure
(`fragment_membership_rego.py`) run on the corpus as it stood at each version's commit.

Config Validator passes the asset at `input.asset` and the whole Constraint at
`input.constraint`, and its policies are `deny` rules. The analysis that builds the witness
space was written against Gatekeeper's `input.review`, `input.parameters` and `violation`, so
for Config Validator it reads a copy of each module's syntax tree with those names substituted;
every decision is still taken by OPA on the original module.

    python scripts/rego_real_faults_study.py study --corpora ~/trustweave-corpora --workers 6 \\
        --json docs/rego-real-faults-v1.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import io
import json
import multiprocessing
import random
import re
import statistics
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "REAL_FAULTS_PROTOCOL_REGO.md"
PROTOCOL_SHA256 = "98a45a877f71f5eb87730535d7a3c4859163a7987a0e1fda1de65289677eba7e"
SEED = 20261004
RESAMPLES = 10_000
DRAWS = 200
MAX_CELLS = 250_000
EVAL_TIMEOUT = 900
STRATEGIES = ("refinement", "quotient", "decision", "random_quotient", "random_decision")
HYPOTHESES = (
    ("H1", "quotient", "random_quotient", "greater"),
    ("H2", "quotient", "decision", "greater"),
)


@dataclass(frozen=True)
class Profile:
    """Where a corpus keeps its modules, what its policies read and which rule decides."""

    corpus: str
    repository: str  # relative to the corpora root
    subject: str  # the input key the policy reads its subject from
    setting: str  # the input key its instantiation arrives at
    rule: str


PROFILES = {
    "gatekeeper": Profile(
        "gatekeeper", "rego/gatekeeper-library", "review", "parameters", "violation"
    ),
    "gcp": Profile("gcp", "gcp/policy-library", "asset", "constraint", "deny"),
}
DEVELOPMENT = {("gatekeeper", "4416aa12b4"), ("gcp", "0f5a5d99a7")}


def require_protocol(development_only: bool) -> str:
    found = hashlib.sha256(PROTOCOL.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if found != PROTOCOL_SHA256 and not development_only:
        raise SystemExit(
            f"{PROTOCOL.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the "
            "study ran; a changed protocol is a different study, so this one refuses to run"
        )
    return found


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


# --- the population, as the protocol fixes it --------------------------------------------------


_ROW = re.compile(
    r"^\| (\d+) \| (\w+) \| `([0-9a-f]+)` \| `([^`]+)` \| (behaviour fix|excluded) \| (.*) \|$"
)


def candidates(text: str | None = None) -> list[dict[str, Any]]:
    """Every candidate of the protocol's table, in its order."""

    rows = []
    for line in (text if text is not None else PROTOCOL.read_text(encoding="utf-8")).splitlines():
        match = _ROW.match(line.strip())
        if match:
            number, corpus, commit, module, klass, reason = match.groups()
            rows.append(
                {
                    "number": int(number),
                    "corpus": corpus,
                    "commit": commit,
                    "module": module,
                    "class": klass,
                    "reason": reason,
                }
            )
    return rows


def population(text: str | None = None) -> list[dict[str, Any]]:
    """The behaviour fixes in the corpora the instrument runs."""

    return [
        r for r in candidates(text) if r["class"] == "behaviour fix" and r["corpus"] in PROFILES
    ]


# --- one version of a corpus -------------------------------------------------------------------


def materialise(repository: Path, revision: str, into: Path) -> str:
    """The tree at `revision`, unpacked into `into`; returns the full commit id."""

    full = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", f"{revision}^{{commit}}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    archive = subprocess.run(
        ["git", "-C", str(repository), "archive", "--format=tar", full],
        capture_output=True,
        check=True,
    ).stdout
    into.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(into, filter="data")
    return full


def library_files(profile: Profile, tree: Path) -> list[Path]:
    """The shared modules a policy of this corpus is evaluated with, tests left out."""

    if profile.corpus == "gatekeeper":
        roots = sorted((tree / "src" / "rego").glob("lib_*"))
    else:
        roots = [tree / "lib"]
    return [
        f
        for root in roots
        if root.exists()
        for f in sorted(root.rglob("*.rego"))
        if not f.name.endswith("_test.rego")
    ]


def test_file(profile: Profile, tree: Path, module: str) -> Path:
    path = tree / module
    if profile.corpus == "gatekeeper":
        return path.with_name("src_test.rego")
    return path.with_name(path.stem + "_test.rego")


# --- the engine --------------------------------------------------------------------------------


def _package(source: str) -> str:
    match = re.search(r"^package\s+([\w.]+)", source, flags=re.M)
    if not match:
        raise ValueError("no package line")
    return match.group(1)


def wrap(profile: Profile, subject: Any, setting: Any, absent: Any) -> dict[str, Any]:
    value: dict[str, Any] = {profile.subject: subject}
    if setting is not absent:
        value[profile.setting] = setting
    return value


def decide(
    opa: str, profile: Profile, source: str, libs: list[Path], inputs: list[Any]
) -> list[Any]:
    """The decision on every input: True (denied), False (allowed) or "error".

    A batch that fails is bisected, and an input whose evaluation errs -- or outruns the
    timeout -- is decided "error", which is an outcome like the others.
    """

    package = _package(source)
    harness = (
        "package tw_harness\n\n"
        "decisions := {i: d | some i; x := data.tw_inputs[i]; "
        f"d := count(data.{package}.{profile.rule}) > 0 with input as x}}\n"
    )

    def run(batch: list[int]) -> dict[int, Any]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "module.rego").write_text(source, encoding="utf-8")
            (root / "harness.rego").write_text(harness, encoding="utf-8")
            (root / "inputs.json").write_text(
                json.dumps({"tw_inputs": [inputs[i] for i in batch]}), encoding="utf-8"
            )
            try:
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
            except subprocess.TimeoutExpired as expired:
                raise RuntimeError("timeout") from expired
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

    if inputs:
        settle(list(range(len(inputs))))
    return [out[i] for i in range(len(inputs))]


def compiles(opa: str, source: str, libs: list[Path]) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        module = Path(directory) / "module.rego"
        module.write_text(source, encoding="utf-8")
        try:
            done = subprocess.run(
                [opa, "check", "--v0-compatible", str(module), *(str(p) for p in libs)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return False
    return done.returncode == 0


# --- the authors' inputs -----------------------------------------------------------------------


def instrumented(opa: str, source: str, rule: str) -> str:
    """The module with a print of its input at the start of every body of `rule`."""

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
    for item in ast.get("rules") or []:
        head = item.get("head", {})
        name = head.get("name") or ".".join(
            str(p.get("value")) for p in head.get("ref", []) if p.get("type") in ("var", "string")
        )
        if name != rule:
            continue
        current: dict[str, Any] | None = item
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


def authors_inputs(opa: str, profile: Profile, source: str, tree: Path, module: str) -> list[Any]:
    """The inputs the module's own suite at this version sends to it."""

    test = test_file(profile, tree, module)
    if not test.exists():
        return []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        copy = root / "module.rego"
        copy.write_text(instrumented(opa, source, profile.rule), encoding="utf-8")
        files = [str(copy), str(test), *(str(p) for p in library_files(profile, tree))]
        if profile.corpus == "gcp":
            utilities = tree / "validator" / "test_utils.rego"
            if utilities.exists():
                files.append(str(utilities))
            # Only the fixtures this test reads, loaded as data.test.fixtures.* as `opa test
            # lib/ validator/` loads them: one malformed fixture elsewhere in the tree would
            # otherwise stop the whole run.
            names = set(
                re.findall(r"data\.test\.fixtures\.(\w+)", test.read_text(encoding="utf-8"))
            )
            data_root = root / "data"
            for name in sorted(names):
                fixtures = tree / "validator" / "test" / "fixtures" / name
                if fixtures.is_dir():
                    _copy_tree(fixtures, data_root / "test" / "fixtures" / name)
            if data_root.exists():
                files.append(str(data_root))
        try:
            done = subprocess.run(
                [opa, "test", *files, "--v0-compatible", "-v"],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            return []
    found: list[Any] = []
    seen: set[str] = set()
    for line in done.stdout.splitlines():
        marker = line.find("TWINPUT ")
        if marker < 0:
            continue
        try:
            value = json.loads(line[marker + len("TWINPUT ") :].strip())
        except json.JSONDecodeError:
            continue
        key = json.dumps(value, sort_keys=True)
        if key not in seen:
            seen.add(key)
            found.append(value)
    return found


def _copy_tree(source: Path, target: Path) -> None:
    for path in source.rglob("*"):
        if path.is_file() and not path.name.endswith(".rego"):
            destination = target / path.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(path.read_bytes())


# --- the analysis's view of a Config Validator module ------------------------------------------


def renamed(node: Any, profile: Profile) -> Any:
    """A syntax tree with this corpus's input keys and rule renamed to Gatekeeper's.

    Only the analysis that builds the witness space reads the copy; OPA decides on the module
    as written.
    """

    if profile.corpus == "gatekeeper":
        return node
    keys = {profile.subject: "review", profile.setting: "parameters"}

    def walk(value: Any) -> Any:
        if isinstance(value, list):
            return [walk(v) for v in value]
        if not isinstance(value, dict):
            return value
        out = {k: walk(v) for k, v in value.items()}
        if out.get("type") == "ref" and isinstance(out.get("value"), list):
            parts = out["value"]
            if (
                len(parts) >= 2
                and parts[0].get("type") == "var"
                and parts[0].get("value") == "input"
                and parts[1].get("type") == "string"
                and parts[1].get("value") in keys
            ):
                parts[1] = {**parts[1], "value": keys[parts[1]["value"]]}
        if "head" in out and isinstance(out["head"], dict):
            head = out["head"]
            if head.get("name") == profile.rule:
                head["name"] = "violation"
            ref = head.get("ref")
            if isinstance(ref, list) and ref and ref[0].get("value") == profile.rule:
                ref[0] = {**ref[0], "value": "violation"}
        return out

    return walk(node)


def as_review(profile: Profile, item: Any) -> Any:
    """An authors' input in the analysis's convention."""

    if profile.corpus == "gatekeeper" or not isinstance(item, dict):
        return item
    value = {}
    if profile.subject in item:
        value["review"] = item[profile.subject]
    if profile.setting in item:
        value["parameters"] = item[profile.setting]
    return value


# --- exposure ----------------------------------------------------------------------------------


def exposure(per_setting: list[dict[str, Any]]) -> dict[str, Fraction]:
    """Each strategy's probability of exposing the fault, the settings drawn independently.

    A suite exposes the fault when, under some setting the suites test, it contains a cell on
    which the two versions decide differently; the miss probabilities of the settings multiply.
    """

    payoff = _load("rego_payoff_study")
    missed = {strategy: Fraction(1) for strategy in STRATEGIES}
    for setting in per_setting:
        hits = set(setting["delta"])
        cells = setting["cells"]
        classes = setting["classes"]
        decisions = setting["decision_groups"]
        chance = {
            "refinement": Fraction(1 if hits else 0),
            "quotient": payoff._detection(classes, hits),
            "decision": payoff._detection(decisions, hits),
            "random_quotient": payoff._random_detection(cells, len(hits), len(classes)),
            "random_decision": payoff._random_detection(cells, len(hits), len(decisions)),
        }
        for strategy in STRATEGIES:
            missed[strategy] *= 1 - chance[strategy]
    return {strategy: 1 - missed[strategy] for strategy in STRATEGIES}


def union_of_classes(per_setting: list[dict[str, Any]]) -> bool:
    """Whether, under every setting, the difference set is a union of the policy's classes."""

    for setting in per_setting:
        hits = set(setting["delta"])
        for group in setting["classes"]:
            inside = sum(1 for cell in group if cell in hits)
            if 0 < inside < len(group):
                return False
    return any(setting["delta"] for setting in per_setting)


# --- one fault ---------------------------------------------------------------------------------


def study_fault(task: tuple[dict[str, Any], str, str]) -> dict[str, Any]:
    fault, corpora, opa = task
    profile = PROFILES[fault["corpus"]]
    space = _load("rego_witness_space")
    payoff = _load("rego_payoff_study")
    membership = _load("fragment_membership_rego")
    repository = Path(corpora) / profile.repository
    record: dict[str, Any] = {
        **{k: fault[k] for k in ("number", "corpus", "commit", "module")},
        "development": (fault["corpus"], fault["commit"]) in DEVELOPMENT,
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        versions = {}
        for name, revision in (("policy", f"{fault['commit']}^"), ("fix", fault["commit"])):
            tree = root / name
            full = materialise(repository, revision, tree)
            source_path = tree / fault["module"]
            if not source_path.exists():
                record["status"] = f"excluded: the {name} has no module at this path"
                return record
            versions[name] = {
                "commit": full,
                "tree": tree,
                "source": source_path.read_text(encoding="utf-8", errors="replace"),
                "libs": library_files(profile, tree),
            }
        record["policy_commit"] = versions["policy"]["commit"]
        record["fix_commit"] = versions["fix"]["commit"]

        # 1. both versions compile
        for name in ("policy", "fix"):
            v = versions[name]
            if not compiles(opa, v["source"], v["libs"]):
                record["status"] = f"excluded: the {name} does not compile"
                return record

        # 2. membership, on the corpus as it stood at each version's commit
        verdicts = {}
        for name in ("policy", "fix"):
            v = versions[name]
            membership.discover(v["tree"])
            verdict = membership.classify(v["source"])
            verdicts[name] = {"verdict": verdict.verdict, "reason": verdict.reason}
        record["membership"] = verdicts
        for name, verdict in verdicts.items():
            acceptable = verdict["verdict"] == "inside" or (
                verdict["verdict"] == "outside"
                and verdict["reason"].startswith("is a policy schema")
            )
            if not acceptable:
                record["status"] = (
                    f"excluded: the {name} is {verdict['verdict']}: {verdict['reason']}"
                )
                return record

        # 3. the authors' inputs, from both suites, and the settings they instantiate
        absent = space.ABSENT
        inputs = []
        seen: set[str] = set()
        for name in ("policy", "fix"):
            v = versions[name]
            for item in authors_inputs(opa, profile, v["source"], v["tree"], fault["module"]):
                key = json.dumps(item, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    inputs.append(item)
        settings: list[Any] = []
        labels: set[str] = set()
        for item in inputs:
            setting = item.get(profile.setting, absent) if isinstance(item, dict) else absent
            label = "absent" if setting is absent else json.dumps(setting, sort_keys=True)
            if label not in labels:
                labels.add(label)
                settings.append(setting)
        if not settings:
            settings = [absent]
        record["authors_inputs"] = len(inputs)
        record["settings"] = len(settings)

        # 4. per setting: the witness space, its check, the quotient of the policy in use
        reviews = [as_review(profile, item) for item in inputs]
        shapes = space.shapes_from(reviews)
        generator = random.Random(f"{SEED}:{fault['corpus']}:{fault['commit']}:{fault['module']}")
        asts = {}
        for name in ("policy", "fix"):
            v = versions[name]
            asts[name] = (
                renamed(space.opa_parse(opa, v["source"]), profile),
                [
                    renamed(space.opa_parse(opa, f.read_text(encoding="utf-8")), profile)
                    for f in v["libs"]
                ],
            )
        per_setting = []
        for setting in settings:
            label = "absent" if setting is absent else setting
            try:
                analysers = {}
                for name in ("policy", "fix"):
                    module_ast, lib_asts = asts[name]
                    analyser = space.Analyzer(
                        [module_ast, *lib_asts], space.package_of(module_ast), setting
                    )
                    analyser.run()
                    analysers[name] = analyser
                merged = space.Analyzer(
                    [asts["policy"][0], *asts["policy"][1]],
                    space.package_of(asts["policy"][0]),
                    setting,
                )
                merged.run()
                for segs, hints in analysers["fix"].hints.items():
                    merged.hints[segs] |= hints
                merged.read |= analysers["fix"].read
                merged.links |= analysers["fix"].links
                cells = space.build(merged, shapes, MAX_CELLS)
            except space.Unsupported as reason:
                record["status"] = f"excluded: {reason}"
                record["setting_failed"] = label
                return record

            pool = space.leaf_pool(cells)
            drawn = [space.perturb(generator.choice(cells), pool, generator) for _ in range(DRAWS)]
            wanted = "absent" if setting is absent else json.dumps(setting, sort_keys=True)
            authors = [
                r["review"]
                for r in reviews
                if isinstance(r, dict)
                and "review" in r
                and (
                    "absent"
                    if "parameters" not in r
                    else json.dumps(r["parameters"], sort_keys=True)
                )
                == wanted
            ]
            authors_drawn = (
                [space.perturb(generator.choice(authors), pool, generator) for _ in range(DRAWS)]
                if authors
                else []
            )
            checks = drawn + authors + authors_drawn
            everything = [wrap(profile, s, setting, absent) for s in cells + checks]
            policy = decide(
                opa, profile, versions["policy"]["source"], versions["policy"]["libs"], everything
            )
            fix = decide(
                opa, profile, versions["fix"]["source"], versions["fix"]["libs"], everything
            )
            delta = [i for i in range(len(cells)) if policy[i] != fix[i]]
            off = [j for j in range(len(cells), len(everything)) if policy[j] != fix[j]]
            if not delta and off:
                record["status"] = "excluded: missing cell"
                record["missing_cell"] = {"setting": label, "input": everything[off[0]]}
                return record

            quotient = payoff.Quotient(analysers["policy"], shapes)
            quotient.decide(opa, quotient.values_to_decide(cells))
            by_signature: dict[str, list[int]] = {}
            for i, cell in enumerate(cells):
                by_signature.setdefault(repr(quotient.signature(cell)), []).append(i)
            classes = list(by_signature.values())
            varying = sum(1 for group in classes if len({json.dumps(policy[i]) for i in group}) > 1)
            if varying:
                record["status"] = (
                    f"excluded: the policy's decision varies inside {varying} classes"
                )
                return record
            decision_groups: dict[str, list[int]] = {}
            for i in range(len(cells)):
                decision_groups.setdefault(json.dumps(policy[i]), []).append(i)
            per_setting.append(
                {
                    "label": label,
                    "cells": len(cells),
                    "classes": classes,
                    "decision_groups": list(decision_groups.values()),
                    "delta": delta,
                    "unmerged_paths": len(quotient.unmerged),
                    "checks": len(checks),
                }
            )

        if not any(s["delta"] for s in per_setting):
            record["status"] = "no decision change under the tested settings"
            return record

        chance = exposure(per_setting)
        new_paths = sorted(
            {repr(p) for p in analysers["fix"].read} - {repr(p) for p in analysers["policy"].read}
        )
        record.update(
            {
                "status": "scored",
                "per_setting": [
                    {
                        "setting": s["label"],
                        "cells": s["cells"],
                        "quotient_classes": len(s["classes"]),
                        "decision_classes": len(s["decision_groups"]),
                        "difference_cells": len(s["delta"]),
                        "unmerged_paths": s["unmerged_paths"],
                        "checks": s["checks"],
                    }
                    for s in per_setting
                ],
                "exposure": {k: round(float(v), 6) for k, v in chance.items()},
                "difference_is_a_union_of_classes": union_of_classes(per_setting),
                "quotient_exposes_with_certainty": chance["quotient"] == 1,
                "fix_reads_paths_the_policy_does_not": len(new_paths) > 0,
            }
        )
    return record


# --- the study ---------------------------------------------------------------------------------


def compare(scores: list[dict[str, float]]) -> dict[str, Any]:
    payoff = _load("rego_payoff_study")
    results: dict[str, Any] = {}
    raw: dict[str, float] = {}
    for name, left, right, alternative in HYPOTHESES:
        differences = [score[left] - score[right] for score in scores]
        low, high = payoff.bootstrap_interval(differences)
        raw[name] = payoff.sign_flip_p(differences, alternative)
        results[name] = {
            "strategies": [left, right],
            "alternative": alternative,
            "faults": len(differences),
            "mean_difference": round(statistics.fmean(differences), 6),
            "median_difference": round(statistics.median(differences), 6),
            "bootstrap_95": [round(low, 6), round(high, 6)],
            "p_value": round(raw[name], 4),
            "wins": sum(1 for d in differences if d > 0),
            "ties": sum(1 for d in differences if d == 0),
            "losses": sum(1 for d in differences if d < 0),
        }
    for name, adjusted in payoff.holm(raw).items():
        results[name]["p_value_holm"] = round(adjusted, 4)
    return results


def summarise(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    scored = [r for r in records if r.get("status") == "scored"]
    if not scored:
        return None
    return {
        "faults": len(scored),
        "difference_is_a_union_of_classes": sum(
            r["difference_is_a_union_of_classes"] for r in scored
        ),
        "quotient_exposes_with_certainty": sum(
            r["quotient_exposes_with_certainty"] for r in scored
        ),
        "fix_reads_paths_the_policy_does_not": sum(
            r["fix_reads_paths_the_policy_does_not"] for r in scored
        ),
        "mean_exposure": {
            s: round(statistics.fmean(r["exposure"][s] for r in scored), 6) for s in STRATEGIES
        },
        "comparisons": compare([r["exposure"] for r in scored]) if len(scored) > 1 else None,
    }


def study(corpora: Path, workers: int, only: list[int] | None) -> dict[str, Any]:
    faults = population()
    development_numbers = {f["number"] for f in faults if (f["corpus"], f["commit"]) in DEVELOPMENT}
    protocol_sha256 = require_protocol(
        development_only=bool(only) and set(only) <= development_numbers
    )
    if only:
        faults = [f for f in faults if f["number"] in set(only)]
    suite = _load("rego_suite_study")
    opa = suite._opa()
    tasks = [(fault, str(corpora), opa) for fault in faults]
    records: list[dict[str, Any]] = []
    context = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers, mp_context=context) as pool:
        futures = {pool.submit(study_fault, task): task[0] for task in tasks}
        for done, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            fault = futures[future]
            try:
                record = future.result()
            except Exception as error:  # an instrument failure is reported, not hidden
                record = {
                    **{k: fault[k] for k in ("number", "corpus", "commit", "module")},
                    "status": f"error: {type(error).__name__}: {str(error)[:200]}",
                }
            records.append(record)
            print(
                f"{done}/{len(tasks)} #{fault['number']} {fault['corpus']} {fault['commit']} "
                f"{fault['module']}: {record.get('status')}",
                flush=True,
            )
    records.sort(key=lambda r: r["number"])
    pooled = [r for r in records if not r.get("development")]
    return {
        "schema_version": "v1",
        "protocol_sha256": protocol_sha256,
        "engine": f"opa {suite._engine_version()}",
        "seed": SEED,
        "resamples": RESAMPLES,
        "max_cells": MAX_CELLS,
        "draws": DRAWS,
        "population": len([r for r in records if not r.get("development")]),
        "statuses": dict(Counter(r.get("status") for r in pooled)),
        "headline": summarise(pooled),
        "by_corpus": {c: summarise([r for r in pooled if r["corpus"] == c]) for c in PROFILES},
        "development": [r for r in records if r.get("development")],
        "faults": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("study")
    run.add_argument("--corpora", type=Path, required=True)
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--only", type=int, nargs="*")
    run.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    result = study(args.corpora, args.workers, args.only)
    text = json.dumps(result, indent=2, sort_keys=False)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
