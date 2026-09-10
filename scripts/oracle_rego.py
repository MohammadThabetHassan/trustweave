"""Check the Rego membership instrument against the engine that runs the policies.

The fragment-membership adapter decides, from a module's syntax, whether every guard is a
function of the request and literals in the policy. That is a claim about what the module
*reads*, and OPA can be asked the same question independently: `opa deps` compiles a bundle
and reports the base documents -- `input.*`, `data.*` -- that a package's rules depend on,
transitively through every rule they call. Its answer comes from the engine's own compiler,
not from this repository's walk over the AST, so where the two agree the adapter's verdict
rests on something other than its author's reading of Rego, and where they disagree one of
them is wrong about a specific module and says which.

This is differential testing in the ordinary sense: two implementations of one question,
compared on every input we have. Three things it found on the first run are recorded in the
artifact rather than smoothed over, because an oracle whose findings are fixed silently is
indistinguishable from one that found nothing.

  * A published module calls `http.send(request, response)` as a top-level statement. In
    the AST that is a bare list of terms headed by the function's reference, not a `call`
    node, and the adapter's walker looked for the wrapped form alone. The module was
    recorded inside the fragment. It is not.
  * The adapter listed by hand five builtins whose result is not a function of their
    arguments. The engine's capabilities document flags nine. No measured module calls
    the other four, so no verdict turned on it, but the list is the engine's to give.
  * Google's Config Validator templates read Constraint parameters through
    `input.constraint`, not Gatekeeper's `input.parameters`, and the adapter knew only the
    second. The same construct was a schema in one corpus and a policy in the other.

The static check covers every module in every corpus. The dynamic check runs each
Gatekeeper template's own test suite twice, once as shipped and once with an injected data
document standing for cluster state the policy did not write, and requires the outcome of
every test to be identical for a module the adapter calls inside: a guard that is a
function of the request cannot notice what else is in `data`. A module the adapter calls
outside for reading `data.inventory` is reported but not judged this way, because its tests
mock the inventory and the mock shadows the injection.

Usage:
    python scripts/oracle_rego.py CORPUS_ROOT [CORPUS_ROOT ...] [--dynamic] [--json out.json]

`CORPUS_ROOT` is the same root the membership artifact was measured from, so the subjects
line up: `corpora/gcp` for the Config Validator library, `corpora/rego` for the four
Gatekeeper-adjacent repositories.
"""

from __future__ import annotations

import argparse
import io
import json
import random
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import fragment_membership as core  # noqa: E402
import fragment_membership_rego as rego  # noqa: E402

DEFAULT_SEED = 20260909

# Base-document roots the host supplies at evaluation time. The adapter and the engine-side
# rule both name `data.inventory`; the list is here so the oracle does not import the
# adapter's constant and thereby agree with it by construction.
INJECTED_ROOTS = ("inventory",)
PARAMETER_PREFIXES = (("input", "parameters"), ("input", "constraint", "spec", "parameters"))
PARAMETER_FETCHER = "get_constraint_params"


def _opa() -> str:
    found = shutil.which("opa")
    if not found:
        raise SystemExit("opa is not on PATH; the oracle needs the engine to disagree with")
    return found


def _run(arguments: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=timeout)


def opa_version() -> str:
    completed = _run([_opa(), "version"])
    match = re.search(r"Version:\s*(\S+)", completed.stdout)
    return match.group(1) if match else "unknown"


def engine_nondeterministic_builtins() -> frozenset[str]:
    """The builtins the engine itself flags as not a function of their arguments."""

    completed = _run([_opa(), "capabilities", "--current"])
    if completed.returncode != 0:
        raise SystemExit("could not read opa capabilities")
    document = json.loads(completed.stdout)
    return frozenset(
        entry["name"] for entry in document.get("builtins", []) if entry.get("nondeterministic")
    )


# ---------------------------------------------------------------------------------------
# Bundles. Built by hand rather than with `opa build`, for two reasons: `opa build
# --v0-compatible` rewrites a v0 module into v1 syntax on the way in, and the rewrite fails
# on one published module; and a bundle's manifest can carry a Rego version per file, which
# is what a corpus mixing dialects needs. The bundle is only a container here.
# ---------------------------------------------------------------------------------------


def rego_version(path: Path) -> int | None:
    """0 or 1 for the dialect this file parses under, None when it parses under neither."""

    if _run([_opa(), "parse", "--v0-compatible", str(path)]).returncode == 0:
        return 0
    if _run([_opa(), "parse", str(path)]).returncode == 0:
        return 1
    return None


def build_bundle(repository: Path, destination: Path) -> dict[str, Any]:
    """Every non-test module of one repository, tagged with the dialect it parses under."""

    modules: list[Path] = []
    unparsed: list[str] = []
    versions: dict[str, int] = {}
    for path in sorted(repository.rglob("*.rego")):
        if ".git" in path.parts:
            continue
        if path.name.endswith("_test.rego") or path.name.startswith("test_"):
            continue
        version = rego_version(path)
        if version is None:
            unparsed.append(path.relative_to(repository).as_posix())
            continue
        modules.append(path)
        versions["/" + path.relative_to(repository).as_posix()] = version

    majority = Counter(versions.values()).most_common(1)[0][0] if versions else 0
    manifest: dict[str, Any] = {"revision": "", "roots": [""], "rego_version": majority}
    exceptions = {name: version for name, version in versions.items() if version != majority}
    if exceptions:
        manifest["file_rego_versions"] = exceptions

    with tarfile.open(destination, "w:gz") as bundle:
        for path in modules:
            data = path.read_bytes()
            info = tarfile.TarInfo("/" + path.relative_to(repository).as_posix())
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
        data = json.dumps(manifest).encode("utf-8")
        info = tarfile.TarInfo("/.manifest")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))
    return {"modules": len(modules), "unparsed": unparsed, "rego_version": majority}


def dependencies(bundle: Path, package: str) -> tuple[set[str], set[str]] | str:
    """(base document paths, virtual document paths) for `data.<package>`, or an error."""

    completed = _run([_opa(), "deps", "--format=json", "-b", str(bundle), f"data.{package}"])
    if completed.returncode != 0:
        return (completed.stderr or completed.stdout).strip().splitlines()[0][:200]
    document = json.loads(completed.stdout)

    def path_of(term: list[dict[str, Any]]) -> str:
        return ".".join(str(part.get("value")) for part in term)

    base = {path_of(term) for term in document.get("base") or []}
    virtual = {path_of(term) for term in document.get("virtual") or []}
    return base, virtual


# ---------------------------------------------------------------------------------------
# The engine-side verdict. Computed from what `opa deps` says the package reads, the
# engine's own list of nondeterministic builtins, and a textual scan for calls to them; the
# adapter's AST walk is not consulted.
# ---------------------------------------------------------------------------------------


def engine_view(
    base: set[str],
    virtual: set[str],
    declared_packages: set[str],
    text: str,
    nondeterministic: frozenset[str],
    own_package: str = "",
) -> dict[str, Any]:
    """What the engine says this package reads, sorted into the categories that matter.

    Reading a parameter *key* -- a base document strictly below the parameter block -- is
    kept apart from fetching the block: a template that calls `get_constraint_params` and
    never indexes the result has a decision function no parameter can change, and four of
    the measured templates do exactly that. The engine cannot see through the local variable
    the fetch binds, so for a template that does index it the engine reports only the fetch;
    the adapter's own key list is the finer instrument there, and the agreement rule below
    says what each pairing is allowed to mean. A package's own rules are not counted as
    fetching: the library that defines the fetcher is not thereby reading parameters.
    """
    reads_injected = sorted(
        path for path in base if path.split(".")[:2] in [["data", root] for root in INJECTED_ROOTS]
    )
    undefined = []
    for path in base:
        parts = path.split(".")
        if parts[0] != "data" or path in reads_injected:
            continue
        names = parts[1:]
        if not any(
            ".".join(names[:length]) in declared_packages for length in range(len(names), 0, -1)
        ):
            undefined.append(path)
    reads_key = sorted(
        path
        for path in base
        if any(
            tuple(path.split(".")[: len(prefix)]) == prefix and len(path.split(".")) > len(prefix)
            for prefix in PARAMETER_PREFIXES
        )
    )
    fetches = sorted(
        path
        for path in base
        if any(tuple(path.split(".")) == prefix for prefix in PARAMETER_PREFIXES)
    ) + sorted(
        path
        for path in virtual
        if path.split(".")[-1] == PARAMETER_FETCHER
        and ".".join(path.split(".")[1:-1]) != own_package
    )
    called = sorted(
        name for name in nondeterministic if re.search(rf"\b{re.escape(name)}\s*\(", text)
    )
    if reads_injected or undefined or called:
        verdict = "external"
    elif reads_key:
        verdict = "reads a parameter key"
    elif fetches:
        verdict = "fetches the parameter block"
    else:
        verdict = "request and literals only"
    return {
        "verdict": verdict,
        "reads_injected": reads_injected,
        "reads_undefined_data": sorted(undefined),
        "reads_parameter_keys": reads_key,
        "fetches_parameters": fetches,
        "nondeterministic_calls": called,
        "base_documents": sorted(base),
    }


def adapter_view(outcome: core.Verdict) -> dict[str, Any]:
    reason = outcome.reason
    reads = outcome.detail.get("parameter_reads") or {}
    if outcome.verdict == core.INSIDE:
        kind = "inside, parameters defaulted" if reads else "inside"
    elif "policy schema" in reason:
        kind = "schema"
    elif "not a function of its arguments" in reason:
        kind = "outside: nondeterministic builtin"
    elif outcome.verdict == core.OUTSIDE:
        kind = "outside: reads state the subject does not carry"
    else:
        kind = "undetermined"
    return {"verdict": outcome.verdict, "kind": kind, "reason": reason}


def agree(adapter: dict[str, Any], engine: dict[str, Any]) -> bool:
    """Whether the two readings of one module are consistent.

    The engine cannot see defaults, so a module the adapter calls inside because every
    parameter read is defaulted is consistent with the engine seeing the parameters read or
    fetched. A module the adapter calls inside with no parameter read may still fetch the
    block -- four measured templates bind it and never index it -- so that pairing is
    allowed too. Every other pairing is strict: a schema needs the engine to see the
    parameters at all, a nondeterministic exclusion needs the textual scan to find the
    builtin, and any other exclusion needs an injected or undefined document in the
    dependency set.
    """

    kind, verdict = adapter["kind"], engine["verdict"]
    parameters_seen = bool(engine["reads_parameter_keys"] or engine["fetches_parameters"])
    if kind == "inside":
        # Fetching the block without indexing it leaves the decision function alone.
        return verdict in ("request and literals only", "fetches the parameter block")
    if kind == "inside, parameters defaulted":
        return verdict != "external"
    if kind == "schema":
        return parameters_seen
    if kind == "outside: nondeterministic builtin":
        return bool(engine["nondeterministic_calls"])
    if kind == "outside: reads state the subject does not carry":
        return bool(engine["reads_injected"] or engine["reads_undefined_data"])
    return False


def static_check(root: Path, nondeterministic: frozenset[str], workspace: Path) -> dict[str, Any]:
    subjects = rego.discover(root)
    repositories = sorted({root / Path(subject).parts[0] for subject, _ in subjects}) or [root]
    if (
        len(repositories) == 1
        and not (repositories[0] / ".git").exists()
        and (root / ".git").exists()
    ):
        repositories = [root]

    bundles: dict[Path, dict[str, Any]] = {}
    declared: dict[Path, set[str]] = defaultdict(set)
    for repository in repositories:
        bundle_path = workspace / (repository.name.replace("/", "_") + ".tar.gz")
        bundles[repository] = {"path": bundle_path, **build_bundle(repository, bundle_path)}
    for subject, path in subjects:
        ast = rego.parse(path.read_text(encoding="utf-8", errors="ignore"))
        if ast is not None:
            declared[_repository_of(root, subject, repositories)].add(rego.package_of(ast))

    deps_cache: dict[tuple[Path, str], tuple[set[str], set[str]] | str] = {}
    modules: list[dict[str, Any]] = []
    agreements = disagreements = unloaded = 0
    package_members: Counter[tuple[Path, str]] = Counter()
    for subject, path in subjects:
        text = path.read_text(encoding="utf-8", errors="ignore")
        outcome = rego.classify(text)
        ast = rego.parse(text)
        package = rego.package_of(ast) if ast else ""
        repository = _repository_of(root, subject, repositories)
        package_members[(repository, package)] += 1
        key = (repository, package)
        if key not in deps_cache:
            deps_cache[key] = dependencies(bundles[repository]["path"], package)
        result = deps_cache[key]
        entry: dict[str, Any] = {
            "subject": subject,
            "package": package,
            "adapter": adapter_view(outcome),
        }
        if isinstance(result, str):
            unloaded += 1
            entry["engine"] = {"error": result}
            entry["agree"] = None
        else:
            base, virtual = result
            entry["engine"] = engine_view(
                base, virtual, declared[repository], text, nondeterministic, package
            )
            entry["agree"] = agree(entry["adapter"], entry["engine"])
            if entry["agree"]:
                agreements += 1
            else:
                disagreements += 1
        modules.append(entry)

    shared = sorted(
        f"{repository.name}:{package}"
        for (repository, package), count in package_members.items()
        if count > 1
    )
    return {
        "root": root.name,
        "corpus": core.provenance(root),
        "modules": len(modules),
        "engine_could_not_load": unloaded,
        "agreements": agreements,
        "disagreements": disagreements,
        "disagreeing_modules": [entry for entry in modules if entry["agree"] is False],
        "packages_declared_in_more_than_one_module": shared,
        "bundles": {
            repository.name: {k: v for k, v in bundle.items() if k != "path"}
            for repository, bundle in bundles.items()
        },
        "by_adapter_kind": dict(Counter(entry["adapter"]["kind"] for entry in modules)),
        "by_engine_verdict": dict(
            Counter(entry["engine"].get("verdict", "could not load") for entry in modules)
        ),
        "detail": modules,
    }


def _repository_of(root: Path, subject: str, repositories: list[Path]) -> Path:
    if len(repositories) == 1:
        return repositories[0]
    return root / Path(subject).parts[0]


# ---------------------------------------------------------------------------------------
# The dynamic check: a module inside the fragment cannot tell what else is in `data`.
# ---------------------------------------------------------------------------------------


def _test_outcomes(
    directory: Path, extra: list[Path], dialect: list[str]
) -> dict[str, dict[str, str]] | None:
    """Per-test outcomes for one directory's suite, grouped by the package each test is in.

    A suite runs as a directory, and a directory may hold a template beside the small
    libraries it imports. Attributing every test in the directory to every module in it
    would credit a library with a template's suite, so tests are attributed by package: a
    Gatekeeper suite declares the package of the template it exercises.
    """

    completed = _run(
        [_opa(), "test", *dialect, "--format=json", str(directory), *(str(p) for p in extra)]
    )
    if not completed.stdout.strip():
        return None
    try:
        results = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    outcomes: dict[str, dict[str, str]] = {}
    for result in results:
        package = str(result.get("package") or "").removeprefix("data.")
        if result.get("error"):
            outcome = "error"
        elif result.get("fail"):
            outcome = "fail"
        elif result.get("skip"):
            outcome = "skip"
        else:
            outcome = "pass"
        outcomes.setdefault(package, {})[str(result.get("name"))] = outcome
    return outcomes


def _perturbation(seed: int, workspace: Path) -> Path:
    """A data document standing for cluster state the policy did not write.

    An `inventory` shaped like Gatekeeper's cache, populated at random, plus a root nothing
    declares. A module reading only the request cannot see either.
    """

    generator = random.Random(seed)
    words = ["prod", "dev", "team-a", "ingress", "payments", "shadow", "kube-system"]
    namespaces = {
        generator.choice(words) + str(generator.randint(1, 99)): {
            "metadata": {
                "name": generator.choice(words),
                "labels": {"tier": generator.choice(words)},
            },
        }
        for _ in range(generator.randint(2, 6))
    }
    document = {
        "inventory": {
            "cluster": {"v1": {"Namespace": namespaces}},
            "namespace": {
                name: {"v1": {"Service": {generator.choice(words): {"spec": {"type": "NodePort"}}}}}
                for name in namespaces
            },
        },
        f"unrelated_{generator.randint(1000, 9999)}": {
            "values": [generator.random() for _ in range(3)]
        },
    }
    path = workspace / f"perturbation-{seed}.json"
    path.write_text(json.dumps(document, indent=1), encoding="utf-8")
    return path


def dynamic_check(root: Path, seed: int, workspace: Path) -> dict[str, Any]:
    subjects = rego.discover(root)
    verdicts = {
        subject: rego.classify(path.read_text(encoding="utf-8", errors="ignore"))
        for subject, path in subjects
    }
    perturbations = [_perturbation(seed, workspace), _perturbation(seed + 1, workspace)]
    checked: list[dict[str, Any]] = []
    invariant = changed = skipped = no_tests = 0
    # One run per directory -- as shipped, then under each perturbation -- attributed to the
    # modules in it by package. Config Validator's suites do not load under this engine (its
    # fixture documents are not JSON it accepts), so they fall out as unrunnable rather than
    # being checked badly.
    Run = tuple[dict[str, dict[str, str]], list[dict[str, dict[str, str]] | None]]
    runs: dict[Path, Run | None] = {}
    for subject, path in subjects:
        directory = path.parent
        if not any(sibling.name.endswith("_test.rego") for sibling in directory.iterdir()):
            continue
        if directory not in runs:
            runs[directory] = None
            for flags in ([], ["--v0-compatible"]):
                baseline_all = _test_outcomes(directory, [], flags)
                if baseline_all:
                    perturbed = [_test_outcomes(directory, [p], flags) for p in perturbations]
                    runs[directory] = (baseline_all, perturbed)
                    break
        run = runs[directory]
        if run is None:
            skipped += 1
            continue
        baseline_all, perturbed_all = run
        ast = rego.parse(path.read_text(encoding="utf-8", errors="ignore"))
        package = rego.package_of(ast) if ast else ""
        baseline = baseline_all.get(package)
        if not baseline:
            no_tests += 1
            continue
        outcomes = [(perturbed or {}).get(package, {}) for perturbed in perturbed_all]
        same = all(outcome == baseline for outcome in outcomes)
        verdict = verdicts[subject]
        entry = {
            "subject": subject,
            "adapter_verdict": verdict.verdict,
            "tests": len(baseline),
            "baseline": dict(Counter(baseline.values())),
            "outcomes_identical_under_injected_data": same,
        }
        if not same:
            differing = sorted(
                name
                for outcome in outcomes
                for name in set(outcome) | set(baseline)
                if outcome.get(name) != baseline.get(name)
            )
            entry["tests_that_changed"] = differing[:10]
        if verdict.verdict == core.INSIDE:
            invariant += same
            changed += not same
        checked.append(entry)
    inside_checked = [entry for entry in checked if entry["adapter_verdict"] == core.INSIDE]
    return {
        "root": root.name,
        "seed": seed,
        "modules_with_tests": len(checked),
        "modules_without_a_runnable_suite": skipped,
        "modules_whose_directory_suite_has_no_tests_in_their_package": no_tests,
        "inside_modules_checked": len(inside_checked),
        "inside_modules_invariant_under_injected_data": invariant,
        "inside_modules_whose_outcomes_changed": changed,
        "tests_compared": sum(entry["tests"] for entry in inside_checked),
        "outside_modules_reported_not_judged": sum(
            1 for entry in checked if entry["adapter_verdict"] != core.INSIDE
        ),
        "detail": checked,
    }


# ---------------------------------------------------------------------------------------


def builtin_list_check(roots: list[Path], nondeterministic: frozenset[str]) -> dict[str, Any]:
    """The adapter's hand list against the engine's flags, and what the corpora call."""

    hand = rego.NONDETERMINISTIC_BUILTINS
    used: Counter[str] = Counter()
    for root in roots:
        for _subject, path in rego.discover(root):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for name in nondeterministic | hand:
                if re.search(rf"\b{re.escape(name)}\s*\(", text):
                    used[name] += 1
    return {
        "hand_listed": sorted(hand),
        "engine_flagged": sorted(nondeterministic),
        "engine_flagged_not_hand_listed": sorted(nondeterministic - hand),
        "hand_listed_not_engine_flagged": sorted(hand - nondeterministic),
        "adapter_now_uses": sorted(rego.nondeterministic_builtins()),
        "called_in_measured_corpora": dict(sorted(used.items())),
    }


def measure(roots: list[Path], dynamic: bool, seed: int) -> dict[str, Any]:
    nondeterministic = engine_nondeterministic_builtins()
    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        static = [static_check(root, nondeterministic, workspace) for root in roots]
        dynamics = []
        if dynamic:
            for root in roots:
                result = dynamic_check(root, seed, workspace)
                if result["modules_with_tests"]:
                    dynamics.append(result)
    return {
        "schema_version": "v1",
        "engine": {"name": "opa", "version": opa_version()},
        "seed": seed,
        "builtins": builtin_list_check(roots, nondeterministic),
        "static": static,
        "dynamic": dynamics,
        "modules": sum(entry["modules"] for entry in static),
        "agreements": sum(entry["agreements"] for entry in static),
        "disagreements": sum(entry["disagreements"] for entry in static),
        "engine_could_not_load": sum(entry["engine_could_not_load"] for entry in static),
    }


def render(findings: dict[str, Any]) -> str:
    lines = [
        f"opa {findings['engine']['version']}: {findings['modules']} modules, "
        f"{findings['agreements']} agree, {findings['disagreements']} disagree, "
        f"{findings['engine_could_not_load']} the engine could not load"
    ]
    for corpus in findings["static"]:
        lines.append(
            f"  {corpus['root']}: {corpus['modules']} modules, "
            f"{corpus['disagreements']} disagreements"
        )
        for entry in corpus["disagreeing_modules"][:10]:
            lines.append(
                f"    {entry['subject']}: adapter says {entry['adapter']['kind']!r}, "
                f"engine sees {entry['engine'].get('verdict')!r}"
            )
    builtins = findings["builtins"]
    if builtins["engine_flagged_not_hand_listed"]:
        lines.append(
            "  engine flags builtins the hand list lacked: "
            + ", ".join(builtins["engine_flagged_not_hand_listed"])
        )
    for dynamic in findings["dynamic"]:
        lines.append(
            f"  dynamic {dynamic['root']}: {dynamic['inside_modules_checked']} inside modules, "
            f"{dynamic['tests_compared']} tests, "
            f"{dynamic['inside_modules_invariant_under_injected_data']} invariant, "
            f"{dynamic['inside_modules_whose_outcomes_changed']} changed"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument(
        "--dynamic", action="store_true", help="also run each suite under injected data"
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    findings = measure(args.roots, args.dynamic, args.seed)
    print(render(findings))
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 1 if findings["disagreements"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
