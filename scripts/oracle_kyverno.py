"""Check the Kyverno membership instrument against the engine that runs the policies.

The fragment-membership adapter decides, from a policy's syntax, whether every guard is a
function of the admission request and literals in the policy. Kyverno has no `opa deps`,
but it ships two things that can be asked a related question. Its test harness makes the
suite author declare what the request does not carry: a `Values` file stubs context
variables and namespace labels, and a `Context` file stubs the cluster resources and image
manifests a CEL policy fetches. And the engine runs the suite, so the same suite can be run
twice and compared, as `scripts/oracle_rego.py` does with an injected `data` document.

Three comparisons, each recorded per policy:

  * Static. What the shipped suite stubs, classified by whether the policy declares it: a
    field of the admission request itself (`request.namespace`, `request.operation`), a
    `variable` the policy computes from the request, or something else -- an `apiCall`,
    `configMap` or `imageRegistry` entry, a namespace label, a context file, or a name the
    policy never declares. Only the last group is *external*. A policy the adapter calls
    inside whose suite stubs nothing external is consistent with the adapter; one whose
    suite does is a candidate disagreement, settled by the engine below.
  * Injection. Every runnable suite is run as shipped and again with namespace labels the
    policy did not write injected for every namespace its resources name, plus a global
    value nothing declares. A guard that reads only the request cannot notice either, so an
    inside policy's outcomes must be identical.
  * Removal. A suite that stubs external data is run again with those stubs removed and
    the request-field stubs kept. If the engine's outcome changes, the suite needed what the
    adapter says the policy reads. For an outside policy that is agreement; for an inside
    policy it is a disagreement. If nothing changes, the stub was not reached by the suite
    and the policy is reported rather than judged.

What this cannot adjudicate is stated in the artifact rather than smoothed over. A policy
outside for selecting on the requester's role bindings has nothing a suite can stub, and an
outside policy whose suite stubs nothing is not judged either way. Disagreements are
printed, not fixed here: an oracle whose findings are fixed silently is indistinguishable
from one that found nothing.

Usage:
    python scripts/oracle_kyverno.py CORPUS_ROOT [--seed N] [--limit N] [--json out.json]

`CORPUS_ROOT` is the same checkout `docs/fragment-membership-kyverno-wide-v1.json` was
measured from, and policies are discovered exactly as that measurement discovers them, so
the subjects line up.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml  # type: ignore[import-untyped]

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

DEFAULT_SEED = 20260916
INSIDE, OUTSIDE, UNDETERMINED = "inside", "outside", "undetermined"
AGREE, DISAGREE, NOT_JUDGED = "agree", "disagree", "not judged"

# Context entry kinds a classic policy declares. A `variable` is computed from the request
# by a JMESPath expression; everything else reaches past it.
EXTERNAL_CONTEXT_KINDS = frozenset({"apiCall", "configMap", "imageRegistry", "globalReference"})
# Names Kyverno binds without a declaration when a rule verifies images. The image manifest
# and config they hold come from a registry, which the admission request does not carry.
IMPLICIT_EXTERNAL_ROOTS = frozenset({"imageData", "images", "image"})
# The values file's own keys, so a `Values` document is read and not guessed at.
VALUES_HEADER = {"apiVersion": "cli.kyverno.io/v1alpha1", "kind": "Values"}


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    if specification is None or specification.loader is None:  # pragma: no cover
        raise SystemExit(f"cannot load {name}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


core = _load("fragment_membership")
kyverno = _load("fragment_membership_kyverno")
mutation = _load("kyverno_mutation")


# --- the engine -----------------------------------------------------------------------


def _kyverno() -> str:
    found = shutil.which("kyverno")
    if not found:
        raise SystemExit("kyverno is not on PATH; install the CLI to run this oracle")
    return found


def _run(arguments: list[str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=timeout)


def kyverno_version() -> str:
    completed = _run([_kyverno(), "version"])
    for line in completed.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def parse_outcomes(output: str) -> dict[str, str] | None:
    """{policy|rule|resource: result} from `kyverno test -o json`, or None if it did not run.

    The engine prints its loading log before the JSON array, so the array is cut out by
    its brackets rather than parsed from the whole stream.
    """

    start = output.find("\n[")
    end = output.rfind("\n]")
    if start < 0 or end < 0 or end < start:
        return None
    try:
        rows = json.loads(output[start + 1 : end + 2])
    except json.JSONDecodeError:
        return None
    if not isinstance(rows, list):
        return None
    outcomes: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = "|".join(str(row.get(column, "")) for column in ("POLICY", "RULE", "RESOURCE"))
        outcomes[key] = str(row.get("RESULT", ""))
    return outcomes


def suite_outcomes(directory: Path) -> dict[str, str] | None:
    """Run one suite as it stands in `directory` and read every result row."""

    try:
        completed = _run([_kyverno(), "test", str(directory), "-o", "json", "--remove-color"])
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_outcomes(completed.stdout + "\n")


# --- what a suite stubs ---------------------------------------------------------------


@dataclass
class Stubs:
    """Everything a suite supplies that an admission request would not."""

    values_file: str | None = None
    context_file: str | None = None
    rule_values: list[str] = field(default_factory=list)
    global_values: list[str] = field(default_factory=list)
    namespace_labels: bool = False
    subresources: bool = False


def _read_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        return None


def _read_yaml_all(path: Path) -> list[Any]:
    try:
        return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        return []


def stubs_of(test_directory: Path) -> Stubs:
    manifest = _read_yaml(test_directory / "kyverno-test.yaml")
    stubs = Stubs()
    if not isinstance(manifest, dict):
        return stubs
    context = manifest.get("context")
    if isinstance(context, str):
        stubs.context_file = context
    values_name = manifest.get("variables")
    if not isinstance(values_name, str):
        return stubs
    stubs.values_file = values_name
    values = _read_yaml(test_directory / values_name)
    if not isinstance(values, dict):
        return stubs
    for policy in values.get("policies") or []:
        if not isinstance(policy, dict):
            continue
        for rule in policy.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            for block in ("values", "foreachValues"):
                held = rule.get(block)
                if isinstance(held, dict):
                    stubs.rule_values.extend(str(name) for name in held)
    held = values.get("globalValues")
    if isinstance(held, dict):
        stubs.global_values.extend(str(name) for name in held)
    stubs.namespace_labels = bool(values.get("namespaceSelector"))
    stubs.subresources = bool(values.get("subresources"))
    return stubs


def declared_context(policy_text: str) -> dict[str, str]:
    """{name: kind} for every context entry and CEL variable the policy declares."""

    declared: dict[str, str] = {}
    for document in _documents(policy_text):
        specification = document.get("spec")
        if not isinstance(specification, dict):
            continue
        for variable in specification.get("variables") or []:
            if isinstance(variable, dict) and isinstance(variable.get("name"), str):
                declared[variable["name"]] = "variable"
        for rule in specification.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            for entry in rule.get("context") or []:
                if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                    continue
                kinds = [kind for kind in EXTERNAL_CONTEXT_KINDS if kind in entry]
                declared[entry["name"]] = kinds[0] if kinds else "variable"
    return declared


def _documents(text: str) -> list[dict[str, Any]]:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []
    return [document for document in documents if isinstance(document, dict)]


def classify_stub(name: str, declared: dict[str, str]) -> str:
    """Which side of the request a stubbed name lies on.

    `request` names a field of the AdmissionReview, which the CLI cannot construct offline
    and a suite is entitled to supply. `declared-variable` is a value the policy computes
    from the request. Everything else is external to the request.
    """

    root = name.split(".", 1)[0]
    if root == "request":
        return "request"
    kind = declared.get(root)
    if kind == "variable":
        return "declared-variable"
    if kind in EXTERNAL_CONTEXT_KINDS:
        return "declared-context"
    if root in IMPLICIT_EXTERNAL_ROOTS:
        return "implicit-external"
    return "undeclared"


def external_stubs(stubs: Stubs, declared: dict[str, str]) -> list[str]:
    """The stubbed names and mechanisms that supply something outside the request."""

    found = [
        f"{name} ({classify_stub(name, declared)})"
        for name in [*stubs.rule_values, *stubs.global_values]
        if classify_stub(name, declared) not in ("request", "declared-variable")
    ]
    if stubs.namespace_labels:
        found.append("namespace labels (namespaceSelector)")
    if stubs.context_file:
        found.append(f"context file ({stubs.context_file})")
    return found


# --- perturbed copies of a suite ------------------------------------------------------


def _resource_namespaces(test_directory: Path, manifest: dict[str, Any]) -> list[str]:
    namespaces: set[str] = set()
    for reference in manifest.get("resources") or []:
        if not isinstance(reference, str):
            continue
        for document in _read_yaml_all(test_directory / reference):
            metadata = document.get("metadata") if isinstance(document, dict) else None
            namespace = metadata.get("namespace") if isinstance(metadata, dict) else None
            namespaces.add(namespace if isinstance(namespace, str) else "default")
    return sorted(namespaces) or ["default"]


def _stage(test_directory: Path, workspace: Path, label: str) -> Path:
    """Copy the policy directory (the suite's parent) so `../policy.yaml` still resolves."""

    source = test_directory.parent
    destination = workspace / label / source.name
    shutil.copytree(source, destination)
    return destination / test_directory.name


def injected_suite(test_directory: Path, workspace: Path, seed: int) -> Path:
    """The suite with namespace labels and a global value the policy did not write."""

    staged = _stage(test_directory, workspace, "injected")
    manifest = _read_yaml(staged / "kyverno-test.yaml")
    if not isinstance(manifest, dict):
        return staged
    generator = random.Random(seed)
    values_name = manifest.get("variables")
    values = _read_yaml(staged / values_name) if isinstance(values_name, str) else None
    if not isinstance(values, dict):
        values = dict(VALUES_HEADER)
        values_name = "trustweave-oracle-values.yaml"
        manifest["variables"] = values_name
    selectors = values.get("namespaceSelector")
    if not isinstance(selectors, list):
        selectors = []
    present = {entry.get("name") for entry in selectors if isinstance(entry, dict)}
    injected_labels = {
        f"trustweave-oracle/{seed}": "injected",
        "tier": generator.choice(["prod", "dev", "payments", "shadow"]),
    }
    for namespace in _resource_namespaces(staged, manifest):
        if namespace in present:
            for entry in selectors:
                if isinstance(entry, dict) and entry.get("name") == namespace:
                    labels = entry.setdefault("labels", {})
                    if isinstance(labels, dict):
                        labels.update(injected_labels)
        else:
            selectors.append({"name": namespace, "labels": dict(injected_labels)})
    values["namespaceSelector"] = selectors
    globals_held = values.get("globalValues")
    if not isinstance(globals_held, dict):
        globals_held = {}
    globals_held[f"trustweaveOracleInjected{generator.randint(1000, 9999)}"] = "unrelated"
    values["globalValues"] = globals_held
    (staged / str(values_name)).write_text(yaml.safe_dump(values, sort_keys=False), "utf-8")
    (staged / "kyverno-test.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), "utf-8")
    return staged


def stripped_suite(test_directory: Path, workspace: Path, declared: dict[str, str]) -> Path:
    """The suite with every external stub removed and the request-field stubs kept."""

    staged = _stage(test_directory, workspace, "stripped")
    manifest = _read_yaml(staged / "kyverno-test.yaml")
    if not isinstance(manifest, dict):
        return staged
    manifest.pop("context", None)
    values_name = manifest.get("variables")
    values = _read_yaml(staged / values_name) if isinstance(values_name, str) else None
    if isinstance(values, dict):
        kept_policies = []
        for policy in values.get("policies") or []:
            if not isinstance(policy, dict):
                continue
            kept_rules = []
            for rule in policy.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                for block in ("values", "foreachValues"):
                    held = rule.get(block)
                    if isinstance(held, dict):
                        rule[block] = {
                            name: value
                            for name, value in held.items()
                            if classify_stub(str(name), declared)
                            in ("request", "declared-variable")
                        }
                        if not rule[block]:
                            del rule[block]
                if any(block in rule for block in ("values", "foreachValues")):
                    kept_rules.append(rule)
            if kept_rules:
                policy["rules"] = kept_rules
                kept_policies.append(policy)
        values.pop("namespaceSelector", None)
        held = values.get("globalValues")
        if isinstance(held, dict):
            values["globalValues"] = {
                name: value
                for name, value in held.items()
                if classify_stub(str(name), declared) in ("request", "declared-variable")
            }
            if not values["globalValues"]:
                del values["globalValues"]
        if kept_policies:
            values["policies"] = kept_policies
        else:
            values.pop("policies", None)
        if set(values) - set(VALUES_HEADER) - {"subresources"}:
            (staged / str(values_name)).write_text(yaml.safe_dump(values, sort_keys=False), "utf-8")
        else:
            manifest.pop("variables", None)
    (staged / "kyverno-test.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), "utf-8")
    return staged


# --- the comparison -------------------------------------------------------------------


def _changed(baseline: dict[str, str], other: dict[str, str] | None) -> list[str]:
    if other is None:
        return ["suite did not run"]
    return sorted(key for key in set(baseline) | set(other) if baseline.get(key) != other.get(key))


def judge_policy(
    name: str, policy_path: Path, test_directory: Path, workspace: Path, seed: int
) -> dict[str, Any]:
    text = policy_path.read_text(encoding="utf-8", errors="ignore")
    verdict = kyverno.classify(text)
    declared = declared_context(text)
    stubs = stubs_of(test_directory)
    external = external_stubs(stubs, declared)
    entry: dict[str, Any] = {
        "subject": name,
        "adapter_verdict": verdict.verdict,
        "adapter_reason": verdict.reason,
        "suite_stubs": {
            "request_fields": sorted(
                stub
                for stub in [*stubs.rule_values, *stubs.global_values]
                if classify_stub(stub, declared) == "request"
            ),
            "declared_variables": sorted(
                stub
                for stub in [*stubs.rule_values, *stubs.global_values]
                if classify_stub(stub, declared) == "declared-variable"
            ),
            "external": external,
        },
    }
    baseline = suite_outcomes(test_directory)
    if not baseline:
        entry["baseline"] = None
        entry["status"] = NOT_JUDGED
        entry["why"] = "the suite does not run under this engine as shipped"
        if verdict.verdict == INSIDE and external:
            entry["status"] = DISAGREE
            entry["why"] = "the suite stubs external data and the engine could not settle it"
        elif verdict.verdict == OUTSIDE and external:
            entry["status"] = AGREE
            entry["why"] = "the suite stubs what the adapter says the policy reads"
        return entry
    entry["baseline"] = dict(Counter(baseline.values()))
    entry["tests"] = len(baseline)

    injected = suite_outcomes(injected_suite(test_directory, workspace, seed))
    injected_changes = _changed(baseline, injected)
    entry["outcomes_identical_under_injected_labels"] = not injected_changes
    if injected_changes:
        entry["tests_changed_by_injection"] = injected_changes[:10]

    if external:
        stripped = suite_outcomes(stripped_suite(test_directory, workspace, declared))
        removal_changes = _changed(baseline, stripped)
        entry["outcomes_identical_with_external_stubs_removed"] = not removal_changes
        if removal_changes:
            entry["tests_changed_by_removal"] = removal_changes[:10]

    if verdict.verdict == UNDETERMINED:
        entry["status"] = NOT_JUDGED
        entry["why"] = "the adapter declines to judge this policy"
    elif verdict.verdict == INSIDE:
        if injected_changes:
            entry["status"] = DISAGREE
            entry["why"] = "outcomes changed under injected namespace labels"
        elif external and not entry["outcomes_identical_with_external_stubs_removed"]:
            entry["status"] = DISAGREE
            entry["why"] = "the engine needed external data the adapter says the policy never reads"
        elif external:
            entry["status"] = AGREE
            entry["why"] = "the suite stubs external data the engine did not need"
        else:
            entry["status"] = AGREE
            entry["why"] = "invariant under injected labels; the suite stubs nothing external"
    else:
        if external and not entry["outcomes_identical_with_external_stubs_removed"]:
            entry["status"] = AGREE
            entry["why"] = "the engine needed what the adapter says the policy reads"
        elif injected_changes:
            entry["status"] = AGREE
            entry["why"] = "outcomes changed under injected namespace labels"
        elif external:
            entry["status"] = NOT_JUDGED
            entry["why"] = "the suite stubs external data but never reaches the guard reading it"
        else:
            entry["status"] = NOT_JUDGED
            entry["why"] = "the suite stubs nothing the engine could be denied"
    return entry


def measure(root: Path, seed: int, limit: int | None = None) -> dict[str, Any]:
    subjects = kyverno.discover(root)
    manifests = mutation.policy_manifests(root)
    if limit is not None:
        subjects = subjects[:limit]
    detail: list[dict[str, Any]] = []
    seen: set[str] = set()
    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        for index, (name, policy_path) in enumerate(subjects):
            candidates = manifests.get(name)
            # One row per subject, judged on the first file discovery names for it, which
            # is the file the membership measurement classifies.
            if not candidates or name in seen:
                continue
            seen.add(name)
            scratch = workspace / str(index)
            scratch.mkdir()
            detail.append(judge_policy(name, policy_path, candidates[0], scratch, seed))
            shutil.rmtree(scratch, ignore_errors=True)
    statuses = Counter(entry["status"] for entry in detail)
    inside = [entry for entry in detail if entry["adapter_verdict"] == INSIDE]
    inside_run = [entry for entry in inside if entry.get("baseline")]
    outside = [entry for entry in detail if entry["adapter_verdict"] == OUTSIDE]
    with_external = [entry for entry in detail if entry["suite_stubs"]["external"]]
    return {
        "schema_version": "v1",
        "engine": {"name": "kyverno", "version": kyverno_version()},
        "seed": seed,
        # The same provenance the membership artifact records, file counts included, so the
        # two can be checked against each other field for field.
        "corpus": core.provenance(root),
        "policies": len(detail),
        "agreements": statuses[AGREE],
        "disagreements": statuses[DISAGREE],
        "not_judged": statuses[NOT_JUDGED],
        "disagreeing_policies": [
            {"subject": entry["subject"], "why": entry["why"]}
            for entry in detail
            if entry["status"] == DISAGREE
        ],
        "static": {
            "suites_stubbing_external_data": len(with_external),
            "inside_policies_whose_suite_stubs_external_data": sum(
                1 for entry in inside if entry["suite_stubs"]["external"]
            ),
            "outside_policies_whose_suite_stubs_external_data": sum(
                1 for entry in outside if entry["suite_stubs"]["external"]
            ),
            "outside_policies_whose_suite_stubs_nothing_external": sum(
                1 for entry in outside if not entry["suite_stubs"]["external"]
            ),
        },
        "dynamic": {
            "suites_run": sum(1 for entry in detail if entry.get("baseline")),
            "suites_that_did_not_run": sum(1 for entry in detail if not entry.get("baseline")),
            "inside_policies_checked": len(inside_run),
            "inside_policies_invariant_under_injected_labels": sum(
                1 for entry in inside_run if entry["outcomes_identical_under_injected_labels"]
            ),
            "inside_policies_whose_outcomes_changed": sum(
                1 for entry in inside_run if not entry["outcomes_identical_under_injected_labels"]
            ),
            "tests_compared": sum(entry["tests"] for entry in inside_run),
            "outside_policies_whose_outcomes_changed_when_stubs_were_removed": sum(
                1
                for entry in outside
                if entry.get("outcomes_identical_with_external_stubs_removed") is False
            ),
            "outside_policies_unchanged_when_stubs_were_removed": sum(
                1
                for entry in outside
                if entry.get("outcomes_identical_with_external_stubs_removed") is True
            ),
        },
        "by_status_and_verdict": {
            f"{verdict}/{status}": count
            for (verdict, status), count in sorted(
                Counter((entry["adapter_verdict"], entry["status"]) for entry in detail).items()
            )
        },
        "detail": detail,
    }


def render(findings: dict[str, Any]) -> str:
    lines = [
        f"kyverno {findings['engine']['version']}: {findings['policies']} policies, "
        f"{findings['agreements']} agree, {findings['disagreements']} disagree, "
        f"{findings['not_judged']} not judged"
    ]
    dynamic = findings["dynamic"]
    lines.append(
        f"  injection: {dynamic['inside_policies_checked']} inside policies, "
        f"{dynamic['tests_compared']} tests, "
        f"{dynamic['inside_policies_invariant_under_injected_labels']} invariant, "
        f"{dynamic['inside_policies_whose_outcomes_changed']} changed"
    )
    lines.append(
        f"  removal: {dynamic['outside_policies_whose_outcomes_changed_when_stubs_were_removed']} "
        "outside policies changed, "
        f"{dynamic['outside_policies_unchanged_when_stubs_were_removed']} unchanged"
    )
    for entry in findings["disagreeing_policies"][:20]:
        lines.append(f"    {entry['subject']}: {entry['why']}")
    for key, count in sorted(findings["by_status_and_verdict"].items()):
        lines.append(f"  {key}: {count}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--limit", type=int, help="judge only the first N policies")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    findings = measure(args.root, args.seed, args.limit)
    print(render(findings))
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 1 if findings["disagreements"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
