"""Test the measure's predictions where its decision domain is larger than binary.

`scripts/rego_mutation.py` asked whether decision-blindness predicts missed faults in
Gatekeeper. It could only make one prediction, because a two-valued domain leaves almost
every suite looking covered. Kyverno labels each expected result `pass`, `fail` or `skip`,
and 23 of its validate rules are blind, so the same question can be asked with a sample.

The design is case-control rather than a sweep. Every blind validate rule is measured, plus
a comparison group drawn deterministically from the covered ones, because running every
policy in the library would spend hours to answer a question a balanced sample answers.

A mutant here edits the policy, not the test: a condition operator is negated, a required
value becomes any value, a boolean is flipped. Each keeps the manifest valid YAML, so a
surviving mutant is a statement about the suite rather than about the parser.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import random
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

sys.path.insert(0, str(Path(__file__).resolve().parent))

import suite_coverage_kyverno  # noqa: E402
from suite_coverage import provenance  # noqa: E402

SCHEMA_VERSION = "trustweave.dev/kyverno-mutation/v1alpha1"

# Condition operators, paired with their negation. Editing one changes which resources a
# rule matches without changing whether the manifest parses.
OPERATOR_PAIRS: tuple[tuple[str, str], ...] = (
    ("AnyNotIn", "AnyIn"),
    ("AllNotIn", "AllIn"),
    ("NotEquals", "Equals"),
    ("GreaterThanOrEquals", "LessThan"),
    ("LessThanOrEquals", "GreaterThan"),
    ("GreaterThan", "LessThanOrEquals"),
    ("LessThan", "GreaterThanOrEquals"),
    ("AnyIn", "AnyNotIn"),
    ("AllIn", "AllNotIn"),
    ("Equals", "NotEquals"),
)
# Kyverno's newer policies carry their logic in CEL expression strings rather than in
# condition blocks, so the mutable sites are operators inside a quoted expression. Without
# these the generator found one or two sites in such a policy and it was skipped, which is
# what left the replication with five of twenty-three blind policies.
CEL_OPERATORS: tuple[tuple[str, str], ...] = (
    (".all(", ".exists("),
    (".exists(", ".all("),
    ("&&", "||"),
    ("||", "&&"),
    ("==", "!="),
    ("!=", "=="),
    (">=", ">"),
    ("<=", "<"),
    (" > ", " >= "),
    (" < ", " <= "),
)

# `"?*"` requires a non-empty value; `"*"` accepts anything, including absence of content.
WEAKENINGS: tuple[tuple[str, str], ...] = (('"?*"', '"*"'), ("'?*'", "'*'"))

# A boolean flip mutates the policy only where the boolean is a value the guard reads. The
# old rule fired on any `true` or `false` token anywhere on a line, so it edited prose inside
# `message:` text and flipped keys that configure the run rather than the guard: 48 of the
# 248 scored Kyverno mutants sat on `background:`, `enabled:` or `message:`. This matches a
# key whose whole value is a boolean, and declines the three that are not guards.
STRUCTURAL_BOOLEAN = re.compile(
    r"""^\s*(?:-\s*)?(?P<key>\S(?:[^:]*\S)?)\s*:\s*(?P<value>true|false)\s*$"""
)
NON_STRUCTURAL_BOOLEAN_KEYS = frozenset({"background", "enabled", "message"})
# Thresholds written inside quoted pattern strings, e.g. `">0"` or `"<=4"`.
THRESHOLDS: tuple[tuple[str, str], ...] = (
    ('">="', '"<"'),
    ('"<="', '">"'),
    ('">', '"<'),
    ('"<', '">'),
)
# `=(field)` matches only when the field is present; dropping the anchor makes it required.
ANCHORS: tuple[tuple[str, str], ...] = (("=(", "("),)

# A score computed from one or two mutants describes the operator set, not the suite.
MINIMUM_MUTANTS = 3


@dataclass(frozen=True)
class Mutant:
    name: str
    source: str


def _kyverno() -> str:
    found = shutil.which("kyverno")
    if not found:
        raise SystemExit("kyverno is not on PATH; install the CLI to run this experiment")
    return found


def _run_test(test_directory: Path) -> bool | None:
    """True when the suite passes, False when it fails, None when it could not run."""

    try:
        completed = subprocess.run(
            [_kyverno(), "test", str(test_directory)],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = completed.stdout + completed.stderr
    if "Test Summary" not in output:
        # A manifest the CLI refused to load says nothing about the suite.
        return None
    return completed.returncode == 0


def _replace_once(line: str, original: str, replacement: str) -> str | None:
    position = line.find(original)
    if position < 0:
        return None
    return line[:position] + replacement + line[position + len(original) :]


def _mutate(source: str) -> list[Mutant]:
    """Every single-edit variant of one policy manifest."""

    mutants: list[Mutant] = []
    lines = source.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        code = line.split("#", 1)[0]
        seen: set[str] = set()
        for original, replacement in (
            *OPERATOR_PAIRS,
            *CEL_OPERATORS,
            *THRESHOLDS,
            *WEAKENINGS,
            *ANCHORS,
        ):
            if original in seen or original not in code:
                continue
            # The operator table lists longer names first, so a match on `AnyNotIn` must not
            # also fire the `AnyIn` rule for the same site.
            seen.update({original, replacement})
            edited = _replace_once(line, original, replacement)
            if edited is None or edited == line:
                continue
            mutated = list(lines)
            mutated[index] = edited
            mutants.append(Mutant(f"L{index + 1}:{original}->{replacement}", "\n".join(mutated)))

        boolean = STRUCTURAL_BOOLEAN.match(code)
        if boolean is None:
            continue
        # Kyverno writes anchors into pattern keys (`=(hostNetwork)`), and annotation keys
        # carry a namespace, so the name compared against the declined set is the last
        # segment of the key with any anchor and quoting removed.
        key = boolean.group("key").strip("\"'").rsplit("/", 1)[-1].rsplit(".", 1)[-1]
        key = key.strip("=X^<+()")
        if key in NON_STRUCTURAL_BOOLEAN_KEYS:
            continue
        held = boolean.group("value")
        flipped = "false" if held == "true" else "true"
        mutated = list(lines)
        mutated[index] = line[: boolean.start("value")] + flipped + line[boolean.end("value") :]
        mutants.append(Mutant(f"L{index + 1}:{held}->{flipped}", "\n".join(mutated)))
    return mutants


def _policy_files(test_directory: Path) -> list[Path]:
    manifest = test_directory / "kyverno-test.yaml"
    try:
        document = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(document, dict):
        return []
    found = []
    for reference in document.get("policies") or []:
        if isinstance(reference, str):
            resolved = (test_directory / reference).resolve()
            if resolved.exists():
                found.append(resolved)
    return found


def measure_policy(name: str, test_directory: Path, limit: int | None) -> dict[str, Any]:
    """Mutate one policy and run its own suite against every mutant.

    `name` is the policy's identity as the manifest states it, not the directory it happens
    to sit in. Those are not the same: the corpus publishes `-cel` and `-vpol` variants of a
    policy in sibling directories, all naming the same policy.
    """

    policies = _policy_files(test_directory)
    if len(policies) != 1:
        return {"policy": name, "skipped": f"{len(policies)} policy files referenced"}
    policy_path = policies[0]

    # Counting mutable sites is free; running the suite is not. Deciding the floor first
    # keeps a scan over the whole library from paying a CLI invocation per skipped policy.
    mutants = _mutate(policy_path.read_text(encoding="utf-8"))
    if len(mutants) < MINIMUM_MUTANTS:
        return {"policy": name, "skipped": f"{len(mutants)} mutable sites in the policy"}
    if limit is not None:
        mutants = mutants[:limit]

    if _run_test(test_directory) is not True:
        return {"policy": name, "skipped": "suite does not pass unmutated"}

    killed = 0
    survivors: list[str] = []
    unrunnable = 0
    root = test_directory.parent
    with tempfile.TemporaryDirectory() as workspace:
        staged_root = Path(workspace) / root.name
        shutil.copytree(root, staged_root)
        staged_policy = staged_root / policy_path.relative_to(root)
        staged_tests = staged_root / test_directory.relative_to(root)
        for mutant in mutants:
            staged_policy.write_text(mutant.source, encoding="utf-8")
            outcome = _run_test(staged_tests)
            if outcome is None:
                unrunnable += 1
            elif outcome:
                survivors.append(mutant.name)
            else:
                killed += 1

    live = killed + len(survivors)
    if live < MINIMUM_MUTANTS:
        return {
            "policy": name,
            "skipped": f"only {live} mutants applied, below the {MINIMUM_MUTANTS} needed to score",
        }
    return {
        "policy": name,
        "mutants_applied": live,
        "mutants_unrunnable": unrunnable,
        "killed": killed,
        "survived": len(survivors),
        "mutation_score": round(killed / live, 4) if live else None,
        "survivors": sorted(survivors)[:20],
    }


def blind_validate_rules(coverage: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Split the measured Kyverno policies into those with a blind rule and those without.

    This reads the pooled coverage artifact, which folds every variant of a policy together
    under one name with an any-blind rollup. It decides which policies are *worth measuring*;
    the flag each measurement is then scored against comes from the manifest that measurement
    actually ran, through `manifest_blindness`.
    """

    blind: set[str] = set()
    covered: set[str] = set()
    for subject in coverage["subjects"]:
        if subject["domain"] != "kyverno_validate":
            continue
        policy = subject["subject"].split("/")[0]
        (blind if subject["blind"] else covered).add(policy)
    return blind, covered - blind


def manifest_cases(manifest: Path) -> dict[str, int]:
    """Policy names the manifest's `results` block pins, and how many cases each carries.

    This is the identity the coverage adapter joins on, and the only one the manifest itself
    states. Keying on the directory instead collapsed the pinned corpus's 495 manifests into
    235 entries, and because `Path` compares part-wise the survivor of each collision was the
    `-cel` or `-vpol` variant: 36 of the 49 scored policies were mutated in a sibling of the
    directory whose coverage verdict labelled them.
    """

    counts: dict[str, int] = {}
    try:
        documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        return counts
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != "Test":
            continue
        results = document.get("results")
        for entry in results if isinstance(results, list) else []:
            if isinstance(entry, dict) and isinstance(entry.get("policy"), str):
                counts[entry["policy"]] = counts.get(entry["policy"], 0) + 1
    return counts


def policy_manifests(root: Path) -> dict[str, list[Path]]:
    """Every test directory whose manifest names each policy, in a stable order.

    A policy named by several manifests keeps all of them. The first in path order is measured
    and the rest are recorded beside the result, so a variant collision is visible in the
    artifact rather than resolved by a dict overwrite nobody chose. Path order compares
    part-wise, so `other` sorts before `other-cel` and `other-vpol`: the base directory is
    measured and its variants are recorded. The old dict took the *last* match of the same
    ordering, which is why the variant was the one that survived.
    """

    found: dict[str, list[Path]] = {}
    for manifest in sorted(root.rglob("kyverno-test.yaml")):
        for name in sorted(manifest_cases(manifest)):
            found.setdefault(name, []).append(manifest.parent)
    return found


def manifest_blindness(manifest: Path) -> dict[str, bool]:
    """Whether each policy the manifest names has a blind validate rule *in this manifest*.

    The same definition the suite-coverage instrument uses -- a subject witnessing fewer than
    two decisions is blind, and a policy with any blind validate rule is blind -- applied to
    one file instead of to the pooled rollup over every variant of it.
    """

    reading = suite_coverage_kyverno.read(manifest, manifest.as_posix())
    witnessed: dict[str, set[str]] = {}
    for observation in reading.observations:
        if observation.domain != "kyverno_validate":
            continue
        witnessed.setdefault(observation.subject, set()).add(observation.decision)
    blind: dict[str, bool] = {}
    for subject, decisions in witnessed.items():
        policy = subject.split("/")[0]
        blind[policy] = blind.get(policy, False) or len(decisions) < 2
    return blind


# Enumerating every split is exact and cheap at these sample sizes; beyond this many it is
# sampled instead, with a fixed seed so the reported figure is reproducible.
MAX_EXACT_SPLITS = 400_000


def permutation_test(blind: list[float], covered: list[float]) -> dict[str, Any]:
    """How often chance alone would separate the groups at least this far.

    A difference in medians between two small groups is easy to read as an effect. This
    states what the same data would look like if the labels carried no information, which
    is the only way a single-digit group can honestly be reported.

    The test is one-sided: it asks how often chance produces a gap at least as large *in
    the direction the hypothesis predicts*, blind policies scoring lower. A two-sided
    reading of the same figure is roughly twice the p-value reported here.
    """

    if not blind or not covered:
        return {"observed_difference": None, "p_value": None, "method": "not applicable"}

    pool = blind + covered
    size = len(blind)
    observed = sum(covered) / len(covered) - sum(blind) / len(blind)
    splits = math.comb(len(pool), size)

    def difference(indices: tuple[int, ...]) -> float:
        chosen = set(indices)
        left = [pool[i] for i in chosen]
        right = [pool[i] for i in range(len(pool)) if i not in chosen]
        return sum(right) / len(right) - sum(left) / len(left)

    if splits <= MAX_EXACT_SPLITS:
        extreme = sum(
            1
            for combination in itertools.combinations(range(len(pool)), size)
            if difference(combination) >= observed
        )
        return {
            "observed_difference": round(observed, 4),
            "p_value": round(extreme / splits, 4),
            "method": f"exact over {splits} splits, one-sided",
        }

    generator = random.Random(0)
    trials = 100_000
    indices = list(range(len(pool)))
    extreme = 0
    for _ in range(trials):
        generator.shuffle(indices)
        if difference(tuple(indices[:size])) >= observed:
            extreme += 1
    return {
        "observed_difference": round(observed, 4),
        "p_value": round(extreme / trials, 4),
        "method": f"sampled, {trials} permutations, seed 0, one-sided",
    }


def analyze(
    root: Path,
    coverage: dict[str, Any],
    comparison: int,
    limit: int | None,
    attempts: int = 200,
    invocation: list[str] | None = None,
) -> dict[str, Any]:
    blind, covered = blind_validate_rules(coverage)
    directories = policy_manifests(root)
    unmatched: list[dict[str, str]] = []

    def run(name: str, corpus_blind: bool) -> dict[str, Any] | None:
        """Measure one policy in the manifest that names it, and label it from that manifest."""

        candidates = directories.get(name)
        if not candidates:
            unmatched.append(
                {
                    "policy": name,
                    "reason": "no kyverno-test.yaml names this policy in its results block",
                }
            )
            return None
        chosen = candidates[0]
        manifest = chosen / "kyverno-test.yaml"
        local = manifest_blindness(manifest)
        if name not in local:
            # The grouping variable has to come from the same file as the score, and this
            # manifest states no validate expectation for this policy. Recording the refusal
            # keeps it out of the contrast rather than letting the pooled label stand in.
            unmatched.append(
                {
                    "policy": name,
                    "reason": f"{manifest.as_posix()} states no validate expectation for it",
                }
            )
            return None
        result = measure_policy(name, chosen, limit)
        result["blind_from"] = manifest.as_posix()
        result["decision_blind"] = local[name]
        result["corpus_blind"] = corpus_blind
        result["test_cases"] = manifest_cases(manifest).get(name, 0)
        if len(candidates) > 1:
            result["manifest_candidates"] = [path.as_posix() for path in candidates]
        return result

    # Every blind policy is measured. The comparison group is then filled by walking the
    # covered policies in name order until enough of them score, rather than by taking a
    # fixed slice: many policies fall below the mutant floor, and a fixed slice of six
    # yielded a comparison group of zero. The floor is identical for both arms, so scanning
    # further to fill one does not select on anything the other was not also filtered by.
    measured = []
    for name in sorted(blind):
        result = run(name, corpus_blind=True)
        if result is not None:
            measured.append(result)

    filled = 0
    attempted = 0
    for name in sorted(covered):
        if filled >= comparison or attempted >= attempts:
            break
        if name not in directories:
            unmatched.append(
                {
                    "policy": name,
                    "reason": "no kyverno-test.yaml names this policy in its results block",
                }
            )
            continue
        attempted += 1
        result = run(name, corpus_blind=False)
        if result is None:
            continue
        measured.append(result)
        if result.get("mutation_score") is not None:
            filled += 1

    scored = [entry for entry in measured if entry.get("mutation_score") is not None]
    groups: dict[str, list[float]] = {"blind": [], "covered": []}
    for entry in scored:
        groups["blind" if entry["decision_blind"] else "covered"].append(entry["mutation_score"])
    # The same scores under the pooled label the coverage artifact carries, so the corrected
    # contrast and the one it corrects can be read side by side instead of one replacing the
    # other silently.
    pooled: dict[str, list[float]] = {"blind": [], "covered": []}
    for entry in scored:
        pooled["blind" if entry["corpus_blind"] else "covered"].append(entry["mutation_score"])

    def summarise(scores: list[float]) -> dict[str, Any]:
        ordered = sorted(scores)
        middle = len(ordered) // 2
        return {
            "policies": len(ordered),
            "median_mutation_score": (
                None
                if not ordered
                else (
                    ordered[middle]
                    if len(ordered) % 2
                    else round((ordered[middle - 1] + ordered[middle]) / 2, 4)
                )
            ),
            "mean_mutation_score": (None if not ordered else round(sum(ordered) / len(ordered), 4)),
            "min": ordered[0] if ordered else None,
            "max": ordered[-1] if ordered else None,
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "design": "case-control: every blind validate policy, plus covered ones in name order",
        "invocation": invocation if invocation is not None else [],
        "corpus": provenance(root),
        "comparison_group_attempts": attempted,
        "policies_scored": len(scored),
        "skipped": [
            {"policy": e["policy"], "reason": e["skipped"]} for e in measured if "skipped" in e
        ]
        + unmatched,
        "blind": summarise(groups["blind"]),
        "covered": summarise(groups["covered"]),
        "permutation_test": permutation_test(groups["blind"], groups["covered"]),
        # Labelled by the pooled coverage artifact rather than by the manifest measured. Kept
        # because the published figure was computed this way, and a reader comparing the two
        # is comparing labellings of one set of scores rather than two different runs.
        "labelled_by_pooled_coverage": {
            "blind": summarise(pooled["blind"]),
            "covered": summarise(pooled["covered"]),
            "permutation_test": permutation_test(pooled["blind"], pooled["covered"]),
        },
        "detail": sorted(scored, key=lambda entry: entry["policy"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--comparison", type=int, default=25)
    parser.add_argument("--attempts", type=int, default=200)
    parser.add_argument("--limit", type=int, default=8, help="cap mutants per policy")
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)

    coverage = json.loads(arguments.coverage.read_text(encoding="utf-8"))
    report = analyze(
        arguments.corpus,
        coverage,
        arguments.comparison,
        arguments.limit,
        arguments.attempts,
        invocation=[Path(sys.argv[0]).name, *(argv if argv is not None else sys.argv[1:])],
    )
    lines = [f"policies scored: {report['policies_scored']}"]
    for label in ("blind", "covered"):
        group = report[label]
        lines.append(
            f"  decision-{label:8} {group['policies']:3}  "
            f"median {group['median_mutation_score']}  "
            f"mean {group['mean_mutation_score']}"
        )
    test = report["permutation_test"]
    lines.append(
        f"  difference {test['observed_difference']}  p = {test['p_value']}  ({test['method']})"
    )
    print("\n".join(lines))
    if arguments.json:
        arguments.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
