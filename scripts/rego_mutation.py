"""Ask whether decision-blindness predicts undetected faults in real Rego policies.

`docs/DECISION_CLASS_COVERAGE.md` proves that inside the policy fragment, witnessing every
cell is equivalent to killing every non-equivalent mutant. That proof does not reach Rego:
its subjects are arbitrary JSON and its guards are general expressions, so no enumeration
exhausts them and equivalence is undecidable there.

What can still be asked is whether the criterion *predicts* anything outside the setting it
was proved in. This mutates real Gatekeeper policies, runs each policy's own suite against
each mutant, and reports how many survive. Cross-referenced with
`scripts/suite_coverage.py`, that answers the question the theory cannot: do suites this
measure calls blind actually miss more faults?

Two honest limits, both consequences of leaving the fragment. Survivors cannot be separated
from equivalent mutants, so the score is a lower bound on suite quality rather than an exact
figure -- which is precisely the thing the fragment buys and Rego does not. And the operator
set is syntactic, so it measures the suite against these edits, not against all faults.

Run: python scripts/rego_mutation.py CORPUS [--json out.json] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "trustweave.dev/rego-mutation/v1alpha1"

# Syntax-preserving edits. Each changes what the policy decides for some input without
# changing whether it parses, so a surviving mutant is a statement about the suite.
OPERATORS: tuple[tuple[str, str], ...] = (
    ("==", "!="),
    ("!=", "=="),
    (">=", ">"),
    ("<=", "<"),
    (" > ", " >= "),
    (" < ", " <= "),
    ("true", "false"),
    ("false", "true"),
)
NEGATION = "not "


@dataclass(frozen=True)
class Mutant:
    name: str
    source: str


def _opa() -> str:
    found = shutil.which("opa")
    if not found:
        raise SystemExit("opa is not on PATH; install it to run this experiment")
    return found


def _run_tests(
    directory: Path, dialect: list[str] | None = None, libraries: list[Path] | None = None
) -> tuple[bool, str]:
    """Return whether the suite passes, trying Rego v1 then v0 as the corpus requires.

    The dialect is stable for a policy and its mutants, so callers pass back the flags that
    worked; retrying both for every mutant doubles the experiment's runtime on a v0 corpus.
    """

    attempts = (
        [[_opa(), "test", *dialect, str(directory)]]
        if dialect is not None
        else [
            [_opa(), "test", str(directory)],
            [_opa(), "test", "--v0-compatible", str(directory)],
        ]
    )
    for arguments in attempts:
        try:
            completed = subprocess.run(
                arguments, check=False, capture_output=True, text=True, timeout=120
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = completed.stdout + completed.stderr
        if "rego_parse_error" in output or "rego_type_error" in output:
            continue
        return completed.returncode == 0, output
    return False, "did not run"


def _dialect_for(directory: Path, libraries: list[Path] | None = None) -> list[str] | None:
    """The flags under which this policy parses, or None when it does not parse at all."""

    extra = [str(path) for path in libraries or []]
    for flags in ([], ["--v0-compatible"]):
        try:
            completed = subprocess.run(
                [_opa(), "test", *flags, str(directory), *extra],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = completed.stdout + completed.stderr
        if "rego_parse_error" not in output and "rego_type_error" not in output:
            return flags
    return None


def _outside_quotes(line: str) -> bool:
    return line.count('"') % 2 == 0


def _mutate(source: str) -> list[Mutant]:
    """Every single-edit variant of one policy, one edit per site."""

    mutants: list[Mutant] = []
    lines = source.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") or not stripped or not _outside_quotes(line):
            continue
        # Only the code before an inline comment is a candidate.
        code = line.split("#", 1)[0]
        for original, replacement in OPERATORS:
            position = code.find(original)
            if position < 0:
                continue
            edited = list(lines)
            edited[index] = line[:position] + replacement + line[position + len(original) :]
            mutants.append(
                Mutant(f"L{index + 1}:{original.strip()}->{replacement.strip()}", "\n".join(edited))
            )
        position = code.find(NEGATION)
        if position >= 0:
            edited = list(lines)
            edited[index] = line[:position] + line[position + len(NEGATION) :]
            mutants.append(Mutant(f"L{index + 1}:drop-not", "\n".join(edited)))
    return mutants


def shared_libraries(root: Path) -> list[Path]:
    """Non-test Rego files a policy may import.

    Gatekeeper keeps exemption helpers in `src/rego/lib_*`. A policy importing one of them
    does not type-check on its own, so measuring it in isolation silently drops it -- which
    is what an earlier run of this experiment did to 30 of 49 policies, leaving a sample of
    only the self-contained ones.
    """

    found = []
    for path in sorted(root.rglob("*.rego")):
        if path.name.endswith("_test.rego") or path.name == "src.rego":
            continue
        if any(part.startswith("lib") for part in path.parts):
            found.append(path)
    return found


def _measure_policy(
    directory: Path, limit: int | None, libraries: list[Path] | None = None
) -> dict[str, Any] | None:
    policy_path = directory / "src.rego"
    suite_path = directory / "src_test.rego"
    if not policy_path.exists() or not suite_path.exists():
        return None

    libraries = libraries or []
    dialect = _dialect_for(directory, libraries)
    if dialect is None:
        return {"policy": directory.name, "skipped": "does not parse as Rego v1 or v0"}
    passes, _ = _run_tests(directory, dialect, libraries)
    if not passes:
        # A suite that does not pass against its own policy cannot say anything about a
        # mutant of it.
        return {"policy": directory.name, "skipped": "suite does not pass unmutated"}

    source = policy_path.read_text(encoding="utf-8")
    mutants = _mutate(source)
    if limit is not None:
        mutants = mutants[:limit]

    killed = 0
    survivors: list[str] = []
    unparsed = 0
    with tempfile.TemporaryDirectory() as workspace:
        staging = Path(workspace)
        (staging / "src_test.rego").write_text(suite_path.read_text(encoding="utf-8"), "utf-8")
        for index, library in enumerate(libraries):
            (staging / f"lib{index}.rego").write_text(
                library.read_text(encoding="utf-8"), encoding="utf-8"
            )
        for mutant in mutants:
            (staging / "src.rego").write_text(mutant.source, encoding="utf-8")
            ran, output = _run_tests(staging, dialect)
            if output == "did not run":
                unparsed += 1
                continue
            if ran:
                survivors.append(mutant.name)
            else:
                killed += 1

    live = killed + len(survivors)
    return {
        "policy": directory.name,
        "mutants_applied": live,
        "mutants_unparsed": unparsed,
        "killed": killed,
        "survived": len(survivors),
        "mutation_score": round(killed / live, 4) if live else None,
        "survivors": sorted(survivors)[:20],
    }


def analyze(root: Path, limit: int | None = None) -> dict[str, Any]:
    directories = sorted({path.parent for path in root.rglob("src_test.rego")})
    libraries = shared_libraries(root)
    measured = []
    for directory in directories:
        result = _measure_policy(directory, limit, libraries)
        if result is not None:
            measured.append(result)

    scored = [entry for entry in measured if entry.get("mutation_score") is not None]
    total_killed = sum(entry["killed"] for entry in scored)
    total_live = sum(entry["mutants_applied"] for entry in scored)
    return {
        "schema_version": SCHEMA_VERSION,
        "policies_considered": len(directories),
        "shared_libraries": len(libraries),
        "policies_scored": len(scored),
        "policies_skipped": [e["policy"] for e in measured if "skipped" in e],
        "mutants_applied": total_live,
        "mutants_killed": total_killed,
        "overall_mutation_score": round(total_killed / total_live, 4) if total_live else None,
        "detail": sorted(scored, key=lambda entry: entry["policy"]),
    }


def predictive_validity(report: dict[str, Any], coverage: dict[str, Any]) -> dict[str, Any]:
    """Join mutation score against the decision-coverage verdict for the same policy.

    The theory proves cell coverage equivalent to mutation adequacy only inside the policy
    fragment. Rego is outside it, so the question here is empirical: when this measure calls
    a suite blind, does that suite actually miss more faults?

    Reported alongside is the reason the answer is limited. In a binary decision domain the
    measure is nearly saturated, so it makes very few predictions -- which is the same
    conclusion Corollary 5 reaches from the other direction.
    """

    scores = {entry["policy"]: entry for entry in report["detail"]}
    verdicts: dict[str, bool] = {}
    for subject in coverage["subjects"]:
        if subject["domain"] != "violation_set":
            continue
        parts = subject["subject"].split("::")[0].split("/")
        if len(parts) > 1:
            verdicts[parts[-2]] = bool(subject["blind"])

    joined = [
        {"policy": name, "blind": verdicts[name], "mutation_score": entry["mutation_score"]}
        for name, entry in sorted(scores.items())
        if name in verdicts and entry["mutation_score"] is not None
    ]
    blind = [row for row in joined if row["blind"]]
    covered = [row for row in joined if not row["blind"]]
    ranked = sorted(joined, key=lambda row: row["mutation_score"])

    # Under the null that blindness is unrelated to detection, the chance that a flagged
    # suite lands at the very bottom of n policies is 1/n.
    flagged_are_worst = bool(blind) and all(row["blind"] for row in ranked[: len(blind)])
    return {
        "policies_joined": len(joined),
        "blind": {
            "count": len(blind),
            "mutation_scores": [row["mutation_score"] for row in blind],
        },
        "covered": {
            "count": len(covered),
            "min_mutation_score": min((row["mutation_score"] for row in covered), default=None),
            "max_mutation_score": max((row["mutation_score"] for row in covered), default=None),
        },
        "flagged_suites_rank_lowest": flagged_are_worst,
        "probability_by_chance": round(1 / len(joined), 4)
        if flagged_are_worst and joined
        else None,
        "detail": joined,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--limit", type=int, default=None, help="cap mutants per policy")
    parser.add_argument(
        "--coverage", type=Path, help="suite-coverage rego artifact, to join against"
    )
    arguments = parser.parse_args(argv)

    report = analyze(arguments.corpus, arguments.limit)
    print(
        f"policies scored: {report['policies_scored']} of {report['policies_considered']}\n"
        f"  mutants applied  {report['mutants_applied']}\n"
        f"  killed           {report['mutants_killed']}\n"
        f"  mutation score   {report['overall_mutation_score']}"
    )
    if arguments.coverage:
        coverage = json.loads(arguments.coverage.read_text(encoding="utf-8"))
        joined = predictive_validity(report, coverage)
        report["predictive_validity"] = joined
        blind_scores = joined["blind"]["mutation_scores"]
        print(
            f"  joined with coverage  {joined['policies_joined']} policies\n"
            f"    decision-blind      {joined['blind']['count']} "
            f"(mutation score {blind_scores})\n"
            f"    decision-covered    {joined['covered']['count']} "
            f"({joined['covered']['min_mutation_score']}-"
            f"{joined['covered']['max_mutation_score']})\n"
            f"    flagged rank lowest {joined['flagged_suites_rank_lowest']} "
            f"(by chance p={joined['probability_by_chance']})"
        )
    if arguments.json:
        arguments.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
