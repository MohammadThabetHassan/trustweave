"""Measure decision-class coverage of Rego policy test suites.

Structural coverage tells you a line ran. It does not tell you the suite constrained what
that line returns, and `benchmark/orthogonality-witness` shows a suite at 100% coverage that
cannot detect its policy's default changing. This measures the thing coverage misses: which
decisions a suite actually pins, and how often it settles for an assertion that merely
excludes one.

The adapter reads the OPA AST rather than the source text, so it sees what OPA sees:

    opa parse <file> --format json

For every rule named `test_*` it records each comparison in the body — the operator, the
reference under test, and the literal being compared against. An `equal` against a string
literal pins that value; a `neq` executes the same line while leaving the value open.

Run: python scripts/rego_suite_coverage.py PATH [PATH ...] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

# Comparison operators OPA lowers into a rule body, and whether each pins a value.
PINNING_OPERATORS = {"equal", "eq"}
EXCLUDING_OPERATORS = {"neq"}
# `:=` lowers to assign and `=` to eq; both can bind a rule output to a local name.
ASSIGNING_OPERATORS = {"assign", "eq"}
# Suites assert emptiness both ways: `count(r) == 0` and `count(r) > 0`. Admitting only
# equality reads a suite that tests both outcomes as testing one.
ORDERING_OPERATORS = {"gt", "gte", "lt", "lte"}
MIRRORED_OPERATORS = {"gt": "lt", "lt": "gt", "gte": "lte", "lte": "gte"}


def _opa() -> str:
    found = shutil.which("opa")
    if not found:
        raise SystemExit("opa is not on PATH; install it to run this adapter")
    return found


def _parse(path: Path) -> dict[str, Any] | None:
    """Return the OPA AST for one Rego file, or None when it does not parse."""

    # OPA 1.x parses Rego v1 by default, which requires the `if` keyword before a body.
    # Most published policy suites predate that and are still v0, so a v1-only adapter
    # silently measures almost nothing. Try v1, then fall back rather than dropping the file.
    for arguments in (
        [_opa(), "parse", str(path), "--format", "json"],
        [_opa(), "parse", "--v0-compatible", str(path), "--format", "json"],
    ):
        try:
            completed = subprocess.run(
                arguments, check=False, capture_output=True, text=True, timeout=60
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode != 0 or not completed.stdout.strip():
            continue
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _git(repository: Path, *arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() or None if completed.returncode == 0 else None


def _provenance(root: Path) -> list[dict[str, str]]:
    """Pin the corpus to exact commits, so a reported number can be reproduced."""

    if not root.is_dir():
        return []
    repositories = []
    for candidate in [root, *sorted(child for child in root.iterdir() if child.is_dir())]:
        if not (candidate / ".git").exists():
            continue
        remote = _git(candidate, "remote", "get-url", "origin")
        commit = _git(candidate, "rev-parse", "HEAD")
        if remote and commit:
            repositories.append({"name": candidate.name, "remote": remote, "commit": commit})
    return repositories


def _operator(term: dict[str, Any]) -> str | None:
    value = term.get("value")
    if not isinstance(value, list) or not value:
        return None
    head = value[0]
    return head.get("value") if isinstance(head, dict) else None


def _reference(term: dict[str, Any]) -> str | None:
    """Render a ref term as a dotted name, so `authz.decision` is comparable."""

    value = term.get("value")
    # A rule invoked by bare name (`results := violation`) arrives as a var, not a ref.
    # Treating only refs as nameable silently drops every such binding.
    if term.get("type") == "var":
        return value if isinstance(value, str) else None
    if term.get("type") != "ref" or not isinstance(value, list):
        return None
    parts: list[str] = []
    for element in value:
        if not isinstance(element, dict):
            return None
        piece = element.get("value")
        if not isinstance(piece, str):
            return None
        parts.append(piece)
    return ".".join(parts)


def _literal(term: dict[str, Any]) -> str | None:
    """Return the string a comparison pins, or None when it pins something else."""

    value = term.get("value")
    return value if term.get("type") == "string" and isinstance(value, str) else None


def _base_var(term: dict[str, Any]) -> str | None:
    """The leading variable of a ref term, so `results[result]` names `results`."""

    if term.get("type") != "ref":
        return None
    value = term.get("value")
    if not isinstance(value, list) or not value:
        return None
    head = value[0]
    if not isinstance(head, dict) or head.get("type") != "var":
        return None
    name = head.get("value")
    return name if isinstance(name, str) else None


def _counted_var(term: dict[str, Any]) -> str | None:
    """`count(results)` -> `results`, so a cardinality assertion names the set it counts."""

    if term.get("type") != "call":
        return None
    value = term.get("value")
    if not isinstance(value, list) or len(value) != 2:
        return None
    if _reference(value[0]) != "count":
        return None
    argument = value[1]
    if not isinstance(argument, dict):
        return None
    if argument.get("type") == "var":
        name = argument.get("value")
        return name if isinstance(name, str) else None
    return _base_var(argument)


def _cardinality(term: dict[str, Any], operator: str) -> str | None:
    """Turn a count comparison into the decision it asserts, or None when it is ambiguous.

    Only comparisons that settle emptiness are usable. `count(r) != 2` is a real assertion
    but says nothing about whether the policy denied, so it is refused rather than guessed.
    """

    if term.get("type") != "number":
        return None
    count = term.get("value")
    if not isinstance(count, (int, float)):
        return None
    if operator in PINNING_OPERATORS:
        return "empty" if count == 0 else "nonempty"
    if operator in EXCLUDING_OPERATORS:
        return "nonempty" if count == 0 else None
    if operator == "gt":
        return "nonempty" if count >= 0 else None
    if operator == "gte":
        return "nonempty" if count >= 1 else None
    if operator == "lt":
        return "empty" if count <= 1 else None
    if operator == "lte":
        return "empty" if count == 0 else None
    return None


def _assertions(ast: dict[str, Any]) -> list[dict[str, str]]:
    """Every decision a test rule constrains, in whichever form the ecosystem uses.

    Three shapes appear in practice and they are not interchangeable:

    labelled       an attribute policy returns a decision string and tests compare to it
    boolean        a helper rule is invoked directly, asserting it holds or does not
    violation_set  an admission policy returns a set of violations, and the test binds it
                   (`results := violation with input as ...`) before asserting the set is
                   non-empty (`results[result]`, a denial) or empty (`count(results) == 0`,
                   a permit)

    All three are decisions over a finite domain, so all three are measurable, but a reader
    must be told which domain a number refers to. The violation-set form is the one that
    needs the binding tracked: the assertion names a local variable, and only the earlier
    assignment says which rule that variable holds the output of.
    """

    found: list[dict[str, str]] = []
    for rule in ast.get("rules") or []:
        name = ((rule.get("head") or {}).get("name")) or ""
        if not name.startswith("test_"):
            continue
        under_test: dict[str, str] = {}
        for expression in rule.get("body") or []:
            terms = expression.get("terms")
            negated = bool(expression.get("negated"))

            # A bare term: `results[result]` iterates the set, which succeeds only when it
            # has a member. Negated, it asserts the set is empty.
            if isinstance(terms, dict):
                base = _base_var(terms)
                if base is not None and base in under_test:
                    found.append(
                        {
                            "test": name,
                            "operator": "pins",
                            "subject": under_test[base],
                            "value": "empty" if negated else "nonempty",
                            "domain": "violation_set",
                        }
                    )
                continue
            if not isinstance(terms, list) or not terms:
                continue

            if len(terms) != 3:
                subject = _reference(terms[0])
                if subject is None:
                    continue
                found.append(
                    {
                        "test": name,
                        "operator": "pins",
                        "subject": subject,
                        "value": "does_not_hold" if negated else "holds",
                        "domain": "boolean",
                    }
                )
                continue

            operator = _operator(terms[0])

            # `results := violation` names the rule this test exercises. Recording the
            # binding rather than reporting it is what lets the later assertion resolve.
            if operator in ASSIGNING_OPERATORS and _literal(terms[2]) is None:
                target = terms[1].get("value") if terms[1].get("type") == "var" else None
                source = _reference(terms[2])
                if isinstance(target, str) and source is not None:
                    under_test[target] = source
                    continue

            if operator is None:
                continue

            counted = _counted_var(terms[1])
            other = terms[2]
            effective = operator
            if counted is None:
                counted = _counted_var(terms[2])
                other = terms[1]
                # `0 < count(r)` asserts the same thing as `count(r) > 0`.
                effective = MIRRORED_OPERATORS.get(operator, operator)
            if counted is not None and counted in under_test:
                decision = _cardinality(other, effective)
                if decision is not None:
                    found.append(
                        {
                            "test": name,
                            "operator": "pins",
                            "subject": under_test[counted],
                            "value": decision,
                            "domain": "violation_set",
                        }
                    )
                # A count comparison is never a labelled assertion, whether or not it
                # resolved, so it must not fall through to the string-literal path.
                continue

            if operator not in PINNING_OPERATORS | EXCLUDING_OPERATORS:
                continue

            subject = _reference(terms[1])
            expected = _literal(terms[2])
            if expected is None:
                expected = _literal(terms[1])
                subject = _reference(terms[2])
            if subject is None or expected is None:
                continue
            found.append(
                {
                    "test": name,
                    "operator": "pins" if operator in PINNING_OPERATORS else "excludes",
                    "subject": subject,
                    "value": expected,
                    "domain": "labelled",
                }
            )
    return found


def analyze(paths: list[Path]) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    unparsed: list[str] = []
    not_extracted: list[dict[str, Any]] = []
    corpus: list[dict[str, str]] = []
    for root in paths:
        corpus.extend(_provenance(root))
        # Paths are recorded relative to the root supplied, so the artifact describes the
        # corpus rather than the machine that happened to measure it.
        base = root if root.is_dir() else root.parent
        candidates = sorted(root.rglob("*_test.rego")) if root.is_dir() else [root]
        for path in candidates:
            relative = str(path.relative_to(base))
            ast = _parse(path)
            if ast is None:
                unparsed.append(relative)
                continue
            assertions = _assertions(ast)
            if not assertions:
                # Name what was dropped. A bare extraction percentage invites the reader to
                # assume the remainder is uninteresting; these are auditable instead.
                test_rules = sum(
                    1
                    for rule in ast.get("rules") or []
                    if str((rule.get("head") or {}).get("name") or "").startswith("test_")
                )
                not_extracted.append({"file": relative, "test_rules": test_rules})
                continue
            domains = {a.get("domain", "labelled") for a in assertions}
            pinned = sorted({a["value"] for a in assertions if a["operator"] == "pins"})
            excluded = sorted({a["value"] for a in assertions if a["operator"] == "excludes"})
            files.append(
                {
                    "file": relative,
                    "domain": "mixed" if len(domains) > 1 else next(iter(domains)),
                    "test_assertions": len(assertions),
                    "values_pinned": pinned,
                    "values_only_excluded": sorted(set(excluded) - set(pinned)),
                    "excluding_assertions": sum(
                        1 for a in assertions if a["operator"] == "excludes"
                    ),
                }
            )

    totals: Counter[str] = Counter()
    for entry in files:
        totals["files"] += 1
        totals["assertions"] += entry["test_assertions"]
        totals["excluding"] += entry["excluding_assertions"]
        if entry["excluding_assertions"]:
            totals["files_with_excluding_assertions"] += 1
        if not entry["values_pinned"]:
            totals["files_pinning_nothing"] += 1

    considered = totals["files"] + len(unparsed) + len(not_extracted)
    extraction = totals["files"] / considered if considered else 0.0
    return {
        "schema_version": "trustweave.dev/rego-suite-coverage/v1alpha1",
        "corpus": corpus,
        # A per-file conclusion drawn from a fraction of the suites is a conclusion about
        # the extractor, not the ecosystem. This number gates every other number here.
        "extraction_rate": round(extraction, 4),
        "files_considered": considered,
        "files_yielding_no_assertions": len(not_extracted),
        "not_extracted": not_extracted,
        "sufficient_for_summary": extraction >= 0.80,
        "files_measured": totals["files"],
        "files_unparsed": len(unparsed),
        "assertions": totals["assertions"],
        "excluding_assertions": totals["excluding"],
        "files_with_excluding_assertions": totals["files_with_excluding_assertions"],
        "files_pinning_nothing": totals["files_pinning_nothing"],
        "detail": files,
        "unparsed": unparsed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=Path, nargs="+")
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args()

    report = analyze(arguments.paths)
    print(
        f"files measured: {report['files_measured']} of {report['files_considered']} "
        f"({report['extraction_rate']:.0%} extraction)"
    )
    if not report["sufficient_for_summary"]:
        print(
            "  WARNING: extraction is below 80%. The measured files are whichever ones this\n"
            "  adapter happens to understand, which is not a sample of the ecosystem. Treat\n"
            "  the figures below as adapter diagnostics, not as a result."
        )
    print(f"  test assertions           {report['assertions']}")
    print(f"  excluding (non-pinning)   {report['excluding_assertions']}")
    print(f"  files using exclusion     {report['files_with_excluding_assertions']}")
    print(f"  files pinning nothing     {report['files_pinning_nothing']}")
    if arguments.json:
        arguments.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
