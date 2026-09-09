"""What exhaustive coverage costs on deployed policy.

The theory says a policy inside the fragment has a finite quotient, and that witnessing
every cell of it decides the mutation score exactly rather than estimating it. That is only
useful if the quotient is small, and nothing so far has said whether it is. This applies the
paper's own per-component bound to the two largest deployed corpora -- AWS managed IAM
policies and Azure Policy built-in definitions -- and reports the distribution.

The bound is the one from the finite-quotient theorem, not `2` to the power of the guard
count. Guards are grouped by the component they read, and each group contributes the smaller
of two counts:

* `2**n`, always valid for `n` guards; and
* `(exclusive + 1) * 2**patterns`, where guards that can hold of at most one value each --
  `equals`, `in`, `exists` and their negations -- contribute one class per named value plus
  one for everything else, while pattern guards need the exponential because they overlap.
  `like` `'a*'` and `like` `'ab*'` are both true of `abc`, so `n + 1` is *not* a bound for
  them; that is the same trap the capability-pattern remark in the paper describes, and the
  first version of this script fell into it.

Counting is deliberately an over-estimate. The real quotient is smaller, because unachievable
signatures are discarded -- which is what the solver certification is about -- so a claim of
the form "this many policies need at most this many cases" is safe in the direction that
matters.

    python scripts/coverage_cost.py [--json out.json]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

# Above this the quotient is not enumerable in practice and the exact score is unavailable;
# `policy_mutation.py` refuses rather than pretending, and so does this count.
INTRACTABLE = 10**9

CONNECTIVES = frozenset({"allof", "anyof", "not"})
OPERANDS = ("field", "value", "count")

# Guards that hold of at most one value of their component, so `n` of them cut it into at
# most `n + 1` classes.
AZURE_EXCLUSIVE = frozenset(
    {"equals", "notequals", "in", "notin", "exists", "containskey", "notcontainskey"}
)
IAM_EXCLUSIVE = frozenset(
    {
        "stringequals",
        "stringnotequals",
        "stringequalsignorecase",
        "stringnotequalsignorecase",
        "arnequals",
        "arnnotequals",
        "bool",
        "null",
        "numericequals",
        "numericnotequals",
        "dateequals",
        "datenotequals",
        "binaryequals",
    }
)


def _adapter(name: str) -> Any:
    for module in ("fragment_membership", f"fragment_membership_{name}"):
        specification = importlib.util.spec_from_file_location(module, SCRIPTS / f"{module}.py")
        if specification is None or specification.loader is None:  # pragma: no cover
            raise SystemExit(f"cannot load {module}")
        loaded = importlib.util.module_from_spec(specification)
        sys.modules.setdefault(module, loaded)
        specification.loader.exec_module(loaded)
    return sys.modules[f"fragment_membership_{name}"]


def pattern_kind(pattern: str) -> str:
    """How a match pattern constrains its component, which decides how it is counted.

    The distinction is not cosmetic. Counting every action and ARN entry as an overlapping
    pattern reported a median of 16{,}384 cells for IAM and 461 policies as intractable; in
    fact 78.9% of those entries are literals, which are mutually exclusive.
    """

    if pattern == "*":
        return "everything"
    if "*" not in pattern and "?" not in pattern:
        return "literal"
    if pattern.count("*") == 1 and pattern.endswith("*") and "?" not in pattern:
        return "prefix"
    return "wildcard"


def cells_from_groups(groups: dict[str, list[str]], exclusive: frozenset[str]) -> int:
    """The per-component bound, multiplied out and capped.

    Each component's guards are counted by how they can overlap:

    * A guard true of at most one value -- an equality, or a literal match pattern --
      contributes one class per named value plus one for everything else, so `n` of them
      give `n + 1`.
    * Prefix patterns give `n + 1` as well, and this needs an argument. A string matches
      `q*` exactly when `q` prefixes it, and any two prefixes of one string are comparable,
      so the set of prefix patterns a string matches is a *chain*. A chain is determined by
      its longest member, so `n` prefix patterns admit at most `n + 1` signatures rather
      than `2**n`.
    * A pattern with an interior or trailing-question wildcard can overlap another
      arbitrarily, so those need the exponential.
    * A pattern of `*` alone is true of everything and splits nothing.
    """

    product = 1
    for operators in groups.values():
        kinds = Counter(
            "exclusive"
            if name.lower() in exclusive or name == "literal"
            else name
            if name in {"prefix", "wildcard", "everything"}
            else "wildcard"
            for name in operators
        )
        bound = 1
        bound *= kinds["exclusive"] + 1
        bound *= kinds["prefix"] + 1
        bound *= 2 ** kinds["wildcard"]
        # Never claim more than the unconditional bound for the group.
        total = sum(count for kind, count in kinds.items() if kind != "everything")
        product = min(product * min(bound, 2**total if total < 64 else bound), INTRACTABLE)
    return product


def azure_guards(rule: Any) -> dict[str, list[str]]:
    """Leaf guards of an Azure condition tree, grouped by the component each reads."""

    groups: dict[str, list[str]] = defaultdict(list)

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        lowered = {key.lower(): key for key in node}
        for connective in set(lowered) & CONNECTIVES:
            walk(node[lowered[connective]])
        rest = set(lowered) - CONNECTIVES
        if not rest & set(OPERANDS):
            return
        operand = next((json.dumps(node[lowered[key]]) for key in OPERANDS if key in lowered), "")
        for operator in rest - set(OPERANDS):
            groups[operand].append(operator)
        nested = node.get(lowered.get("count", ""))
        if isinstance(nested, dict):
            walk(nested.get("where"))

    walk(rule)
    return groups


def iam_guards(document: dict[str, Any]) -> dict[str, list[str]]:
    """Guards of an IAM policy, grouped by component: action, resource, condition keys."""

    groups: dict[str, list[str]] = defaultdict(list)
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements or []:
        if not isinstance(statement, dict):
            continue
        for component in ("Action", "NotAction", "Resource", "NotResource"):
            value = statement.get(component)
            if value is None:
                continue
            patterns = value if isinstance(value, list) else [value]
            for pattern in patterns:
                if isinstance(pattern, str):
                    groups[component.replace("Not", "")].append(pattern_kind(pattern))
        condition = statement.get("Condition")
        if isinstance(condition, dict):
            for operator, comparison in condition.items():
                if not isinstance(comparison, dict):
                    continue
                for key in comparison:
                    groups[f"condition:{key}"].append(operator)
    return groups


def _distribution(cells: list[int]) -> dict[str, Any]:
    ordered = sorted(cells)

    def percentile(fraction: float) -> int:
        return ordered[int(fraction * (len(ordered) - 1))]

    thresholds = (4, 8, 16, 64, 256, 1024, 10**6)
    return {
        "policies": len(ordered),
        "median_cells": percentile(0.50),
        "p75_cells": percentile(0.75),
        "p90_cells": percentile(0.90),
        "p99_cells": percentile(0.99),
        "at_or_above_intractable": sum(1 for value in ordered if value >= INTRACTABLE),
        "share_at_most": {
            str(threshold): round(
                sum(1 for value in ordered if value <= threshold) / len(ordered), 4
            )
            for threshold in thresholds
        },
    }


def measure(azure_root: Path, iam_root: Path, docs: Path) -> dict[str, Any]:
    findings: dict[str, Any] = {"schema_version": "v1", "intractable_at": INTRACTABLE}

    azure = _adapter("azure")
    art = json.loads((docs / "fragment-membership-azure-wide-v1.json").read_text("utf-8"))
    inside = {row["subject"] for row in art["policies"] if row["verdict"] == "inside"}
    cells: list[int] = []
    guards: list[int] = []
    if azure_root.is_dir():
        # One measurement per subject, at the first path carrying it, because that is the
        # path the membership verdict was reached on: this corpus reuses a definition name
        # across directories, and counting pairs rather than subjects measured seven
        # definitions twice and left the cost denominator larger than the inside set.
        seen: set[str] = set()
        for subject, path in azure.discover(azure_root):
            if subject not in inside or subject in seen:
                continue
            seen.add(subject)
            document = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            rule = (document.get("properties") or {}).get("policyRule") or {}
            groups = azure_guards(rule.get("if"))
            cells.append(cells_from_groups(groups, AZURE_EXCLUSIVE))
            guards.append(sum(len(value) for value in groups.values()))
    if cells:
        findings["azure"] = {
            **_distribution(cells),
            "median_guards": int(statistics.median(guards)),
            "max_guards": max(guards),
        }
        if len(cells) != len(inside):
            raise SystemExit(
                f"cost was measured over {len(cells)} definitions but "
                f"{len(inside)} are inside the fragment; the two corpora disagree"
            )

    iam = _adapter("iam")
    art = json.loads((docs / "fragment-membership-iam-wide-v1.json").read_text("utf-8"))
    inside = {row["subject"] for row in art["policies"] if row["verdict"] == "inside"}
    cells, guards = [], []
    if iam_root.is_dir():
        seen = set()
        for subject, path in iam.discover(iam_root):
            if subject not in inside or subject in seen:
                continue
            seen.add(subject)
            document = iam.document_of(path.read_text(encoding="utf-8", errors="ignore"))
            if document is None:
                continue
            groups = iam_guards(document)
            cells.append(cells_from_groups(groups, IAM_EXCLUSIVE))
            guards.append(sum(len(value) for value in groups.values()))
    if cells:
        findings["iam"] = {
            **_distribution(cells),
            "median_guards": int(statistics.median(guards)),
            "max_guards": max(guards),
        }
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--azure", type=Path, required=True)
    parser.add_argument("--iam", type=Path, required=True)
    parser.add_argument("--docs", type=Path, default=ROOT / "docs")
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)

    findings = measure(arguments.azure, arguments.iam, arguments.docs)
    for name in ("azure", "iam"):
        row = findings.get(name)
        if not row:
            continue
        print(f"{name}: {row['policies']} policies inside the fragment")
        print(f"  guards   median {row['median_guards']}  max {row['max_guards']}")
        print(
            f"  cells    median {row['median_cells']}  p75 {row['p75_cells']}  "
            f"p90 {row['p90_cells']}  p99 {row['p99_cells']}"
        )
        for threshold, share in row["share_at_most"].items():
            print(f"    at most {threshold:>8} cells: {100 * share:5.1f}%")
        print(f"  intractable (>= {INTRACTABLE:,}): {row['at_or_above_intractable']}")
    if arguments.json:
        arguments.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
