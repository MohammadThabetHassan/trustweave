"""Read what a Rego test suite pins, from the OPA AST.

The adapter works on `opa parse --format json` output rather than the source text, so it
sees what OPA sees. Suites express a decision in one of three forms:

    violation_set  `results := violation with input as x` then `results[r]` (a denial) or
                   `count(results) == 0` (a permit). This dominates admission policy, and
                   it is the form that needs the binding tracked: the assertion names a
                   local variable, and only the earlier assignment says which rule that
                   variable holds the output of.
    boolean        a helper rule invoked directly, asserting it holds or does not.
    labelled       a comparison against a decision string.

Comparisons that do not settle the question are refused rather than guessed. `count(r) != 2`
is a real assertion, but says nothing about whether the policy denied.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from suite_coverage import Observation, Reading

NAME = "rego"
DECISION_DOMAINS = {
    "violation_set": ["empty", "nonempty"],
    "boolean": ["does_not_hold", "holds"],
    # `labelled` is an open set of decision strings; it is reported without a denominator.
}

PINNING_OPERATORS = {"equal", "eq"}
EXCLUDING_OPERATORS = {"neq"}
# `:=` lowers to assign and `=` to eq; both can bind a rule output to a local name.
ASSIGNING_OPERATORS = {"assign", "eq"}
# Suites assert emptiness both ways: `count(r) == 0` and `count(r) > 0`. Admitting only
# equality reads a suite that tests both outcomes as testing one.
ORDERING_OPERATORS = {"gt", "gte", "lt", "lte"}
MIRRORED_OPERATORS = {"gt": "lt", "lt": "gt", "gte": "lte", "lte": "gte"}

_BUILTINS: frozenset[str] | None = None


def builtins() -> frozenset[str]:
    """Function names OPA defines, taken from the binary rather than hand-listed.

    A test body calling `trace("...")` is structurally identical to one calling a policy
    helper `is_exempt(input)`: both are a one-argument call. Only the builtin list separates
    a debug statement from a decision, and hand-maintaining that list would silently rot
    against the OPA version actually installed.
    """

    global _BUILTINS
    if _BUILTINS is None:
        _BUILTINS = frozenset()
        try:
            completed = subprocess.run(
                [_opa(), "capabilities", "--current"],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return _BUILTINS
        if completed.returncode == 0:
            try:
                document = json.loads(completed.stdout)
            except json.JSONDecodeError:
                return _BUILTINS
            if isinstance(document, dict):
                _BUILTINS = frozenset(
                    entry["name"]
                    for entry in document.get("builtins") or []
                    if isinstance(entry, dict) and isinstance(entry.get("name"), str)
                )
    return _BUILTINS


def discover(root: Path) -> list[Path]:
    return sorted(root.rglob("*_test.rego")) if root.is_dir() else [root]


def _opa() -> str:
    found = shutil.which("opa")
    if not found:
        raise SystemExit("opa is not on PATH; install it to run the rego adapter")
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
    """Turn a count comparison into the decision it asserts, or None when ambiguous."""

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


def _is_unconditional(expression: dict[str, Any]) -> bool:
    """True when an expression cannot fail: a literal assignment, or the implicit `true`."""

    if expression.get("negated"):
        return False
    terms = expression.get("terms")
    if isinstance(terms, dict):
        return terms.get("type") == "boolean" and terms.get("value") is True
    if not isinstance(terms, list) or len(terms) != 3:
        return False
    if _operator(terms[0]) not in ASSIGNING_OPERATORS:
        return False
    return terms[2].get("type") in {"string", "number", "boolean", "null"}


def _constant_nonempty_rules(ast: dict[str, Any]) -> frozenset[str]:
    """Rules that unconditionally define a non-empty set.

    A suite may compare a bound violation set against an expected set defined alongside it
    (`result == policy_violation`). Reading that as a denial requires knowing the expected
    set is non-empty. Only the unambiguous case is resolved: a partial set rule whose body
    binds literals and reads nothing, so it always yields a member. Anything else is left
    unresolved rather than assumed.
    """

    names = set()
    for rule in ast.get("rules") or []:
        head = rule.get("head") or {}
        name = head.get("name")
        if not isinstance(name, str) or head.get("key") is None:
            continue
        if all(_is_unconditional(expression) for expression in rule.get("body") or []):
            names.add(name)
    return frozenset(names)


def _rule_observations(
    rule: dict[str, Any],
    test: str,
    scope: str,
    known_builtins: frozenset[str],
    nonempty_rules: frozenset[str],
) -> list[Observation]:
    found: list[Observation] = []
    under_test: dict[str, str] = {}
    for expression in rule.get("body") or []:
        terms = expression.get("terms")
        negated = bool(expression.get("negated"))

        # A bare term: `results[result]` iterates the set, which succeeds only when it has
        # a member. Negated, it asserts the set is empty.
        if isinstance(terms, dict):
            base = _base_var(terms)
            if base is not None and base in under_test:
                found.append(
                    Observation(
                        domain="violation_set",
                        subject=f"{scope}::{under_test[base]}",
                        decision="empty" if negated else "nonempty",
                        test=test,
                    )
                )
            continue
        if not isinstance(terms, list) or not terms:
            continue

        if len(terms) != 3:
            subject = _reference(terms[0])
            if subject is None or subject in known_builtins:
                # `trace(...)` and `print(...)` are debug statements, not decisions.
                continue
            found.append(
                Observation(
                    domain="boolean",
                    subject=f"{scope}::{subject}",
                    decision="does_not_hold" if negated else "holds",
                    test=test,
                )
            )
            continue

        operator = _operator(terms[0])
        if operator is None:
            continue

        # `results := violation` names the rule this test exercises. Recording the binding
        # rather than reporting it is what lets the later assertion resolve.
        if operator in ASSIGNING_OPERATORS and _literal(terms[2]) is None:
            target = terms[1].get("value") if terms[1].get("type") == "var" else None
            source = _reference(terms[2])
            if isinstance(target, str) and source is not None:
                under_test[target] = source
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
                    Observation(
                        domain="violation_set",
                        subject=f"{scope}::{under_test[counted]}",
                        decision=decision,
                        test=test,
                    )
                )
            # A count comparison is never a labelled assertion, whether or not it resolved,
            # so it must not fall through to the string-literal path.
            continue

        if operator not in PINNING_OPERATORS | EXCLUDING_OPERATORS:
            continue

        # `results[_].msg == "..."` reads a field of a bound violation set. Iterating that
        # set succeeds only when it has a member, so the expression witnesses a denial. It
        # is an assertion about the message, not a decision label of its own.
        if not negated:
            member = _base_var(terms[1]) or _base_var(terms[2])
            if member is not None and member in under_test:
                found.append(
                    Observation(
                        domain="violation_set",
                        subject=f"{scope}::{under_test[member]}",
                        decision="nonempty",
                        test=test,
                    )
                )
                continue

        # `result == policy_violation` compares the bound set against an expected set. When
        # that expected set is provably non-empty, the comparison witnesses a denial.
        if operator in PINNING_OPERATORS and not negated:
            resolved = None
            for bound, other in ((terms[1], terms[2]), (terms[2], terms[1])):
                base = bound.get("value") if bound.get("type") == "var" else _base_var(bound)
                if not isinstance(base, str) or base not in under_test:
                    continue
                if _reference(other) in nonempty_rules:
                    resolved = under_test[base]
                    break
            if resolved is not None:
                found.append(
                    Observation(
                        domain="violation_set",
                        subject=f"{scope}::{resolved}",
                        decision="nonempty",
                        test=test,
                    )
                )
                continue

        subject = _reference(terms[1])
        expected = _literal(terms[2])
        if expected is None:
            expected = _literal(terms[1])
            subject = _reference(terms[2])
        if subject is None or expected is None:
            continue
        if operator in EXCLUDING_OPERATORS:
            # `decision != "deny"` executes the line while leaving the value open. It is
            # not a witnessed decision, so it must not count as one.
            continue
        found.append(
            Observation(
                domain="labelled", subject=f"{scope}::{subject}", decision=expected, test=test
            )
        )
    return found


def assertions(
    ast: dict[str, Any], scope: str = "suite", known_builtins: frozenset[str] = frozenset()
) -> list[Observation]:
    """Every decision the test rules in one parsed suite constrain."""

    found: list[Observation] = []
    nonempty_rules = _constant_nonempty_rules(ast)
    for rule in ast.get("rules") or []:
        name = str((rule.get("head") or {}).get("name") or "")
        if not name.startswith("test_"):
            continue
        found.extend(_rule_observations(rule, name, scope, known_builtins, nonempty_rules))
    return found


def read(path: Path, relative: str) -> Reading:
    ast = _parse(path)
    if ast is None:
        return Reading(path=relative, not_extracted="does not parse as Rego v1 or v0")
    observations = assertions(ast, scope=relative, known_builtins=builtins())
    if not observations:
        # Name what was dropped. A bare extraction percentage invites the reader to assume
        # the remainder is uninteresting; these are auditable instead.
        tests = sum(
            1
            for rule in ast.get("rules") or []
            if str((rule.get("head") or {}).get("name") or "").startswith("test_")
        )
        reason = "no test rules" if tests == 0 else f"{tests} test rules, no decision pinned"
        return Reading(path=relative, not_extracted=reason)
    return Reading(path=relative, observations=observations)
