"""AWS IAM fragment membership: guards are Action, Resource and Condition matches.

This corpus is the reason the adapter exists. The other four ecosystems are vendor test
and conformance directories, which is the limitation the study reports and cannot argue
away. AWS's *managed* policies are neither: they are published by AWS, attached in
millions of accounts, and retrievable as JSON. They are deployed policy in the most widely
used access-control language there is.

An IAM statement states three kinds of guard and combines them conjunctively.

`Action` and `NotAction` match the request's action against patterns the policy writes
down, with `*` as the only metacharacter. `Resource` and `NotResource` do the same for the
ARN. Both are finitely refining: the pattern set is finite, each pattern splits the space
two ways, and a witness for either side is readable off the pattern. The `Not` forms are
complements and change nothing about finiteness.

`Condition` is where the interesting case is. An operator compares a request context key
against values in the policy, and the operator names decompose into a family, an optional
`ForAllValues:`/`ForAnyValue:` quantifier prefix for multi-valued keys, and an optional
`IfExists` suffix that adds an outcome for an absent key. Every family in this corpus --
string equality and matching, ARN equality and matching, numeric and date comparison,
`Bool`, `Null`, `IpAddress` -- compares against a literal, so each induces finitely many
classes with constructible witnesses. The quantifiers and the suffix keep the outcome
finite. Membership follows the family, not the datatype, exactly as in XACML.

The case worth stating is the one that looks like an exclusion and is not. 237 of these
policies interpolate a policy variable -- `${aws:username}`,
`${aws:PrincipalTag/Project}`, `${aws:PrincipalAccount}` -- into a resource ARN or a
condition value. It is tempting to call that a pattern taken from the input and place it
outside, and that is the mistake this project already made once about Gatekeeper's
`input.parameters`. It does not hold here either, and for a cleaner reason: the substituted
value is an attribute of *the request being authorized*, so the guard relates two
components of the subject to each other. Its outcome is still binary and a witness for
either side is still constructible -- a request whose resource matches its own principal's
name, and one whose resource does not. The store, the parameters and the interpolated
attribute are all in the subject; what leaves the fragment is a guard reading something the
subject does not carry, and IAM's condition keys are all carried by the request.

The adapter refuses rather than guesses: an operator from no known family, or a statement
shape it does not recognise, is undetermined.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fragment_membership import INSIDE, UNDETERMINED, Verdict

ECOSYSTEM = "iam"

# Condition operator families whose partition is fixed by literals in the policy. Each
# compares a request context key against values the policy writes down, so it names
# finitely many sets of subjects and a witness for every achieved combination is readable
# off the syntax.
FINITELY_REFINING_FAMILIES = frozenset(
    {
        # String comparison against literals and against patterns whose only
        # metacharacter is `*`.
        "StringEquals",
        "StringNotEquals",
        "StringEqualsIgnoreCase",
        "StringNotEqualsIgnoreCase",
        "StringLike",
        "StringNotLike",
        # ARN comparison, the same shapes over a structured identifier.
        "ArnEquals",
        "ArnNotEquals",
        "ArnLike",
        "ArnNotLike",
        # Ordered comparison against a literal bound: two classes, the two sides of it.
        "NumericEquals",
        "NumericNotEquals",
        "NumericLessThan",
        "NumericLessThanEquals",
        "NumericGreaterThan",
        "NumericGreaterThanEquals",
        "DateEquals",
        "DateNotEquals",
        "DateLessThan",
        "DateLessThanEquals",
        "DateGreaterThan",
        "DateGreaterThanEquals",
        # Two-valued and presence tests.
        "Bool",
        "Null",
        "BinaryEquals",
        # CIDR membership against a literal block: a function of the address it is given.
        "IpAddress",
        "NotIpAddress",
    }
)

# Quantifier prefixes for multi-valued context keys. A quantifier over a finite set of
# values yields one boolean, so it does not enlarge the outcome domain.
QUANTIFIERS = ("ForAllValues:", "ForAnyValue:")

# Suffix admitting one further outcome, "the key is absent", which keeps the count finite.
OPTIONAL_SUFFIX = "IfExists"

GUARD_KEYS = ("Action", "NotAction", "Resource", "NotResource", "Condition")


def base_operator(operator: str) -> str:
    """An operator with its quantifier prefix and optional suffix stripped.

    Membership is a property of the family. `ForAllValues:StringLikeIfExists` and
    `StringEquals` differ in how many outcomes they admit and not in whether the partition
    is fixed by the policy, so both resolve to a family this adapter can judge.
    """

    name = operator
    for quantifier in QUANTIFIERS:
        if name.startswith(quantifier):
            name = name[len(quantifier) :]
            break
    if name.endswith(OPTIONAL_SUFFIX) and name != OPTIONAL_SUFFIX:
        name = name[: -len(OPTIONAL_SUFFIX)]
    return name


def is_finitely_refining(operator: str) -> bool:
    return base_operator(operator) in FINITELY_REFINING_FAMILIES


def document_of(text: str) -> dict[str, Any] | None:
    """The policy document, whether the file is one or wraps one in metadata."""

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    inner = parsed.get("document")
    if isinstance(inner, dict):
        return inner
    return parsed if "Statement" in parsed else None


def statements_of(document: dict[str, Any]) -> list[dict[str, Any]] | None:
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return None
    return [entry for entry in statements if isinstance(entry, dict)]


def discover(root: Path) -> list[tuple[str, Path]]:
    """Every managed policy document in the corpus, named by its policy name."""

    if not root.is_dir():
        return []
    found: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*.json")):
        if ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if document_of(text) is None:
            continue
        found.append((path.stem, path))
    return found


def classify(text: str) -> Verdict:
    document = document_of(text)
    if document is None:
        return Verdict(UNDETERMINED, "not a JSON policy document")
    statements = statements_of(document)
    if statements is None:
        return Verdict(UNDETERMINED, "states no Statement list")
    if not statements:
        return Verdict(
            INSIDE,
            "states no statement, so every subject falls in one decision class",
            {"statements": 0},
        )

    operators: set[str] = set()
    unrecognised_shapes: list[str] = []
    for statement in statements:
        condition = statement.get("Condition")
        if condition is None:
            continue
        if not isinstance(condition, dict):
            unrecognised_shapes.append("Condition is not an object")
            continue
        for operator, comparison in condition.items():
            operators.add(operator)
            if not isinstance(comparison, dict):
                unrecognised_shapes.append(f"{operator} does not compare named keys")

    detail: dict[str, Any] = {
        "statements": len(statements),
        "condition_operators": sorted(operators),
    }

    if unrecognised_shapes:
        detail["unrecognised_shapes"] = sorted(set(unrecognised_shapes))
        return Verdict(UNDETERMINED, "states a condition this test cannot read", detail)

    unjudged = sorted(operator for operator in operators if not is_finitely_refining(operator))
    if unjudged:
        detail["unjudged_operators"] = unjudged
        return Verdict(UNDETERMINED, "names a condition operator from no known family", detail)

    if not any(key in statement for statement in statements for key in GUARD_KEYS):
        return Verdict(
            INSIDE,
            "states no guard, so every subject falls in one decision class",
            detail,
        )

    return Verdict(
        INSIDE,
        "every guard matches the request against patterns and literals in the policy",
        detail,
    )
