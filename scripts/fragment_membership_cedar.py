"""Cedar fragment membership: guards are the scope and the `when`/`unless` conditions.

Cedar has no construct for reading data the request does not carry. There is no HTTP
call, no cluster query, no clock: an authorization decision is a function of the request
and the entity store handed to the engine, both of which are inputs. So the question for
Cedar is not whether a guard reaches outside, but whether every operator it uses induces a
partition fixed by a literal in the policy.

One judgement is worth stating plainly because it is the debatable one. `principal in
Group::"admins"` is true or false depending on the entity store, and the store is not in
the policy text. It is still finitely refining: the predicate has two outcomes, the policy
names the parent entity, so a store realising either outcome is constructible from the
policy. The store is an input to authorization, which puts it in the subject rather than
outside it. A transitive hierarchy of unbounded depth does not change that, because the
predicate's outcome is all the policy can observe.

That Cedar comes out entirely inside is not a surprise about this corpus. Cedar is designed
to admit automated reasoning -- it ships an SMT-based analysis tool -- and the fragment is
one statement of what that design buys.
"""

from __future__ import annotations

import re
from pathlib import Path

from fragment_membership import INSIDE, UNDETERMINED, Verdict

ECOSYSTEM = "cedar"

# Method calls whose partition is fixed by a literal in the policy. The comparisons are
# thresholds against a decimal the policy names; the set operations are finite tests
# against a set the policy names; the IP predicates split the address space in two, and a
# witness for either side is a constant.
FINITELY_REFINING_CALLS = frozenset(
    {
        "contains",
        "containsAll",
        "containsAny",
        "greaterThan",
        "greaterThanOrEqual",
        "lessThan",
        "lessThanOrEqual",
        "isInRange",
        "isIpv4",
        "isIpv6",
        "isLoopback",
        "isMulticast",
        "getTag",
        "hasTag",
    }
)

# Extension constructors, which take a literal and produce a value to compare against.
FINITELY_REFINING_CONSTRUCTORS = frozenset({"decimal", "ip", "datetime", "duration"})

POLICY_KEYWORD = re.compile(r"\b(?:permit|forbid)\s*\(")
COMMENT = re.compile(r"//.*")
METHOD_CALL = re.compile(r"\.(\w+)\s*\(")
FREE_CALL = re.compile(r"(?<![.\w])(\w+)\s*\(")
# `permit`, `forbid`, `if`, `when` and `unless` are syntax rather than calls.
SYNTAX = frozenset({"permit", "forbid", "if", "when", "unless"})


def discover(root: Path) -> list[tuple[str, Path]]:
    """Cedar policy sets, named by the path the suite-coverage adapter records."""

    found: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*.cedar")):
        # The adapter records paths relative to the corpus checkout, and the corpus is
        # nested one directory below the root this walk starts from.
        parts = path.relative_to(root).parts
        subject = "/".join(parts[1:]) if parts and parts[0] != "tests" else "/".join(parts)
        found.append((subject, path))
    return found


def classify(text: str) -> Verdict:
    body = COMMENT.sub("", text)
    if not POLICY_KEYWORD.search(body):
        return Verdict(UNDETERMINED, "contains no permit or forbid statement")

    methods = sorted(set(METHOD_CALL.findall(body)))
    constructors = sorted(name for name in set(FREE_CALL.findall(body)) if name not in SYNTAX)
    detail = {"method_calls": methods, "constructors": constructors}

    unrecognised = sorted(
        (set(methods) - FINITELY_REFINING_CALLS)
        | (set(constructors) - FINITELY_REFINING_CONSTRUCTORS)
    )
    if unrecognised:
        return Verdict(
            UNDETERMINED,
            "uses an operator this test does not judge",
            {**detail, "unrecognised": unrecognised},
        )
    return Verdict(
        INSIDE,
        "every guard's partition is fixed by a literal or an entity the policy names",
        detail,
    )
