"""XACML fragment membership: guards are Target matches and Condition applications."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from fragment_membership import INSIDE, OUTSIDE, UNDETERMINED, Verdict

ECOSYSTEM = "xacml"

# Predicates whose induced partition is fixed by a literal the policy contains. Each names
# finitely many sets of subjects and a witness for every achieved combination can be read
# off the syntax: an equality names one value and its complement, a bag membership names
# the bag, a range names its endpoints, a case fold is a total function applied before an
# equality, and a bag quantifier is a finite disjunction over the bag.
FINITELY_REFINING_FUNCTIONS = frozenset(
    {
        "string-equal",
        "string-equal-ignore-case",
        "boolean-equal",
        "integer-equal",
        "double-equal",
        "date-equal",
        "time-equal",
        "dateTime-equal",
        "anyURI-equal",
        "x500Name-equal",
        "rfc822Name-equal",
        "string-one-and-only",
        "boolean-one-and-only",
        "integer-one-and-only",
        "anyURI-one-and-only",
        "ipAddress-one-and-only",
        "string-is-in",
        "anyURI-is-in",
        "integer-is-in",
        "string-normalize-to-lower-case",
        "string-normalize-space",
        "boolean-from-string",
        "ip-in-range",
        "integer-greater-than",
        "integer-greater-than-or-equal",
        "integer-less-than",
        "integer-less-than-or-equal",
        "any-of",
        "all-of",
        "any-of-any",
        "and",
        "or",
        "not",
        # A regular-expression match against a pattern the policy contains. XACML's regexp
        # is the XML Schema one, which has no backreferences, so the pattern denotes a
        # regular language: the predicate splits the string space in two, emptiness of
        # either side is decidable, and a witness for either is constructible from the
        # pattern. Combining it with an equality on the same attribute stays decidable,
        # since that is testing whether one literal matches the pattern. A pattern taken
        # from the request rather than the policy would not qualify, and XACML has no form
        # for that.
        "string-regexp-match",
        "anyURI-regexp-match",
    }
)

# Selecting over request content is the construct that leaves the fragment: the subject
# then contains an arbitrary XML document rather than a tuple of labels, and no witness
# for an XPath predicate is constructible from the policy text alone.
CONTENT_SELECTION = "AttributeSelector"

# XACML names a Target predicate with MatchId and a Condition predicate with FunctionId.
# Scanning only the second missed every Target match, which made a policy whose only guard
# is a string-equal Target read as naming no function at all.
PREDICATE_ID = re.compile(r'(?:FunctionId|MatchId)="([^"]+)"')
POLICY_FILE = re.compile(r"^TestPolicy_(\d+)\.xml$")


def discover(root: Path) -> list[tuple[str, Path]]:
    """Policy documents belonging to a multi-case suite, matching the study's selection."""

    return [
        (subject_for(path), path)
        for path in sorted(root.rglob("TestPolicy_*.xml"))
        if path.parent.name.lower() == "policies" and POLICY_FILE.match(path.name)
    ]


def subject_for(path: Path) -> str:
    """The subject name the suite-coverage adapter gives this policy."""

    match = POLICY_FILE.match(path.name)
    assert match is not None
    suite = path.parent.parent
    name = f"{suite.name}/policy_{match.group(1)}"
    if suite.parent.name:
        name = f"{suite.parent.name}/{name}"
    return name


def classify(text: str) -> Verdict:
    try:
        ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        return Verdict(UNDETERMINED, f"not well-formed XML: {error}")

    functions = sorted({found.rsplit(":", 1)[-1] for found in PREDICATE_ID.findall(text)})
    unrecognised = sorted(set(functions) - FINITELY_REFINING_FUNCTIONS)

    if CONTENT_SELECTION in text:
        return Verdict(OUTSIDE, "selects over request content with XPath", {"functions": functions})
    if unrecognised:
        return Verdict(
            UNDETERMINED,
            "names a function this test does not judge",
            {"unrecognised": unrecognised, "functions": functions},
        )
    if not functions:
        return Verdict(UNDETERMINED, "names no function at all", {"functions": functions})
    return Verdict(
        INSIDE,
        "every guard compares a designator against a literal in the policy",
        {"functions": functions},
    )
