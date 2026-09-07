"""Which published XACML policies lie inside the decidable fragment.

docs/DECISION_CLASS_COVERAGE.md section 4b locates the obstacle to the exactness results
in a policy's *guards*: a guard is inside the fragment when the partition it induces on
the subject space is fixed by the policy text, so finitely many classes exist and a
witness for each is constructible. That is a characterisation, and a characterisation with
no measurement beside it invites the reader to assume the answer is "almost none".

This measures it, on the same XACML policies docs/SUITE_COVERAGE_STUDY.md measures, which
are the four-valued corpus and therefore the interesting one.

The test is deliberately conservative and refuses rather than guesses, which is the rule
the suite-coverage adapters follow. A policy is reported INSIDE only when every function
it names is on an allowlist of predicates whose partition is fixed by a literal in the
policy, and it names no AttributeSelector. It is reported OUTSIDE when it selects over
arbitrary XML content with XPath, because the subject then includes a document and no
witness is constructible from the policy text. Anything else is UNDETERMINED and counted
as such: an unrecognised function is not evidence either way, and calling it one would be
the error that made an early revision of the Rego measurement support the opposite of its
conclusion.

Usage:
    python scripts/xacml_fragment_membership.py <corpus-root> [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ElementTree
from collections import Counter
from pathlib import Path
from typing import Any

# Predicates whose induced partition is fixed by a literal the policy contains. Each
# names finitely many sets of subjects and a witness for every achieved combination can be
# read off the syntax: an equality names one value and its complement, a bag membership
# names the bag, a range names its endpoints, a case fold is a total function applied
# before an equality, and a bag quantifier is a finite disjunction over the bag.
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
        # A regular-expression match against a pattern the policy contains. XACML's
        # regexp is the XML Schema one, which has no backreferences, so the pattern
        # denotes a regular language: the predicate splits the string space in two,
        # emptiness of either side is decidable, and a witness for either is constructible
        # from the pattern. Combining it with an equality on the same attribute stays
        # decidable, since that is testing whether one literal matches the pattern. A
        # pattern taken from the request rather than the policy would not qualify, and
        # XACML has no form for that.
        "string-regexp-match",
        "anyURI-regexp-match",
    }
)

# Selecting over request content is the construct that leaves the fragment: the subject
# then contains an arbitrary XML document rather than a tuple of labels, and no witness
# for an XPath predicate is constructible from the policy text alone.
CONTENT_SELECTION = "AttributeSelector"

# XACML names a Target predicate with MatchId and a Condition predicate with
# FunctionId. Scanning only the second missed every Target match, which made a policy
# whose only guard is a string-equal Target read as naming no function at all.
PREDICATE_ID = re.compile(r'(?:FunctionId|MatchId)="([^"]+)"')
POLICY_FILE = re.compile(r"^TestPolicy_(\d+)\.xml$")

INSIDE = "inside"
OUTSIDE = "outside"
UNDETERMINED = "undetermined"


def _local(name: str) -> str:
    return name.rsplit(":", 1)[-1]


def classify_policy(text: str) -> tuple[str, dict[str, Any]]:
    """Return (verdict, evidence) for one policy document."""

    try:
        ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        return UNDETERMINED, {"reason": f"not well-formed XML: {error}"}

    functions = sorted({_local(found) for found in PREDICATE_ID.findall(text)})
    unrecognised = sorted(set(functions) - FINITELY_REFINING_FUNCTIONS)
    selects_content = CONTENT_SELECTION in text

    if selects_content:
        return OUTSIDE, {
            "reason": "selects over request content with XPath",
            "functions": functions,
        }
    if unrecognised:
        return UNDETERMINED, {
            "reason": "names a function this test does not judge",
            "unrecognised_functions": unrecognised,
            "functions": functions,
        }
    if not functions:
        return UNDETERMINED, {"reason": "names no function at all", "functions": functions}
    return INSIDE, {
        "reason": "every guard compares a designator against a literal in the policy",
        "functions": functions,
    }


def discover(root: Path) -> list[Path]:
    """Policy documents belonging to a multi-case suite, matching the study's selection."""

    return sorted(
        path
        for path in root.rglob("TestPolicy_*.xml")
        if path.parent.name.lower() == "policies" and POLICY_FILE.match(path.name)
    )


def subject_for(path: Path) -> str:
    """The subject name the suite-coverage adapter uses for this policy."""

    index = POLICY_FILE.match(path.name).group(1)  # type: ignore[union-attr]
    suite = path.parent.parent
    name = f"{suite.name}/policy_{index}"
    if suite.parent.name:
        name = f"{suite.parent.name}/{name}"
    return name


def measure(root: Path, measured_subjects: set[str] | None) -> dict[str, Any]:
    policies = []
    for path in discover(root):
        subject = subject_for(path)
        if measured_subjects is not None and subject not in measured_subjects:
            continue
        verdict, evidence = classify_policy(path.read_text(encoding="utf-8", errors="ignore"))
        policies.append({"subject": subject, "verdict": verdict, **evidence})
    policies.sort(key=lambda entry: entry["subject"])
    counts = Counter(entry["verdict"] for entry in policies)
    return {
        "schema_version": "v1",
        "ecosystem": "xacml",
        "policies_considered": len(policies),
        "counts": {name: counts.get(name, 0) for name in (INSIDE, OUTSIDE, UNDETERMINED)},
        "share_inside": (round(counts.get(INSIDE, 0) / len(policies), 4) if policies else None),
        "policies": policies,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="corpus root to walk")
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--only-measured",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "docs" / "suite-coverage-xacml-v1.json",
        help="restrict to the subjects this suite-coverage artifact measured",
    )
    args = parser.parse_args(argv)

    measured: set[str] | None = None
    if args.only_measured and args.only_measured.is_file():
        reading = json.loads(args.only_measured.read_text(encoding="utf-8"))
        measured = {subject["subject"] for subject in reading["subjects"]}

    findings = measure(args.root, measured)
    counts = findings["counts"]
    print(f"policies considered: {findings['policies_considered']}")
    print(f"  inside the fragment:  {counts['inside']}")
    print(f"  outside:              {counts['outside']}")
    print(f"  undetermined:         {counts['undetermined']}")
    print(f"  share inside:         {findings['share_inside']}")
    for entry in findings["policies"]:
        if entry["verdict"] != INSIDE:
            print(f"    {entry['verdict']:12s} {entry['subject']}: {entry['reason']}")
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
