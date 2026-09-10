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


# XACML names a function `<type>-<family>`, and membership is a property of the family, not
# of the datatype: `integer-greater-than` and `time-greater-than` both compare a designator
# against a literal, and both split the subject space into the two sides of that literal.
# Enumerating names one datatype at a time therefore under-reports the fragment -- the
# conformance corpus exercises 182 names the flat list did not carry, and all but one of
# them belong to a family the flat list already accepted for some other type.
#
# Each family below is finitely refining in the sense of the paper's Definition 5: the
# partition it induces is fixed by literals the policy contains, and a witness for every
# achieved combination is computable from the syntax.
FINITELY_REFINING_FAMILIES = frozenset(
    {
        # Equality and ordering against a literal: two or three classes, witnessed by the
        # literal and by any value on each side of it.
        "equal",
        "equal-ignore-case",
        "value-equal",
        "greater-than",
        "greater-than-or-equal",
        "less-than",
        "less-than-or-equal",
        # Extraction from a bag, and bag construction from literals. Total on the value
        # they receive, so they compose with the comparisons above without adding classes.
        "one-and-only",
        "bag",
        "bag-size",
        # Set predicates over a bag the policy writes out: a finite disjunction or a
        # finite conjunction over named elements.
        "is-in",
        "at-least-one-member-of",
        "subset",
        "set-equals",
        "intersection",
        "union",
        # Arithmetic against a literal. The partition is the two sides of a shifted
        # threshold, and a witness is computable by inverting the shift.
        "add",
        "subtract",
        "multiply",
        "divide",
        "mod",
        "abs",
        "add-dayTimeDuration",
        "subtract-dayTimeDuration",
        "add-yearMonthDuration",
        "subtract-yearMonthDuration",
        # Total string and conversion functions applied before a comparison.
        "substring",
        "concatenate",
        "starts-with",
        "ends-with",
        "contains",
        "normalize-to-lower-case",
        "normalize-space",
        "to-double",
        "to-integer",
        "from-string",
        "to-string",
        # Pattern predicates against a literal pattern. XACML's regexp is the XML Schema
        # one, which has no backreferences, so the pattern denotes a regular language and a
        # witness for either side of the split is constructible.
        "regexp-match",
        "match",
    }
)

# Functions that are total on their arguments and take no datatype prefix.
FINITELY_REFINING_NAMES = frozenset(
    {
        "and",
        "or",
        "not",
        "n-of",
        "equal",
        "floor",
        "round",
        "any-of",
        "all-of",
        "any-of-any",
        "all-of-any",
        "any-of-all",
        "all-of-all",
        "map",
    }
)

# Functions that read something the policy does not contain. The XPath functions select
# over the request's `Content`, which is an arbitrary XML document, so no witness for the
# predicate is constructible from the policy text -- the same reason an `AttributeSelector`
# places a policy outside. `access-permitted` re-enters the PDP on a request the policy
# constructs, so its value is a property of the whole policy set at evaluation time.
EXTERNAL_FUNCTIONS = frozenset(
    {
        "xpath-node-count",
        "xpath-node-equal",
        "xpath-node-match",
        "access-permitted",
    }
)


def is_finitely_refining(function: str) -> bool:
    """Whether this function's induced partition is fixed by the policy's own literals."""

    if function in FINITELY_REFINING_NAMES or function in FINITELY_REFINING_FUNCTIONS:
        return True
    return any(
        function == family or function.endswith(f"-{family}")
        for family in FINITELY_REFINING_FAMILIES
    )


def discover(root: Path) -> list[tuple[str, Path]]:
    """Policy documents belonging to a multi-case suite, matching the study's selection."""

    return [
        (subject_for(path), path)
        for path in sorted(root.rglob("TestPolicy_*.xml"))
        if path.parent.name.lower() == "policies" and POLICY_FILE.match(path.name)
    ]


# The conformance suites name a policy by its directory. authzforce carries the OASIS
# XACML 3.0 conformance corpus as one directory per case holding `Policy.xml` with a single
# `Request.xml`/`Response.xml` pair; balana carries multi-case suites under `policies/`.
# `discover` takes only the latter because measuring decision coverage needs more than one
# case. Membership is decided from policy text, so it can read both.
WIDE_POLICY_NAMES = ("Policy.xml", "policy.xml")


def discover_wide(root: Path) -> list[tuple[str, Path]]:
    """Every XACML policy document in the corpus, selected by what it is.

    Selection used to be by filename -- `TestPolicy_*.xml` under a `policies/` directory, or
    a file called `Policy.xml` -- which is how the two projects happen to name most of their
    conformance cases. It is not a property of the documents, and it silently decided the
    corpus: 459 policies were left out, among them every one of the 15 that read the standard
    clock designators, so the XACML row reported no clock reader because none had been
    selected rather than because none exists. A XACML policy is a document whose root element
    is `Policy` or `PolicySet`, and that is the criterion now.
    """

    # The documents a study scores keep the names the study gave them, so the wide corpus
    # still contains the joined one and the two can be compared subject by subject.
    found: list[tuple[str, Path]] = list(discover(root))
    seen: set[Path] = {path for _, path in found}
    for path in sorted(root.rglob("*.xml")):
        if path in seen:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            tag = ElementTree.fromstring(text).tag
        except ElementTree.ParseError:
            continue
        if tag.rsplit("}", 1)[-1] not in ("Policy", "PolicySet"):
            continue
        seen.add(path)
        found.append((wide_subject_for(path, root), path))
    found.sort(key=lambda pair: pair[0])
    return found


def wide_subject_for(path: Path, root: Path) -> str:
    """A policy's own path relative to the corpus, which names it uniquely.

    The directory used to be enough, because selection took at most one `Policy.xml` from
    each. Selecting by root element puts several policies in one directory -- the OASIS
    conformance cases sit together as `IIC001Policy.xml`, `IIC002Policy.xml` and so on -- and
    naming them by their directory collapsed 1{,}007 documents to 539 subjects, silently
    dropping the rest through the core's first-subject rule. This is the same defect the
    Azure adapter had, and it is caught the same way, by a count that did not add up.
    """

    try:
        relative = path.relative_to(root)
    except ValueError:  # pragma: no cover - rglob results are always under the root.
        relative = path
    return relative.as_posix()


def subject_for(path: Path) -> str:
    """The subject name the suite-coverage adapter gives this policy."""

    match = POLICY_FILE.match(path.name)
    assert match is not None
    suite = path.parent.parent
    name = f"{suite.name}/policy_{match.group(1)}"
    if suite.parent.name:
        name = f"{suite.parent.name}/{name}"
    return name


# The elements a XACML policy states a predicate in. A document containing none of them
# states no predicate at all, whatever its functions scan to.
GUARD_ELEMENTS = frozenset({"Match", "Condition", "Apply", "VariableDefinition"})


def _guard_elements(text: str) -> list[str]:
    """The guard-bearing elements the document contains, by local name."""

    try:
        tree = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []
    return sorted(
        {
            element.tag.rsplit("}", 1)[-1]
            for element in tree.iter()
            if element.tag.rsplit("}", 1)[-1] in GUARD_ELEMENTS
        }
    )


# The standard environment attributes a PDP supplies from its own clock when the request
# does not carry them. XACML 3.0 requires the PDP to fill these in, so a policy naming one
# is asking the evaluator what time it is: the same obstruction as Rego's `time.now_ns` and
# Azure's `utcNow()`, and it belongs in the same row of the taxonomy. Nothing in the function
# scan could see it, because the clock arrives through an attribute designator rather than a
# function, and so 15 conformance policies that read it were reported inside.
CLOCK_DESIGNATORS = frozenset(
    {
        "urn:oasis:names:tc:xacml:1.0:environment:current-time",
        "urn:oasis:names:tc:xacml:1.0:environment:current-date",
        "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime",
    }
)


def clock_designators(text: str) -> list[str]:
    """Every standard clock attribute the document names."""

    return sorted(name for name in CLOCK_DESIGNATORS if name in text)


def classify(text: str) -> Verdict:
    try:
        ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        return Verdict(UNDETERMINED, f"not well-formed XML: {error}")

    functions = sorted({found.rsplit(":", 1)[-1] for found in PREDICATE_ID.findall(text)})
    external = sorted(set(functions) & EXTERNAL_FUNCTIONS)
    unrecognised = sorted(function for function in functions if not is_finitely_refining(function))

    clock = clock_designators(text)
    if clock:
        return Verdict(
            OUTSIDE,
            "reads the clock: the evaluator supplies the standard environment time "
            "attributes from its own clock when the request omits them",
            {"clock_designators": clock, "functions": functions},
        )
    if CONTENT_SELECTION in text:
        return Verdict(OUTSIDE, "selects over request content with XPath", {"functions": functions})
    if external:
        return Verdict(
            OUTSIDE,
            "names a function that reads outside the policy and the request attributes",
            {"external_functions": external, "functions": functions},
        )
    if unrecognised:
        return Verdict(
            UNDETERMINED,
            "names a function this test does not judge",
            {"unrecognised": unrecognised, "functions": functions},
        )
    if not functions:
        # A scan that finds no function has two causes that must not be conflated. If the
        # document also contains no element that can carry a predicate, the policy really
        # states none: every rule applies to every subject, the quotient has one class, and
        # the policy is inside the fragment in the strongest way available. If it does
        # contain such an element, the scan missed something and the honest answer is that
        # this test did not judge it.
        guards = _guard_elements(text)
        if guards:
            return Verdict(
                UNDETERMINED,
                "states a guard whose function this test could not read",
                {"functions": functions, "guard_elements": guards},
            )
        return Verdict(
            INSIDE,
            "states no predicate, so every subject falls in one decision class",
            {"functions": functions, "guard_elements": guards},
        )
    return Verdict(
        INSIDE,
        "every guard compares a designator against a literal in the policy",
        {"functions": functions},
    )
