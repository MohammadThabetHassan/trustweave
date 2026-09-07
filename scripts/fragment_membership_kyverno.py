"""Kyverno fragment membership: a guard is inside when it reads only the resource.

Kyverno decides on an admission request. Its guards are the resource selectors in
`match`/`exclude`, the structural `pattern`, the `deny.conditions` list, `preconditions`,
and CEL expressions. Those read the object under admission, and the values they compare
against sit in the policy, so their partitions are fixed by the policy text.

What leaves the fragment is a guard that reads something the policy does not contain. A
`context` entry fetches it -- `apiCall` queries the cluster, `configMap` reads one,
`imageRegistry` queries a registry, `globalReference` reads a global context entry -- and a
variable then substitutes the result into a condition. The truth of that condition is a
property of the cluster at admission time, not of the request, so no witness for it is
constructible from the policy. `now()` is the same problem with the clock.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from fragment_membership import INSIDE, OUTSIDE, UNDETERMINED, Verdict

ECOSYSTEM = "kyverno"

# Context sources that fetch data from outside the admission request.
EXTERNAL_CONTEXT_SOURCES = ("apiCall", "configMap", "imageRegistry", "globalReference")

# Variable roots that resolve inside the admission request or the rule's own iteration.
# `request` is the admission review, `element`/`elementIndex` are the foreach cursor over a
# field of the request, and the rest are JMESPath functions over those.
RESOURCE_VARIABLE_ROOTS = frozenset(
    {
        "request",
        "element",
        "elementIndex",
        "@",
        "serviceAccountName",
        "serviceAccountNamespace",
        "target",
        # Kyverno computes `images` by parsing the container image references already in
        # the admission request, so it is a function of the request and nothing else. It
        # must not be confused with the `imageRegistry` context entry or the `imageData`
        # variable that entry binds, which do query a registry and are treated as external
        # below.
        "images",
        "imageInfos",
    }
)

# JMESPath and Kyverno filter functions that are total on the value they receive, so they
# compute from the request rather than reaching past it.
RESOURCE_VARIABLE_FUNCTIONS = frozenset(
    {
        "length",
        "divide",
        "multiply",
        "add",
        "subtract",
        "round",
        "truncate",
        "to_string",
        "to_number",
        "keys",
        "values",
        "contains",
        "starts_with",
        "ends_with",
        "join",
        "split",
        "sort",
        "sum",
        "max",
        "min",
        "regex_match",
        "pattern_match",
        "label_match",
        "items",
        "not_null",
        "parse_json",
        "semver_compare",
        "time_diff",
    }
)

# CEL calls that are total functions of their receiver. `all`, `exists`, `filter` and `map`
# are finite quantifiers over a list already present in the request.
RESOURCE_CEL_CALLS = frozenset(
    {
        "all",
        "exists",
        "exists_one",
        "filter",
        "map",
        "size",
        "contains",
        "startsWith",
        "endsWith",
        "matches",
        "split",
        "join",
        "trim",
        "lowerAscii",
        "upperAscii",
        "indexOf",
        "sum",
        "min",
        "max",
        "orValue",
        "hasValue",
        "isSorted",
        "replace",
        "substring",
        "format",
    }
)

# CEL calls that reach outside the request. The image extensions query a registry; `now`
# reads the clock, which is not part of the subject at all.
EXTERNAL_CEL_CALLS = frozenset({"GetMetadata", "Get", "GetImageData", "now"})

VARIABLE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")
CEL_CALL = re.compile(r"\.(\w+)\(")
CEL_BLOCK = re.compile(r"^\s*(?:expression|expressionWarn|messageExpression):", re.MULTILINE)
CONTEXT_BLOCK = re.compile(r"^\s*context:", re.MULTILINE)


def _referenced_policies(test_directory: Path) -> list[Path]:
    """The policy files a `kyverno-test.yaml` points at, resolved as the CLI resolves them."""

    try:
        document = yaml.safe_load((test_directory / "kyverno-test.yaml").read_text("utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(document, dict):
        return []
    found = []
    for reference in document.get("policies") or []:
        if isinstance(reference, str):
            resolved = (test_directory / reference).resolve()
            if resolved.is_file():
                found.append(resolved)
    return found


def discover(root: Path) -> list[tuple[str, Path]]:
    """Policies resolved exactly as scripts/kyverno_mutation.py resolves them.

    This corpus ships most policies three times -- a classic ClusterPolicy, a `-cel`
    variant and a `-vpol` ValidatingPolicy -- so a policy name alone does not identify a
    file. 38 of the 49 policies the mutation experiment scored exist at more than one path.
    Walking `*.yaml` and keying on the file stem picked whichever sorted first, which
    joined a verdict about one file to a mutation score for another.

    The experiment keys test directories by the policy directory's name, keeping the last
    in sorted order, and reads the policy paths out of the test manifest. Repeating that
    here is what makes the join sound.
    """

    directories = {
        path.parent.parent.name: path.parent for path in sorted(root.rglob("kyverno-test.yaml"))
    }
    found: list[tuple[str, Path]] = []
    for name in sorted(directories):
        for policy in _referenced_policies(directories[name]):
            found.append((name, policy))
    return found


def _variable_roots(text: str) -> set[str]:
    roots: set[str] = set()
    for expression in VARIABLE.findall(text):
        token = re.split(r"[.\[(\s|]", expression.strip(), maxsplit=1)[0]
        roots.add(token)
    return roots


def classify(text: str) -> Verdict:
    detail: dict[str, object] = {}

    sources = [source for source in EXTERNAL_CONTEXT_SOURCES if source in text]
    if sources:
        return Verdict(
            OUTSIDE,
            "a context entry fetches data from outside the admission request",
            {"external_context_sources": sources},
        )

    external_calls = sorted({call for call in EXTERNAL_CEL_CALLS if f".{call}(" in text})
    if external_calls:
        return Verdict(
            OUTSIDE,
            "a CEL expression reads something outside the admission request",
            {"external_cel_calls": external_calls},
        )

    roots = _variable_roots(text)
    detail["variable_roots"] = sorted(roots)
    unknown_roots = sorted(roots - RESOURCE_VARIABLE_ROOTS - RESOURCE_VARIABLE_FUNCTIONS)
    if unknown_roots:
        # A context block was not found above, so an unrecognised root is more likely a
        # function this adapter has not enumerated than an external read. Either way it is
        # not judged.
        detail["unrecognised_variable_roots"] = unknown_roots
        return Verdict(UNDETERMINED, "substitutes a variable this test does not judge", detail)

    if CEL_BLOCK.search(text):
        calls = sorted(set(CEL_CALL.findall(text)))
        detail["cel_calls"] = calls
        unknown_calls = sorted(set(calls) - RESOURCE_CEL_CALLS - RESOURCE_VARIABLE_FUNCTIONS)
        if unknown_calls:
            detail["unrecognised_cel_calls"] = unknown_calls
            return Verdict(UNDETERMINED, "calls a CEL function this test does not judge", detail)

    if CONTEXT_BLOCK.search(text):
        # A context block with no recognised external source: it may bind a variable from
        # the request, which is admissible, but this adapter does not parse it.
        return Verdict(UNDETERMINED, "declares a context this test does not parse", detail)

    return Verdict(
        INSIDE, "every guard reads the admission request and literals in the policy", detail
    )
