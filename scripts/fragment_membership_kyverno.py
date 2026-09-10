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

import json
import re
from pathlib import Path
from typing import Any

import yaml
from fragment_membership import INSIDE, OUTSIDE, UNDETERMINED, Verdict

ECOSYSTEM = "kyverno"

# Context sources that fetch data from outside the admission request.
EXTERNAL_CONTEXT_SOURCES = ("apiCall", "configMap", "imageRegistry", "globalReference")

# `verifyImages` checks signatures and attestations against a registry and a transparency
# log, and binds the attestation payload for its conditions to read. The payload is not in
# the admission request -- the request names an image, and the signature and predicate are
# fetched -- so a guard over it has no witness constructible from the policy. This was
# missed at first because the block does not look like a `context` entry, and it surfaced
# on a corpus mined from third-party repositories, where three policies read attestation
# fields the adapter could not place.
IMAGE_VERIFICATION_BLOCK = re.compile(r"^\s*verifyImages:", re.MULTILINE)

# JMESPath functions that read the clock rather than compute from their arguments.
# Kyverno's other `time_*` functions -- `time_parse`, `time_add`, `time_diff`,
# `time_truncate`, `time_utc` -- are total on what they are given and stay inside.
CLOCK_FUNCTIONS = frozenset({"time_now", "time_now_utc", "time_since"})

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
        # Time functions that are total on their arguments: they convert or compare
        # timestamps they are handed. The clock readers are in CLOCK_FUNCTIONS and are
        # external -- these are not, and refusing them made a third-party policy
        # undetermined that is plainly inside.
        "time_parse",
        "time_add",
        "time_truncate",
        "time_utc",
        "time_before",
        "time_after",
        "time_between",
        "time_to_cron",
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
        # Time functions that are total on their arguments. The clock readers are in
        # CLOCK_FUNCTIONS above and are external; these convert or compare timestamps
        # they are handed, so their partition is fixed by the policy's own literals.
        "time_parse",
        "time_add",
        "time_diff",
        "time_truncate",
        "time_utc",
        "time_before",
        "time_after",
        "time_between",
        "time_to_cron",
    }
)

# CEL calls that reach outside the request. The image extensions query a registry; `now`
# reads the clock, which is not part of the subject at all; and the `resource` receiver
# reaches the API server -- `Get` fetches one object, `List` fetches a collection whose
# membership is a property of the cluster at admission time, and `Post` sends a request and
# reads the response. A guard over any of them has no witness constructible from the policy.
EXTERNAL_CEL_CALLS = frozenset({"GetMetadata", "Get", "GetImageData", "List", "Post", "now"})

# Calls that are total on the value they receive, so they compute from the request rather
# than reaching past it. `jsonpatch.escapeKey` escapes a string for use as a JSON-pointer
# segment. `image(...).registry()` parses an image reference that is already in the
# admission request and returns its registry field -- it is a string operation and not a
# registry query, which is why `GetMetadata` above is treated as external and this is not.
PURE_CEL_CALLS = frozenset({"escapeKey", "registry"})

# Calls that state an effect rather than a guard. Kyverno's `generate` block applies
# downstream resources through `generator.Apply`; membership is a property of a policy's
# guards, so an effect neither places a policy outside nor leaves it unjudged.
EFFECT_CEL_CALLS = frozenset({"Apply"})

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


# Kyverno numbers the foreach cursor by nesting depth, so a rule iterating a list inside a
# list binds `elementIndex0` and `elementIndex1` beside the unsuffixed `elementIndex`.
NESTED_CURSOR = re.compile(r"^element(?:Index)?\d+$")


def _context_bindings(text: str) -> tuple[set[str], set[str]]:
    """(names the policy's own context binds, the roots those bindings read).

    Only reached when no external context source appears anywhere in the file, because
    that check returns `outside` first. Every binding here is therefore a `variable` entry
    whose value is a JMESPath expression, and the roots it reads are returned so the caller
    can screen them the same way it screens a substituted variable -- a binding is not
    admissible merely because the policy declared it.
    """

    names: set[str] = set()
    roots: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "context" and isinstance(value, list):
                    for entry in value:
                        if not isinstance(entry, dict):
                            continue
                        name = entry.get("name")
                        if isinstance(name, str):
                            names.add(name)
                        variable = entry.get("variable")
                        if isinstance(variable, dict):
                            expression = variable.get("jmesPath")
                            if isinstance(expression, str):
                                roots.add(re.split(r"[.\[(\s|]", expression.strip(), maxsplit=1)[0])
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        # No bindings can be read, so none are reported. This does not weaken the verdict:
        # the external-source check is a substring test over the raw text and has already
        # run, and a variable root that is in fact a binding this parse missed stays
        # unrecognised below, which refuses rather than guesses.
        return set(), set()
    for document in documents:
        walk(document)
    return names, roots


def _variable_roots(text: str) -> set[str]:
    roots: set[str] = set()
    for expression in VARIABLE.findall(text):
        token = re.split(r"[.\[(\s|]", expression.strip(), maxsplit=1)[0]
        roots.add(token)
    return roots


def _documents(text: str) -> list[dict[str, Any]]:
    """Every YAML document in the file that is a mapping, or none if it will not parse."""

    try:
        loaded = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []
    return [document for document in loaded if isinstance(document, dict)]


def _context_entries(text: str) -> list[dict[str, Any]]:
    """The context entries the policy declares, from the parsed document.

    Context entries live at `spec.rules[].context[]` in a ClusterPolicy and at
    `spec.context[]` in the newer validating and mutating shapes. Reading them from the
    parse is the whole point: the previous test asked whether the string `configMap`
    occurred anywhere in the file, which is true of a description sentence, of a CEL
    expression reading `object.spec.volumes.configMap`, and of a mutation payload injecting
    `configMapRef` -- none of which fetches anything. Three of the corpus's exclusions were
    that mistake.
    """

    entries: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "context" and isinstance(value, list):
                    entries.extend(item for item in value if isinstance(item, dict))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    # Every `context` list anywhere in the document, not just on the rule. Kyverno declares
    # them on a rule, on the spec of the newer shapes, and inside a `foreach` -- and it was
    # the last of those that made a first version of this walk report five image-registry
    # policies as reading nothing outside.
    for document in _documents(text):
        walk(document)
    return entries


def _namespace_selectors(text: str) -> list[str]:
    """Match and exclude clauses that select on Namespace labels.

    The AdmissionReview carries the resource and its namespace's *name*, not the namespace
    object, so Kyverno resolves a `namespaceSelector` against labels it fetches for itself.
    A guard behind one is therefore not determined by the request.
    """

    found: list[str] = []
    for document in _documents(text):
        specification = document.get("spec")
        if not isinstance(specification, dict):
            continue
        for rule in (specification.get("rules") or []) + [specification]:
            if not isinstance(rule, dict):
                continue
            for clause_name in ("match", "exclude", "matchConstraints"):
                clause = rule.get(clause_name)
                if isinstance(clause, dict) and "namespaceSelector" in json.dumps(clause):
                    found.append(f"{clause_name}.namespaceSelector")
    return sorted(set(found))


def classify(text: str) -> Verdict:
    detail: dict[str, object] = {}

    sources = sorted(
        {
            source
            for entry in _context_entries(text)
            for source in entry
            if source in EXTERNAL_CONTEXT_SOURCES
        }
    )
    if sources:
        return Verdict(
            OUTSIDE,
            "a context entry fetches data from outside the admission request",
            {"external_context_sources": sources},
        )

    if IMAGE_VERIFICATION_BLOCK.search(text):
        return Verdict(
            OUTSIDE,
            "verifies an image against a registry, so its guards read a signature or "
            "attestation the admission request does not carry",
            {"image_verification": True},
        )

    clock = sorted({name for name in CLOCK_FUNCTIONS if f"{name}(" in text})
    if clock:
        return Verdict(
            OUTSIDE,
            "reads the clock, which is not part of the subject",
            {"clock_functions": clock},
        )

    external_calls = sorted({call for call in EXTERNAL_CEL_CALLS if f".{call}(" in text})
    if external_calls:
        return Verdict(
            OUTSIDE,
            "a CEL expression reads something outside the admission request",
            {"external_cel_calls": external_calls},
        )

    selectors = _namespace_selectors(text)
    if selectors:
        return Verdict(
            OUTSIDE,
            "selects on Namespace labels, which the admission request does not carry",
            {"namespace_selectors": selectors},
        )

    roots = _variable_roots(text)
    detail["variable_roots"] = sorted(roots)
    bound_names, binding_roots = _context_bindings(text)
    if bound_names:
        detail["context_bound_names"] = sorted(bound_names)
    known = RESOURCE_VARIABLE_ROOTS | RESOURCE_VARIABLE_FUNCTIONS
    unresolved_bindings = sorted(binding_roots - known)
    if unresolved_bindings:
        detail["unresolved_context_bindings"] = unresolved_bindings
        return Verdict(UNDETERMINED, "binds a context variable this test does not resolve", detail)
    unknown_roots = sorted(
        root for root in roots - known - bound_names if not NESTED_CURSOR.match(root)
    )
    if unknown_roots:
        # A context block was not found above, so an unrecognised root is more likely a
        # function this adapter has not enumerated than an external read. Either way it is
        # not judged.
        detail["unrecognised_variable_roots"] = unknown_roots
        return Verdict(UNDETERMINED, "substitutes a variable this test does not judge", detail)

    if CEL_BLOCK.search(text):
        calls = sorted(set(CEL_CALL.findall(text)))
        detail["cel_calls"] = calls
        unknown_calls = sorted(
            set(calls)
            - RESOURCE_CEL_CALLS
            - RESOURCE_VARIABLE_FUNCTIONS
            - PURE_CEL_CALLS
            - EFFECT_CEL_CALLS
        )
        if unknown_calls:
            detail["unrecognised_cel_calls"] = unknown_calls
            return Verdict(UNDETERMINED, "calls a CEL function this test does not judge", detail)

    if CONTEXT_BLOCK.search(text) and not bound_names:
        # A context block whose entries this adapter could not read at all. The bindings it
        # did read are screened above, so reaching here means the block is shaped in a way
        # the parser does not recognise, and an unread guard is not a guard known to be
        # inside.
        return Verdict(UNDETERMINED, "declares a context this test does not parse", detail)

    return Verdict(
        INSIDE, "every guard reads the admission request and literals in the policy", detail
    )
