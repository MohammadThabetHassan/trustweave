"""Azure Policy fragment membership: guards are the leaves of the policyRule condition.

Azure Policy is the second of the three major clouds measured here, and its built-in
definitions are the analogue of AWS's managed policies: Microsoft publishes them and every
tenant evaluates them. A definition states a condition tree under `policyRule.if`, built
from `allOf`, `anyOf` and `not` over leaves, and an effect under `policyRule.then`.

A leaf compares something -- a `field` of the resource under evaluation, a computed `value`,
or a `count` over an array -- against a literal, using one of a small set of operators:
`equals`, `like`, `in`, `exists`, `greater`, `contains` and their negations. Every one of
them is finitely refining: the comparand is in the policy, the leaf splits the resource space
two ways, and a witness for each side is readable off the literal. Membership follows the
operator family and not the field's type, which is the third language in this study where
that turns out to be the right unit -- XACML and IAM were the others. Azure spells some
operators inconsistently (`Like` beside `like`, `notin` beside `notIn`) and evaluates them
case-insensitively, so this adapter normalises before matching, as Azure does.

Two things make this corpus more interesting than a fourth confirmation.

**Parameters, and a distinction the Gatekeeper case did not force.** 2{,}792 of these
definitions are parameterised, and a parameterised artifact is a policy schema rather than a
policy -- the argument this study already had to make about constraint templates. But an
Azure parameter may carry a `defaultValue`, and a definition whose every parameter has one
*does* determine a decision function: evaluating it with its defaults is what Azure does
when a assignment supplies nothing. So the schema/policy line falls in a different place
here, and the adapter draws it where the artifact does: full defaults means a policy, a
parameter without a default means a schema awaiting an assignment.

**A genuine lookup, and a clock read.** `reference()` reads the runtime state of a resource
other than the one
under evaluation, so a guard over it has no witness the policy determines. This is the
Azure form of what `data.inventory` is in Gatekeeper and `context.apiCall` is in Kyverno,
and it is the same reason. `subscription()` and `resourceGroup()` are not that: they return
ambient properties of the evaluation, handed to the evaluator rather than fetched by the
policy, and they sit in the subject exactly as Cedar's entity store does. `utcNow()` and
`newGuid()` are a third thing again: they read no resource, and they are not a function of
their arguments, which is what OPA's own capability data says of `time.now_ns`. They are
reported under that heading here so that the same obstruction carries the same name across
languages.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fragment_membership import INSIDE, OUTSIDE, UNDETERMINED, Verdict

ECOSYSTEM = "azure"

# Azure evaluates these case-insensitively and the corpus spells them inconsistently, so
# every comparison here is against a lowercased key.
CONNECTIVES = frozenset({"allof", "anyof", "not"})

# What a leaf compares.
OPERANDS = frozenset({"field", "value", "count"})

# Leaf operators, lowercased. Each compares against a literal the policy contains and
# splits the resource space finitely, with a witness readable off the literal.
FINITELY_REFINING_OPERATORS = frozenset(
    {
        "equals",
        "notequals",
        "like",
        "notlike",
        "match",
        "notmatch",
        "matchinsensitively",
        "notmatchinsensitively",
        "in",
        "notin",
        "contains",
        "notcontains",
        "containskey",
        "notcontainskey",
        "exists",
        "greater",
        "greaterorequals",
        "less",
        "lessorequals",
    }
)

# ARM template functions that compute from the resource under evaluation, the policy's own
# parameters and variables, or their arguments.
PURE_ARM_FUNCTIONS = frozenset(
    {
        "parameters",
        "variables",
        "field",
        "current",
        "concat",
        "if",
        "equals",
        "not",
        "and",
        "or",
        "coalesce",
        "empty",
        "length",
        "first",
        "last",
        "split",
        "join",
        "string",
        "int",
        "bool",
        "float",
        "array",
        "json",
        "add",
        "sub",
        "mul",
        "div",
        "mod",
        "min",
        "max",
        "union",
        "intersection",
        "contains",
        "startsWith",
        "endsWith",
        "substring",
        "replace",
        "toLower",
        "toUpper",
        "trim",
        "indexOf",
        "lastIndexOf",
        "skip",
        "take",
        "range",
        "less",
        "lessOrEquals",
        "greater",
        "greaterOrEquals",
        "createArray",
        "createObject",
        "padLeft",
        "uniqueString",
        "guid",
        "base64",
        "base64ToString",
        "uri",
        "uriComponent",
        "dataUri",
        "resourceId",
        "subscriptionResourceId",
        "tenantResourceId",
        "extensionResourceId",
        "subscription",
        "resourceGroup",
        "managementGroup",
        "policy",
        "requestContext",
        "dateTimeAdd",
        "dateTimeFromEpoch",
        "dateTimeToEpoch",
        "format",
        "items",
        "objectKeys",
        "intersects",
        "path",
        "reduce",
        "filter",
        "map",
        "sort",
        "flatten",
        # Policy-specific helpers, all total on their arguments: date arithmetic over a base
        # the caller supplies, a safe property read, the null constant, CIDR containment, and
        # the index of a copy loop.
        "addDays",
        "tryGet",
        "null",
        "true",
        "false",
        "ipRangeContains",
        "copyIndex",
    }
)

# Functions that read state the policy was not handed. `reference` fetches the runtime
# state of another resource; the deployment and key functions reach further still.
# `claims` is here rather than with the ambient functions on purpose. Under Azure Policy's
# external-evaluation feature a definition declares a Resource Graph query, the platform runs
# it across the tenant and projects named values out of the result, and `claims()` reads one
# of those -- in the pinned tree, how many other subnets share a network security group, or
# whether a referencing resource exists. The resource under evaluation does not determine the
# guard, which is the same reason `context.apiCall` puts a Kyverno policy outside.
EXTERNAL_ARM_FUNCTIONS = frozenset(
    {"reference", "listKeys", "list", "providers", "deployment", "claims"}
)

# Functions whose result is not a function of their arguments: two evaluations of the same
# definition against the same resource in the same environment can differ. ARM documents
# both as usable only in a parameter default, for exactly this reason. These are the ARM
# counterparts of OPA's nondeterministic builtins, and they are reported as the same kind of
# exclusion -- previously they were pooled with `reference`, which filed a clock read under
# the heading for reading another resource.
NONDETERMINISTIC_ARM_FUNCTIONS = frozenset({"utcNow", "newGuid"})

# Directory names under which the corpus repeats a definition for a sovereign cloud.
SOVEREIGN_CLOUD_DIRECTORIES = frozenset({"Azure Government", "Azure China"})

# Where a definition identifier appears in more than one directory, the copy judged is the
# one from the earliest directory here. The repository publishes the built-in definitions
# under the first two and tutorial or pattern variants under the others, and a variant may
# reuse a built-in's identifier while stating a different rule -- 25 identifiers appear
# twice in the pinned tree and 7 of those pairs differ. Preferring the built-in is a choice,
# and it is made here rather than left to whichever path happened to sort first.
CANONICAL_DIRECTORIES = ("built-in-policies", "built-in-references")

# Keys under `then.details` that name a policy program living somewhere else. An Azure
# definition targeting a Kubernetes cluster does not state its own guard: it points at a
# Gatekeeper ConstraintTemplate published at a URL --
# `store.policy.core.windows.net/kubernetes/<name>/v1/template.yaml` -- and the decision is
# made by the Rego inside that template against the values the definition supplies. The `if`
# region only selects which clusters the rule applies to. Reading `if` alone and reporting
# "every guard compares the resource under evaluation against literals in the policy" was
# therefore false of 43 definitions: the guard was not in the file at all.
DELEGATING_DETAIL_KEYS = ("templateInfo", "constraintTemplate")

ARM_CALL = re.compile(r"([a-zA-Z][a-zA-Z0-9_]*)\s*\(")

# ARM string literals are single-quoted, and their contents are prose. One built-in reads
# "... for type API Management services (microsoft.apimanagement/service), resourceName ...",
# in which `services (` looks exactly like a call and is not one -- which is why literals
# come out before function names go in.
ARM_LITERAL = re.compile(r"'[^']*'")


def _without_literals(expression: str) -> str:
    return ARM_LITERAL.sub("''", expression)


def _properties(document: Any) -> dict[str, Any] | None:
    if not isinstance(document, dict):
        return None
    properties = document.get("properties")
    return properties if isinstance(properties, dict) else None


def document_of(text: str) -> dict[str, Any] | None:
    """The policy definition, when the file is one."""

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    properties = _properties(parsed)
    if properties is None:
        return None
    if not isinstance(properties.get("policyRule"), dict):
        return None
    return parsed


def leaf_operators(condition: Any) -> tuple[set[str], set[str]]:
    """(operators the leaves use, leaf keys that are neither operand nor operator)."""

    operators: set[str] = set()
    unrecognised: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        by_lower = {key.lower(): key for key in node}
        for connective in set(by_lower) & CONNECTIVES:
            walk(node[by_lower[connective]])
        rest = set(by_lower) - CONNECTIVES
        if not rest:
            return
        if rest & OPERANDS:
            for key in rest - OPERANDS:
                if key in FINITELY_REFINING_OPERATORS:
                    operators.add(key)
                else:
                    unrecognised.add(by_lower[key])
            # `count` carries a nested `where` condition over an array of the resource.
            nested = node.get(by_lower.get("count", "count"))
            if isinstance(nested, dict):
                walk(nested.get("where"))
        else:
            unrecognised.update(by_lower[key] for key in rest)

    walk(condition)
    return operators, unrecognised


def arm_functions(rule: Any) -> set[str]:
    """Every ARM template function the rule invokes.

    An ARM expression is an entire string value wrapped in brackets, so the walk looks at
    string values rather than scanning the serialised rule: a field path such as
    `Microsoft.Sql/servers/databases[*].name` also contains brackets, and reading those as
    expressions reported resource-type segments -- `pools`, `vaults`, `Topics` -- as
    unjudged template functions, which left 387 definitions undetermined for no reason.
    """

    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str):
            text = node.strip()
            if text.startswith("[") and text.endswith("]"):
                found.update(ARM_CALL.findall(_without_literals(text[1:-1])))

    walk(rule)
    return found


def unparameterised(properties: dict[str, Any]) -> tuple[bool, list[str]]:
    """(whether every declared parameter has a default, the ones that do not)."""

    parameters = properties.get("parameters")
    if not isinstance(parameters, dict) or not parameters:
        return True, []
    missing = sorted(
        name
        for name, declaration in parameters.items()
        if not isinstance(declaration, dict) or "defaultValue" not in declaration
    )
    return not missing, missing


def _authority(path: Path, root: Path) -> tuple[int, str]:
    """Sort key: canonical directories first, then a stable path order."""

    try:
        parts = path.relative_to(root).parts
    except ValueError:  # pragma: no cover - a path from outside the corpus
        parts = path.parts
    top = parts[0] if parts else ""
    rank = (
        CANONICAL_DIRECTORIES.index(top)
        if top in CANONICAL_DIRECTORIES
        else len(CANONICAL_DIRECTORIES)
    )
    return rank, path.as_posix()


def discover(root: Path) -> list[tuple[str, Path]]:
    """Every policy definition in the repository, named by the identifier Azure gives it.

    Not by file stem. This corpus organises definitions into category directories and
    reuses stems across them -- `Audit.json` and its like -- so keying on the stem
    collapsed 5{,}130 definitions to 3{,}593 distinct subjects and silently dropped 1{,}537
    of them, since the core keeps the first subject it sees. Each definition carries a
    `name`, which is a GUID and unique; the path is the fallback for anything that does
    not. This is the same defect the Kyverno adapter had, found the same way, by an
    arithmetic check that did not add up.

    Unique within a directory, that is. An identifier can appear again under `samples/` or
    `patterns/` on a document stating a different rule, so the order paths are visited in
    decides which copy is judged. It is decided by `CANONICAL_DIRECTORIES` and not by the
    filesystem: the published built-in wins, and the variant is skipped by the core's
    first-subject rule.
    """

    if not root.is_dir():
        return []
    found: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*.json"), key=lambda candidate: _authority(candidate, root)):
        if ".git" in path.parts:
            continue
        # The corpus ships each definition twice: once for the commercial cloud and once
        # under `Azure Government` with the same GUID and cloud-specific content. Those
        # are two documents for one logical policy, so counting both double-counts it --
        # and deduplicating by GUID silently kept whichever sorted first, which is the
        # Government variant. The commercial one is the primary and the other is skipped.
        if SOVEREIGN_CLOUD_DIRECTORIES & {part for part in path.parts}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        document = document_of(text)
        if document is None:
            continue
        name = document.get("name")
        subject = name if isinstance(name, str) and name else path.relative_to(root).as_posix()
        found.append((subject, path))
    return found


def classify(text: str) -> Verdict:
    document = document_of(text)
    if document is None:
        return Verdict(UNDETERMINED, "not an Azure policy definition")
    properties = _properties(document) or {}
    rule = properties.get("policyRule") or {}

    # The guard regions, and only those. A definition's decision is made by `if` and, for
    # the `AuditIfNotExists` and `DeployIfNotExists` shapes, by
    # `then.details.existenceCondition`; `then.details.deployment` is the remediation
    # template, which is the effect and decides nothing. Walking the whole `policyRule` for
    # functions while reading only `if` for operators was inconsistent in a way that mattered:
    # 96 of 99 exclusions for reading another resource's runtime state were `reference()`
    # calls inside a remediation template, and the existence condition -- the deciding guard
    # of 1,330 definitions -- was never read at all.
    then = rule.get("then") if isinstance(rule.get("then"), dict) else {}
    details = then.get("details") if isinstance(then.get("details"), dict) else {}
    existence = details.get("existenceCondition")

    # Before anything else: if the guard is not in this document, nothing can be said about
    # it. This is the refusal the procedure is built to make, and it is the honest verdict --
    # the templates are public and the project already has a Rego adapter, so fetching and
    # judging them is the obvious next step rather than something the criterion forbids.
    operators, unrecognised = leaf_operators(rule.get("if"))
    if existence is not None:
        more_operators, more_unrecognised = leaf_operators(existence)
        operators |= more_operators
        unrecognised |= more_unrecognised
    functions = arm_functions(rule.get("if")) | arm_functions(existence)
    declared = properties.get("parameters")
    detail: dict[str, Any] = {
        "leaf_operators": sorted(operators),
        "arm_functions": sorted(functions),
        # Recorded for every definition, inside or out or unjudged, so that the corpus-wide
        # parameter counts the study quotes are derivable from the artifact instead of from a
        # separate pass over the corpus that nothing checks against it. Whether a parameter
        # carries a default is a fact about the document, and stays knowable even when the
        # guard is a program the document does not contain.
        "parameters_declared": len(declared) if isinstance(declared, dict) else 0,
    }
    _, missing_defaults = unparameterised(properties)
    if missing_defaults:
        detail["parameters_without_defaults"] = missing_defaults

    delegated = sorted(key for key in DELEGATING_DETAIL_KEYS if key in details)
    if delegated:
        detail["delegates_guard_to"] = delegated
        delegated_source = details.get(delegated[0])
        if isinstance(delegated_source, dict) and delegated_source.get("url"):
            detail["guard_source"] = delegated_source["url"]
        return Verdict(
            UNDETERMINED,
            "delegates its guard to a policy program the definition does not contain",
            detail,
        )

    lowered = {name.lower() for name in functions}
    nondeterministic = sorted(lowered & {name.lower() for name in NONDETERMINISTIC_ARM_FUNCTIONS})
    external = sorted(lowered & {name.lower() for name in EXTERNAL_ARM_FUNCTIONS})
    complete = not missing_defaults

    # Every obstruction this definition carries, recorded whichever one the verdict names, so
    # that a definition excluded for two reasons is visible as such in the artifact rather
    # than only as the reason that happened to win. The order below is the reporting rule
    # stated in the taxonomy: an assignment removes the schema obstruction and removes
    # neither of the others, so the reason reported is the one that survives instantiation.
    reasons: list[str] = []
    # `then.details.type` names a resource other than the one under evaluation, and the
    # decision is whether such a resource exists -- among the subject's children by default,
    # or anywhere in its resource group under `existenceScope`. The evaluator fetches those
    # resources after `if` has matched; they are not in the request the decision is about.
    # This is the Azure form of Gatekeeper's injected inventory, and it is outside for the
    # same reason: supplying the value is not the same as the subject determining it.
    if "type" in details or existence is not None:
        detail["related_resource"] = {
            "type": details.get("type"),
            "scope": details.get("existenceScope", "resource"),
            "has_existence_condition": existence is not None,
        }
        reasons.append(
            "the decision turns on whether a related resource exists, which the resource "
            "under evaluation does not determine"
        )
    if nondeterministic:
        detail["nondeterministic_functions"] = nondeterministic
        reasons.insert(
            0,
            "calls a template function whose result is not a function of its arguments: "
            + ", ".join(nondeterministic),
        )
    if external:
        detail["external_functions"] = external
        reasons.append("reads the runtime state of a resource other than the one under evaluation")
    if not complete:
        reasons.append(
            "is a policy schema rather than a policy: a parameter it reads has no default, "
            "so it determines no decision function until an assignment supplies one"
        )
    if reasons:
        if len(reasons) > 1:
            detail["reasons"] = reasons
        return Verdict(OUTSIDE, reasons[0], detail)

    if unrecognised:
        detail["unrecognised_leaf_keys"] = sorted(unrecognised)
        return Verdict(UNDETERMINED, "states a condition leaf this test cannot read", detail)

    unjudged = sorted(lowered - {name.lower() for name in PURE_ARM_FUNCTIONS})
    if unjudged:
        detail["unjudged_functions"] = unjudged
        return Verdict(UNDETERMINED, "calls a template function this test does not judge", detail)

    if not operators:
        return Verdict(
            INSIDE,
            "states no condition leaf, so every resource falls in one decision class",
            detail,
        )
    return Verdict(
        INSIDE,
        "every guard compares the resource under evaluation against literals in the policy",
        detail,
    )
