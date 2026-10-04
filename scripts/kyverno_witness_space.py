"""A witness space for a Kyverno policy: resources on which the engine settles every mutant.

`docs/EXACT_ADEQUACY_PROTOCOL_KYVERNO.md` says what this builds and why; this module is the
construction. It reads each validate rule's `pattern`, its `anyPattern` alternatives, its deny
conditions and preconditions, and the `names`, `namespaces` and `operations` its `match` and
`exclude` blocks select by, and records the request's observables and the values to try for each.
From those it builds the cells: the resources the study asks the engine to decide.

Nothing here decides a policy. Whether a mutant is equivalent is the engine's answer on the
cells, and whether the cells are enough is checked against resources this construction did not
choose (`perturb` draws them).
"""

from __future__ import annotations

import copy
import itertools
import json
import math
import random
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

# A field the resource leaves out. Distinct from `None`, which is a JSON null the resource holds.
ABSENT: Any = type("Absent", (), {"__repr__": lambda self: "ABSENT"})()

FRESH = "tw-fresh"
OPERATIONS: tuple[str | None, ...] = ("CREATE", "UPDATE", "DELETE", "CONNECT", None)

# An anchor wraps a pattern key: `=(k)`, `X(k)`, `(k)`, `^(k)`, `<(k)`, `+(k)`.
_ANCHOR = re.compile(r"^(?P<anchor>[=X^<+]?)\((?P<name>.+)\)$")
_COMPARISON = re.compile(r"^(?P<op>>=|<=|>|<)\s*(?P<operand>.+)$")
_NUMBER = re.compile(r"^(?P<number>-?\d+(?:\.\d+)?)(?P<unit>[A-Za-z]*)$")
_RANGE = re.compile(r"^(?P<low>-?\d+(?:\.\d+)?[A-Za-z]*)-(?P<high>-?\d+(?:\.\d+)?[A-Za-z]*)$")
# `{{ request.object.a."b.c".d || 'default' }}` and `{{ request.operation }}`, the only condition
# keys the protocol admits in a policy. A mutant may turn the `||` into `&&`; it still reads the
# same path, and what `&&` makes of it is the engine's to decide.
_NAME = r'(?:[A-Za-z0-9_\-]+|"[^"]+")'
_DEFAULT = r"(?:\s*(?:\|\||&&)\s*'(?P<default>[^']*)')?"
_OBJECT_KEY = re.compile(
    r"^\{\{\s*request\.object(?P<path>(?:\." + _NAME + r")+)" + _DEFAULT + r"\s*\}\}$"
)
_OPERATION_KEY = re.compile(r"^\{\{\s*request\.operation" + _DEFAULT + r"\s*\}\}$")
_PATH_PART = re.compile(_NAME)

# API versions for the core kinds, used when a policy's own suite has no resource of the kind.
CORE_API_VERSIONS: dict[str, tuple[str, bool]] = {
    "Pod": ("v1", True),
    "Service": ("v1", True),
    "ConfigMap": ("v1", True),
    "Secret": ("v1", True),
    "ServiceAccount": ("v1", True),
    "PersistentVolumeClaim": ("v1", True),
    "Namespace": ("v1", False),
    "Node": ("v1", False),
    "PersistentVolume": ("v1", False),
    "Deployment": ("apps/v1", True),
    "StatefulSet": ("apps/v1", True),
    "DaemonSet": ("apps/v1", True),
    "ReplicaSet": ("apps/v1", True),
    "Job": ("batch/v1", True),
    "CronJob": ("batch/v1", True),
    "Ingress": ("networking.k8s.io/v1", True),
    "NetworkPolicy": ("networking.k8s.io/v1", True),
    "Role": ("rbac.authorization.k8s.io/v1", True),
    "RoleBinding": ("rbac.authorization.k8s.io/v1", True),
    "ClusterRole": ("rbac.authorization.k8s.io/v1", False),
    "ClusterRoleBinding": ("rbac.authorization.k8s.io/v1", False),
    "PodDisruptionBudget": ("policy/v1", True),
    "HorizontalPodAutoscaler": ("autoscaling/v2", True),
    "StorageClass": ("storage.k8s.io/v1", False),
}


class Unsupported(ValueError):
    """The policy uses a construct the protocol excludes; the message is the reason."""


@dataclass
class Node:
    """One position in the merged request: the values patterns and conditions name there."""

    children: dict[str, Node] = field(default_factory=dict)
    element: Node | None = None
    scalars: list[Any] = field(default_factory=list)
    scalar_lists: list[list[Any]] = field(default_factory=list)
    condition_values: list[Any] = field(default_factory=list)
    required: bool = False  # a resource cannot leave it out (the name)

    def child(self, name: str) -> Node:
        return self.children.setdefault(name, Node())


def strip_anchor(key: Any) -> str:
    text = str(key)
    found = _ANCHOR.match(text)
    return found.group("name") if found else text


def merge_pattern(node: Node, pattern: Any) -> None:
    """Add a pattern's structure and values to `node`."""

    if isinstance(pattern, dict):
        for key, value in pattern.items():
            merge_pattern(node.child(strip_anchor(key)), value)
    elif isinstance(pattern, list):
        if pattern and all(not isinstance(item, (dict, list)) for item in pattern):
            node.scalar_lists.append(list(pattern))
        else:
            for item in pattern:
                if node.element is None:
                    node.element = Node()
                merge_pattern(node.element, item)
    else:
        node.scalars.append(pattern)


def object_path(key: str) -> list[str] | None:
    """The `request.object` path a condition key reads, or None when it reads no such path."""

    found = _OBJECT_KEY.match(key.strip())
    if not found:
        return None
    return [part.strip('"') for part in _PATH_PART.findall(found.group("path"))]


def _conditions(block: Any) -> list[dict[str, Any]]:
    if not block:
        return []
    if isinstance(block, list):
        return [c for c in block if isinstance(c, dict)]
    if isinstance(block, dict):
        listed = list(block.get("any") or []) + list(block.get("all") or [])
        return [c for c in listed if isinstance(c, dict)]
    return []


def _selector_groups(block: Any) -> list[dict[str, Any]]:
    if not isinstance(block, dict):
        return []
    groups = list(block.get("any") or []) + list(block.get("all") or [])
    if "resources" in block:
        groups.append({"resources": block["resources"]})
    return [g for g in groups if isinstance(g, dict)]


@dataclass
class RuleSpace:
    """The observables of one rule, merged over the policy and its mutants."""

    name: str
    kind: str
    root: Node
    reads_operation: bool


def _first_kind(rule: dict[str, Any]) -> str:
    for group in _selector_groups(rule.get("match")):
        kinds = (group.get("resources") or {}).get("kinds") or []
        if kinds:
            return str(kinds[0])
    raise Unsupported("a rule whose match names no kind")


def merge_rule(space: RuleSpace, rule: dict[str, Any]) -> None:
    """Add one rule's guards (from the policy or a mutant) to its space."""

    validate = rule.get("validate") or {}
    merge_pattern(space.root, validate.get("pattern") or {})
    for alternative in validate.get("anyPattern") or []:
        merge_pattern(space.root, alternative)
    conditions = _conditions(rule.get("preconditions")) + _conditions(
        (validate.get("deny") or {}).get("conditions")
    )
    for condition in conditions:
        key = str(condition.get("key", ""))
        if _OPERATION_KEY.match(key.strip()):
            space.reads_operation = True
            continue
        path = object_path(key)
        if path is None:
            raise Unsupported("a condition the witness space does not model")
        node = space.root
        for part in path:
            node = node.child(part)
        value = condition.get("value")
        node.condition_values.extend(value if isinstance(value, list) else [value])
        default = _OBJECT_KEY.match(key.strip()).group("default")  # type: ignore[union-attr]
        if default is not None:
            node.condition_values.append(default)
    for selector in ("match", "exclude"):
        for group in _selector_groups(rule.get(selector)):
            resources = group.get("resources") or {}
            metadata = space.root.child("metadata")
            for name in resources.get("names") or []:
                metadata.child("name").scalars.append(name)
            for namespace in resources.get("namespaces") or []:
                metadata.child("namespace").scalars.append(namespace)
            if resources.get("operations"):
                space.reads_operation = True
    metadata = space.root.children.get("metadata")
    if metadata is not None and "name" in metadata.children:
        metadata.children["name"].required = True


def rule_spaces(policy: dict[str, Any], mutants: Sequence[dict[str, Any]]) -> list[RuleSpace]:
    """One space per rule of `policy`, with the candidates its mutants add."""

    rules = (policy.get("spec") or {}).get("rules") or []
    spaces = [RuleSpace(str(rule.get("name")), _first_kind(rule), Node(), False) for rule in rules]
    for document in (policy, *mutants):
        mutated_rules = (document.get("spec") or {}).get("rules") or []
        if len(mutated_rules) != len(rules):
            continue
        for space, rule in zip(spaces, mutated_rules, strict=True):
            merge_rule(space, rule)
    return spaces


# ---------------------------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------------------------


def _number(text: str) -> float | int:
    value = float(text)
    return int(value) if value.is_integer() else value


def _around(operand: str) -> list[Any]:
    """`n - 1`, `n` and `n + 1` in the operand's own unit; the operand itself otherwise."""

    found = _NUMBER.match(operand.strip())
    if not found:
        return [operand.strip()]
    number, unit = _number(found.group("number")), found.group("unit")
    steps = [number - 1, number, number + 1]
    if unit:
        return [f"{step}{unit}" for step in steps]
    return steps


def _changed_last_literal(text: str, literal_positions: list[int]) -> str | None:
    if not literal_positions:
        return None
    at = literal_positions[-1]
    replacement = "x" if text[at] != "x" else "y"
    return text[:at] + replacement + text[at + 1 :]


def _wildcard_candidates(token: str) -> list[str]:
    empty = []
    positions = []
    for character in token:
        if character == "*":
            continue
        if character == "?":
            empty.append("a")
            continue
        positions.append(len(empty))
        empty.append(character)
    first = "".join(empty)
    found = [first, token.replace("*", "tw").replace("?", "a")]
    near = _changed_last_literal(first, positions)
    if near is not None:
        found.append(near)
    return found


def pattern_candidates(value: Any) -> list[Any]:
    """The values the protocol tries for one pattern value."""

    if isinstance(value, bool):
        return [True, False]
    if isinstance(value, (int, float)):
        return [value - 1, value, value + 1]
    if value is None:
        return [None]
    text = str(value).strip()
    if text.lower() in ("true", "false"):
        return [True, False]
    found: list[Any] = []
    for token in re.split(r"\s*[|&]\s*", text):
        token = token.strip()
        if token.startswith("!"):
            token = token[1:].strip()
        if not token:
            continue
        comparison = _COMPARISON.match(token)
        bounds = _RANGE.match(token)
        if comparison:
            found.extend(_around(comparison.group("operand")))
        elif bounds:
            found.extend(_around(bounds.group("low")) + _around(bounds.group("high")))
        elif "*" in token or "?" in token:
            found.extend(_wildcard_candidates(token))
        elif _NUMBER.match(token):
            found.extend(_around(token))
        else:
            found.extend([token, token + "x"])
    return found


def condition_candidates(value: Any) -> list[Any]:
    """Every literal a condition names, with `x` appended, and `n - 1`, `n + 1` for a number."""

    if isinstance(value, bool):
        return [True, False]
    if isinstance(value, (int, float)):
        return [value - 1, value, value + 1]
    if value is None:
        return [None]
    text = str(value)
    if _NUMBER.match(text.strip()):
        return [text, *_around(text)]
    return [text, text + "x"]


def _unique(values: Sequence[Any]) -> list[Any]:
    seen: set[str] = set()
    kept = []
    for value in values:
        key = "ABSENT" if value is ABSENT else json.dumps(value, sort_keys=True)
        if key not in seen:
            seen.add(key)
            kept.append(value)
    return kept


def leaf_candidates(node: Node) -> list[Any]:
    found: list[Any] = []
    for value in node.scalars:
        found.extend(pattern_candidates(value))
    for value in node.condition_values:
        found.extend(condition_candidates(value))
    for listed in node.scalar_lists:
        found.extend([list(listed), [], [FRESH], [*listed, FRESH]])
        found.extend([[item] for item in listed])
    found.extend(["", FRESH])
    return found


def options(node: Node) -> list[Any]:
    """Every value the subtree takes in some cell, `ABSENT` included unless it is required."""

    found: list[Any] = [] if node.required else [ABSENT]
    if node.children:
        names = sorted(node.children)
        choices = [options(node.children[name]) for name in names]
        for combination in itertools.product(*choices):
            found.append({n: v for n, v in zip(names, combination, strict=True) if v is not ABSENT})
    if node.element is not None:
        found.append([])
        found.extend([value] for value in options(node.element) if value is not ABSENT)
    if node.scalars or node.condition_values or node.scalar_lists:
        found.extend(leaf_candidates(node))
    return _unique(found)


def option_bound(node: Node) -> int:
    """An upper bound on `len(options(node))`, computed without enumerating."""

    total = 1
    if node.children:
        total += math.prod(option_bound(child) for child in node.children.values())
    if node.element is not None:
        total += 1 + option_bound(node.element)
    if node.scalars or node.condition_values or node.scalar_lists:
        total += len(leaf_candidates(node))
    return total


# ---------------------------------------------------------------------------------------------
# Cells and resources
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Cell:
    rule: int
    index: int
    operation: str | None
    resource: dict[str, Any]


def kind_identity(kind: str, suite_resources: Sequence[dict[str, Any]]) -> tuple[str, str, bool]:
    """(apiVersion, Kind, namespaced) for a kind as a policy's `match` writes it."""

    parts = kind.split("/")
    name = parts[-1]
    for resource in suite_resources:
        if resource.get("kind") == name and resource.get("apiVersion"):
            namespaced = bool((resource.get("metadata") or {}).get("namespace"))
            core = CORE_API_VERSIONS.get(name)
            if core is not None and not core[1]:
                namespaced = False
            return str(resource["apiVersion"]), name, namespaced
    if len(parts) == 3 and "*" not in parts[1]:
        return f"{parts[0]}/{parts[1]}", name, True
    if name in CORE_API_VERSIONS:
        version, namespaced = CORE_API_VERSIONS[name]
        return version, name, namespaced
    raise Unsupported("a kind with neither a suite resource nor a core API version")


def build_resource(
    value: dict[str, Any], identity: tuple[str, str, bool], name: str
) -> dict[str, Any] | None:
    """The resource a root option describes, or None when the option cannot be one."""

    resource = copy.deepcopy(value)
    metadata = resource.get("metadata", {})
    if not isinstance(metadata, dict):
        return None
    api_version, kind, namespaced = identity
    resource["apiVersion"] = api_version
    resource["kind"] = kind
    if metadata.get("name") in (None, "") or not isinstance(metadata.get("name"), str):
        metadata["name"] = name
    if namespaced and "namespace" not in metadata:
        metadata["namespace"] = "default"
    resource["metadata"] = metadata
    return resource


def cell_bound(spaces: Sequence[RuleSpace]) -> int:
    operations = len(OPERATIONS) if any(space.reads_operation for space in spaces) else 1
    return sum(option_bound(space.root) for space in spaces) * operations


def cells(
    spaces: Sequence[RuleSpace], suite_resources: Sequence[dict[str, Any]], cap: int
) -> list[Cell]:
    """The policy's cells in construction order: rule, then option, then operation."""

    if cell_bound(spaces) > cap * 50:
        raise Unsupported("over the cell cap")
    operations = OPERATIONS if any(space.reads_operation for space in spaces) else (None,)
    built: list[Cell] = []
    for rule_index, space in enumerate(spaces):
        identity = kind_identity(space.kind, suite_resources)
        root_options = [option for option in options(space.root) if isinstance(option, dict)]
        # A rule that reads no field still applies to a resource of its kind.
        for option in root_options or [{}]:
            resource = build_resource(option, identity, f"tw-{rule_index}-{len(built)}")
            if resource is None:
                continue
            for operation in operations:
                built.append(Cell(rule_index, len(built), operation, resource))
    if len(built) > cap:
        raise Unsupported("over the cell cap")
    return built


# ---------------------------------------------------------------------------------------------
# Drawn resources for the completeness check
# ---------------------------------------------------------------------------------------------

# A drawn resource keeps its identity: the engine keys every result by kind, namespace and name.
_IDENTITY = {
    ("apiVersion",),
    ("kind",),
    ("metadata",),
    ("metadata", "name"),
    ("metadata", "namespace"),
}
OTHER_TYPES: tuple[Any, ...] = (7, True, False, "tw-other", {}, [], None)


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> Iterator[tuple[tuple[Any, ...], Any]]:
    yield prefix, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _paths(item, (*prefix, key))
    elif isinstance(value, list):
        for position, item in enumerate(value):
            yield from _paths(item, (*prefix, position))


def _get(value: Any, path: tuple[Any, ...]) -> Any:
    for part in path:
        value = value[part]
    return value


def _schematic(path: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple("[]" if isinstance(part, int) else part for part in path)


class Perturber:
    """Draws resources by perturbing a base: a list extended, a value replaced, a field added or
    removed. Replacement values come from other resources at the same position or are of another
    type; identity fields are never touched."""

    def __init__(self, pool: Sequence[dict[str, Any]], rng: random.Random) -> None:
        self.rng = rng
        self.by_shape: dict[tuple[Any, ...], list[Any]] = {}
        sample = list(pool) if len(pool) <= 400 else rng.sample(list(pool), 400)
        for other in sample:
            for path, value in _paths(other):
                if path:
                    self.by_shape.setdefault(_schematic(path), []).append(value)

    def draw(self, resource: dict[str, Any]) -> dict[str, Any]:
        rng = self.rng
        drawn = copy.deepcopy(resource)
        for _ in range(rng.randint(1, 3)):
            located = [
                (path, value)
                for path, value in _paths(drawn)
                if path and _schematic(path) not in _IDENTITY
            ]
            if not located:
                break
            operation = rng.choice(("extend", "replace", "add", "remove"))
            lists = [(p, v) for p, v in located if isinstance(v, list)]
            if operation == "extend" and lists:
                path, value = rng.choice(lists)
                elements = [
                    element
                    for found in self.by_shape.get(_schematic(path), [])
                    if isinstance(found, list)
                    for element in found
                ]
                extra = rng.choice(elements) if elements else (value[0] if value else FRESH)
                value.append(copy.deepcopy(extra))
            elif operation == "replace":
                path, _ = rng.choice(located)
                others = self.by_shape.get(_schematic(path), [])[:20]
                replacement = rng.choice([*others, *OTHER_TYPES])
                _get(drawn, path[:-1])[path[-1]] = copy.deepcopy(replacement)
            elif operation == "add":
                maps = [(p, v) for p, v in located if isinstance(v, dict)] or [((), drawn)]
                _, value = rng.choice(maps)
                value[f"twUnrelated{rng.randint(0, 99)}"] = "tw-unrelated"
            else:
                path, _ = rng.choice(located)
                if len(path) > 1 and rng.random() < 0.3 and _schematic(path[:-1]) not in _IDENTITY:
                    path = path[:-1]
                parent = _get(drawn, path[:-1])
                if isinstance(parent, list):
                    parent.pop(path[-1])
                else:
                    parent.pop(path[-1], None)
        return drawn
