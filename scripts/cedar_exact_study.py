"""The suite-strategy study replicated on real Cedar policies, decided by the Cedar engine.

The first exact study (`exact_evaluation_study.py`) scored suite strategies on generated
policies in this project's own language. This one asks the same questions of Cedar policy
that other people wrote -- the third-party sample of `docs/third-party-sample-cedar-*` --
under `docs/EXACT_EVALUATION_PROTOCOL_CEDAR.md`, whose hash is fixed below.

Every decision is the Cedar engine's, through the `cedarpy` bindings. The script builds a
witness space per file -- one candidate set per observable: the identities, types and named
ancestors of the principal, action and resource, and every attribute chain the policies read
-- and its cells are the product. The quotient classes are the cells grouped by what the
engine says each atom of the file is at that cell; no model of Cedar written here decides
anything. A file's witness space is exact only if no request separates a mutant from its
policy that no cell separates, and the script checks that adversarially for every file
before it is scored.

`cedarpy` is not a dependency of the package or of its test extra; install it to run this
(`pip install cedarpy==4.12.1`), and the tests that need it skip without it.

Usage:
    python scripts/cedar_exact_study.py study --cache DIR \\
        --json docs/cedar-suite-strategy-study-v1.json
    python scripts/cedar_exact_study.py edits --cache DIR --history HISTORY.json \\
        --json docs/cedar-real-edits-v1.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import hashlib
import importlib.util
import itertools
import json
import random
import statistics
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "EXACT_EVALUATION_PROTOCOL_CEDAR.md"
# Fixed when the protocol was written, before the study ran on its population.
PROTOCOL_SHA256 = "0103fa4a038da6c1606caf82b46ef739f5eef014a9632f51dcc2f781f4cbbbcc"
ENGINE = "cedarpy 4.12.1"
SEED = 20261003
MAX_CELLS = 20_000
FUZZ_REQUESTS = 200
ABSENT = ("absent",)
PRESENT = ("present",)
OUTSIDER = "tw-outsider"
FRESH_TYPE = "TwOutsiderType"
ROLES = ("principal", "action", "resource")
VARIABLES = (*ROLES, "context")
PERMISSIVENESS = {"Deny": 0, "Allow": 1}


def _load(name: str) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def _cedar() -> tuple[Any, Any]:
    import cedarpy
    import cedarpy._internal as internal

    return cedarpy, internal


def require_protocol() -> None:
    found = hashlib.sha256(PROTOCOL.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if found != PROTOCOL_SHA256:
        raise SystemExit(
            f"{PROTOCOL.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the "
            "study ran; a changed protocol is a different study, so this one refuses to run"
        )


# ---------------------------------------------------------------------------------------
# Eligibility
# ---------------------------------------------------------------------------------------


def is_path(expression: dict[str, Any]) -> bool:
    """A request variable, or an attribute chain off one."""

    if "Var" in expression:
        return expression["Var"] in VARIABLES
    if "." in expression:
        return is_path(expression["."]["left"])
    return False


def path_of(expression: dict[str, Any]) -> tuple[str, ...]:
    if "Var" in expression:
        return (expression["Var"],)
    return (*path_of(expression["."]["left"]), expression["."]["attr"])


def is_literal(expression: dict[str, Any]) -> bool:
    if "Value" in expression:
        return True
    if "Set" in expression:
        return all(is_literal(item) for item in expression["Set"])
    return False


def is_entity(expression: dict[str, Any]) -> bool:
    return (
        "Value" in expression
        and isinstance(expression["Value"], dict)
        and "__entity" in expression["Value"]
    )


def _integer(expression: dict[str, Any]) -> bool:
    value = expression.get("Value")
    return isinstance(value, int) and not isinstance(value, bool)


def why_not(expression: Any) -> str | None:
    """None if the condition is a boolean combination of eligible atoms, else the reason."""

    if not isinstance(expression, dict) or len(expression) != 1:
        return "a malformed expression"
    ((operator, body),) = expression.items()
    if operator in ("&&", "||"):
        return why_not(body["left"]) or why_not(body["right"])
    if operator == "!":
        return why_not(body["arg"])
    if operator == "Value":
        return None if isinstance(body, bool) else "a non-boolean literal as a condition"
    if operator in ("Var", "."):
        return None if is_path(expression) else "an attribute of something other than the request"
    if operator in ("==", "!="):
        left, right = body["left"], body["right"]
        if (is_path(left) and is_literal(right)) or (is_literal(left) and is_path(right)):
            return None
        return "compares two non-literal terms"
    if operator in ("<", "<=", ">", ">="):
        left, right = body["left"], body["right"]
        if (is_path(left) and _integer(right)) or (_integer(left) and is_path(right)):
            return None
        return "orders two non-literal terms"
    if operator == "has":
        return None if is_path(body["left"]) else "has on something other than the request"
    if operator == "in":
        left, right = body["left"], body["right"]
        targets_named = is_entity(right) or (
            "Set" in right and all(is_entity(item) for item in right["Set"])
        )
        if "Var" in left and left["Var"] in ROLES and targets_named:
            return None
        return "in over something other than a request entity and named entities"
    if operator == "is":
        left = body["left"]
        if "Var" in left and left["Var"] in ROLES and ("in" not in body or is_entity(body["in"])):
            return None
        return "is over something other than a request entity"
    if operator in ("contains", "containsAll", "containsAny"):
        left, right = body["left"], body["right"]
        if is_path(left) and is_literal(right):
            return None
        return f"{operator} with a non-literal argument"
    return f"uses {operator}"


def eligibility(est: dict[str, Any]) -> list[str]:
    """Every reason a policy set is not exact-eligible; empty when it is."""

    reasons: list[str] = []
    if est.get("templates"):
        reasons.append("holds a template")
    for policy in est.get("staticPolicies", {}).values():
        for role in ROLES:
            if "slot" in policy[role]:
                reasons.append("a slot in scope")
        for condition in policy.get("conditions", []):
            reason = why_not(condition["body"])
            if reason:
                reasons.append(reason)
    return sorted(set(reasons))


# ---------------------------------------------------------------------------------------
# Observables and candidates
# ---------------------------------------------------------------------------------------


def _uid(value: dict[str, Any]) -> tuple[str, str]:
    entity = value["__entity"]
    return (entity["type"], entity["id"])


class Observables:
    """What a policy set can observe of a request, collected from its Cedar JSON form."""

    def __init__(self) -> None:
        self.named: dict[str, set[tuple[str, str]]] = {role: set() for role in ROLES}
        self.ancestors: dict[str, set[tuple[str, str]]] = {role: set() for role in ROLES}
        self.types: dict[str, set[str]] = {role: set() for role in ROLES}
        self.equals: dict[tuple[str, ...], list[Any]] = defaultdict(list)
        self.thresholds: dict[tuple[str, ...], set[int]] = defaultdict(set)
        self.members: dict[tuple[str, ...], list[Any]] = defaultdict(list)
        self.booleans: set[tuple[str, ...]] = set()
        self.chains: set[tuple[str, ...]] = set()

    def chain(self, path: tuple[str, ...]) -> None:
        for end in range(2, len(path) + 1):
            self.chains.add(path[:end])

    def literal(self, path: tuple[str, ...], value: Any) -> None:
        if len(path) == 1 and path[0] in ROLES:
            if isinstance(value, dict) and "__entity" in value:
                self.named[path[0]].add(_uid(value))
                self.types[path[0]].add(_uid(value)[0])
            return
        self.chain(path)
        if isinstance(value, dict) and "__entity" in value:
            self.equals[path].append(value)
        elif isinstance(value, list):
            self.members[path].extend(value)
        else:
            self.equals[path].append(value)

    def scope(self, role: str, constraint: dict[str, Any]) -> None:
        operator = constraint["op"]
        if operator == "==":
            self.named[role].add(_uid({"__entity": constraint["entity"]}))
            self.types[role].add(constraint["entity"]["type"])
        elif operator == "in":
            targets = constraint.get("entities") or [constraint["entity"]]
            for target in targets:
                uid = (target["type"], target["id"])
                self.named[role].add(uid)
                self.ancestors[role].add(uid)
                self.types[role].add(uid[0])
        elif operator == "is":
            self.types[role].add(constraint["entity_type"])
            if "in" in constraint:
                uid = (constraint["in"]["entity"]["type"], constraint["in"]["entity"]["id"])
                self.named[role].add(uid)
                self.ancestors[role].add(uid)

    def condition(self, expression: dict[str, Any]) -> None:
        ((operator, body),) = expression.items()
        if operator in ("&&", "||"):
            self.condition(body["left"])
            self.condition(body["right"])
        elif operator == "!":
            self.condition(body["arg"])
        elif operator in ("Var", "."):
            path = path_of(expression)
            self.chain(path)
            self.booleans.add(path)
        elif operator in ("==", "!="):
            left, right = body["left"], body["right"]
            path, literal = (left, right) if is_path(left) else (right, left)
            value = literal["Value"] if "Value" in literal else [x["Value"] for x in literal["Set"]]
            self.literal(path_of(path), value)
        elif operator in ("<", "<=", ">", ">="):
            left, right = body["left"], body["right"]
            path, literal = (left, right) if is_path(left) else (right, left)
            self.chain(path_of(path))
            self.thresholds[path_of(path)].add(literal["Value"])
        elif operator == "has":
            self.chain((*path_of(body["left"]), body["attr"]))
        elif operator == "in":
            role = body["left"]["Var"]
            right = body["right"]
            targets = [right] if "Value" in right else right["Set"]
            for target in targets:
                uid = _uid(target["Value"])
                self.named[role].add(uid)
                self.ancestors[role].add(uid)
                self.types[role].add(uid[0])
        elif operator == "is":
            role = body["left"]["Var"]
            self.types[role].add(body["entity_type"])
            if "in" in body:
                uid = _uid(body["in"]["Value"])
                self.named[role].add(uid)
                self.ancestors[role].add(uid)
        elif operator in ("contains", "containsAll", "containsAny"):
            path = path_of(body["left"])
            right = body["right"]
            values = [right["Value"]] if "Value" in right else [x["Value"] for x in right["Set"]]
            self.chain(path)
            self.members[path].extend(values)


def observables_of(*estimates: dict[str, Any]) -> Observables:
    found = Observables()
    for est in estimates:
        for policy in est.get("staticPolicies", {}).values():
            for role in ROLES:
                found.scope(role, policy[role])
            for condition in policy.get("conditions", []):
                found.condition(condition["body"])
    return found


def _key(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def _unique(values: list[Any]) -> list[Any]:
    seen: dict[str, Any] = {}
    for value in values:
        seen.setdefault(_key(value), value)
    return list(seen.values())


def chain_candidates(found: Observables, path: tuple[str, ...]) -> list[Any]:
    """The values one attribute chain ranges over in the witness space."""

    if _is_prefix(found, path):
        # A prefix of a longer chain: absent, or a record its children fill.
        return [ABSENT, PRESENT]
    values = _scalar_candidates(found, path)
    members = _unique(found.members.get(path, []))
    if members:
        for size in range(len(members) + 1):
            for subset in itertools.combinations(members, size):
                values.append(list(subset))
    if len(values) == 1:
        values.append(OUTSIDER)
    return _unique(values)


def _is_prefix(found: Observables, path: tuple[str, ...]) -> bool:
    return any(other[: len(path)] == path and len(other) > len(path) for other in found.chains)


def chain_candidate_count(found: Observables, path: tuple[str, ...]) -> int:
    """How many candidates `chain_candidates` returns, without building them.

    A chain tested against many literals of a set has a power set of candidates, and building
    it to learn that the witness space is over the cap is how a file exhausts memory.
    """

    if _is_prefix(found, path):
        return 2
    members = len(_unique(found.members.get(path, [])))
    total = len(_unique(_scalar_candidates(found, path))) + (2**members if members else 0)
    return total if total > 1 else 2


def _scalar_candidates(found: Observables, path: tuple[str, ...]) -> list[Any]:
    values: list[Any] = [ABSENT]
    literals = found.equals.get(path, [])
    values.extend(literals)
    kinds = {type(v).__name__ if not isinstance(v, dict) else "entity" for v in literals}
    if "str" in kinds:
        values.append(OUTSIDER)
    if "int" in kinds:
        values.append(
            max(v for v in literals if isinstance(v, int) and not isinstance(v, bool)) + 1
        )
    if "bool" in kinds or path in found.booleans:
        values.extend([True, False])
    if "entity" in kinds:
        for entity_type in sorted({v["__entity"]["type"] for v in literals if isinstance(v, dict)}):
            values.append({"__entity": {"type": entity_type, "id": OUTSIDER}})
    for threshold in found.thresholds.get(path, ()):
        values.extend([threshold - 1, threshold, threshold + 1])
    return _unique(values)


def identity_candidates(found: Observables, role: str) -> list[tuple[str, str]]:
    # A fresh identity is fresh for its role: a principal and a resource that shared one would
    # be the same entity, and a request whose principal is its resource is a different subject.
    fresh = f"{OUTSIDER}-{role}"
    if role == "action":
        named = sorted(found.named["action"])
        return [*named, ("Action", fresh)]
    named = sorted(found.named[role])
    types = sorted(found.types[role] | {uid[0] for uid in named})
    return [*named, *((entity_type, fresh) for entity_type in types), (FRESH_TYPE, fresh)]


def ancestor_candidates(found: Observables, role: str) -> list[tuple[tuple[str, str], ...]]:
    named = sorted(found.ancestors[role])
    return [
        subset for size in range(len(named) + 1) for subset in itertools.combinations(named, size)
    ]


class WitnessSpace:
    """The product of every observable's candidates, and the requests it stands for."""

    def __init__(self, found: Observables, cap: int | None = None) -> None:
        self.found = found
        self.chains = sorted(found.chains)
        # Sized before it is built: an axis with a power set of candidates is counted, and the
        # candidates are only materialised when the whole product fits under the cap.
        total = 1
        for role in ROLES:
            total *= len(identity_candidates(found, role)) * 2 ** len(found.ancestors[role])
        for path in self.chains:
            total *= chain_candidate_count(found, path)
        self.total = total
        self.axes: list[tuple[str, list[Any]]] = []
        if cap is not None and total > cap:
            return
        for role in ROLES:
            self.axes.append((f"{role}.identity", identity_candidates(found, role)))
            self.axes.append((f"{role}.ancestors", ancestor_candidates(found, role)))
        for path in self.chains:
            self.axes.append((".".join(path), chain_candidates(found, path)))

    def size(self) -> int:
        return self.total

    def cells(self) -> Iterator[tuple[Any, ...]]:
        if self.total and not self.axes:
            raise RuntimeError("the witness space is over its cap and was not built")
        return itertools.product(*(candidates for _, candidates in self.axes))


def _set_path(record: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    for name in path[:-1]:
        record = record.setdefault(name, {})
        if not isinstance(record, dict):
            return
    if value is PRESENT:
        record.setdefault(path[-1], {})
    elif value is not ABSENT:
        record[path[-1]] = value


def _entity_ref(uid: tuple[str, str]) -> dict[str, Any]:
    return {"__entity": {"type": uid[0], "id": uid[1]}}


def _request_uid(uid: tuple[str, str]) -> str:
    return f"{uid[0]}::{json.dumps(uid[1])}"


def _acyclic(entities: dict[str, dict[str, Any]]) -> bool:
    """Whether an entity store's parent relation has no cycle, which Cedar requires."""

    parents = {
        uid: [json.dumps(parent, sort_keys=True) for parent in entity.get("parents", [])]
        for uid, entity in entities.items()
    }
    state: dict[str, int] = {}

    def visit(uid: str) -> bool:
        if state.get(uid) == 1:
            return False
        if state.get(uid) == 2:
            return True
        state[uid] = 1
        if not all(visit(parent) for parent in parents.get(uid, [])):
            return False
        state[uid] = 2
        return True

    return all(visit(uid) for uid in parents)


def request_of(
    space: WitnessSpace, cell: tuple[Any, ...], suffix: str = ""
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """A Cedar request and entity store realising one cell, or None if none can.

    `suffix` makes a fresh identity fresh per request. It still equals no literal, so it
    stands for the same class of subject, and requests built with distinct suffixes can share
    one entity store because their fresh entities never collide.
    """

    choice = dict(zip((name for name, _ in space.axes), cell, strict=True))
    identities = {
        role: ((uid[0], f"{uid[1]}-{suffix}") if suffix and uid[1].startswith(OUTSIDER) else uid)
        for role in ROLES
        for uid in [choice[f"{role}.identity"]]
    }
    if (
        len(set(identities.values())) < len(ROLES)
        and identities["principal"] == identities["resource"]
    ):
        return None
    attributes: dict[str, dict[str, Any]] = {variable: {} for variable in VARIABLES}
    # An absent record has no fields: a chain under an absent prefix is not set, or setting it
    # would bring the prefix back and the absent cell would never be realised.
    absent = {path for path in space.chains if choice[".".join(path)] is ABSENT}
    for path in space.chains:
        if any(path[:end] in absent for end in range(2, len(path))):
            continue
        _set_path(attributes[path[0]], path[1:], choice[".".join(path)])
    entities: dict[tuple[str, str], dict[str, Any]] = {}
    for role in ROLES:
        uid = identities[role]
        # The hierarchy must be acyclic, so an entity is never its own parent; being one of the
        # named ancestors already makes `in` hold of it, since `in` is reflexive.
        entities[uid] = {
            "uid": _entity_ref(uid),
            "attrs": attributes[role],
            "parents": [
                _entity_ref(parent) for parent in choice[f"{role}.ancestors"] if parent != uid
            ],
        }
    for role in ROLES:
        for parent in space.found.ancestors[role]:
            entities.setdefault(parent, {"uid": _entity_ref(parent), "attrs": {}, "parents": []})
    request = {
        "principal": _request_uid(identities["principal"]),
        "action": _request_uid(identities["action"]),
        "resource": _request_uid(identities["resource"]),
        "context": attributes["context"],
    }
    # A cell whose named entities would form a cycle of ancestry -- a principal in a group the
    # resource is, while the resource is in the principal -- is no request: Cedar refuses a
    # cyclic hierarchy, so no subject realises it.
    if not _acyclic({json.dumps(e["uid"], sort_keys=True): e for e in entities.values()}):
        return None
    return request, list(entities.values())


# ---------------------------------------------------------------------------------------
# Deciding, atoms and mutants
# ---------------------------------------------------------------------------------------


def decide(text: str, request: dict[str, Any], entities: list[dict[str, Any]]) -> tuple[str, bool]:
    """The engine's decision, and whether any policy errored on the way to it."""

    cedarpy, _ = _cedar()
    result = cedarpy.is_authorized(request, text, entities)
    decision = str(result.decision).rsplit(".", 1)[-1]
    if decision not in PERMISSIVENESS:
        # The engine could not read the request or its entities: a malformed witness, which
        # would be scored as a decision if it were let through.
        raise RuntimeError(
            f"{decision}: {[str(error)[:200] for error in result.diagnostics.errors]}"
        )
    return decision, bool(result.diagnostics.errors)


Batch = tuple[list[int], list[dict[str, Any]], Any]


def batches_of(made: list[tuple[dict[str, Any], list[dict[str, Any]]]]) -> list[Batch]:
    """The requests grouped so each group shares one consistent entity store.

    Two requests can share a store unless they give one entity two different sets of
    attributes or parents, which only happens to an entity the policies name. The store of
    each group is parsed once and reused for every policy set evaluated against it.
    """

    cedarpy, _ = _cedar()
    groups: list[dict[str, Any]] = []
    for index, (request, entities) in enumerate(made):
        keyed = {
            json.dumps(entity["uid"], sort_keys=True): (json.dumps(entity, sort_keys=True), entity)
            for entity in entities
        }
        for group in groups:
            if all(
                group["assigned"].get(uid, text) == text for uid, (text, _) in keyed.items()
            ) and _acyclic({**group["entities"], **{uid: e for uid, (_, e) in keyed.items()}}):
                # Consistent with the group, and merging it closes no cycle.
                break
        else:
            group = {"assigned": {}, "entities": {}, "indices": [], "requests": []}
            groups.append(group)
        for uid, (text, entity) in keyed.items():
            group["assigned"][uid] = text
            group["entities"][uid] = entity
        group["indices"].append(index)
        group["requests"].append(request)
    return [
        (
            group["indices"],
            group["requests"],
            cedarpy.Entities.from_json_str(json.dumps(list(group["entities"].values()))),
        )
        for group in groups
    ]


def evaluate(policies: Any, batches: list[Batch], count: int) -> list[tuple[str, bool]]:
    """The engine's decision on every request, and whether any policy errored, in order."""

    cedarpy, _ = _cedar()
    decided: list[tuple[str, bool]] = [("", False)] * count
    for indices, requests, entities in batches:
        for index, result in zip(
            indices, cedarpy.is_authorized_batch(requests, policies, entities), strict=True
        ):
            decision = str(result.decision).rsplit(".", 1)[-1]
            if decision not in PERMISSIVENESS:
                raise RuntimeError(
                    f"{decision}: {[str(error)[:200] for error in result.diagnostics.errors]}"
                )
            decided[index] = (decision, bool(result.diagnostics.errors))
    return decided


def parsed(text: str) -> Any:
    cedarpy, _ = _cedar()
    return cedarpy.PolicySet.from_str(text)


def _policy_text(est: dict[str, Any]) -> str:
    _, internal = _cedar()
    return str(internal.policies_from_json_str(json.dumps(est)))


def atoms_of(est: dict[str, Any]) -> list[str]:
    """Each atom of the set as its own one-line policy, so the engine can be asked about it."""

    texts: list[str] = []

    def single(scope: dict[str, Any] | None, body: dict[str, Any] | None) -> str:
        policy = {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [] if body is None else [{"kind": "when", "body": body}],
        }
        if scope is not None:
            policy[scope["role"]] = scope["constraint"]
        return _policy_text(
            {"staticPolicies": {"atom": policy}, "templates": {}, "templateLinks": []}
        )

    def leaves(expression: dict[str, Any]) -> Iterator[dict[str, Any]]:
        ((operator, body),) = expression.items()
        if operator in ("&&", "||"):
            yield from leaves(body["left"])
            yield from leaves(body["right"])
        elif operator == "!":
            yield from leaves(body["arg"])
        elif operator != "Value":
            yield expression

    for policy in est.get("staticPolicies", {}).values():
        for role in ROLES:
            if policy[role]["op"] != "All":
                texts.append(single({"role": role, "constraint": policy[role]}, None))
        for condition in policy.get("conditions", []):
            for leaf in leaves(condition["body"]):
                texts.append(single(None, leaf))
    return sorted(set(texts))


def _expressions(
    node: Any, path: tuple[Any, ...] = ()
) -> Iterator[tuple[tuple[Any, ...], dict[str, Any]]]:
    if isinstance(node, dict) and len(node) == 1:
        yield path, node
        ((operator, body),) = node.items()
        if operator in ("&&", "||", "==", "!=", "<", "<=", ">", ">="):
            yield from _expressions(body["left"], (*path, operator, "left"))
            yield from _expressions(body["right"], (*path, operator, "right"))
        elif operator == "!":
            yield from _expressions(body["arg"], (*path, operator, "arg"))


def _replace(root: dict[str, Any], path: tuple[Any, ...], new: dict[str, Any]) -> dict[str, Any]:
    if not path:
        return new
    copied = copy.deepcopy(root)
    node = copied
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = new
    return copied


STRICTNESS = {"<": "<=", "<=": "<", ">": ">=", ">=": ">"}


def mutants_of(est: dict[str, Any], found: Observables) -> Iterator[tuple[str, dict[str, Any]]]:
    """The protocol's operators, as edited Cedar JSON, one at a time.

    A generator, because a policy set of dozens of policies has thousands of mutants and
    holding every edited copy at once does not fit in memory.
    """

    policies = est.get("staticPolicies", {})

    def with_policy(
        name: str, changed: dict[str, Any] | None, label: str
    ) -> tuple[str, dict[str, Any]]:
        edited = dict(est)
        edited["staticPolicies"] = dict(est["staticPolicies"])
        if changed is None:
            del edited["staticPolicies"][name]
        else:
            edited["staticPolicies"][name] = changed
        return f"{label}[{name}]", edited

    for name, policy in policies.items():
        flipped = copy.deepcopy(policy)
        flipped["effect"] = "forbid" if policy["effect"] == "permit" else "permit"
        yield with_policy(name, flipped, "flip_effect")
        yield with_policy(name, None, "delete_policy")
        for role in ROLES:
            if policy[role]["op"] != "All":
                widened = copy.deepcopy(policy)
                widened[role] = {"op": "All"}
                yield with_policy(name, widened, f"widen_{role}")
        for index, condition in enumerate(policy.get("conditions", [])):
            dropped = copy.deepcopy(policy)
            del dropped["conditions"][index]
            yield with_policy(name, dropped, f"drop_condition{index}")
            negated = copy.deepcopy(policy)
            negated["conditions"][index]["kind"] = (
                "unless" if condition["kind"] == "when" else "when"
            )
            yield with_policy(name, negated, f"negate_condition{index}")
            for place, node in _expressions(condition["body"]):
                ((operator, body),) = node.items()
                replacements: list[tuple[str, dict[str, Any]]] = []
                if operator in ("&&", "||"):
                    replacements += [
                        (f"keep_left_of_{operator}", body["left"]),
                        (f"keep_right_of_{operator}", body["right"]),
                    ]
                if operator in ("==", "!="):
                    swapped = "!=" if operator == "==" else "=="
                    replacements.append((f"{operator}_to_{swapped}", {swapped: body}))
                if operator in STRICTNESS:
                    replacements.append(
                        (f"{operator}_to_{STRICTNESS[operator]}", {STRICTNESS[operator]: body})
                    )
                if operator in ("==", "!=", "<", "<=", ">", ">="):
                    left, right = body["left"], body["right"]
                    side = "right" if is_path(left) else "left"
                    term, literal = (left, right) if side == "right" else (right, left)
                    if "Value" in literal and is_path(term):
                        vocabulary = found.equals.get(path_of(term), []) + sorted(
                            found.thresholds.get(path_of(term), ())
                        )
                        for other in _unique(vocabulary):
                            if _key(other) != _key(literal["Value"]) and type(other) is type(
                                literal["Value"]
                            ):
                                changed_body = dict(body)
                                changed_body[side] = {"Value": other}
                                replacements.append(
                                    (f"literal_to_{_key(other)[:24]}", {operator: changed_body})
                                )
                for label, replacement in replacements:
                    mutated = copy.deepcopy(policy)
                    mutated["conditions"][index]["body"] = _replace(
                        condition["body"], place, replacement
                    )
                    yield with_policy(name, mutated, f"{label}@c{index}{'/'.join(map(str, place))}")


# ---------------------------------------------------------------------------------------
# One file, exactly
# ---------------------------------------------------------------------------------------


def _perturb(value: Any, generator: random.Random) -> Any:
    if value is ABSENT:
        return generator.choice([OUTSIDER, generator.randint(-5, 50), True, ["x"]])
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + generator.choice([-2, 2, 7])
    if isinstance(value, str):
        return f"{value}-{generator.randint(0, 999)}"
    if isinstance(value, list):
        return [*value, f"fresh-{generator.randint(0, 99)}"]
    if isinstance(value, dict) and "__entity" in value:
        return {
            "__entity": {
                "type": value["__entity"]["type"],
                "id": f"fresh-{generator.randint(0, 99)}",
            }
        }
    return ABSENT


def fuzz_requests(
    space: WitnessSpace, generator: random.Random, count: int
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """Requests drawn from the candidates and perturbed off them, to visit their boundaries."""

    drawn: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    attempts = 0
    while len(drawn) < count and attempts < count * 20:
        attempts += 1
        cell = []
        for name, candidates in space.axes:
            value = generator.choice(candidates)
            # Cedar requires an action, and every ancestor of an action, to be an action entity,
            # so the action's perturbations keep its type; the others may take a fresh type.
            is_action = name.startswith("action.")
            if name.endswith(".identity") and generator.random() < 0.2:
                entity_type = (
                    value[0]
                    if is_action or generator.random() < 0.7
                    else f"Fresh{generator.randint(0, 9)}"
                )
                value = (entity_type, f"fresh-{generator.randint(0, 999)}")
            elif name.endswith(".ancestors") and generator.random() < 0.2:
                group = "Action" if is_action else "FreshGroup"
                value = (*value, (group, f"fresh-group-{generator.randint(0, 9)}"))
            elif not name.endswith((".identity", ".ancestors")) and generator.random() < 0.3:
                value = _perturb(value, generator) if value is not PRESENT else value
            cell.append(value)
        made = request_of(space, tuple(cell), f"fuzz{attempts}")
        if made is not None:
            request, entities = made
            if generator.random() < 0.3:
                request["context"] = {**request["context"], f"noise{generator.randint(0, 9)}": 1}
            drawn.append((request, entities))
    return drawn


def _signatures(atoms: list[Any], batches: list[Batch], count: int) -> list[tuple[str, ...]]:
    """Each request's atom valuation -- true, false or error -- as the engine gives it."""

    columns = [evaluate(atom, batches, count) for atom in atoms]
    return (
        [
            tuple("error" if errored else decision for decision, errored in row)
            for row in zip(*columns, strict=True)
        ]
        if columns
        else [()] * count
    )


def analyse_file(est: dict[str, Any], *, generator: random.Random) -> dict[str, Any]:
    """Cells, classes, every mutant's difference set, and the completeness verdict."""

    cedarpy, _ = _cedar()
    ees = _load("exact_evaluation_study")
    found = observables_of(est)
    space = WitnessSpace(found, cap=MAX_CELLS)
    if space.size() > MAX_CELLS:
        return {"status": "over the cell cap", "cells": space.size()}
    original = cedarpy.PolicySet.from_json_str(json.dumps(est))
    made = [
        request
        for index, cell in enumerate(space.cells())
        if (request := request_of(space, cell, str(index))) is not None
    ]
    batches = batches_of(made)
    reference = [decision for decision, _ in evaluate(original, batches, len(made))]

    atoms = [parsed(text) for text in atoms_of(est)]
    signatures: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for position, signature in enumerate(_signatures(atoms, batches, len(made))):
        signatures[signature].append(position)
    by_decision: dict[str, list[int]] = defaultdict(list)
    for position, decision in enumerate(reference):
        by_decision[decision].append(position)
    classes, decisions = list(signatures.values()), list(by_decision.values())

    fuzz = fuzz_requests(space, generator, FUZZ_REQUESTS)
    fuzz_batches = batches_of(fuzz)
    fuzz_reference = [d for d, _ in evaluate(original, fuzz_batches, len(fuzz))]
    # A drawn request whose atoms take a combination no cell takes is a quotient class the
    # witness space lacks. That corrupts the quotient strategy even when no mutant is misjudged,
    # which is why this is checked beside the mutants (a deviation the artifact records).
    missing_classes = sum(
        1
        for signature in _signatures(atoms, fuzz_batches, len(fuzz))
        if signature not in signatures
    )

    records: list[dict[str, Any]] = []
    missing: list[str] = []
    for name, mutated in mutants_of(est, found):
        try:
            mutant = cedarpy.PolicySet.from_json_str(json.dumps(mutated))
        except Exception:  # noqa: BLE001 - an edit Cedar cannot read is not a policy
            records.append({"mutant": name, "status": "unrunnable"})
            continue
        resolved = [decision for decision, _ in evaluate(mutant, batches, len(made))]
        changed = {p for p, d in enumerate(resolved) if d != reference[p]}
        if not changed:
            drawn = [d for d, _ in evaluate(mutant, fuzz_batches, len(fuzz))]
            if drawn != fuzz_reference:
                missing.append(name)
        weakened = {
            p for p in changed if PERMISSIVENESS[resolved[p]] > PERMISSIVENESS[reference[p]]
        }
        record: dict[str, Any] = {
            "mutant": name,
            "status": "live" if changed else "equivalent",
        }
        for target, hits in (("change", changed), ("weakening", weakened)):
            record[f"{target}_detection"] = {
                "refinement": Fraction(1 if hits else 0),
                "quotient": ees._detection(classes, hits),
                "decision": ees._detection(decisions, hits),
                "random_quotient": ees._random_detection(len(made), len(hits), len(classes)),
                "random_decision": ees._random_detection(len(made), len(hits), len(decisions)),
            }
        records.append(record)
    return {
        "status": "missing cells" if missing or missing_classes else "scored",
        "cells": len(made),
        "batches": len(batches),
        "quotient_classes": len(classes),
        "decision_range": len(decisions),
        "atoms": len(atoms),
        "with_condition": any(p.get("conditions") for p in est["staticPolicies"].values()),
        "missing_cells_for": sorted(set(missing)),
        "fuzz_requests_in_no_class": missing_classes,
        "mutants": records,
    }


# ---------------------------------------------------------------------------------------
# The study
# ---------------------------------------------------------------------------------------


def _texts(manifest: dict[str, Any], cache: Path) -> dict[str, bytes | None]:
    measure = _load("measure_third_party_policies")
    texts: dict[str, bytes | None] = {}
    for entry in manifest["files"]:
        subject = f"{entry['repo']}/{entry['path']}"
        stored = cache / hashlib.sha256(subject.encode()).hexdigest()
        if stored.exists() and hashlib.sha256(stored.read_bytes()).hexdigest() == entry["sha256"]:
            texts[subject] = stored.read_bytes()
            continue
        content, _ = measure.fetch_bytes(entry)
        if content is not None and hashlib.sha256(content).hexdigest() == entry["sha256"]:
            stored.parent.mkdir(parents=True, exist_ok=True)
            stored.write_bytes(content)
            texts[subject] = content
        else:
            texts[subject] = None
    return texts


def _score(record: dict[str, Any]) -> dict[str, Fraction] | None:
    live = [m for m in record["mutants"] if m["status"] == "live"]
    if not live:
        return None
    ees = _load("exact_evaluation_study")
    return {
        strategy: sum((m["change_detection"][strategy] for m in live), Fraction(0)) / len(live)
        for strategy in ees.STRATEGIES
    }


def _analyse(task: tuple[str, str, int]) -> tuple[str, dict[str, Any]]:
    subject, est_json, seed = task
    est = json.loads(est_json)
    generator = random.Random(f"{seed}:{subject}")
    return subject, analyse_file(est, generator=generator)


def study(cache: Path, workers: int = 8) -> dict[str, Any]:
    require_protocol()
    _, internal = _cedar()
    ees = _load("exact_evaluation_study")
    manifest = json.loads((DOCS / "third-party-sample-cedar-corpus-v1.json").read_text("utf-8"))
    measured = json.loads((DOCS / "third-party-sample-cedar-membership-v1.json").read_text("utf-8"))
    verdicts = {entry["subject"]: entry["verdict"] for entry in measured["policies"]}
    texts = _texts(manifest, cache)
    population: Counter[str] = Counter()
    ineligible: Counter[str] = Counter()
    tasks: list[tuple[str, str, int]] = []
    for subject, content in sorted(texts.items()):
        if verdicts.get(subject) != "inside":
            continue
        population["judged inside"] += 1
        if content is None:
            population["could not be fetched"] += 1
            continue
        try:
            est = json.loads(internal.policies_to_json_str(content.decode("utf-8")))
        except Exception:  # noqa: BLE001 - the engine's parser is the judge of a policy set
            population["Cedar does not parse it"] += 1
            continue
        reasons = eligibility(est)
        if reasons:
            population["not exact-eligible"] += 1
            ineligible.update(reasons)
            continue
        population["exact-eligible"] += 1
        tasks.append((subject, json.dumps(est), SEED))

    analysed: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ProcessPoolExecutor(workers) as pool:
        for subject, record in pool.map(_analyse, tasks):
            analysed[subject] = record

    findings: dict[str, Any] = {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "engine": ENGINE,
        "seed": SEED,
        "resamples": ees.RESAMPLES,
        "max_cells": MAX_CELLS,
        "fuzz_requests_per_file": FUZZ_REQUESTS,
        "population": dict(sorted(population.items())),
        "ineligible_reasons": dict(sorted(ineligible.items())),
        "deviations": [
            "the completeness check also requires every drawn request's atom valuations to "
            "appear among the cells', which detects a missing quotient class; the protocol's "
            "criterion looked only at mutants misjudged equivalent, and on the development set "
            "a deliberately removed class went undetected by it. Added before the study ran on "
            "its population; it can only exclude files.",
            "a first attempt on the population was stopped before it wrote any result: it built "
            "the power sets of witness spaces far over the cap before checking the cap, and ran "
            "out of memory. The space is now sized before it is built, and requests are "
            "evaluated in batches that share an entity store, which on the development set "
            "gave the same decision and atom value as one-by-one evaluation on every cell.",
            "a second attempt stopped with an engine error before writing any result: a cell "
            "naming a principal in a group the resource is, while the resource is in the "
            "principal, has a cyclic hierarchy, which Cedar refuses. Such a cell is no request "
            "and is now omitted, and batches are formed so that merging never closes a cycle.",
        ],
        "files": {},
        "analyses": {},
    }
    statuses = Counter(record["status"] for record in analysed.values())
    findings["file_statuses"] = dict(sorted(statuses.items()))
    for subject, record in sorted(analysed.items()):
        summary = {k: v for k, v in record.items() if k != "mutants"}
        if "mutants" in record:
            summary["mutants"] = dict(Counter(m["status"] for m in record["mutants"]))
            score = _score(record) if record["status"] == "scored" else None
            summary["expected_score"] = (
                {s: ees._round(v) for s, v in score.items()} if score else None
            )
        findings["files"][subject] = summary
    for label, keep in (
        ("primary: files with a condition", lambda r: r["with_condition"]),
        ("secondary: every eligible file", lambda r: True),
    ):
        scores = [
            score
            for record in analysed.values()
            if record["status"] == "scored" and keep(record)
            for score in [_score(record)]
            if score is not None
        ]
        findings["analyses"][label] = {
            "files_scored": len(scores),
            "mean_expected_score": {
                s: ees._round(statistics.fmean(float(x[s]) for x in scores)) for s in ees.STRATEGIES
            }
            if scores
            else None,
            "median_suite_size": {
                "refinement": statistics.median(
                    r["cells"] for r in analysed.values() if r["status"] == "scored" and keep(r)
                ),
                "quotient": statistics.median(
                    r["quotient_classes"]
                    for r in analysed.values()
                    if r["status"] == "scored" and keep(r)
                ),
            }
            if scores
            else None,
            "hypotheses": ees.compare(scores) if len(scores) > 1 else None,
        }
    return findings


# ---------------------------------------------------------------------------------------
# Real edits, descriptive only
# ---------------------------------------------------------------------------------------


def _version(repository: str, commit: str, path: str, cache: Path) -> bytes | None:
    measure = _load("measure_third_party_policies")
    stored = (
        cache / "versions" / hashlib.sha256(f"{repository}@{commit}/{path}".encode()).hexdigest()
    )
    if stored.exists():
        return stored.read_bytes()
    content, _ = measure.fetch_bytes({"repo": repository, "commit": commit, "path": path})
    if content is not None:
        stored.parent.mkdir(parents=True, exist_ok=True)
        stored.write_bytes(content)
    return content


def edit_pair(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """One real edit: does it change a decision, weaken one, and would a suite of the earlier
    version have caught it?

    The suites are built from the earlier version, as a regression suite written before the
    edit would be, over the witness space of both versions together.
    """

    cedarpy, _ = _cedar()
    ees = _load("exact_evaluation_study")
    found = observables_of(before, after)
    space = WitnessSpace(found, cap=MAX_CELLS)
    if space.size() > MAX_CELLS:
        return {"status": "over the cell cap", "cells": space.size()}
    made = [
        request
        for index, cell in enumerate(space.cells())
        if (request := request_of(space, cell, str(index))) is not None
    ]
    batches = batches_of(made)
    old = [
        d
        for d, _ in evaluate(
            cedarpy.PolicySet.from_json_str(json.dumps(before)), batches, len(made)
        )
    ]
    new = [
        d
        for d, _ in evaluate(cedarpy.PolicySet.from_json_str(json.dumps(after)), batches, len(made))
    ]
    changed = {p for p in range(len(made)) if old[p] != new[p]}
    weakened = {p for p in changed if PERMISSIVENESS[new[p]] > PERMISSIVENESS[old[p]]}
    signatures: dict[tuple[str, ...], list[int]] = defaultdict(list)
    atoms = [parsed(text) for text in atoms_of(before)]
    for position, signature in enumerate(_signatures(atoms, batches, len(made))):
        signatures[signature].append(position)
    by_decision: dict[str, list[int]] = defaultdict(list)
    for position, decision in enumerate(old):
        by_decision[decision].append(position)
    classes, decisions = list(signatures.values()), list(by_decision.values())
    cells = made
    return {
        "status": "measured",
        "cells": len(cells),
        "changes_a_decision": bool(changed),
        "weakens_a_decision": bool(weakened),
        "detection": {
            "refinement": 1.0 if changed else 0.0,
            "quotient": ees._round(ees._detection(classes, changed)),
            "decision": ees._round(ees._detection(decisions, changed)),
            "random_quotient": ees._round(
                ees._random_detection(len(cells), len(changed), len(classes))
            ),
            "random_decision": ees._round(
                ees._random_detection(len(cells), len(changed), len(decisions))
            ),
        },
    }


def real_edits(cache: Path, history: list[dict[str, Any]]) -> dict[str, Any]:
    require_protocol()
    _, internal = _cedar()
    measured = json.loads((DOCS / "third-party-sample-cedar-membership-v1.json").read_text("utf-8"))
    inside = {e["subject"] for e in measured["policies"] if e["verdict"] == "inside"}
    pairs: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    for entry in sorted(history, key=lambda e: (e["repo"], e["path"])):
        subject = f"{entry['repo']}/{entry['path']}"
        versions = entry.get("versions") or []
        if subject not in inside or len(versions) < 2:
            continue
        for newer, older in itertools.pairwise(versions):
            texts = [
                _version(entry["repo"], commit, entry["path"], cache) for commit in (older, newer)
            ]
            if any(text is None for text in texts):
                skipped["a version could not be fetched at its commit"] += 1
                continue
            if texts[0] == texts[1]:
                skipped["the commit did not change the file's bytes"] += 1
                continue
            try:
                ests = [json.loads(internal.policies_to_json_str(t.decode("utf-8"))) for t in texts]
            except Exception:  # noqa: BLE001 - the engine's parser judges a policy set
                skipped["a version Cedar does not parse"] += 1
                continue
            if any(eligibility(est) for est in ests):
                skipped["a version that is not exact-eligible"] += 1
                continue
            record = edit_pair(*ests)
            record.update(
                {
                    "subject": subject,
                    "before": {"commit": older, "sha256": hashlib.sha256(texts[0]).hexdigest()},
                    "after": {"commit": newer, "sha256": hashlib.sha256(texts[1]).hexdigest()},
                }
            )
            pairs.append(record)
    measured_pairs = [p for p in pairs if p["status"] == "measured"]
    semantic = [p for p in measured_pairs if p["changes_a_decision"]]
    ees = _load("exact_evaluation_study")
    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "engine": ENGINE,
        "what_this_is": (
            "every earlier-version pair of an exact-eligible sampled Cedar file, as a real edit; "
            "descriptive only, no hypothesis is tested on these"
        ),
        "suites_built_from": "the earlier version of each pair",
        "pairs_skipped": dict(sorted(skipped.items())),
        "pairs_measured": len(measured_pairs),
        "pairs_over_the_cell_cap": len(pairs) - len(measured_pairs),
        "change_a_decision": len(semantic),
        "weaken_a_decision": sum(1 for p in measured_pairs if p["weakens_a_decision"]),
        "mean_detection_of_decision_changes": {
            strategy: ees._round(statistics.fmean(p["detection"][strategy] for p in semantic))
            for strategy in ees.STRATEGIES
        }
        if semantic
        else None,
        "pairs": pairs,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    study_command = commands.add_parser("study")
    study_command.add_argument("--cache", type=Path, required=True)
    study_command.add_argument("--json", type=Path, required=True)
    edits_command = commands.add_parser("edits")
    edits_command.add_argument("--cache", type=Path, required=True)
    edits_command.add_argument("--history", type=Path, required=True)
    edits_command.add_argument("--json", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "study":
        findings = study(arguments.cache)
    else:
        history = json.loads(arguments.history.read_text("utf-8"))
        findings = real_edits(arguments.cache, history)
    arguments.json.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", "utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
