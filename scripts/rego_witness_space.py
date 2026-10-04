"""A witness space for a Rego module: reviews on which the engine settles every mutant.

`docs/EXACT_ADEQUACY_PROTOCOL_REGO.md` says what this builds and why; this module is the
construction. It reads the module's abstract syntax tree (from `opa parse`), resolves every
reference below `input.review` through the variables, rules and functions that bind it, and
records, per path, what the module compares it with. From those hints it builds candidate values
per path, and from the candidates the cells: the reviews the study asks the engine to decide.

Nothing here decides a policy. The analysis only finds which fields matter and which values to
try; whether a mutant is equivalent is the engine's answer on the cells, and whether the cells
are enough is checked against inputs this construction did not choose.
"""

from __future__ import annotations

import itertools
import json
import random
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

try:  # Python 3.11+
    import re._parser as sre_parse  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    import sre_parse  # type: ignore[no-redef]

STAR = "*"


class Unsupported(Exception):
    """A construct the witness space does not cover; the module is excluded by this reason."""


class _Absent:
    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = _Absent()


# --- abstract values -------------------------------------------------------------------------


@dataclass(frozen=True)
class Path:
    """A path below `input`; a STAR segment is any element of a collection."""

    segs: tuple[Any, ...]


@dataclass(frozen=True)
class Const:
    text: str  # canonical JSON

    @property
    def value(self) -> Any:
        return json.loads(self.text)


def const(value: Any) -> Const:
    return Const(json.dumps(value, sort_keys=True))


@dataclass(frozen=True)
class Derived:
    """A value a builtin computes from paths: its size, a case change, or something opaque."""

    kind: str  # "count" | "lower" | "upper" | "opaque"
    paths: frozenset[Path]


@dataclass(frozen=True)
class KeyOf:
    """The key (or index) of an element of the collection at `path`."""

    path: Path


@dataclass(frozen=True)
class Coll:
    """The value of a partial set rule: its elements."""

    elements: frozenset[Any]


AV = frozenset  # of Path | Const | Derived | KeyOf | Coll
UNDEFINED: frozenset[Any] = frozenset()


def _paths(av: frozenset[Any]) -> set[Path]:
    out: set[Path] = set()
    for item in av:
        if isinstance(item, Path):
            out.add(item)
        elif isinstance(item, Derived):
            out |= set(item.paths)
        elif isinstance(item, Coll):
            out |= _paths(item.elements)
    return out


def _consts(av: frozenset[Any]) -> list[Any]:
    return [item.value for item in av if isinstance(item, Const)]


# --- the AST ---------------------------------------------------------------------------------


def opa_parse(opa: str, source: str) -> dict[str, Any]:
    done = subprocess.run(
        [opa, "parse", "--format", "json", "--v0-compatible", "/dev/stdin"],
        input=source,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if done.returncode != 0:
        raise Unsupported(f"opa parse failed: {done.stderr.strip()[:200]}")
    return json.loads(done.stdout)


def _ref_strings(ref: list[dict[str, Any]]) -> list[str] | None:
    out = []
    for i, part in enumerate(ref):
        if i == 0 and part.get("type") == "var" or part.get("type") == "string":
            out.append(part["value"])
        else:
            return None
    return out


def package_of(ast: dict[str, Any]) -> tuple[str, ...]:
    path = ast["package"]["path"]
    return tuple(str(p["value"]) for p in path[1:])


def rule_name(rule: dict[str, Any]) -> str:
    head = rule.get("head", {})
    if head.get("name"):
        return str(head["name"])
    ref = head.get("ref") or []
    names = _ref_strings(ref)
    if names:
        return ".".join(names)
    raise Unsupported("a rule head that is not a plain name")


# --- the analysis ----------------------------------------------------------------------------

_COMPARE = {"equal": "==", "neq": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
_AFFIX = {"startswith", "endswith", "contains"}
_PURE_STRING = {
    "trim_suffix": lambda s, x: s[: -len(x)] if x and s.endswith(x) else s,
    "trim_prefix": lambda s, x: s[len(x) :] if x and s.startswith(x) else s,
    "trim": lambda s, x: s.strip(x),
    "trim_left": lambda s, x: s.lstrip(x),
    "trim_right": lambda s, x: s.rstrip(x),
    "concat": lambda sep, xs: sep.join(xs),
    "split": lambda s, sep: s.split(sep),
    "lower": lambda s: s.lower(),
    "upper": lambda s: s.upper(),
}


class Analyzer:
    """Find, for one module under one instantiation, every review path that can matter and the
    values each is compared with."""

    def __init__(self, asts: list[dict[str, Any]], package: tuple[str, ...], params: Any) -> None:
        self.package = package
        self.params = params  # ABSENT when the suite supplies none
        self.rules: dict[tuple[tuple[str, ...], str], list[dict[str, Any]]] = defaultdict(list)
        self.imports: dict[tuple[str, ...], dict[str, tuple[str, ...]]] = {}
        for ast in asts:
            pkg = package_of(ast)
            aliases: dict[str, tuple[str, ...]] = {}
            for imported in ast.get("imports") or []:
                names = _ref_strings(imported["path"]["value"])
                if not names or names[0] != "data":
                    continue
                alias = imported.get("alias") or names[-1]
                aliases[alias] = tuple(names[1:])
            self.imports[pkg] = aliases
            for rule in ast.get("rules") or []:
                self.rules[(pkg, rule_name(rule))].append(rule)
        self.hints: dict[tuple[Any, ...], set[tuple[Any, ...]]] = defaultdict(set)
        self.read: set[tuple[Any, ...]] = set()
        self.links: set[frozenset[tuple[Any, ...]]] = set()
        # The guards themselves, for the quotient: each path's atoms with their operator and the
        # order of their operands, and the paths whose atoms no expression here can restate
        # (an unmodelled builtin, or a comparison with another path), which the quotient then
        # never merges. Nothing the witness space is built from reads these.
        self.atoms: dict[tuple[Any, ...], set[tuple[Any, ...]]] = defaultdict(set)
        self.unmerged: set[tuple[Any, ...]] = set()
        self._memo: dict[Any, frozenset[Any]] = {}
        self._stack: list[Any] = []

    # entry point
    def run(self) -> None:
        bodies = self.rules.get((self.package, "violation"))
        if not bodies:
            raise Unsupported("no violation rule")
        for rule in bodies:
            self._rule(self.package, rule, {})

    # rules and functions
    def _rule(
        self, pkg: tuple[str, ...], rule: dict[str, Any], env: dict[str, frozenset[Any]]
    ) -> frozenset[Any]:
        """Analyse one rule definition (and its else chain); return its value."""

        out: set[Any] = set()
        current: dict[str, Any] | None = rule
        while current is not None:
            local = dict(env)
            for expr in current.get("body") or []:
                self._expr(pkg, expr, local)
            head = current.get("head", {})
            if head.get("key") is not None:
                out |= self._term(pkg, head["key"], local)
            if head.get("value") is not None:
                out |= self._term(pkg, head["value"], local)
            elif head.get("key") is None:
                out.add(const(True))
            current = current.get("else")
        return frozenset(out)

    def _rule_value(self, pkg: tuple[str, ...], name: str) -> frozenset[Any]:
        key = ("rule", pkg, name)
        if key in self._memo:
            return self._memo[key]
        if key in self._stack:
            return frozenset({Derived("opaque", frozenset())})
        self._stack.append(key)
        values: set[Any] = set()
        partial_set = False
        for rule in self.rules[(pkg, name)]:
            head = rule.get("head", {})
            if head.get("args"):
                continue
            if head.get("key") is not None and head.get("value") is None:
                partial_set = True
            values |= self._rule(pkg, rule, {})
        self._stack.pop()
        result = frozenset({Coll(frozenset(values))}) if partial_set else frozenset(values)
        self._memo[key] = result
        return result

    def _call_user(
        self, pkg: tuple[str, ...], name: str, args: list[frozenset[Any]]
    ) -> frozenset[Any]:
        key = ("call", pkg, name, tuple(args))
        if key in self._memo:
            return self._memo[key]
        if key in self._stack or len(self._stack) > 40:
            return frozenset({Derived("opaque", frozenset().union(*map(_paths, args)))})
        self._stack.append(key)
        values: set[Any] = set()
        for rule in self.rules[(pkg, name)]:
            params = rule.get("head", {}).get("args") or []
            if len(params) != len(args):
                continue
            env: dict[str, frozenset[Any]] = {}
            for param, arg in zip(params, args, strict=True):
                if param.get("type") == "var":
                    env[param["value"]] = arg
                else:  # a constant argument pattern, e.g. path_array("/")
                    self._compare("equal", arg, self._term(pkg, param, env))
            values |= self._rule(pkg, rule, env)
        self._stack.pop()
        result = frozenset(values)
        self._memo[key] = result
        return result

    def _resolve_name(
        self, pkg: tuple[str, ...], names: list[str]
    ) -> tuple[tuple[str, ...], str] | None:
        """A dotted name as a rule or function: local, imported, or by its data path."""

        if names[0] == "data":
            full = tuple(names[1:])
            for cut in range(len(full) - 1, 0, -1):
                if (full[:cut], ".".join(full[cut:])) in self.rules:
                    return full[:cut], ".".join(full[cut:])
            return None
        if (pkg, ".".join(names)) in self.rules:
            return pkg, ".".join(names)
        alias = self.imports.get(pkg, {}).get(names[0])
        if alias is not None:
            return self._resolve_name(pkg, ["data", *alias, *names[1:]])
        return None

    # expressions
    def _expr(
        self, pkg: tuple[str, ...], expr: dict[str, Any], env: dict[str, frozenset[Any]]
    ) -> None:
        if expr.get("with"):
            raise Unsupported("an expression with a `with` modifier")
        terms = expr.get("terms")
        if isinstance(terms, dict):
            if terms.get("type") in ("someDecl", "SomeDecl"):
                return
            value = self._term(pkg, terms, env)
            self._condition(value)
            return
        if not isinstance(terms, list) or not terms:
            raise Unsupported("an expression of unknown shape")
        op = _ref_strings(terms[0].get("value", [])) if terms[0].get("type") == "ref" else None
        name = ".".join(op) if op else None
        args = terms[1:]
        if name in ("assign", "eq") and len(args) == 2:
            left, right = args
            if left.get("type") == "var" and (name == "assign" or left["value"] not in env):
                env[left["value"]] = self._term(pkg, right, env)
                return
            if right.get("type") == "var" and right["value"] not in env:
                env[right["value"]] = self._term(pkg, left, env)
                return
            if left.get("type") in ("array", "object"):
                value = self._term(pkg, right, env)
                self._destructure(pkg, left, value, env)
                return
            self._compare("equal", self._term(pkg, left, env), self._term(pkg, right, env))
            return
        if name in _COMPARE and len(args) == 2:
            self._compare(name, self._term(pkg, args[0], env), self._term(pkg, args[1], env))
            return
        if name is None:
            raise Unsupported("a call whose operator is not a name")
        value = self._call(pkg, name, args, env)
        self._condition(value)

    def _destructure(
        self,
        pkg: tuple[str, ...],
        pattern: dict[str, Any],
        value: frozenset[Any],
        env: dict[str, frozenset[Any]],
    ) -> None:
        opaque = frozenset({Derived("opaque", frozenset(_paths(value)))})
        for node in _walk_terms(pattern):
            if node.get("type") == "var" and node["value"] not in env:
                env[node["value"]] = opaque

    def _condition(self, value: frozenset[Any]) -> None:
        for item in value:
            if isinstance(item, Path):
                self._hint(item, ("truthy",))
                self._atom(item, ("truthy",))
            elif isinstance(item, Derived):
                for path in item.paths:
                    self._hint(path, ("truthy",))
                    self._unmerge(path)

    def _compare(self, op: str, a: frozenset[Any], b: frozenset[Any]) -> None:
        for x, y in itertools.product(a, b):
            self._compare_one(op, x, y)
            self._compare_one(op, y, x)
            self._atom_pair(op, x, y)

    _MIRROR = {"lt": "gt", "lte": "gte", "gt": "lt", "gte": "lte", "equal": "equal", "neq": "neq"}

    def _atom_pair(self, op: str, x: Any, y: Any) -> None:
        """The atom `x op y`, kept on the path it reads with the operand order it has."""

        op = "equal" if op in ("eq", "equal") else op
        if isinstance(y, Path | Derived) and isinstance(x, Const):
            x, y, op = y, x, self._MIRROR.get(op, op)
        if isinstance(x, Coll):
            for element in x.elements:
                self._atom_pair(op, element, y)
            return
        if isinstance(y, Coll):
            for element in y.elements:
                self._atom_pair(op, x, element)
            return
        if isinstance(x, Path) and isinstance(y, Const):
            self._atom(x, ("cmp", op, y.text))
        elif isinstance(x, Derived) and isinstance(y, Const):
            for path in x.paths:
                if x.kind == "count" and isinstance(y.value, (int, float)):
                    self._atom(path, ("size", op, y.text))
                elif x.kind in ("lower", "upper") and isinstance(y.value, str):
                    self._atom(path, ("case", x.kind, op, y.text))
                else:
                    self._unmerge(path)
        elif isinstance(x, KeyOf):
            self._unmerge(x.path)
        else:
            for item in (x, y):
                if isinstance(item, Path):
                    self._unmerge(item)
                elif isinstance(item, Derived):
                    for path in item.paths:
                        self._unmerge(path)

    def _atom(self, path: Path, atom: tuple[Any, ...]) -> None:
        if path.segs and path.segs[0] == "review":
            self.atoms[path.segs].add(atom)

    def _unmerge(self, path: Path) -> None:
        if path.segs and path.segs[0] == "review":
            self.unmerged.add(path.segs)

    def _compare_one(self, op: str, x: Any, y: Any) -> None:
        if isinstance(x, Path) and isinstance(y, Const):
            value = y.value
            if (
                op in ("lt", "lte", "gt", "gte")
                and isinstance(value, (int, float))
                and not isinstance(value, bool)
            ):
                self._hint(x, ("ord", value))
            else:
                self._hint(x, ("eq", y.text))
        elif isinstance(x, Path) and isinstance(y, Path):
            self.links.add(frozenset({x.segs, y.segs}))
        elif isinstance(x, Derived) and isinstance(y, Const):
            for path in x.paths:
                if x.kind == "count" and isinstance(y.value, (int, float)):
                    self._hint(path, ("size", y.value))
                elif x.kind in ("lower", "upper") and isinstance(y.value, str):
                    self._hint(path, (x.kind, y.value))
                else:
                    self._hint(path, ("opaque", y.text))
        elif isinstance(x, Derived) and isinstance(y, (Path, Derived)):
            others = {y} if isinstance(y, Path) else set(y.paths)
            for p in x.paths:
                for q in others:
                    self.links.add(frozenset({p.segs, q.segs}))
        elif isinstance(x, KeyOf) and isinstance(y, Const):
            self._hint(x.path, ("key", y.text))
        elif isinstance(x, Coll):
            for element in x.elements:
                self._compare_one(op, element, y)

    def _hint(self, path: Path, hint: tuple[Any, ...]) -> None:
        if path.segs and path.segs[0] == "review":
            self.hints[path.segs].add(hint)
            self.read.add(path.segs)

    # terms
    def _term(
        self, pkg: tuple[str, ...], term: dict[str, Any], env: dict[str, frozenset[Any]]
    ) -> frozenset[Any]:
        kind = term.get("type")
        value = term.get("value")
        if kind in ("null", "boolean", "number", "string"):
            return frozenset({const(value)})
        if kind == "var":
            return self._var(pkg, value, env)
        if kind == "ref":
            return self._ref(pkg, value, env)
        if kind in ("array", "set"):
            items = [self._term(pkg, t, env) for t in value]
            return self._compose(items, list if kind == "array" else "set")
        if kind == "object":
            keys = [self._term(pkg, k, env) for k, _ in value]
            vals = [self._term(pkg, v, env) for _, v in value]
            if all(len(k) == 1 and isinstance(next(iter(k)), Const) for k in keys) and all(
                len(v) == 1 and isinstance(next(iter(v)), Const) for v in vals
            ):
                return frozenset(
                    {
                        const(
                            {
                                next(iter(k)).value: next(iter(v)).value
                                for k, v in zip(keys, vals, strict=True)
                            }
                        )
                    }
                )
            return frozenset(
                {
                    Derived(
                        "opaque",
                        frozenset().union(*map(_paths, keys + vals)) if keys else frozenset(),
                    )
                }
            )
        if kind == "call":
            names = (
                _ref_strings(value[0].get("value", [])) if value[0].get("type") == "ref" else None
            )
            if not names:
                raise Unsupported("a call whose operator is not a name")
            return self._call(pkg, ".".join(names), value[1:], env)
        if kind in ("arraycomprehension", "setcomprehension"):
            local = dict(env)
            for expr in value.get("body") or []:
                self._expr(pkg, expr, local)
            elements = self._term(pkg, value["term"], local)
            return frozenset({Coll(elements)})
        if kind == "objectcomprehension":
            local = dict(env)
            for expr in value.get("body") or []:
                self._expr(pkg, expr, local)
            elements = self._term(pkg, value["value"], local) | self._term(pkg, value["key"], local)
            return frozenset({Derived("opaque", frozenset(_paths(elements)))})
        raise Unsupported(f"a term of type {kind}")

    def _compose(self, items: list[frozenset[Any]], shape: Any) -> frozenset[Any]:
        if all(len(i) == 1 and isinstance(next(iter(i)), Const) for i in items):
            values = [next(iter(i)).value for i in items]
            if shape == "set":
                values = sorted(values, key=lambda v: json.dumps(v, sort_keys=True))
            return frozenset({const(values)})
        if shape == "set" or all(len(i) >= 1 for i in items):
            return frozenset({Coll(frozenset().union(*items))}) if items else frozenset({const([])})
        return frozenset({Derived("opaque", frozenset().union(*map(_paths, items)))})

    def _var(
        self, pkg: tuple[str, ...], name: str, env: dict[str, frozenset[Any]]
    ) -> frozenset[Any]:
        if name in env:
            return env[name]
        if name == "input":
            return frozenset({Path(())})
        resolved = self._resolve_name(pkg, [name])
        if resolved is not None:
            return self._rule_value(*resolved)
        return UNDEFINED  # an unbound variable; refs index with it as a wildcard

    def _ref(
        self, pkg: tuple[str, ...], ref: list[dict[str, Any]], env: dict[str, frozenset[Any]]
    ) -> frozenset[Any]:
        head = ref[0]
        rest = ref[1:]
        if head.get("type") != "var":
            base = self._term(pkg, head, env)
        elif head["value"] == "data":
            names = ["data"]
            index = 0
            while index < len(rest) and rest[index].get("type") == "string":
                names.append(rest[index]["value"])
                index += 1
                resolved = self._resolve_name(pkg, names)
                if resolved is not None:
                    base = self._rule_value(*resolved)
                    return self._index(pkg, base, rest[index:], env)
            if len(names) > 1 and names[1] == "inventory":
                raise Unsupported("reads data.inventory")
            raise Unsupported(f"reads an unknown document {'.'.join(names)}")
        else:
            name = head["value"]
            if name in env:
                return self._index(pkg, env[name], rest, env)
            if name == "input":
                return self._index(pkg, frozenset({Path(())}), rest, env)
            # a rule, local or imported, possibly named through dotted parts
            strings = [name]
            for part in rest:
                if part.get("type") != "string":
                    break
                strings.append(part["value"])
            for cut in range(len(strings), 0, -1):
                found = self._resolve_name(pkg, strings[:cut])
                if found is not None:
                    return self._index(pkg, self._rule_value(*found), rest[cut - 1 :], env)
            return UNDEFINED
        return self._index(pkg, base, rest, env)

    def _index(
        self,
        pkg: tuple[str, ...],
        base: frozenset[Any],
        rest: list[dict[str, Any]],
        env: dict[str, frozenset[Any]],
    ) -> frozenset[Any]:
        current = base
        for part in rest:
            kind = part.get("type")
            keys: list[Any]
            bind: str | None = None
            if kind in ("string", "number", "boolean"):
                keys = [part["value"]]
            elif kind == "var" and part["value"] in env:
                bound = env[part["value"]]
                consts = _consts(bound)
                keys = consts if consts and len(consts) == len(bound) else [STAR]
            elif kind == "var":
                keys = [STAR]
                bind = part["value"]
            else:
                keys = [STAR]
                self._term(pkg, part, env)
            nxt: set[Any] = set()
            for item in current:
                for key in keys:
                    nxt |= self._step(item, key)
            if bind is not None and not bind.startswith("$"):
                env[bind] = frozenset(KeyOf(i) for i in current if isinstance(i, Path))
            current = frozenset(self._settle(nxt))
        return current

    def _step(self, item: Any, key: Any) -> set[Any]:
        if isinstance(item, Path):
            seg = STAR if key == STAR else (key if isinstance(key, str) else STAR)
            return {Path(item.segs + (seg,))}
        if isinstance(item, Const):
            value = item.value
            if key == STAR:
                if isinstance(value, list):
                    return {const(v) for v in value}
                if isinstance(value, dict):
                    return {const(v) for v in value.values()}
                return set()
            if isinstance(value, dict) and isinstance(key, str) and key in value:
                return {const(value[key])}
            if isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
                return {const(value[key])}
            return set()
        if isinstance(item, Coll):
            if key == STAR:
                return set(item.elements)
            return set()
        if isinstance(item, Derived):
            return {Derived("opaque", item.paths)}
        return set()

    def _settle(self, items: set[Any]) -> set[Any]:
        """Turn paths below `input.parameters` into the constants the instantiation fixes, and
        drop paths outside `review` and `parameters`, which no Gatekeeper input carries."""

        out: set[Any] = set()
        for item in items:
            if not isinstance(item, Path) or not item.segs:
                out.add(item)
                continue
            top = item.segs[0]
            if top == "review":
                self.read.add(item.segs)
                out.add(item)
            elif top == "parameters":
                out |= self._parameter(item.segs[1:])
            elif top == STAR:
                out.add(item)  # iterating input itself; resolved by the next step
        return out

    def _parameter(self, segs: tuple[Any, ...]) -> set[Any]:
        if self.params is ABSENT:
            return set()
        values = [self.params]
        for seg in segs:
            nxt = []
            for value in values:
                if seg == STAR:
                    if isinstance(value, list):
                        nxt.extend(value)
                    elif isinstance(value, dict):
                        nxt.extend(value.values())
                elif isinstance(value, dict) and seg in value:
                    nxt.append(value[seg])
            values = nxt
        return {const(v) for v in values}

    # calls
    def _call(
        self,
        pkg: tuple[str, ...],
        name: str,
        args: list[dict[str, Any]],
        env: dict[str, frozenset[Any]],
    ) -> frozenset[Any]:
        resolved = self._resolve_name(pkg, name.split("."))
        if resolved is not None:
            avs = [self._term(pkg, a, env) for a in args]
            return self._call_user(resolved[0], resolved[1], avs)
        avs = [self._term(pkg, a, env) for a in args]
        if name in ("print", "sprintf", "json.marshal", "format_int", "trace"):
            # arguments that must exist for the expression to be defined, compared with nothing
            return frozenset(
                {Derived("text", frozenset().union(*map(_paths, avs)) if avs else frozenset())}
            )
        if name == "object.get" and len(avs) == 3:
            return self._object_get(avs[0], avs[1], avs[2])
        if name in _COMPARE and len(avs) == 2:
            self._compare(name, avs[0], avs[1])
            return frozenset({const(True), const(False)})
        if name == "count" and len(avs) == 1:
            if all(isinstance(i, Const) for i in avs[0]):
                return frozenset(
                    const(len(i.value)) for i in avs[0] if isinstance(i.value, (list, dict, str))
                )
            return frozenset({Derived("count", frozenset(_paths(avs[0])))})
        if name in ("lower", "upper") and len(avs) == 1:
            if all(isinstance(i, Const) for i in avs[0]):
                return frozenset(const(getattr(str(i.value), name)()) for i in avs[0])
            return frozenset({Derived(name, frozenset(_paths(avs[0])))})
        if name in _AFFIX and len(avs) == 2:
            self._affix(name, avs[0], avs[1])
            return frozenset({const(True), const(False)})
        if name in ("strings.any_prefix_match", "strings.any_suffix_match") and len(avs) == 2:
            kind = "startswith" if "prefix" in name else "endswith"
            self._affix(kind, self._flatten(avs[0]), self._flatten(avs[1]))
            return frozenset({const(True), const(False)})
        if name in ("regex.match", "re_match", "glob.match") and len(avs) >= 2:
            pattern, subject = (avs[0], avs[-1])
            for p in _consts(pattern):
                for path in _paths(subject):
                    self._hint(path, ("glob" if name == "glob.match" else "regex", p))
                    self._atom(path, ("glob" if name == "glob.match" else "regex", json.dumps(p)))
            for path in _paths(pattern):
                self._unmerge(path)
            return frozenset({const(True), const(False)})
        if name in _PURE_STRING and all(all(isinstance(i, Const) for i in av) and av for av in avs):
            results = set()
            for combo in itertools.product(*[_consts(av) for av in avs]):
                try:
                    results.add(const(_PURE_STRING[name](*combo)))
                except Exception:  # noqa: BLE001 - a type the builtin would reject
                    continue
            return frozenset(results)
        if name in ("and", "or", "minus", "union", "intersection", "array.concat"):
            return frozenset({Coll(frozenset().union(*(self._flatten(av) for av in avs)))})
        if name in (
            "is_string",
            "is_number",
            "is_boolean",
            "is_array",
            "is_object",
            "is_set",
            "is_null",
        ):
            for path in _paths(avs[0]):
                self._hint(path, ("type", name))
                self._atom(path, ("type", name))
            return frozenset({const(True), const(False)})
        paths = frozenset().union(*map(_paths, avs)) if avs else frozenset()
        consts = [c for av in avs for c in av if isinstance(c, Const)]
        for path in paths:
            for c in consts:
                self._hint(path, ("opaque", c.text))
            self._unmerge(path)
        return frozenset({Derived("opaque", paths)})

    def _flatten(self, av: frozenset[Any]) -> frozenset[Any]:
        out: set[Any] = set()
        for item in av:
            if isinstance(item, Coll):
                out |= self._flatten(item.elements)
            elif isinstance(item, Const) and isinstance(item.value, list):
                out |= {const(v) for v in item.value}
            else:
                out.add(item)
        return frozenset(out)

    def _object_get(
        self, obj: frozenset[Any], key: frozenset[Any], default: frozenset[Any]
    ) -> frozenset[Any]:
        out: set[Any] = set(default)
        for k in _consts(key):
            segs = k if isinstance(k, list) else [k]
            for item in obj:
                current = {item}
                for seg in segs:
                    current = (
                        set().union(*(self._step(c, seg) for c in current)) if current else set()
                    )
                out |= self._settle(current)
        return frozenset(out)

    def _affix(self, kind: str, subject: frozenset[Any], base: frozenset[Any]) -> None:
        for item in subject:
            for value in _consts(base):
                if isinstance(value, str) and isinstance(item, Path):
                    self._atom(item, ("affix", kind, json.dumps(value)))
            if not isinstance(item, Path | Const):
                for path in _paths(frozenset({item})):
                    self._unmerge(path)
        for path in _paths(base):
            self._unmerge(path)
        for path in _paths(subject):
            for value in _consts(base):
                if isinstance(value, str):
                    self._hint(path, (kind, value))
        for path in _paths(base):  # the base read from the review, the subject constant
            for value in _consts(subject):
                if isinstance(value, str):
                    self._hint(path, ("opaque", json.dumps(value)))
        for p in _paths(subject):
            for q in _paths(base):
                self.links.add(frozenset({p.segs, q.segs}))


def _walk_terms(node: Any):
    if isinstance(node, dict):
        if "type" in node and "value" in node:
            yield node
        for value in node.values():
            yield from _walk_terms(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_terms(value)


# --- candidates --------------------------------------------------------------------------------

FRESH = "tw-fresh"
MUTANT = "tw-mutant"  # the string the literal operator of rego_source_mutation substitutes


def regex_samples(pattern: str, limit: int = 6) -> list[str]:
    """Strings meant to match `pattern`, one per alternative it names; the engine confirms."""

    try:
        parsed = sre_parse.parse(pattern)
    except Exception:  # noqa: BLE001
        return []

    def gen(items: Any) -> list[str]:
        outs = [""]
        for op, arg in items:
            name = str(op)
            if name == "LITERAL":
                choices = [chr(arg)]
            elif name == "NOT_LITERAL":
                choices = ["z" if chr(arg) != "z" else "y"]
            elif name == "ANY":
                choices = ["x"]
            elif name == "IN":
                choices = []
                for sub_op, sub_arg in arg:
                    sub = str(sub_op)
                    if sub == "LITERAL":
                        choices.append(chr(sub_arg))
                    elif sub == "RANGE":
                        choices.append(chr(sub_arg[0]))
                    elif sub == "CATEGORY":
                        choices.append(
                            "a"
                            if "WORD" in str(sub_arg)
                            else "1"
                            if "DIGIT" in str(sub_arg)
                            else " "
                        )
                    elif sub == "NEGATE":
                        choices = ["#"]
                        break
                choices = choices[:2] or ["x"]
            elif name in ("MAX_REPEAT", "MIN_REPEAT"):
                low, _high, sub = arg
                inner = gen(sub)[:2]
                count = max(low, 1)
                choices = ["".join([inner[0]] * count)] + (
                    [inner[1] * count] if len(inner) > 1 else []
                )
            elif name == "SUBPATTERN":
                choices = gen(arg[-1])
            elif name == "BRANCH":
                choices = []
                for alternative in arg[1]:
                    choices.extend(gen(alternative)[:2])
            elif name in ("AT", "ASSERT", "ASSERT_NOT"):
                choices = [""]
            elif name == "CATEGORY":
                choices = ["a" if "WORD" in str(arg) else "1" if "DIGIT" in str(arg) else " "]
            else:
                choices = ["x"]
            outs = [o + c for o in outs for c in choices][:limit]
        return outs

    return sorted(set(gen(parsed)))[:limit]


def candidates(hints: set[tuple[Any, ...]]) -> list[Any]:
    """The values to try at one leaf, from what the module compares it with."""

    out: list[Any] = []

    def add(value: Any) -> None:
        if not any(type(value) is type(v) and value == v for v in out):
            out.append(value)

    stringy = False
    for hint in sorted(hints, key=repr):
        kind = hint[0]
        if kind == "eq":
            value = json.loads(hint[1])
            add(value)
            if isinstance(value, bool):
                add(not value)
                add("true" if value else "false")
            elif isinstance(value, (int, float)):
                for delta in (-1, 1, 2):
                    add(value + delta)
            elif isinstance(value, str):
                stringy = True
                add(False)
        elif kind == "ord":
            for delta in (-1, 0, 1, 2):
                add(hint[1] + delta)
        elif kind == "startswith":
            stringy = True
            add(hint[1])
            add(hint[1] + "tw")
        elif kind == "endswith":
            stringy = True
            add(hint[1])
            add("tw" + hint[1])
        elif kind == "contains":
            stringy = True
            add("tw" + hint[1] + "tw")
        elif kind in ("lower", "upper"):
            stringy = True
            add(hint[1])
            add(hint[1].upper() if kind == "lower" else hint[1].lower())
        elif kind == "regex":
            stringy = True
            for sample in regex_samples(hint[1]):
                add(sample)
        elif kind == "glob":
            stringy = True
            add(hint[1].replace("**", "tw").replace("*", "tw").replace("?", "t"))
        elif kind == "opaque":
            value = json.loads(hint[1])
            if isinstance(value, str):
                stringy = True
                for v in (value, value + "/", value + "/tw", value + "tw", value[:-1]):
                    if v:
                        add(v)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                for delta in (-1, 0, 1, 2):
                    add(value + delta)
            else:
                add(value)
        elif kind == "truthy":
            add(True)
            add(False)
        elif kind == "size" and isinstance(hint[1], (int, float)):
            for length in range(max(0, int(hint[1]) - 1), int(hint[1]) + 3):
                add([FRESH] * length)
        elif kind == "type":
            add(FRESH)
            add(1)
            add(True)
            add([])
            add({})
    if stringy:
        add(MUTANT)
    add(FRESH)
    return out


# --- the space ---------------------------------------------------------------------------------


@dataclass
class Node:
    children: dict[Any, Node]
    hints: set[tuple[Any, ...]]
    kind: str = "object"  # "object" | "array" | "map"


def build_trie(analyzer: Analyzer, shapes: dict[tuple[Any, ...], str]) -> Node:
    root = Node({}, set())
    for segs in sorted(analyzer.read | set(analyzer.hints), key=lambda s: [str(x) for x in s]):
        node = root
        prefix: tuple[Any, ...] = ()
        for seg in segs[1:]:  # below "review"
            prefix = prefix + (seg,)
            node = node.children.setdefault(seg, Node({}, set()))
        node.hints |= analyzer.hints.get(segs, set())
    _shape(root, ("review",), shapes)
    return root


def _shape(node: Node, at: tuple[Any, ...], shapes: dict[tuple[Any, ...], str]) -> None:
    if STAR in node.children:
        node.kind = shapes.get(at, "array")
    for seg, child in node.children.items():
        _shape(child, at + (seg,), shapes)


@dataclass
class Space:
    states: list[Any]  # the review values, one per cell
    count: int


def states(node: Node, links: set[frozenset[tuple[Any, ...]]], cap: int) -> list[Any]:
    """Every value this node takes across the cells, ABSENT included."""

    leaf = candidates(node.hints) if node.hints or not node.children else []
    if not node.children:
        return [ABSENT, *leaf]
    out: list[Any] = [ABSENT]
    if STAR in node.children:
        element = states(node.children[STAR], links, cap)
        present = [e for e in element if e is not ABSENT] or [FRESH]
        sizes = {int(h[1]) for h in node.hints if h[0] == "size" and isinstance(h[1], (int, float))}
        lengths = {0, 1} | {n + d for n in sizes for d in (-1, 0, 1, 2) if 0 <= n + d <= 4}
        needs_pairs = bool(sizes) or any(len(link) == 2 for link in links)
        default = present[0]
        for length in sorted(lengths):
            if length == 1:
                out.extend(_make(node.kind, [e]) for e in present)
            elif length == 2 and needs_pairs:
                out.extend(_make(node.kind, [e, default]) for e in present)
            else:
                out.append(_make(node.kind, [default] * length))
        for value in leaf:  # the collection itself compared or used as a condition
            if isinstance(value, bool) or value == FRESH:
                out.append(value)
        if len(out) > cap:
            raise Unsupported(f"a collection with {len(out)} states")
        return out
    keys = [k for k in node.children]
    collections = [k for k in keys if STAR in node.children[k].children]
    scalars = [k for k in keys if k not in collections]
    groups = _collection_groups(collections, node, links)
    scalar_states = [states(node.children[k], links, cap) for k in scalars]
    combos = 1
    for s in scalar_states:
        combos *= len(s)
    collection_options: list[dict[Any, Any]] = [{}]
    for group in groups:
        group_states = [states(node.children[k], links, cap) for k in group]
        for choice in itertools.product(*group_states):
            if all(v is ABSENT for v in choice):
                continue
            collection_options.append(dict(zip(group, choice, strict=True)))
    if combos * len(collection_options) > cap:
        raise Unsupported(f"an object with {combos * len(collection_options)} states")
    for scalar_choice in itertools.product(*scalar_states):
        for option in collection_options:
            value = {}
            for k, v in zip(scalars, scalar_choice, strict=True):
                if v is not ABSENT:
                    value[k] = v
            for k, v in option.items():
                if v is not ABSENT:
                    value[k] = v
            out.append(value)
    for value in leaf:
        if isinstance(value, bool) or value == FRESH:
            out.append(value)
    return out


def _collection_groups(
    collections: list[Any], node: Node, links: set[frozenset[tuple[Any, ...]]]
) -> list[list[Any]]:
    """Collections populated together: those an expression relates; the rest one at a time."""

    groups = [[c] for c in collections]
    if len(collections) < 2:
        return groups
    flat_links = [tuple(link) for link in links if len(link) == 2]

    def mentions(key: Any, segs: tuple[Any, ...]) -> bool:
        return key in segs

    merged = True
    while merged:
        merged = False
        for i in range(len(groups)):
            for j in range(i + 1, len(groups)):
                related = any(
                    (
                        any(mentions(a, p) for a in groups[i])
                        and any(mentions(b, q) for b in groups[j])
                    )
                    or (
                        any(mentions(a, q) for a in groups[i])
                        and any(mentions(b, p) for b in groups[j])
                    )
                    for p, q in flat_links
                )
                if related:
                    groups[i] = groups[i] + groups[j]
                    del groups[j]
                    merged = True
                    break
            if merged:
                break
    return groups


def _make(kind: str, elements: list[Any]) -> Any:
    if kind == "map":
        return {f"tw-k{i}": e for i, e in enumerate(elements)}
    return list(elements)


def build(analyzer: Analyzer, shapes: dict[tuple[Any, ...], str], cap: int) -> list[Any]:
    root = build_trie(analyzer, shapes)
    values = states(root, analyzer.links, cap)
    reviews = [v for v in values if isinstance(v, dict)]
    if not reviews:
        reviews = [{}]
    if len(reviews) > cap:
        raise Unsupported(f"{len(reviews)} cells, over the cap of {cap}")
    return _dedupe(reviews)


def _dedupe(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    out = []
    for value in values:
        key = json.dumps(value, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def shapes_from(inputs: list[Any]) -> dict[tuple[Any, ...], str]:
    """Whether each iterated collection is an array or a map, as the authors' inputs show it."""

    found: dict[tuple[Any, ...], str] = {}

    def walk(value: Any, at: tuple[Any, ...]) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, at + (k,))
                walk(v, at + (STAR,))
            found.setdefault(at, "map") if value else None
        elif isinstance(value, list):
            found[at] = "array"
            for v in value:
                walk(v, at + (STAR,))

    for item in inputs:
        if isinstance(item, dict) and isinstance(item.get("review"), dict):
            walk(item["review"], ("review",))
    return found


# --- drawn reviews -----------------------------------------------------------------------------

_OTHER_TYPES = ["tw-other", 7, True, None, [], {}, ["tw-x"], {"tw-x": 1}]


def perturb(review: Any, pool: list[Any], generator: random.Random, rounds: int = 3) -> Any:
    """One drawn review: a copy with a few random edits of the kinds the protocol names."""

    value = json.loads(json.dumps(review))
    for _ in range(generator.randint(1, rounds)):
        spots = list(_spots(value, ()))
        if not spots:
            break
        container, key = spots[generator.randrange(len(spots))]
        action = generator.randrange(6)
        target = container[key]
        if action == 0 and isinstance(target, list) and target:
            target.append(json.loads(json.dumps(generator.choice(target))))
        elif action == 1 and isinstance(target, list):
            other = generator.choice(pool)
            target.append(json.loads(json.dumps(other)))
        elif action == 2:
            container[key] = json.loads(json.dumps(generator.choice(_OTHER_TYPES)))
        elif action == 3 and isinstance(target, dict):
            target["tw-extra"] = generator.choice(["tw-x", 1, True])
        elif action == 4 and isinstance(container, dict):
            del container[key]
        else:
            container[key] = json.loads(json.dumps(generator.choice(pool)))
    return value


def _spots(value: Any, at: tuple[Any, ...]):
    if isinstance(value, dict):
        for k in list(value):
            yield value, k
            yield from _spots(value[k], at + (k,))
    elif isinstance(value, list):
        for i in range(len(value)):
            yield value, i
            yield from _spots(value[i], at + (i,))


def leaf_pool(reviews: list[Any], limit: int = 400) -> list[Any]:
    """Values found anywhere in the cells, for drawn reviews to recombine."""

    pool: list[Any] = []
    seen: set[str] = set()
    for review in reviews:
        for container, key in _spots(review, ()):
            value = container[key]
            text = json.dumps(value, sort_keys=True)
            if text not in seen and len(text) < 2000:
                seen.add(text)
                pool.append(value)
            if len(pool) >= limit:
                return pool
    return pool or [FRESH]
