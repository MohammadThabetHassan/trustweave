"""Source mutations of a Rego module, located by the AST `opa parse` produces.

This is the mutation engine for the suite-adequacy study (`scripts/rego_suite_study.py`),
and it is deliberately separate from `scripts/rego_mutation.py`. That module edits source by
text search over a fixed operator list (`==`->`!=`, `true`->`false`, and so on) for the
decision-blindness prediction of the suite-coverage study. This one locates every rule,
expression, operator and literal through `opa parse --json-include locations` and edits the
exact span, which lets it add operators the text set cannot express safely -- deleting a rule,
dropping or negating a whole condition, replacing a literal -- and avoids the hazard that
module documents, editing an operator that happens to sit inside a string literal. The two
measure different things and are reported separately.

A mutation is a byte-range replacement in the source text, not a rewrite of an AST we would
then have to print back to Rego (`opa` cannot print its JSON AST back to source). A mutant
that no longer parses is stillborn and is dropped, so every mutant returned is a module the
engine will load; the suite is what decides whether it is killed.

The module shells out to `opa`; it does not import the engine, so it is cheap to import.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Rego's infix comparisons, by the builtin name `opa parse` gives each one. The value is the
# source token and the name of the comparison it becomes under its negation -- the De Morgan
# flip a suite that only exercises one side does not separate.
_COMPARISONS = {
    "equal": ("==", "neq"),
    "eq": ("==", "neq"),
    "neq": ("!=", "equal"),
    "lt": ("<", "gte"),
    "lte": ("<=", "gt"),
    "gt": (">", "lte"),
    "gte": (">=", "lt"),
}
_TOKENS = {"equal": "==", "eq": "==", "neq": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
_STRICTNESS = {"lt": "lte", "lte": "lt", "gt": "gte", "gte": "gt"}


def _opa() -> str:
    found = shutil.which("opa")
    if found is None:
        raise SystemExit("opa is not on PATH; install it to run the rego source mutation module")
    return found


def parse(source: str) -> tuple[dict[str, Any], bool] | None:
    """The AST with locations, and whether v0 syntax was needed; None if it will not parse."""

    # Written byte for byte: a platform that turns "\n" into "\r\n" in text mode would give
    # every multi-line location text a "\r" the source has not got, and its edits would not
    # apply.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".rego", delete=False, encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(source)
        path = handle.name
    try:
        for v0 in (False, True):
            command = [_opa(), "parse", path, "--format", "json", "--json-include", "locations"]
            if v0:
                command.insert(2, "--v0-compatible")
            done = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if done.returncode == 0 and done.stdout.strip():
                return json.loads(done.stdout), v0
        return None
    finally:
        Path(path).unlink(missing_ok=True)


def _line_starts(source: bytes) -> list[int]:
    starts = [0]
    for index, byte in enumerate(source):
        if byte == 0x0A:
            starts.append(index + 1)
    return starts


def _offset(starts: list[int], row: int, col: int) -> int:
    return starts[row - 1] + (col - 1)


def _span(loc: dict[str, Any] | None) -> tuple[int, int, bytes] | None:
    """A location's (row, col) and the exact bytes it spans, from its base64 text."""

    if not loc or not loc.get("text"):
        return None
    return loc["row"], loc["col"], base64.b64decode(loc["text"])


@dataclass(frozen=True)
class Mutant:
    operator: str
    detail: str
    source: str


class _SpanMismatch(Exception):
    """A location's recorded text did not match the source at its row and column."""


def _edit(source: bytes, starts: list[int], span: tuple[int, int, bytes], new: bytes) -> bytes:
    row, col, old = span
    start = _offset(starts, row, col)
    if source[start : start + len(old)] != old:
        raise _SpanMismatch
    return source[:start] + new + source[start + len(old) :]


def _comparison_edits(expr: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any], bytes]]:
    terms = expr.get("terms")
    if not isinstance(terms, list) or len(terms) != 3 or terms[0].get("type") != "ref":
        return
    ref = terms[0]["value"]
    if len(ref) != 1 or ref[0].get("type") != "var":
        return
    name = ref[0].get("value")
    if name not in _COMPARISONS:
        return
    location = terms[0].get("location")
    if not location:
        return
    _, negation = _COMPARISONS[name]
    yield "flip a comparison to its negation", location, _TOKENS[negation].encode()
    if name in _STRICTNESS:
        yield "change a comparison's strictness", location, _TOKENS[_STRICTNESS[name]].encode()


def _is_assignment(expr: dict[str, Any]) -> bool:
    terms = expr.get("terms")
    if not isinstance(terms, list) or not terms or terms[0].get("type") != "ref":
        return False
    ref = terms[0]["value"]
    return len(ref) == 1 and ref[0].get("value") in ("assign", "eq")


def _condition_edits(expr: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any], bytes]]:
    """Drop or negate a boolean condition. Assignments are left alone: replacing one would
    leave a variable the rest of the rule reads unbound, which is a parse-time or eval-time
    failure rather than a behaviour change the suite should be judged on."""

    location = expr.get("location")
    span = _span(location)
    if not location or span is None or _is_assignment(expr):
        return
    text = span[2]
    yield "drop a condition", location, b"true"
    if expr.get("negated"):
        if text.startswith(b"not "):
            yield "remove a negation", location, text[len(b"not ") :]
    else:
        yield "negate a condition", location, b"not " + text


def _literal_edits(term: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any], bytes]]:
    location = term.get("location")
    if not location or not location.get("text"):
        return
    kind, value = term.get("type"), term.get("value")
    if kind == "boolean":
        yield "flip a boolean literal", location, (b"false" if value else b"true")
    elif kind == "number" and isinstance(value, (int, float)):
        yield "change a number literal", location, f"{int(value) + 1}".encode()
    elif kind == "string" and isinstance(value, str):
        other = "tw-mutant" if value != "tw-mutant" else "tw-other"
        yield "change a string literal", location, f'"{other}"'.encode()


def _terms(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        if node.get("type") in ("number", "string", "boolean") and node.get("location"):
            yield node
        for value in node.values():
            yield from _terms(value)
    elif isinstance(node, list):
        for value in node:
            yield from _terms(value)


def mutants(source: str) -> list[Mutant]:
    """Every parsing mutant of the module, one source edit each."""

    parsed = parse(source)
    if parsed is None:
        return []
    ast, _ = parsed
    raw = source.encode("utf-8")
    starts = _line_starts(raw)
    seen: set[str] = set()
    out: list[Mutant] = []

    def add(operator: str, detail: str, span: tuple[int, int, bytes], new: bytes) -> None:
        try:
            edited = _edit(raw, starts, span, new).decode("utf-8")
        except (_SpanMismatch, UnicodeDecodeError):
            return
        if edited == source or edited in seen:
            return
        if parse(edited) is None:  # a stillborn mutant the engine would not load
            return
        seen.add(edited)
        out.append(Mutant(operator, detail, edited))

    for rule in ast.get("rules", []):
        rule_span = _span(rule.get("location"))
        if rule_span is not None:
            head = rule.get("head", {})
            name = (
                ".".join(str(part.get("value")) for part in head.get("ref", []) if part) or "rule"
            )
            add("delete a rule", f"remove rule {name}", rule_span, b"")
        for expr in rule.get("body", []):
            for detail, location, new in _comparison_edits(expr):
                span = _span(location)
                if span is not None:
                    add(
                        "flip a comparison" if detail.startswith("flip") else "change a comparison",
                        detail,
                        span,
                        new,
                    )
            for detail, location, new in _condition_edits(expr):
                span = _span(location)
                if span is not None:
                    add(detail, detail, span, new)
        for term in _terms(rule):
            for detail, location, new in _literal_edits(term):
                span = _span(location)
                if span is not None:
                    add(detail, detail, span, new)
    return out
