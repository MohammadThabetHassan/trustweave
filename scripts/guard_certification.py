"""Certify the inside verdicts call by call.

Under `docs/GUARD_CERTIFICATION_PROTOCOL.md`, fixed and hashed before any corpus was read with it.
The membership adapters accept a guard family by name; finite refinement holds for some families
whatever fills their operands and for others only when a named operand is a literal, which no
adapter checks. This reads every guard call of every artifact Table 1 judges inside, classifies
each operand as a literal, a read of the request, or computed, and certifies the verdict only when
every call meets the protocol's rule for its language.

    python scripts/guard_certification.py --corpora DIR [--json docs/guard-certification-v1.json]

`--corpora` holds the clones `scripts/clone_pinned_corpora.py` makes. Before certifying, each
corpus is re-measured from that clone and its counts compared with the committed artifact, so a
census over a checkout that does not reproduce the published verdicts says so.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
import xml.etree.ElementTree as ElementTree
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "GUARD_CERTIFICATION_PROTOCOL.md"
# Fixed when the protocol was committed (20a1123), before any corpus was read with it.
PROTOCOL_SHA256 = "a36501613f8e9a93ffd7291bec69fadf7bbb50d683e6bc5eb4380a541bc4779d"

if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

LITERAL, READ, COMPUTED = "literal", "read", "computed"


def protocol_digest(path: Path = PROTOCOL) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def require_protocol() -> None:
    found = protocol_digest()
    if found != PROTOCOL_SHA256:
        raise SystemExit(
            f"{PROTOCOL.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the census "
            "ran; a changed protocol is a different census, so this one refuses to run"
        )


def _load(name: str) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


# --- XACML -------------------------------------------------------------------------------------

XACML_FREE_FAMILIES = (
    "equal-ignore-case",
    "value-equal",
    "greater-than-or-equal",
    "less-than-or-equal",
    "greater-than",
    "less-than",
    "equal",
    "one-and-only",
    "bag-size",
    "bag",
    "is-in",
    "at-least-one-member-of",
    "subset",
    "set-equals",
    "intersection",
    "union",
    "add",
    "subtract",
    "abs",
    "normalize-space",
    "normalize-to-lower-case",
    "from-string",
    "to-string",
    "to-double",
    "to-integer",
    "ip-in-range",
)
XACML_FREE_NAMES = frozenset({"and", "or", "not", "n-of", "floor", "round", "equal"})
XACML_HIGHER_ORDER = frozenset(
    {"any-of", "all-of", "any-of-any", "all-of-any", "any-of-all", "all-of-all"}
)
XACML_UNARY_FREE = ("normalize-space", "normalize-to-lower-case", "to-double", "to-integer")
XACML_LITERAL_FIRST = ("regexp-match", "starts-with", "ends-with", "contains", "match")
XACML_ONE_LITERAL = ("multiply", "divide", "mod")
XACML_DURATION = (
    "add-dayTimeDuration",
    "subtract-dayTimeDuration",
    "add-yearMonthDuration",
    "subtract-yearMonthDuration",
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _function(identifier: str | None) -> str:
    return (identifier or "").rsplit(":", 1)[-1]


def _family(name: str, families: tuple[str, ...]) -> str | None:
    for family in families:
        if name == family or name.endswith(f"-{family}"):
            return family
    return None


def _xacml_arguments(element: ElementTree.Element) -> list[ElementTree.Element]:
    return [child for child in element if _local(child.tag) != "Description"]


def xacml_kind(element: ElementTree.Element) -> str:
    tag = _local(element.tag)
    if tag == "AttributeValue":
        return LITERAL
    if tag.endswith("AttributeDesignator") or tag == "AttributeSelector":
        return READ
    if tag == "Apply":
        name = _function(element.get("FunctionId"))
        arguments = _xacml_arguments(element)
        if name.endswith("-bag") and all(xacml_kind(a) == LITERAL for a in arguments):
            return LITERAL
    return COMPUTED


def xacml_call_issue(name: str, arguments: list[ElementTree.Element]) -> str | None:
    """None when the call is certified, else the family that is not."""

    if name in XACML_HIGHER_ORDER:
        if not arguments or _local(arguments[0].tag) != "Function":
            return name
        return xacml_call_issue(_function(arguments[0].get("FunctionId")), arguments[1:])
    if name == "map":
        if not arguments or _local(arguments[0].tag) != "Function":
            return name
        inner = _function(arguments[0].get("FunctionId"))
        return None if _family(inner, XACML_UNARY_FREE) else "map"
    kinds = [xacml_kind(a) for a in arguments]
    if family := _family(name, XACML_DURATION):
        return None if len(kinds) > 1 and kinds[1] == LITERAL else family
    if family := _family(name, XACML_LITERAL_FIRST):
        return None if kinds and kinds[0] == LITERAL else family
    if family := _family(name, XACML_ONE_LITERAL):
        return None if LITERAL in kinds else family
    if _family(name, ("substring",)):
        return None if len(kinds) > 2 and kinds[1] == kinds[2] == LITERAL else "substring"
    if _family(name, ("concatenate",)):
        return None if sum(1 for kind in kinds if kind != LITERAL) <= 1 else "concatenate"
    if name in XACML_FREE_NAMES or _family(name, XACML_FREE_FAMILIES):
        return None
    return name


def certify_xacml(text: str) -> list[str]:
    """Every uncertified call's family, in document order."""

    root = ElementTree.fromstring(text)
    issues: list[str] = []
    for element in root.iter():
        tag = _local(element.tag)
        if tag == "Apply":
            name = _function(element.get("FunctionId"))
        elif tag.endswith("Match") and element.get("MatchId"):
            name = _function(element.get("MatchId"))
        else:
            continue
        issue = xacml_call_issue(name, _xacml_arguments(element))
        if issue:
            issues.append(issue)
    return issues


# --- Azure Policy ------------------------------------------------------------------------------

AZURE_LITERAL_OPERATORS = frozenset(
    {
        "like",
        "notlike",
        "match",
        "notmatch",
        "matchinsensitively",
        "notmatchinsensitively",
        "contains",
        "notcontains",
    }
)
AZURE_FREE_OPERATORS = frozenset(
    {
        "equals",
        "notequals",
        "in",
        "notin",
        "less",
        "lessorequals",
        "greater",
        "greaterorequals",
        "exists",
        "containskey",
        "notcontainskey",
    }
)
AZURE_FUNCTION_NAMES = (
    ("field", "current", "parameters", "requestContext", "subscription", "resourceGroup"),
    ("concat", "split", "replace", "toLower", "toUpper", "substring", "first", "last"),
    ("length", "empty", "contains", "startsWith", "endsWith", "indexOf", "if", "equals"),
    ("less", "lessOrEquals", "greater", "greaterOrEquals", "and", "or", "not", "int"),
    ("string", "bool", "tryGet", "createArray", "createObject", "array", "union"),
    ("intersection", "ipRangeContains"),
)
AZURE_FUNCTIONS = frozenset(name.lower() for group in AZURE_FUNCTION_NAMES for name in group)
AZURE_READS = re.compile(r"\b(field|current)\s*\(", re.IGNORECASE)


def _arm_inner(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("[[") or not (text.startswith("[") and text.endswith("]")):
        return None
    return text[1:-1]


def azure_expression_issue(inner: str) -> str | None:
    azure = _load("fragment_membership_azure")
    stripped = azure._without_literals(inner)
    names = {name.lower() for name in azure.ARM_CALL.findall(stripped)}
    unknown = sorted(names - AZURE_FUNCTIONS)
    if unknown:
        return f"template function {unknown[0]}"
    if len(AZURE_READS.findall(stripped)) > 1:
        return "template expression reading two fields"
    return None


def _azure_literal(value: Any) -> bool:
    if isinstance(value, list):
        return all(_azure_literal(item) for item in value)
    if isinstance(value, dict):
        return all(_azure_literal(item) for item in value.values())
    inner = _arm_inner(value)
    if inner is None:
        return True
    azure = _load("fragment_membership_azure")
    return not AZURE_READS.search(azure._without_literals(inner))


def certify_azure(text: str) -> list[str]:
    azure = _load("fragment_membership_azure")
    document = azure.document_of(text)
    if document is None:
        return ["not an Azure policy definition"]
    rule = (azure._properties(document) or {}).get("policyRule") or {}
    then = rule.get("then") if isinstance(rule.get("then"), dict) else {}
    details = then.get("details") if isinstance(then.get("details"), dict) else {}
    issues: list[str] = []

    def strings(node: Any) -> Iterator[str]:
        if isinstance(node, dict):
            for value in node.values():
                yield from strings(value)
        elif isinstance(node, list):
            for value in node:
                yield from strings(value)
        elif isinstance(node, str):
            yield node

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        by_lower = {key.lower(): key for key in node}
        for connective in set(by_lower) & azure.CONNECTIVES:
            walk(node[by_lower[connective]])
        for key in set(by_lower) & AZURE_LITERAL_OPERATORS:
            if not _azure_literal(node[by_lower[key]]):
                issues.append(f"{key} with a non-literal operand")
        if "count" in by_lower and isinstance(node[by_lower["count"]], dict):
            walk(node[by_lower["count"]].get("where"))

    for region in (rule.get("if"), details.get("existenceCondition")):
        walk(region)
        for value in strings(region):
            inner = _arm_inner(value)
            if inner is not None and (issue := azure_expression_issue(inner)):
                issues.append(issue)
    return issues


# --- AWS IAM -----------------------------------------------------------------------------------

POLICY_VARIABLE = re.compile(r"\$\{([^}]*)\}")
IAM_ESCAPES = frozenset({"*", "?", "$"})


def certify_iam(text: str) -> list[str]:
    iam = _load("fragment_membership_iam")
    document = iam.document_of(text)
    statements = iam.statements_of(document) if document is not None else None
    issues: list[str] = []
    for statement in statements or []:
        for key in ("Resource", "NotResource", "Condition"):
            for value in iam._strings(statement.get(key)):
                found = [v for v in POLICY_VARIABLE.findall(value) if v not in IAM_ESCAPES]
                if len(found) > 1:
                    issues.append("a pattern with two policy variables")
    return issues


# --- Kyverno -----------------------------------------------------------------------------------

JMESPATH = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)
JMES_FREE = frozenset({"to_upper", "to_lower", "length"})
JMES_LITERAL_ARGUMENT = {
    "contains": 1,
    "starts_with": 1,
    "ends_with": 1,
    "regex_match": 0,
    "split": 1,
}
JMES_READ = re.compile(r"\b(?:request|element)(?:\.[A-Za-z0-9_\-/]+|\[[^\]]*\])+")
CEL_FREE = frozenset({"size", "has", "exists", "all", "exists_one", "lowerAscii", "upperAscii"})
CEL_LITERAL_ARGUMENT = {"startsWith": 0, "endsWith": 0, "contains": 0, "matches": 0, "split": 0}
CEL_READ = re.compile(r"\b(?:object|oldObject|request)(?:\.[A-Za-z0-9_]+|\[[^\]]*\])+")
CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
STRING_LITERAL = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`[^`]*`")
OUTPUT_KEYS = frozenset({"message", "messageExpression", "name", "mutate", "generate"})


def _split_arguments(text: str, start: int) -> list[str]:
    """The top-level arguments of the call whose opening parenthesis is at `start`."""

    depth, current, arguments, quote = 0, [], [], None
    for character in text[start + 1 :]:
        if quote:
            current.append(character)
            if character == quote:
                quote = None
            continue
        if character in "'\"`":
            quote = character
            current.append(character)
        elif character in "([{":
            depth += 1
            current.append(character)
        elif character in ")]}":
            if depth == 0:
                arguments.append("".join(current).strip())
                return [argument for argument in arguments if argument]
            depth -= 1
            current.append(character)
        elif character == "," and depth == 0:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    return arguments


def _is_literal_text(argument: str) -> bool:
    argument = argument.strip()
    if STRING_LITERAL.fullmatch(argument):
        return True
    return bool(re.fullmatch(r"-?\d+(\.\d+)?", argument))


def _expression_issues(
    expression: str,
    free: frozenset[str],
    literal_argument: dict[str, int],
    reads: re.Pattern[str],
    label: str,
) -> list[str]:
    masked = STRING_LITERAL.sub(lambda m: "_" * len(m.group(0)), expression)
    issues: list[str] = []
    for match in CALL.finditer(masked):
        name = match.group(1)
        if name in free:
            continue
        if name in literal_argument:
            arguments = _split_arguments(expression, match.end() - 1)
            index = literal_argument[name]
            if index < len(arguments) and _is_literal_text(arguments[index]):
                continue
        issues.append(f"{label} {name}")
    if len(set(reads.findall(masked))) > 1:
        issues.append(f"{label} reading two request paths")
    return issues


def certify_kyverno(text: str) -> list[str]:
    issues: list[str] = []

    def walk(node: Any, key: str | None = None, in_cel: bool = False) -> None:
        if isinstance(node, dict):
            for name, value in node.items():
                if name in OUTPUT_KEYS:
                    continue
                walk(value, name, in_cel or name in ("cel", "validations", "matchConditions"))
        elif isinstance(node, list):
            for item in node:
                walk(item, key, in_cel)
        elif isinstance(node, str):
            if in_cel and key == "expression":
                issues.extend(
                    _expression_issues(node, CEL_FREE, CEL_LITERAL_ARGUMENT, CEL_READ, "CEL")
                )
                return
            for expression in JMESPATH.findall(node):
                issues.extend(
                    _expression_issues(
                        expression, JMES_FREE, JMES_LITERAL_ARGUMENT, JMES_READ, "JMESPath"
                    )
                )

    for document in yaml.safe_load_all(text):
        if isinstance(document, dict):
            walk(document.get("spec"))
    return issues


# --- Rego --------------------------------------------------------------------------------------

REGO_FREE = frozenset(
    {
        "equal",
        "neq",
        "lt",
        "lte",
        "gt",
        "gte",
        "plus",
        "minus",
        "abs",
        "round",
        "ceil",
        "floor",
        "count",
        "max",
        "min",
        "and",
        "or",
        "intersection",
        "union",
        "lower",
        "upper",
        "trim_space",
        "is_string",
        "is_number",
        "is_boolean",
        "is_array",
        "is_set",
        "is_object",
        "is_null",
        "type_name",
        "array.concat",
        "eq",
        "assign",
        "internal.member_2",
        "internal.member_3",
    }
)
REGO_LITERAL_ARGUMENT = {
    "startswith": 1,
    "endswith": 1,
    "contains": 1,
    "glob.match": 0,
    "regex.match": 0,
    "trim": 1,
    "trim_left": 1,
    "trim_right": 1,
    "trim_prefix": 1,
    "trim_suffix": 1,
    "split": 1,
    "net.cidr_contains": 0,
    "object.get": 1,
}
REGO_ONE_LITERAL = frozenset({"mul", "div", "rem"})
REGO_DEBUG = frozenset({"print", "trace"})
REGO_SCALARS = frozenset({"string", "number", "boolean", "null"})
PARAMETER_HELPERS = ("get_constraint_params", "get_default")


def _vars_in(node: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        if node.get("type") == "var" and isinstance(node.get("value"), str):
            found.add(node["value"])
        for value in node.values():
            found |= _vars_in(value)
    elif isinstance(node, list):
        for value in node:
            found |= _vars_in(value)
    return found


def _operator_name(term: dict[str, Any]) -> str:
    rego = _load("fragment_membership_rego")
    return ".".join(name for name in rego._tokens(term) if name)


class RegoRule:
    """One rule's guard calls, with the operand kinds the protocol needs."""

    def __init__(self, rule: dict[str, Any], builtins: frozenset[str]) -> None:
        self.rule = rule
        self.builtins = builtins
        self.body = list(rule.get("body") or [])
        self.literal_vars: set[str] = set()
        self.parameter_vars: set[str] = set()
        self._bindings()

    def _bindings(self) -> None:
        for expression in self.body:
            terms = expression.get("terms")
            if not isinstance(terms, list) or not terms:
                continue
            name = _operator_name(terms[0]) if terms[0].get("type") == "ref" else ""
            if name in ("assign", "eq") and len(terms) == 3:
                left, right = terms[1], terms[2]
                if left.get("type") == "var":
                    kind = self.kind(right)
                    if kind == LITERAL and right.get("type") in REGO_SCALARS:
                        self.literal_vars.add(left["value"])
                    elif self._is_parameters(right):
                        self.parameter_vars.add(left["value"])
            elif name.endswith(PARAMETER_HELPERS) and terms[-1].get("type") == "var":
                self.parameter_vars.add(terms[-1]["value"])

    def _is_parameters(self, term: dict[str, Any]) -> bool:
        rego = _load("fragment_membership_rego")
        if term.get("type") == "ref":
            tokens = rego._tokens(term)
            if tokens[:2] == ["input", "parameters"] or tokens[:2] == ["input", "constraint"]:
                return True
            return bool(tokens) and tokens[0] in self.parameter_vars
        if term.get("type") == "call":
            value = term.get("value") or []
            return bool(value) and _operator_name(value[0]).endswith(PARAMETER_HELPERS)
        return False

    def kind(self, term: dict[str, Any]) -> str:
        rego = _load("fragment_membership_rego")
        kind = term.get("type")
        if kind in REGO_SCALARS:
            return LITERAL
        if kind in ("array", "set"):
            items = term.get("value") or []
            return LITERAL if all(self.kind(item) == LITERAL for item in items) else COMPUTED
        if kind == "object":
            pairs = term.get("value") or []
            literal = all(
                self.kind(pair[0]) == LITERAL and self.kind(pair[1]) == LITERAL
                for pair in pairs
                if isinstance(pair, list) and len(pair) == 2
            )
            return LITERAL if literal else COMPUTED
        if kind == "var":
            name = term.get("value")
            return LITERAL if name in self.literal_vars | self.parameter_vars else COMPUTED
        if kind == "ref":
            if self._is_parameters(term):
                return LITERAL
            tokens = rego._tokens(term)
            if tokens and tokens[0] == "input":
                return READ
            if tokens and tokens[0] in self.literal_vars:
                return LITERAL
            return COMPUTED
        return COMPUTED

    def _output_only(self, index: int, expression: dict[str, Any], head_vars: set[str]) -> bool:
        terms = expression.get("terms")
        if not isinstance(terms, list) or len(terms) < 2:
            return False
        name = _operator_name(terms[0]) if terms[0].get("type") == "ref" else ""
        target = terms[1] if name in ("assign", "eq") and len(terms) == 3 else terms[-1]
        if target.get("type") != "var" or target.get("value") not in head_vars:
            return False
        others = [e for i, e in enumerate(self.body) if i != index]
        return target["value"] not in _vars_in(others)

    def issues(self) -> list[str]:
        head_vars = _vars_in(self.rule.get("head") or {})
        found: list[str] = []

        def check(term: dict[str, Any]) -> None:
            if term.get("type") == "call":
                value = term.get("value") or []
                if value:
                    self._check_call(_operator_name(value[0]), value[1:], found)
                for item in value[1:]:
                    check(item)
                return
            for item in term.values() if isinstance(term, dict) else []:
                if isinstance(item, dict):
                    check(item)
                elif isinstance(item, list):
                    for element in item:
                        if isinstance(element, dict):
                            check(element)

        for index, expression in enumerate(self.body):
            if self._output_only(index, expression, head_vars):
                continue
            terms = expression.get("terms")
            if isinstance(terms, list) and terms and terms[0].get("type") == "ref":
                self._check_call(_operator_name(terms[0]), terms[1:], found)
                for term in terms[1:]:
                    check(term)
            elif isinstance(terms, dict):
                check(terms)
        return found

    def _check_call(self, name: str, arguments: list[dict[str, Any]], found: list[str]) -> None:
        if name in REGO_DEBUG or name not in self.builtins:
            return  # a user function's body is a rule of its own, reached separately
        if name in REGO_FREE:
            return
        if name in REGO_LITERAL_ARGUMENT:
            index = REGO_LITERAL_ARGUMENT[name]
            if index < len(arguments) and self.kind(arguments[index]) == LITERAL:
                return
            found.append(name)
            return
        if name in REGO_ONE_LITERAL:
            if any(self.kind(argument) == LITERAL for argument in arguments):
                return
            found.append(name)
            return
        found.append(name)


def rego_census(root: Path, inside: set[str]) -> dict[str, list[str]]:
    """Every inside module's uncertified calls, over the rules its own rules reach."""

    rego = _load("fragment_membership_rego")
    discovered = rego.discover(root)  # fills the package tables the resolution reads
    builtins = rego.builtins()
    index: dict[tuple[str, str], list[tuple[dict[str, Any], str, dict[str, list[str]]]]] = {}
    asts: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*.rego")):
        if ".git" in path.parts:
            continue
        ast = rego.parse(path.read_text(encoding="utf-8", errors="ignore"))
        if ast is None:
            continue
        asts[path.relative_to(root).as_posix()] = ast
        package = rego.package_of(ast)
        aliases = rego._alias_map(ast)
        for rule in ast.get("rules") or []:
            name = ((rule.get("head") or {}).get("name")) or ""
            if not name:
                tokens = [
                    t
                    for t in rego._tokens(
                        {"type": "ref", "value": (rule.get("head") or {}).get("ref") or []}
                    )
                    if t
                ]
                name = tokens[0] if tokens else ""
            index.setdefault((package, name), []).append((rule, package, aliases))

    results: dict[str, list[str]] = {}
    for subject, _ in discovered:
        if subject not in inside:
            continue
        ast = asts.get(subject)
        if ast is None:
            results[subject] = ["module does not parse"]
            continue
        package = rego.package_of(ast)
        aliases = rego._alias_map(ast)
        frontier = [(rule, package, aliases) for rule in ast.get("rules") or []]
        seen: set[int] = set()
        issues: list[str] = []
        while frontier:
            rule, rule_package, rule_aliases = frontier.pop()
            if id(rule) in seen:
                continue
            seen.add(id(rule))
            issues.extend(RegoRule(rule, builtins).issues())
            for target in rego.referenced_rules(rule, rule_package, rule_aliases):
                frontier.extend(index.get(target, []))
        results[subject] = issues
    return results


# --- the census --------------------------------------------------------------------------------

CERTIFIERS: dict[str, Callable[[str], list[str]]] = {
    "xacml": certify_xacml,
    "azure": certify_azure,
    "iam": certify_iam,
    "kyverno": certify_kyverno,
}


def _reproduce(stem: str, artifact: dict[str, Any], corpora: Path) -> tuple[Path, dict[str, Any]]:
    provenance = _load("verify_corpus_provenance")
    membership = provenance._membership()
    available = provenance.checkouts(corpora)
    repositories = [available[entry["commit"]] for entry in artifact["corpus"]]
    root = provenance._measurement_root(repositories)
    fresh = membership.measure(
        membership.load_adapter(str(artifact["ecosystem"])), root, None, wide=True
    )
    return root, fresh


def census(corpora: Path) -> dict[str, Any]:
    require_protocol()
    taxonomy = _load("exclusion_taxonomy")
    measure = _load("measure_third_party_policies")
    rows: list[dict[str, Any]] = []
    uncertified_by_subject: dict[str, dict[str, str]] = {}
    for label, stem in taxonomy.CORPORA:
        artifact = json.loads((DOCS / f"{stem}.json").read_text("utf-8"))
        ecosystem = artifact["ecosystem"]
        inside = {e["subject"] for e in artifact["policies"] if e["verdict"] == "inside"}
        row: dict[str, Any] = {"corpus": label, "artifact": stem, "inside": len(inside)}
        issues_of: dict[str, list[str]] = {}
        if ecosystem == "cedar":
            row["argument"] = "the designers' sound and complete logical encoding"
            issues_of = {subject: [] for subject in inside}
        elif artifact.get("corpus_scope") == "third-party":
            files = json.loads((DOCS / "third-party-kyverno-corpus-v1.json").read_text("utf-8"))
            for entry in files["files"]:
                subject = f"{entry['repo']}/{entry['path']}"
                if subject not in inside:
                    continue
                content, _ = measure.fetch_bytes(entry)
                if content is None or hashlib.sha256(content).hexdigest() != entry["sha256"]:
                    issues_of[subject] = ["text not recovered"]
                    continue
                issues_of[subject] = certify_kyverno(content.decode("utf-8", "replace"))
        else:
            root, fresh = _reproduce(stem, artifact, corpora)
            row["reproduced"] = fresh["counts"] == artifact["counts"]
            if ecosystem == "rego":
                issues_of = rego_census(root, inside)
            else:
                membership = _load("verify_corpus_provenance")._membership()
                adapter = membership.load_adapter(ecosystem)
                discovery = membership.discovery_for(adapter, True)
                seen: set[str] = set()
                for subject, path in discovery(root):
                    if subject in seen or subject not in inside:
                        continue
                    seen.add(subject)
                    text = path.read_text(encoding="utf-8", errors="ignore")
                    try:
                        issues_of[subject] = CERTIFIERS[ecosystem](text)
                    except (ElementTree.ParseError, yaml.YAMLError) as error:
                        issues_of[subject] = [f"does not parse: {type(error).__name__}"]
        missing = sorted(inside - set(issues_of))
        for subject in missing:
            issues_of[subject] = ["text not recovered"]
        certified = sorted(s for s, issues in issues_of.items() if not issues)
        families = Counter(issue for issues in issues_of.values() for issue in set(issues))
        row.update(
            {
                "certified": len(certified),
                "uncertified": len(issues_of) - len(certified),
                "not_recovered": sum(
                    1 for issues in issues_of.values() if issues == ["text not recovered"]
                ),
                "uncertified_families": dict(families.most_common()),
            }
        )
        rows.append(row)
        uncertified_by_subject[stem] = {
            subject: issues[0] for subject, issues in sorted(issues_of.items()) if issues
        }
    inside_total = sum(row["inside"] for row in rows)
    certified_total = sum(row["certified"] for row in rows)
    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "rows": rows,
        "inside": inside_total,
        "certified": certified_total,
        "share_certified_of_inside": round(certified_total / inside_total, 4),
        "every_corpus_reproduced": all(row.get("reproduced", True) for row in rows),
        "first_uncertified_call": uncertified_by_subject,
        "deviations": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpora", type=Path, required=True)
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)
    findings = census(arguments.corpora.resolve())
    text = json.dumps(findings, indent=2, sort_keys=True) + "\n"
    if arguments.json:
        arguments.json.write_text(text, encoding="utf-8")
    for row in findings["rows"]:
        print(
            f"{row['corpus']:24s} inside {row['inside']:5d}  certified {row['certified']:5d}  "
            f"reproduced {row.get('reproduced', '-')}"
        )
    print(f"certified {findings['certified']} of {findings['inside']} inside verdicts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
