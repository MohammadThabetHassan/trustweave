"""Rego fragment membership: a guard is inside when it reads only `input` and literals.

The other three adapters read a declarative document. Rego is a language, so this one
reads the AST `opa parse` produces rather than the text, and resolves references across
the whole bundle instead of one file at a time.

What leaves the fragment, in the order it actually occurs in published policy:

A constraint template states its guard against values a *Constraint* supplies later --
allowed repositories, permitted profiles, numeric ranges -- and it needs stating carefully,
because the obvious reason to exclude it is the wrong one. It is tempting to call that "a
pattern taken from the input" and be done. That does not survive the definition: if the
parameters arrive in the input document, the guard's outcome map over that document still
has finite image with witnesses computable from the guard's syntax, which is all finite
refinement asks.

The real reason is that such a template is not a policy. It is a policy *schema* -- a
function from parameter bindings to policies -- and it determines no decision function until
a Constraint is applied. Membership is a property of a policy, so the artifact has to be
instantiated before the question can be asked of it.

The criterion has to be the same one the Azure adapter applies, or the two corpora are not
comparable: an artifact is a schema when it reads a parameter *the policy supplies no
default for*. A parameter read through `object.get(input.parameters, "key", literal)` or
through Config Validator's `lib.get_default(params, "key", literal)` carries its own
instantiation, exactly as an Azure `defaultValue` does, and a template every one of whose
parameter reads is defaulted determines a decision function with nothing supplied. So the
line does not fall at "reads parameters"; it falls at "reads a parameter with no default".
Gatekeeper passes parameters at `input.parameters`; Google's Config Validator passes the
whole Constraint at `input.constraint` and templates take `.spec.parameters` from it,
usually through `lib.get_constraint_params`. The first version of this adapter knew only
the Gatekeeper plumbing, so it called every Config Validator template a policy and every
Gatekeeper template a schema, which is the same construct classified two ways.

For each schema the adapter records the Constraints in the corpus that supply its
parameters, so the claim that the instantiation exists can be checked rather than asserted.

That is a different kind of exclusion from the one below, and the two should not be pooled
without saying so: a schema is not outside the fragment, it is not yet a policy.

`data.inventory` is the cluster state Gatekeeper caches and injects at evaluation time. The
corpus contains a fixture that mocks it out, whose own comment says so, which is the
clearest available evidence that the real thing is not in the policy.

A policy reaches outside through a library when a rule it *evaluates* does, and the unit of
propagation is the rule, not the import. The first version of this adapter propagated along
imports: a module importing a library any rule of which read outside was outside itself.
That is the wrong granularity in both directions, and the differential check against `opa
deps` found one case of each. `redhat-cop`'s `lib.openshift` has one helper reading
`data.inventory` and a dozen reading only the request; twenty-four policies call the first,
one calls only the second, and the import graph excluded all twenty-five. And a module
importing a package *prefix* -- `data.istio.audit.vetter`, with the reading rules in packages
beneath it -- was never matched to them at all, so a policy whose every verdict comes from
cluster state was recorded inside. Propagating along referenced rules, resolved through each
module's import aliases, gets both right, and the engine's dependency analysis agrees on
every module.

A builtin whose result is not a function of its arguments -- the clock, the network, the
OS environment, entropy -- is outside for the same reason. Note that most of the `time.*`
and `net.*` namespaces are *not* in this category: `time.parse_rfc3339_ns` and
`net.cidr_contains` compute from what they are given. Which builtins do reach past their
arguments is taken from the engine's own capabilities document rather than kept by hand;
see `nondeterministic_builtins` for why.

One shape of call needs naming because the first version of this adapter did not see it. A
Rego statement `f(x, out)` -- a call whose output is its last argument, in the v0 style, or
one whose result is simply not assigned -- is not a `call` node in the AST. It is a bare list
of terms headed by the function's reference, and only calls nested inside another term are
wrapped as `call`. A walker that looks for the wrapped form alone therefore never sees
`http.send(request, response)` at the top of a rule body, and one published module that
does exactly that was recorded inside the fragment. The differential check against `opa
deps` in `scripts/oracle_rego.py` is what found it.

Everything else -- a comparison against a literal, a set membership, `startswith` against a
literal prefix, a regex the policy writes down, arithmetic, a comprehension over the request
-- keeps the partition fixed by the policy text.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml
from fragment_membership import INSIDE, OUTSIDE, UNDETERMINED, Verdict

ECOSYSTEM = "rego"

# Builtins whose result is not a function of their arguments, as this adapter first listed
# them by hand. The engine's own capabilities document is the source now (see
# `nondeterministic_builtins`); this set is kept as a floor for an `opa` too old to flag them.
NONDETERMINISTIC_BUILTINS = frozenset(
    {
        "http.send",
        "net.lookup_ip_addr",
        "time.now_ns",
        "rand.intn",
        "opa.runtime",
    }
)

# What each such builtin reaches for. The taxonomy keeps the clock apart from the rest --
# the clock is state that does not exist until evaluation, not state some subject could have
# carried -- and a network response or a random number is the same kind of thing.
EVALUATION_TIME_STATE: dict[str, str] = {
    "time.now_ns": "the clock",
    "io.jwt.decode_verify": "the clock",
    "http.send": "the network",
    "net.lookup_ip_addr": "the network",
    "rand.intn": "entropy",
    "uuid.rfc4122": "entropy",
    "io.jwt.encode_sign": "entropy",
    "io.jwt.encode_sign_raw": "entropy",
    "opa.runtime": "the runtime environment",
}

# Document roots supplied by the host at evaluation time rather than written in the policy.
EXTERNAL_DOCUMENT_ROOTS = ("inventory",)

# Where a Constraint's parameters arrive. Gatekeeper puts the parameter block at
# `input.parameters`; Config Validator passes the whole Constraint at `input.constraint` and
# a template reads `.spec.parameters` from it, usually through `lib.get_constraint_params`.
CONSTRAINT_PARAMETERS = ("input", "parameters")
CONFIG_VALIDATOR_PARAMETERS = ("input", "constraint", "spec", "parameters")
PARAMETER_ROOTS = (CONSTRAINT_PARAMETERS, CONFIG_VALIDATOR_PARAMETERS)
PARAMETER_FETCHERS = frozenset({"get_constraint_params"})
# Reading a parameter through one of these, with a literal default, is what makes the read
# complete: the template decides something when no Constraint supplies the key.
DEFAULTING_FUNCTIONS = frozenset({"get", "get_default"})
GUARDING_FUNCTIONS = frozenset({"has_field"})

_CAPABILITIES: dict[str, Any] | None = None
_BUILTINS: frozenset[str] | None = None
_NONDETERMINISTIC: frozenset[str] | None = None

# Corpus-wide facts, populated by `discover` and consulted by `classify`: which packages
# the bundle declares, what each package imports, and which packages reach outside. A
# policy that calls a library which reaches outside is outside itself, so the verdicts
# have to propagate along the import graph rather than stopping at one file.
_DECLARED_PACKAGES: set[str] = set()
_PACKAGE_RULES: dict[str, set[str]] = {}
# Rule-level reach, computed once per corpus: which (package, rule) pairs read outside,
# directly or through the rules they reference, and the terminal cause for each.
_RULE_CAUSE: dict[tuple[str, str], tuple[tuple[str, str], str]] = {}
# Constraints that supply parameters. Gatekeeper's are keyed by the policy directory's
# name -- a template and its Constraint sit in different trees, `src/general/<name>/` and
# `library/general/<name>/samples/*/`, so they match by name rather than by path. Config
# Validator's are keyed by the Constraint's `kind`, which is the last segment of the
# template's package. Which policy a subject is, and so which key applies, is recorded per
# subject by `discover`.
_CONSTRAINTS: dict[str, list[str]] = {}
_CONSTRAINTS_BY_KIND: dict[str, list[str]] = {}
_SUBJECT_PACKAGE: dict[str, str] = {}


def _opa() -> str:
    found = shutil.which("opa")
    if not found:
        raise SystemExit("opa is not on PATH; install it to run the rego adapter")
    return found


def _capabilities() -> dict[str, Any]:
    """The engine's capabilities document, read once."""

    global _CAPABILITIES
    if _CAPABILITIES is None:
        completed = subprocess.run(
            [_opa(), "capabilities", "--current"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if completed.returncode != 0:
            raise SystemExit("could not read opa capabilities")
        _CAPABILITIES = json.loads(completed.stdout)
    return _CAPABILITIES


def builtins() -> frozenset[str]:
    """OPA's own builtin names, from the binary rather than from a hand-kept list."""

    global _BUILTINS
    if _BUILTINS is None:
        _BUILTINS = frozenset(entry["name"] for entry in _capabilities().get("builtins", []))
    return _BUILTINS


def nondeterministic_builtins() -> frozenset[str]:
    """Builtins whose result is not a function of their arguments, from the engine.

    OPA flags these itself in its capabilities document, and the engine's list is longer
    than the one this adapter kept by hand: it also names the JWT verification and signing
    builtins and `uuid.rfc4122`. None of the measured corpora calls those four, so no
    verdict turned on the difference -- but an instrument that asserts by hand what the
    engine already states is an instrument with a gap waiting for the corpus that exercises
    it. The hand list is kept as a floor for an `opa` old enough to lack the flag.
    """

    global _NONDETERMINISTIC
    if _NONDETERMINISTIC is None:
        flagged = {
            entry["name"]
            for entry in _capabilities().get("builtins", [])
            if entry.get("nondeterministic")
        }
        _NONDETERMINISTIC = frozenset(flagged | NONDETERMINISTIC_BUILTINS)
    return _NONDETERMINISTIC


def parse(source: str) -> dict[str, Any] | None:
    """The AST for one Rego module, or None when it does not parse.

    OPA 1.x parses Rego v1 by default, which wants `if` before a rule body. Most published
    policy predates that, so a v1-only reader measures almost nothing; try v1 then v0,
    exactly as scripts/suite_coverage_rego.py does.
    """

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "module.rego"
        path.write_text(source, encoding="utf-8")
        for arguments in (
            [_opa(), "parse", str(path), "--format", "json"],
            [_opa(), "parse", "--v0-compatible", str(path), "--format", "json"],
        ):
            try:
                completed = subprocess.run(
                    arguments, check=False, capture_output=True, text=True, timeout=60
                )
            except (OSError, subprocess.TimeoutExpired):
                return None
            if completed.returncode == 0 and completed.stdout.strip():
                try:
                    return json.loads(completed.stdout)
                except json.JSONDecodeError:
                    continue
    return None


def _tokens(term: dict[str, Any]) -> list[str | None]:
    """A ref's path as a list of names, with None for a computed index.

    Only the head of a reference is a name. Every later part is either a string -- a static
    key, `input.review.object` -- or something computed: a variable, a number, a nested
    call. `vetter[_].info[result]` indexes a package prefix by a variable, and reading that
    variable as if it were the key `_` is how a policy whose every result comes from cluster
    state was resolved to nothing and recorded inside the fragment.
    """

    names: list[str | None] = []
    for index, part in enumerate(term.get("value") or []):
        value = part.get("value")
        if index == 0:
            names.append(value if isinstance(value, str) else None)
        else:
            names.append(value if part.get("type") == "string" and isinstance(value, str) else None)
    return names


def package_of(ast: dict[str, Any]) -> str:
    """The module's package, without OPA's leading `data.`.

    Package paths, import paths and `data.` references are all normalised the same way --
    with the `data.` root dropped -- because they are compared against each other. Keeping
    it on one and not the others is why the first version of this adapter resolved nothing
    and reported the bundle's own `lib.konstraint.core` as an external document.
    """

    parts = [
        term.get("value")
        for term in (ast.get("package") or {}).get("path") or []
        if isinstance(term.get("value"), str)
    ]
    return ".".join(parts).removeprefix("data.")


def imports_of(ast: dict[str, Any]) -> list[str]:
    """The dotted paths this module imports, normalised like `package_of`."""

    found = []
    for entry in ast.get("imports") or []:
        names = [name for name in _tokens(entry.get("path") or {}) if name]
        if names:
            found.append(".".join(names).removeprefix("data."))
    return found


def rule_names(ast: dict[str, Any]) -> set[str]:
    """Every rule and function this module defines.

    A head carries `name` for a plain rule and `ref` -- a bare list of terms, not a
    wrapped ref -- for a dotted one. Both forms appear in the measured corpora.
    """

    names: set[str] = set()
    for rule in ast.get("rules") or []:
        head = rule.get("head") or {}
        name = head.get("name")
        if isinstance(name, str):
            names.add(name)
        for term in head.get("ref") or []:
            value = term.get("value") if isinstance(term, dict) else None
            if isinstance(value, str):
                names.add(value)
    return names


def is_test_module(ast: dict[str, Any], path: Path | None = None) -> bool:
    """Whether this module is a test rather than a policy.

    `opa test` discovers cases by their `test_` prefix, so a module defining even one such
    rule is a test module -- requiring *every* rule to be one is too weak, because a test
    file also defines its fixtures: the corpus's `src_test.rego` holds fourteen `test_`
    rules beside helpers like `input_review`, and that shape let fifty-one test files into
    the policy corpus on the first attempt.

    The filename is checked too, since the corpora use `*_test.rego` and `test_*.rego`
    interchangeably, and neither check subsumes the other.
    """

    if path is not None and (path.name.endswith("_test.rego") or path.name.startswith("test_")):
        return True
    return any(name.startswith("test_") for name in rule_names(ast))


def references_and_calls(ast: dict[str, Any]) -> tuple[list[list[str | None]], set[str]]:
    """Every `data`/`input` reference path, and every function name called."""

    references: list[list[str | None]] = []
    calls: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            # A statement `f(x, out)` -- a call whose output is its last argument, or whose
            # result is not assigned -- is a bare list of terms headed by the function's
            # ref, not a `call` node. Only nested calls are wrapped. Looking for the wrapped
            # form alone is how `http.send(request, response)` at the top of a rule body went
            # unseen and a module making network calls was recorded inside the fragment.
            terms = node.get("terms")
            if isinstance(terms, list) and len(terms) > 1 and terms[0].get("type") == "ref":
                names = _tokens(terms[0])
                if all(isinstance(name, str) for name in names):
                    calls.add(".".join(name for name in names if name))
            if node.get("type") == "call":
                operands = node.get("value") or []
                if operands and operands[0].get("type") == "ref":
                    names = _tokens(operands[0])
                    if all(isinstance(name, str) for name in names):
                        calls.add(".".join(name for name in names if name))
                for operand in operands[1:]:
                    walk(operand)
                return
            if node.get("type") == "ref":
                names = _tokens(node)
                if names and names[0] in ("data", "input"):
                    references.append(names)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(ast)
    return references, calls


def parameter_reads(ast: dict[str, Any]) -> dict[str, list[str]]:
    """How this module reads Constraint parameters: which keys raw, which with a default.

    Returns `without_default`, `with_default` and `guarded` key lists, plus `whole` for the
    functions outside this module the parameter block was handed to entire. A key is read
    raw when it is indexed directly -- `input.parameters.repos`, `params.allowed` -- and
    with a default when it is read through `object.get` or Config Validator's
    `lib.get_default` with a literal key, or tested first with `lib.has_field`. The
    variable standing for the block is found by following
    `params := lib.get_constraint_params(c)`, the v0 output-argument form
    `lib.get_constraint_params(c, params)`, or a plain `params := input.parameters`.
    """

    bound: set[tuple[str, ...]] = {tuple(root) for root in PARAMETER_ROOTS}
    without_default: set[str] = set()
    with_default: set[str] = set()
    guarded: set[str] = set()
    whole: set[str] = set()
    # A block handed entire to a function defined in this module is not a read: the
    # function's body is walked too, and its reads are counted where they occur. Only a
    # block handed to something whose body is not here -- an import, a builtin, a name
    # that does not resolve -- is opaque, and opaque is treated as undefaulted.
    local_rules = rule_names(ast)

    def block_reference(node: dict[str, Any]) -> tuple[tuple[str, ...], list[str | None]] | None:
        if node.get("type") == "var" and (node.get("value"),) in bound:
            return (node["value"],), [node["value"]]
        if node.get("type") == "ref":
            names = _tokens(node)
            for root in bound:
                if len(names) >= len(root) and tuple(names[: len(root)]) == root:
                    return root, names
        return None

    def literal_key(node: dict[str, Any]) -> str | None:
        value = node.get("value")
        return value if node.get("type") == "string" and isinstance(value, str) else None

    def handle_call(head: dict[str, Any], arguments: list[dict[str, Any]]) -> bool:
        """Record a defaulting, guarding or fetching call; True when the call is consumed."""

        names = _tokens(head) if head.get("type") == "ref" else []
        short = names[-1] if names and isinstance(names[-1], str) else ""
        if short in PARAMETER_FETCHERS:
            if len(arguments) >= 2 and arguments[-1].get("type") == "var":
                bound.add((arguments[-1]["value"],))
            return True
        first = arguments[0] if arguments else None
        if first is not None and block_reference(first) is not None and len(arguments) >= 2:
            key = literal_key(arguments[1])
            if short in DEFAULTING_FUNCTIONS and key is not None:
                with_default.add(key)
                return True
            if short in GUARDING_FUNCTIONS and key is not None:
                guarded.add(key)
                return True
        callee = ".".join(name for name in names if name) or "<unnamed>"
        if callee.split(".")[0] not in local_rules:
            for argument in arguments:
                found = block_reference(argument)
                if found is not None and len(found[1]) == len(found[0]):
                    whole.add(callee)
        return False

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            terms = node.get("terms")
            if isinstance(terms, list) and terms and terms[0].get("type") == "ref":
                head_names = _tokens(terms[0])
                if head_names == ["assign"] and len(terms) == 3 and terms[1].get("type") == "var":
                    target = terms[1]["value"]
                    right = terms[2]
                    if right.get("type") == "call" and (right.get("value") or []):
                        callee = right["value"][0]
                        callee_names = _tokens(callee) if callee.get("type") == "ref" else []
                        if callee_names and callee_names[-1] in PARAMETER_FETCHERS:
                            bound.add((target,))
                            return
                    found = block_reference(right)
                    if found is not None and len(found[1]) == len(found[0]):
                        bound.add((target,))
                        return
                elif len(terms) > 1 and handle_call(terms[0], terms[1:]):
                    for argument in terms[1:]:
                        if argument.get("type") != "var":
                            walk(argument)
                    return
            if node.get("type") == "call":
                operands = node.get("value") or []
                if (
                    operands
                    and operands[0].get("type") == "ref"
                    and handle_call(operands[0], operands[1:])
                ):
                    for argument in operands[1:]:
                        if argument.get("type") != "var":
                            walk(argument)
                    return
                for operand in operands[1:]:
                    walk(operand)
                return
            found = block_reference(node)
            if found is not None:
                root, names = found
                if len(names) > len(root):
                    key = names[len(root)]
                    without_default.add(key if isinstance(key, str) else "<computed>")
                return
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    # Two passes, so a read that appears in the text before the binding it uses still counts.
    for _ in range(2):
        walk(ast.get("rules") or [])
    return {
        "without_default": sorted(without_default - with_default - guarded),
        "with_default": sorted(with_default),
        "guarded": sorted(guarded),
        "whole": sorted(whole),
    }


# Term types that are a name or a literal rather than a structure holding further terms.
_ATOMIC_TERMS = frozenset({"var", "string", "number", "boolean", "null"})


def _alias_map(ast: dict[str, Any]) -> dict[str, list[str]]:
    """Import alias -> the full path it stands for, root included.

    The root matters: `import input as aws` makes `aws.SecurityGroups` a read of the
    request, and expanding it under `data` -- as the first version did -- reported two
    policies as reading a document the bundle does not define.
    """

    aliases: dict[str, list[str]] = {}
    for entry in ast.get("imports") or []:
        names = [name for name in _tokens(entry.get("path") or {}) if name]
        if not names:
            continue
        alias = entry.get("alias")
        aliases[alias if isinstance(alias, str) else names[-1]] = names
    return aliases


def _every_name_path(node: Any) -> list[list[str | None]]:
    """Every reference path and bare variable in a rule, whatever its root.

    `references_and_calls` keeps only `data` and `input` roots, which is what the direct
    checks need. Resolving which *rules* a body evaluates needs the rest: an unqualified
    name that is a rule of this package, or an alias-qualified path into another one.
    """

    found: list[list[str | None]] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            kind = item.get("type")
            if kind == "ref":
                found.append(_tokens(item))
                # A ref's own terms are its path, not further names: the `openshift` in
                # `openshift.is_deploymentconfig` is the alias, and reading it as a bare
                # variable would resolve to every rule of the package. Only a composite term
                # inside the path -- a nested ref or call used as an index -- is walked.
                for part in item.get("value") or []:
                    if isinstance(part, dict) and part.get("type") not in _ATOMIC_TERMS:
                        walk(part)
                return
            if kind == "var" and isinstance(item.get("value"), str):
                found.append([item["value"]])
            for value in item.values():
                walk(value)
        elif isinstance(item, list):
            for value in item:
                walk(value)

    walk(node)
    return found


def _rules_under(prefix: str) -> set[tuple[str, str]]:
    """Every rule of every declared package at or beneath a package path."""

    found: set[tuple[str, str]] = set()
    for package, names in _PACKAGE_RULES.items():
        if package == prefix or package.startswith(prefix + "."):
            found.update((package, name) for name in names)
    return found


def _resolve_rules(path: list[str | None]) -> set[tuple[str, str]]:
    """The rules a package-qualified path may evaluate.

    The longest declared package that prefixes the path names the package and the next
    token the rule. A path that stops at a package, or continues with a computed index --
    `vetter[_]` iterating a package prefix -- evaluates every rule beneath it.
    """

    names = list(path)
    for length in range(len(names), 0, -1):
        head = names[:length]
        if any(name is None for name in head):
            continue
        prefix = ".".join(name for name in head if name)
        is_package = prefix in _DECLARED_PACKAGES
        is_prefix = any(package.startswith(prefix + ".") for package in _DECLARED_PACKAGES)
        if not (is_package or is_prefix):
            continue
        rest = names[length:]
        if not rest or rest[0] is None:
            return _rules_under(prefix)
        if is_package and rest[0] in _PACKAGE_RULES.get(prefix, set()):
            return {(prefix, rest[0])}
        # A concrete name beneath a package that is not one of its rules, or beneath a mere
        # prefix of package names, is a data document -- `data.kubernetes.pods` beside a
        # `kubernetes.lib` package -- and not an evaluation of anything. The direct check
        # reports it as undefined data; it is no rule reference.
        return set()
    return set()


def referenced_rules(
    rule: dict[str, Any], package: str, aliases: dict[str, list[str]]
) -> set[tuple[str, str]]:
    """The rules, in any package, that evaluating this rule may evaluate."""

    found: set[tuple[str, str]] = set()
    local = _PACKAGE_RULES.get(package, set())
    head_value = (rule.get("head") or {}).get("value") or {}
    for path in _every_name_path(rule.get("body") or []) + _every_name_path(head_value):
        if not path or path[0] is None:
            continue
        first = path[0]
        if first == "data":
            found |= _resolve_rules(path[1:])
        elif first in aliases:
            target = aliases[first]
            if target and target[0] == "data":
                found |= _resolve_rules([*target[1:], *path[1:]])
        elif first in local:
            found.add((package, first))
    return found


def _direct_cause(
    rule: dict[str, Any], declared: set[str], aliases: dict[str, list[str]]
) -> str | None:
    """Why one rule's own body reads outside, or None when it does not.

    A body reads a document through an import alias as often as through `data.` directly:
    `pods[name]` after `import data.kubernetes.pods` is a read of `data.kubernetes.pods`.
    At module level the import statement itself carries the `data.` reference, so the
    direct check saw it; a rule body carries only the alias, so it is expanded here.
    """

    references, calls = references_and_calls(rule)
    for path in _every_name_path(rule.get("body") or []):
        if path and path[0] in aliases:
            references.append([*aliases[str(path[0])], *path[1:]])
    nondeterministic = sorted(calls & nondeterministic_builtins())
    if nondeterministic:
        return "calls a builtin whose result is not a function of its arguments: " + ", ".join(
            nondeterministic
        )
    injected = sorted(
        {
            str(reference[1])
            for reference in references
            if reference[0] == "data"
            and len(reference) > 1
            and reference[1] in EXTERNAL_DOCUMENT_ROOTS
        }
    )
    if injected:
        return "reads a document the host injects: " + ", ".join(f"data.{n}" for n in injected)
    undefined = sorted(
        {
            ".".join(name for name in reference if name)
            for reference in references
            if reference[0] == "data"
            and not _resolves_to_bundle(reference, declared)
            and not (len(reference) > 1 and reference[1] in EXTERNAL_DOCUMENT_ROOTS)
        }
    )
    if undefined:
        return "reads a data document the bundle does not define: " + ", ".join(undefined[:4])
    return None


def _propagate_reach(modules: dict[Path, dict[str, Any]]) -> None:
    """Mark every rule that reads outside, directly or through a rule it references."""

    _RULE_CAUSE.clear()
    references: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    for ast in modules.values():
        package = package_of(ast)
        aliases = _alias_map(ast)
        for rule in ast.get("rules") or []:
            head = rule.get("head") or {}
            name = head.get("name")
            if not isinstance(name, str):
                candidates = [
                    term.get("value") for term in head.get("ref") or [] if isinstance(term, dict)
                ]
                name = next((n for n in candidates if isinstance(n, str)), None)
            if not isinstance(name, str):
                continue
            key = (package, name)
            cause = _direct_cause(rule, _DECLARED_PACKAGES, aliases)
            if cause and key not in _RULE_CAUSE:
                _RULE_CAUSE[key] = (key, cause)
            references[key] |= referenced_rules(rule, package, aliases) - {key}
    changed = True
    while changed:
        changed = False
        for key, referenced in references.items():
            if key in _RULE_CAUSE:
                continue
            for other in sorted(referenced):
                if other in _RULE_CAUSE:
                    _RULE_CAUSE[key] = _RULE_CAUSE[other]
                    changed = True
                    break


def _resolves_to_bundle(reference: list[str | None], declared: set[str]) -> bool:
    """Whether a `data.` reference names rules the bundle defines.

    A declared package must be a prefix of the reference: the rules live at or above the
    path being read. The reverse -- a package deeper than the reference -- does not make
    the reference resolvable, and treating it as if it did is what first made this adapter
    report Gatekeeper's injected `data.inventory` as bundle code, because the corpus ships
    a fixture that mocks it.
    """

    names = [name for name in reference[1:] if name]
    return any(".".join(names[:length]) in declared for length in range(len(names), 0, -1))


def _external_findings(ast: dict[str, Any], declared: set[str]) -> tuple[list[str], list[str]]:
    """(reasons this module reaches outside, unresolvable call names).

    The reasons are ordered by the taxonomy's reporting rule: nondeterminism first, then
    reading state the subject does not carry, then being a policy schema. Only the last is
    removed by supplying an assignment, so the first entry is the obstruction that survives
    instantiation and is the one the verdict names.
    """

    references, calls = references_and_calls(ast)
    reasons: list[str] = []

    nondeterministic = sorted(calls & nondeterministic_builtins())
    if nondeterministic:
        reasons.append(
            "calls a builtin whose result is not a function of its arguments: "
            + ", ".join(nondeterministic)
        )

    injected = sorted(
        {
            reference[1]
            for reference in references
            if reference[0] == "data"
            and len(reference) > 1
            and reference[1] in EXTERNAL_DOCUMENT_ROOTS
        }
    )
    if injected:
        reasons.append(
            "reads a document the host injects: " + ", ".join(f"data.{n}" for n in injected)
        )

    unresolved_data = sorted(
        {
            ".".join(name for name in reference if name)
            for reference in references
            if reference[0] == "data" and not _resolves_to_bundle(reference, declared)
        }
    )
    unresolved_data = [name for name in unresolved_data if not name.startswith("data.inventory")]
    if unresolved_data:
        reasons.append(
            "reads a data document the bundle does not define: " + ", ".join(unresolved_data[:4])
        )

    # Reach through the rules this module evaluates in other packages, or in other files
    # of its own. A rule's terminal cause is named, so the reason says what is actually read.
    package = package_of(ast)
    own_rules = rule_names(ast)
    aliases = _alias_map(ast)
    reached: dict[str, str] = {}
    for rule in ast.get("rules") or []:
        for other in sorted(referenced_rules(rule, package, aliases)):
            if other[0] == package and other[1] in own_rules:
                continue
            if other in _RULE_CAUSE:
                terminal, cause = _RULE_CAUSE[other]
                reached.setdefault(f"{terminal[0]}.{terminal[1]}", cause)
    for terminal, cause in sorted(reached.items()):
        reasons.append(f"reaches outside through {terminal}, which {cause}")

    # Last, because it is the one obstruction an assignment removes. A module that is a
    # schema and also reads a document the host injects stays outside once a Constraint
    # supplies its parameters, so the reason reported is the one that survives
    # instantiation. Two modules of the wide corpus are in that position; before this
    # ordering they were filed as schemas, which the Azure adapter -- reading the same
    # distinction the other way round -- did not do, and the taxonomy carried both
    # conventions at once.
    reads = parameter_reads(ast)
    undefaulted = reads["without_default"] + [f"whole block to {name}" for name in reads["whole"]]
    if undefaulted:
        reasons.append(
            "is a policy schema rather than a policy: its guard is stated against "
            "parameters a Constraint supplies, so it determines no decision function "
            "until one is applied; no default is given for " + ", ".join(undefaulted[:6])
        )

    known = builtins()
    # Rego packages span files: a rule defined in one file is visible, unqualified, to
    # every other file declaring the same package. Resolving a call against the calling
    # file alone therefore reports helpers as unknown, which is what left four modules
    # undetermined until the table below was built package-wide.
    local_rules = set(rule_names(ast)) | _PACKAGE_RULES.get(package_of(ast), set())
    import_aliases = set()
    for entry in ast.get("imports") or []:
        alias = entry.get("alias")
        names = [name for name in _tokens(entry.get("path") or {}) if name]
        import_aliases.add(alias if isinstance(alias, str) else (names[-1] if names else ""))

    unresolvable = sorted(
        call
        for call in calls
        if call not in known
        and call.split(".")[0] not in local_rules
        and call.split(".")[0] not in import_aliases
    )
    return reasons, unresolvable


def discover(root: Path) -> list[tuple[str, Path]]:
    """Every policy module in the corpus, with the bundle-wide facts recorded.

    Membership is decided per policy file, but not from that file alone: whether a library
    rule it evaluates reaches outside is decided over the whole bundle. This pass therefore
    parses the corpus once, records what each package declares, and marks every rule that
    reads outside -- directly or through the rules it references -- before any policy is
    classified.
    """

    if not root.is_dir():
        return []

    parsed: dict[Path, dict[str, Any]] = {}
    for path in sorted(root.rglob("*.rego")):
        if ".git" in path.parts:
            continue
        ast = parse(path.read_text(encoding="utf-8", errors="ignore"))
        if ast is not None:
            parsed[path] = ast

    _DECLARED_PACKAGES.clear()
    _PACKAGE_RULES.clear()
    # Every parsed module contributes to the package tables, test modules included: a
    # helper a policy calls is visible whichever file declares it.
    for ast in parsed.values():
        package = package_of(ast)
        if package:
            _DECLARED_PACKAGES.add(package)
            _PACKAGE_RULES.setdefault(package, set()).update(rule_names(ast))

    modules = {path: ast for path, ast in parsed.items() if not is_test_module(ast, path)}

    # Constraints that supply parameters, keyed by the directory a policy sits in. A
    # template and its Constraint live in different trees in the measured corpus --
    # `src/general/<name>/` and `library/general/<name>/samples/*/` -- so they are matched
    # by the policy directory's name rather than by path.
    _CONSTRAINTS.clear()
    _CONSTRAINTS_BY_KIND.clear()
    _SUBJECT_PACKAGE.clear()
    for manifest in root.rglob("samples/*/constraint.yaml"):
        try:
            document = yaml.safe_load(manifest.read_text(encoding="utf-8", errors="ignore"))
        except yaml.YAMLError:
            continue
        if not isinstance(document, dict):
            continue
        if not (document.get("spec") or {}).get("parameters"):
            continue
        name = manifest.parent.parent.parent.name
        _CONSTRAINTS.setdefault(name, []).append(manifest.relative_to(root).as_posix())
    # Config Validator ships its sample Constraints flat under `samples/`, one file each,
    # and a template is matched to them by the `kind` its package name ends in.
    for manifest in root.rglob("samples/*.yaml"):
        try:
            document = yaml.safe_load(manifest.read_text(encoding="utf-8", errors="ignore"))
        except yaml.YAMLError:
            continue
        if not isinstance(document, dict):
            continue
        kind = document.get("kind")
        if not isinstance(kind, str) or not (document.get("spec") or {}).get("parameters"):
            continue
        _CONSTRAINTS_BY_KIND.setdefault(kind, []).append(manifest.relative_to(root).as_posix())
    for path, ast in modules.items():
        _SUBJECT_PACKAGE[path.relative_to(root).as_posix()] = package_of(ast)

    # Which rules read outside, directly or through the rules they evaluate. Test modules
    # are left out: a test that mocks `data.inventory` with `with` names the document
    # without a policy reading it.
    _propagate_reach(modules)

    return [
        (path.relative_to(root).as_posix(), path)
        for path in sorted(modules)
        if (modules[path].get("rules") or [])
    ]


def subject_directory(subject: str) -> str:
    """The directory a policy sits in, which is how Constraints are matched to it."""

    parts = Path(subject).parts
    return parts[-2] if len(parts) >= 2 else ""


def constraints_for(subject: str) -> list[str]:
    """Constraints in the corpus that supply this template's parameters.

    Exposed so the claim can be checked rather than asserted: a template excluded as a
    policy schema should have an instantiation, and in the measured corpora every one does.
    Gatekeeper's are found by the template's directory name, Config Validator's by the
    `kind` the template's package ends in.
    """

    found = list(_CONSTRAINTS.get(subject_directory(subject), []))
    package = _SUBJECT_PACKAGE.get(subject, "")
    if package:
        found.extend(_CONSTRAINTS_BY_KIND.get(package.rsplit(".", 1)[-1], []))
    return found


def classify(text: str) -> Verdict:
    ast = parse(text)
    if ast is None:
        return Verdict(UNDETERMINED, "does not parse as Rego v1 or v0")

    reasons, unresolvable = _external_findings(ast, _DECLARED_PACKAGES)
    detail: dict[str, Any] = {"package": package_of(ast)}
    reads = parameter_reads(ast)
    if any(reads.values()):
        detail["parameter_reads"] = reads
    _, calls = references_and_calls(ast)
    reaching = {
        name: EVALUATION_TIME_STATE.get(name, "evaluation-time state")
        for name in sorted(calls & nondeterministic_builtins())
    }
    if reaching:
        detail["evaluation_time_state"] = reaching

    if reasons:
        detail["reasons"] = reasons
        return Verdict(OUTSIDE, reasons[0], detail)
    if unresolvable:
        detail["unresolvable_calls"] = unresolvable
        return Verdict(UNDETERMINED, "calls a name this test cannot resolve", detail)
    return Verdict(INSIDE, "every guard reads the request and literals the policy contains", detail)
