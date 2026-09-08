"""Rego fragment membership: a guard is inside when it reads only `input` and literals.

The other three adapters read a declarative document. Rego is a language, so this one
reads the AST `opa parse` produces rather than the text, and resolves references across
the whole bundle instead of one file at a time.

What leaves the fragment, in the order it actually occurs in published policy:

`input.parameters` is the Gatekeeper constraint's parameter block, and it needs stating
carefully, because the obvious reason is the wrong one. A constraint template states its
guard against values a *Constraint* supplies later -- allowed repositories, permitted
profiles, numeric ranges -- and it is tempting to call that "a pattern taken from the input"
and be done. That does not survive the definition: if the parameters arrive in the input
document, the guard's outcome map over that document still has finite image with witnesses
computable from the guard's syntax, which is all finite refinement asks.

The real reason is that such a template is not a policy. It is a policy *schema* -- a
function from parameter bindings to policies -- and it determines no decision function until
a Constraint is applied. Membership is a property of a policy, so the artifact has to be
instantiated before the question can be asked of it. This adapter therefore records, for
each such template, the Constraints in the corpus that supply its parameters; all 28 in the
measured corpus have one, so every one of them is a policy schema whose instantiation the
corpus itself provides.

That is a different kind of exclusion from the one below, and the two should not be pooled
without saying so: a schema is not outside the fragment, it is not yet a policy.

`data.inventory` is the cluster state Gatekeeper caches and injects at evaluation time. The
corpus contains a fixture that mocks it out, whose own comment says so, which is the
clearest available evidence that the real thing is not in the policy.

A builtin whose result is not a function of its arguments -- the clock, the network, the
OS environment, entropy -- is outside for the same reason. Note that most of the `time.*`
and `net.*` namespaces are *not* in this category: `time.parse_rfc3339_ns` and
`net.cidr_contains` compute from what they are given, and only `time.now_ns`,
`net.lookup_ip_addr`, `http.send`, `rand.intn` and `opa.runtime` reach past their arguments.

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

# Builtins whose result is not a function of their arguments. Everything else in OPA's
# library computes from what it is handed, including the rest of `time.*` and `net.*`.
NONDETERMINISTIC_BUILTINS = frozenset(
    {
        "http.send",
        "net.lookup_ip_addr",
        "time.now_ns",
        "rand.intn",
        "opa.runtime",
    }
)

# Document roots supplied by the host at evaluation time rather than written in the policy.
EXTERNAL_DOCUMENT_ROOTS = ("inventory",)

# The reference prefix a Gatekeeper constraint fills in.
CONSTRAINT_PARAMETERS = ("input", "parameters")

_BUILTINS: frozenset[str] | None = None

# Corpus-wide facts, populated by `discover` and consulted by `classify`: which packages
# the bundle declares, what each package imports, and which packages reach outside. A
# policy that calls a library which reaches outside is outside itself, so the verdicts
# have to propagate along the import graph rather than stopping at one file.
_DECLARED_PACKAGES: set[str] = set()
_PACKAGE_RULES: dict[str, set[str]] = {}
_EXTERNAL_PACKAGES: set[str] = set()
# Constraints that supply parameters, keyed by the policy directory's name. A template and
# its Constraint sit in different trees in the measured corpus -- `src/general/<name>/` and
# `library/general/<name>/samples/*/` -- so they are matched by name rather than by path.
_CONSTRAINTS: dict[str, list[str]] = {}


def _opa() -> str:
    found = shutil.which("opa")
    if not found:
        raise SystemExit("opa is not on PATH; install it to run the rego adapter")
    return found


def builtins() -> frozenset[str]:
    """OPA's own builtin names, from the binary rather than from a hand-kept list."""

    global _BUILTINS
    if _BUILTINS is None:
        completed = subprocess.run(
            [_opa(), "capabilities", "--current"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if completed.returncode != 0:
            raise SystemExit("could not read opa capabilities")
        document = json.loads(completed.stdout)
        _BUILTINS = frozenset(entry["name"] for entry in document.get("builtins", []))
    return _BUILTINS


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
    """A ref's path as a list of names, with None for a computed index."""

    names: list[str | None] = []
    for part in term.get("value") or []:
        value = part.get("value")
        names.append(value if isinstance(value, str) else None)
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


def _external_findings(
    ast: dict[str, Any], declared: set[str], external_packages: set[str]
) -> tuple[list[str], list[str]]:
    """(reasons this module reaches outside, unresolvable call names)."""

    references, calls = references_and_calls(ast)
    reasons: list[str] = []

    nondeterministic = sorted(calls & NONDETERMINISTIC_BUILTINS)
    if nondeterministic:
        reasons.append(
            "calls a builtin whose result is not a function of its arguments: "
            + ", ".join(nondeterministic)
        )

    if any(
        tuple(name for name in reference[:2] if name) == CONSTRAINT_PARAMETERS
        for reference in references
    ):
        reasons.append(
            "is a policy schema rather than a policy: its guard is stated against "
            "parameters a Constraint supplies, so it determines no decision function "
            "until one is applied"
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

    reached = sorted(
        package for package in imports_of(ast) if package.removeprefix("data.") in external_packages
    )
    if reached:
        reasons.append("imports a library that reaches outside: " + ", ".join(reached))

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

    Membership is decided per policy file, but not from that file alone: the import graph
    decides whether a library it calls reaches outside. This pass therefore parses the
    whole corpus once, records what each package declares and imports, and propagates the
    outside verdicts to a fixpoint before any policy is classified.
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
    _EXTERNAL_PACKAGES.clear()
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

    # Direct verdicts first, then propagate along imports until nothing changes.
    imports: dict[str, set[str]] = defaultdict(set)
    for ast in modules.values():
        package = package_of(ast)
        reasons, _ = _external_findings(ast, _DECLARED_PACKAGES, set())
        if reasons and package:
            _EXTERNAL_PACKAGES.add(package)
        for imported in imports_of(ast):
            imports[package].add(imported)

    changed = True
    while changed:
        changed = False
        for package, imported in imports.items():
            if package in _EXTERNAL_PACKAGES:
                continue
            if imported & _EXTERNAL_PACKAGES:
                _EXTERNAL_PACKAGES.add(package)
                changed = True

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
    policy schema should have an instantiation, and in the measured corpus every one does.
    """

    return list(_CONSTRAINTS.get(subject_directory(subject), []))


def classify(text: str) -> Verdict:
    ast = parse(text)
    if ast is None:
        return Verdict(UNDETERMINED, "does not parse as Rego v1 or v0")

    reasons, unresolvable = _external_findings(ast, _DECLARED_PACKAGES, _EXTERNAL_PACKAGES)
    detail: dict[str, Any] = {"package": package_of(ast)}

    if reasons:
        detail["reasons"] = reasons
        return Verdict(OUTSIDE, reasons[0], detail)
    if unresolvable:
        detail["unresolvable_calls"] = unresolvable
        return Verdict(UNDETERMINED, "calls a name this test cannot resolve", detail)
    return Verdict(INSIDE, "every guard reads the request and literals the policy contains", detail)
