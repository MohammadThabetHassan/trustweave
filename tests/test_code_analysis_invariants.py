"""The floor: what the analyzer is allowed to publish as a benign verdict.

`read` is a positive classification, not a fallback. `docs/CODE_DISCOVERY.md` says so, and
the `limits` block stamped into every artifact promises that dynamic dispatch, unresolved
imports and exhausted budgets "are reported as unknown rather than as a clean result". The
analyzer reached `read` at `high` confidence down two different paths, though: one where it
resolved everything and saw nothing, and one where it resolved nothing at all. The two
produced byte-identical records, so a reviewer could not tell them apart, and an audit
demo of four tools -- an HTTP call in a `try`, a shell through a module-level alias, a
`Path.open("w")` and a `getattr(os, "system")` piping to curl -- published every one of
them as `action_class: read` with `status: clear` and exit code 0.

These tests hold the two apart. The first is a property over the labelled benchmark: no
tool may be proposed `read` at `high` unless it either produced evidence or has a body
every call of which this file can name independently. "Independently" is the point -- the
check below re-derives what a name can reach from the source, without asking the analyzer,
so a regression that drops a refusal fails here rather than quietly widening the floor.
"""

from __future__ import annotations

import ast
import builtins
import json
from pathlib import Path

from trustweave.code_analysis import analyze_sources
from trustweave.code_sources import collect_python_sources

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmark" / "tool-classification"
TOOL_IMPORT = "from langchain_core.tools import tool"

# Annotations naming a type whose methods cannot be an effect of this tool. Anything else,
# including no annotation at all, leaves the receiver decided by the caller.
_SAFE_ANNOTATION_ROOTS = frozenset(dir(builtins)) | {"typing", "collections", "datetime"}


def _module_names(tree: ast.Module) -> set[str]:
    """Every name the module itself provides: imports, definitions and top-level bindings."""

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def _opaque_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameters whose annotation does not say what the receiver is."""

    arguments = function.args
    opaque: set[str] = set()
    for parameter in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
        if parameter.arg in {"self", "cls"}:
            continue
        annotation = parameter.annotation
        root = annotation
        while isinstance(root, ast.Attribute | ast.Subscript):
            root = root.value if isinstance(root, ast.Attribute) else root.value
        if annotation is None or not (
            isinstance(root, ast.Name) and root.id in _SAFE_ANNOTATION_ROOTS
        ):
            opaque.add(parameter.arg)
    return opaque


def _bound_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names the body binds itself, which the analyzer can follow to their value."""

    names: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.AnnAssign | ast.AugAssign | ast.For | ast.AsyncFor):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
        elif isinstance(node, ast.comprehension) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
            names.add(node.optional_vars.id)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
    return names


def _root_of(node: ast.expr) -> str | None:
    current: ast.AST = node
    while True:
        if isinstance(current, ast.Name):
            return current.id
        if isinstance(current, ast.Attribute):
            current = current.value
        elif isinstance(current, ast.Call):
            current = current.func
        else:
            return None


def _unnameable_calls(
    tree: ast.Module, function: ast.FunctionDef | ast.AsyncFunctionDef
) -> list[str]:
    """Calls in this body whose callee reaches a name this file cannot account for."""

    known = _module_names(tree) | _bound_names(function) | set(dir(builtins)) | {"self", "cls"}
    opaque = _opaque_parameters(function) - _bound_names(function)
    decorators = {id(inner) for node in function.decorator_list for inner in ast.walk(node)}
    offending: list[str] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or id(node) in decorators:
            continue
        root = _root_of(node.func)
        if root is None:
            # A method on a literal, as in `"\n".join(parts)`: no name is involved.
            continue
        if root in opaque or root not in known:
            offending.append(f"{ast.unparse(node.func)} at line {node.lineno}")
    return offending


def test_a_benign_verdict_is_backed_by_evidence_or_by_a_body_this_file_can_name() -> None:
    """`read` at `high` with no signal is only honest when nothing was left unresolved.

    Before the refusal the analyzer reached this record both ways, so `read`/`high`/
    `signals: []` meant either "this tool does nothing" or "this tool could not be read",
    and the artifact said which only by accident.
    """

    index = json.loads((BENCHMARK / "benchmark.json").read_text(encoding="utf-8"))
    violations: list[str] = []
    for case in index["cases"]:
        module = BENCHMARK / case["module"]
        tools, _ = analyze_sources(collect_python_sources(module))
        sources = [module] if module.is_file() else sorted(module.rglob("*.py"))
        trees = {
            path.name: ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
            for path in sources
        }
        for tool in tools:
            if (
                tool.signals
                or tool.proposed_action_class() != "read"
                or tool.confidence() != "high"
            ):
                continue
            if tool.body is None:
                continue
            unnameable = _unnameable_calls(trees[Path(tool.file).name], tool.body)
            if unnameable:
                violations.append(f"{case['id']}/{tool.name}: {unnameable}")

    assert not violations, violations


def test_a_call_on_a_parameter_the_module_cannot_resolve_is_refused(tmp_path: Path) -> None:
    """The audit's probe: `read`/`high`/`signals: []`/`reasons: []`, and the run was clear."""

    (tmp_path / "agent.py").write_text(
        f"{TOOL_IMPORT}\n\n\n"
        "@tool\n"
        "def relay(client, target: str) -> str:\n"
        '    """Relay a message."""\n'
        "    return str(client.send(target))\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "unknown"
    assert tools[0].confidence() == "review"
    assert tools[0].reasons == {"UNRESOLVED_CALLEE"}


def test_a_bare_name_the_module_does_not_define_is_refused(tmp_path: Path) -> None:
    """`return mystery(target)` -- a name neither defined nor imported -- read as benign."""

    (tmp_path / "agent.py").write_text(
        f"{TOOL_IMPORT}\n\n\n"
        "@tool\n"
        "def relay(target: str) -> str:\n"
        '    """Relay a message."""\n'
        "    return str(mystery(target))\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "unknown"
    assert tools[0].reasons == {"UNRESOLVED_CALLEE"}


def test_a_helper_defined_only_inside_a_conditional_block_is_refused(tmp_path: Path) -> None:
    """A `def` inside `if`/`try` is not indexed, while an `import` there is, so the two
    halves of the same idiom disagreed: the import form refused and the def form was read."""

    (tmp_path / "agent.py").write_text(
        "import sys\n"
        f"{TOOL_IMPORT}\n\n\n"
        "if sys.platform == 'win32':\n\n"
        "    def run_shell(command):\n"
        "        import subprocess\n\n"
        "        return str(subprocess.run(command, shell=True))\n\n\n"
        "@tool\n"
        "def execute(command: str) -> str:\n"
        '    """Run a command."""\n'
        "    return str(run_shell(command))\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "unknown"
    assert "UNRESOLVED_CALLEE" in tools[0].reasons


def test_a_body_of_builtins_and_module_helpers_is_still_positively_benign(tmp_path: Path) -> None:
    """The refusal must not swallow the positive `read` the documentation describes.

    Builtins, a module-level helper and a class defined in the same file are all names this
    module can account for, so a tool built out of them keeps its benign verdict.
    """

    (tmp_path / "agent.py").write_text(
        f"{TOOL_IMPORT}\n\n\n"
        "class Formatter:\n"
        '    """Render a value."""\n\n'
        "    def render(self, value: str) -> str:\n"
        "        return value.strip()\n\n\n"
        "def _widen(value: str) -> str:\n"
        '    """Widen a value."""\n'
        "    return value.ljust(24)\n\n\n"
        "@tool\n"
        "def tidy(value: str) -> str:\n"
        '    """Tidy a value."""\n'
        "    formatter = Formatter()\n"
        "    return str(sorted(list(_widen(formatter.render(value)))))\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "read"
    assert tools[0].confidence() == "high"
    assert tools[0].reasons == set()
