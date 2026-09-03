"""Static discovery of an agent's declared tool surface from local Python source.

The analyzer parses source with the standard library ``ast`` module. It never imports,
compiles, installs, or executes the code it reads, and it resolves nothing outside the
files it was handed.

Two rules shape everything here.

The first is that a bare attribute name is never evidence. ``.post``, ``.execute`` and
``.write`` mean nothing without knowing what they were called on, so a symbol is only
matched once it has been rewritten through an import binding or traced to a receiver
whose origin is known. Anything that cannot be resolved that way becomes a refusal.

The second is that trust is never inferred. This module proposes an action class from
observed effects; it has no opinion about whether a source is trustworthy, and no code
path here can produce a trust label. That judgement belongs to a reviewer, and pretending
otherwise would put a guess behind an attestation.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from typing import Final

from trustweave.code_catalog import (
    ACTION_CLASS_PRECEDENCE,
    CREDENTIAL_PATH_SUFFIXES,
    CREDENTIAL_PATH_TOKENS,
    DB_EXECUTE_METHODS,
    EGRESS_COMMANDS,
    EXTERNAL_RECEIVERS,
    EXTERNAL_SYMBOLS,
    HIGH_SPECIFICITY_PII_TOKENS,
    PATH_RECEIVERS,
    PII_TOKENS,
    READ_RECEIVER_METHODS,
    READ_SYMBOLS,
    SECRET_ENV_TOKENS,
    SENSITIVE_SYMBOLS,
    SQL_READ_TOKENS,
    SQL_WRITE_TOKENS,
    UNKNOWN_ACTION_CLASS,
    WRITE_RECEIVER_METHODS,
    WRITE_SYMBOLS,
)
from trustweave.code_sources import SourceCollection

MAX_AST_NODES_PER_MODULE: Final[int] = 200_000
MAX_REACHABLE_FUNCTIONS_PER_TOOL: Final[int] = 64
MAX_CALL_DEPTH: Final[int] = 3

_ENVIRON_READERS: Final[frozenset[str]] = frozenset(
    {"os.environ.get", "os.getenv", "os.environ.setdefault"}
)
_ENVIRON_BULK: Final[frozenset[str]] = frozenset(
    {"os.environ.items", "os.environ.copy", "os.environ.values"}
)
_KNOWN_BUILTINS: Final[frozenset[str]] = frozenset(
    {"bool", "bytes", "dict", "float", "frozenset", "int", "list", "open", "set", "str", "tuple"}
)
_INSTANCE_RECEIVERS: Final[frozenset[str]] = frozenset({"self", "cls"})
_DYNAMIC_SYMBOLS: Final[frozenset[str]] = frozenset(
    {"eval", "exec", "getattr", "globals", "importlib.import_module", "vars"}
)

LANGCHAIN_TOOL_DECORATORS: Final[frozenset[str]] = frozenset(
    {"langchain_core.tools.tool", "langchain.tools.tool", "langchain.agents.tool"}
)
STRUCTURED_TOOL_FACTORIES: Final[frozenset[str]] = frozenset(
    {
        "langchain_core.tools.StructuredTool.from_function",
        "langchain.tools.StructuredTool.from_function",
        "langchain_core.tools.Tool.from_function",
        "langchain.tools.Tool.from_function",
        "llama_index.core.tools.FunctionTool.from_defaults",
    }
)
AGENT_TOOL_BINDERS: Final[frozenset[str]] = frozenset(
    {
        "langgraph.prebuilt.ToolNode",
        "langgraph.prebuilt.create_react_agent",
        "langchain.agents.initialize_agent",
    }
)


@dataclass(frozen=True)
class EffectSignal:
    """One resolved observation that argues for a particular action class."""

    action_class: str
    symbol: str
    file: str
    line: int
    via: tuple[str, ...]


@dataclass
class DiscoveredTool:
    """One callable the agent can invoke, with the evidence gathered about it."""

    name: str
    framework: str
    file: str
    line: int
    signals: list[EffectSignal] = field(default_factory=list)
    reasons: set[str] = field(default_factory=set)
    budget_state: str = "complete"

    def proposed_action_class(self) -> str:
        """Return the highest-precedence observed class, or ``unknown`` if refused."""

        if self.reasons:
            return UNKNOWN_ACTION_CLASS
        observed = {signal.action_class for signal in self.signals}
        for candidate in ACTION_CLASS_PRECEDENCE:
            if candidate in observed:
                return candidate
        # No recognised effect at all is a positive read classification, not a refusal.
        return "read"

    def confidence(self) -> str:
        return "review" if self.reasons else "high"


@dataclass
class _Module:
    """One parsed source file plus the bindings needed to resolve names inside it."""

    path: str
    tree: ast.Module
    bindings: dict[str, str]
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    wildcard_import: bool
    # Computed once per module. Recomputing it per tool made analysis quadratic in the
    # number of discovered tools while every documented budget still reported "complete".
    module_origins: dict[str, tuple[str, ast.Call]] = field(default_factory=dict)
    # Class methods are discoverable as tools but deliberately absent from `functions`,
    # so a bare call to `send` can never resolve to `SomeClass.send`.
    methods: list[ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=list)


def _dotted(node: ast.AST) -> str | None:
    """Return the dotted source spelling of a name or attribute chain."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


def _index_module(path: str, tree: ast.Module) -> _Module:
    bindings: dict[str, str] = {}
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    wildcard = False

    # Imports may appear at any depth, so bindings are collected across the whole tree.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    wildcard = True
                    continue
                bindings[alias.asname or alias.name] = (
                    f"{module}.{alias.name}" if module else alias.name
                )

    # Only module-level functions may be reached by a bare name. Indexing class methods
    # and nested functions here would let `Class.send` satisfy a call to an imported
    # `send`, and would let a method body be attributed to an unrelated caller.
    methods: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            functions.setdefault(node.name, node)
        elif isinstance(node, ast.ClassDef):
            methods.extend(
                child
                for child in node.body
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
            )

    module = _Module(path, tree, bindings, functions, wildcard, methods=methods)
    module.module_origins = _scope_origins(tree.body, module)
    return module


def _resolve(name: str | None, module: _Module) -> str | None:
    """Rewrite a dotted source spelling through this module's import bindings."""

    if not name:
        return None
    head, _, tail = name.partition(".")
    target = module.bindings.get(head)
    if target is None:
        return name
    return f"{target}.{tail}" if tail else target


def _constant_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_instance_state_call(call: ast.Call) -> bool:
    """True for a call reached through an attribute of ``self`` or ``cls``."""

    func = call.func
    if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Attribute):
        return False
    return isinstance(func.value.value, ast.Name) and func.value.value.id in _INSTANCE_RECEIVERS


def _root_name(node: ast.AST) -> str | None:
    """Return the leftmost ``Name`` of an attribute or call chain, if there is one."""

    current = node
    while True:
        if isinstance(current, ast.Name):
            return current.id
        if isinstance(current, ast.Attribute):
            current = current.value
            continue
        if isinstance(current, ast.Call):
            current = current.func
            continue
        return None


def _dynamic_locals(scope: ast.AST, module: _Module) -> set[str]:
    """Names bound from a subscript or an unresolved call: calling them is dispatch."""

    dynamic: set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, ast.Assign):
            continue
        opaque = isinstance(node.value, ast.Subscript)
        if isinstance(node.value, ast.Call):
            root = _root_name(node.value.func)
            opaque = root is None or (
                root not in module.bindings
                and root not in module.functions
                and root not in _KNOWN_BUILTINS
            )
        if not opaque:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                dynamic.add(target.id)
    return dynamic


def _assigned_names(scope_body: list[ast.stmt]) -> set[str]:
    """Names bound anywhere in this statement list, at this level or nested inside it."""

    bound: set[str] = set()
    for statement in scope_body:
        for node in ast.walk(statement):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bound.add(target.id)
            elif isinstance(
                node, ast.AnnAssign | ast.AugAssign | ast.For | ast.AsyncFor | ast.comprehension
            ) and isinstance(node.target, ast.Name):
                bound.add(node.target.id)
            elif isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
                bound.add(node.optional_vars.id)
    return bound


def _local_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Every name the function itself binds: parameters first, then local assignments."""

    arguments = function.args
    parameters = [
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
        *([arguments.vararg] if arguments.vararg else []),
        *([arguments.kwarg] if arguments.kwarg else []),
    ]
    names = {parameter.arg for parameter in parameters}
    return names | _assigned_names(function.body)


def _scope_origins(scope_body: list[ast.stmt], module: _Module) -> dict[str, tuple[str, ast.Call]]:
    """Track receiver constructors bound directly in one statement list.

    Only assignments at this level count. Walking the whole tree would let a binding
    inside an unrelated function decide what a name means here, which silently changes
    another tool's classification.
    """

    origins: dict[str, tuple[str, ast.Call]] = {}
    ambiguous: set[str] = set()
    for statement in scope_body:
        if not isinstance(statement, ast.Assign) or not isinstance(statement.value, ast.Call):
            continue
        qualified = _resolve(_dotted(statement.value.func), module)
        if qualified is None:
            continue
        if qualified not in EXTERNAL_RECEIVERS and qualified not in PATH_RECEIVERS:
            continue
        for target in statement.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id in origins and origins[target.id][0] != qualified:
                # Rebound to a different receiver: neither reading is safe to assume.
                ambiguous.add(target.id)
            origins[target.id] = (qualified, statement.value)
    for name in ambiguous:
        origins.pop(name, None)
    return origins


def _sql_class(call: ast.Call) -> str | None:
    """Classify a database execute call by the leading keyword of its literal query."""

    if not isinstance(call.func, ast.Attribute) or call.func.attr not in DB_EXECUTE_METHODS:
        return None
    query = _constant_str(call.args[0]) if call.args else None
    if query is None:
        return None
    head = query.strip().split(None, 1)
    if not head:
        return None
    token = head[0].casefold()
    if token in SQL_WRITE_TOKENS:
        return "write"
    if token in SQL_READ_TOKENS:
        return "read"
    return None


def _open_class(call: ast.Call) -> tuple[str | None, str | None]:
    """Return (action_class, refusal_reason) for a builtin ``open`` call."""

    mode_node = call.args[1] if len(call.args) > 1 else _keyword(call, "mode")
    if mode_node is None:
        return "read", None
    mode = _constant_str(mode_node)
    if mode is None:
        return None, "NONLITERAL_ARGUMENT"
    return ("write" if any(flag in mode for flag in "wax+") else "read"), None


def _subprocess_class(call: ast.Call) -> str:
    """Subprocess is privileged execution unless its argv head is a known egress tool."""

    argv = call.args[0] if call.args else None
    head: str | None = None
    if isinstance(argv, ast.List) and argv.elts:
        head = _constant_str(argv.elts[0])
    elif isinstance(argv, ast.Constant):
        literal = _constant_str(argv)
        head = literal.split()[0] if literal and literal.split() else None
    if head and head.rsplit("/", 1)[-1] in EGRESS_COMMANDS:
        return "external"
    return "sensitive"


def _env_is_secret(call: ast.Call, qualified: str) -> bool:
    if qualified in _ENVIRON_BULK:
        return True
    key = _constant_str(call.args[0]) if call.args else None
    if key is None:
        return False
    tokens = {token for token in key.casefold().replace("-", "_").split("_") if token}
    return bool(tokens & SECRET_ENV_TOKENS)


def _is_credential_path(call: ast.Call) -> bool:
    for argument in call.args:
        literal = _constant_str(argument)
        if literal is None:
            continue
        lowered = literal.casefold()
        if any(token in lowered for token in CREDENTIAL_PATH_TOKENS):
            return True
        if any(lowered.endswith(suffix) for suffix in CREDENTIAL_PATH_SUFFIXES):
            return True
    return False


def _classify_call(
    call: ast.Call,
    module: _Module,
    origins: dict[str, tuple[str, ast.Call]],
    dynamic: set[str],
) -> tuple[str | None, str | None, str | None]:
    """Return (action_class, symbol, refusal_reason) for one call site."""

    spelled = _dotted(call.func)
    root = _root_name(call.func)

    if root is not None and root in dynamic:
        # The callee was bound from a subscript, so its behaviour is chosen at runtime.
        return None, None, "DYNAMIC_DISPATCH"

    if spelled is None:
        # A method called directly on a constructor, as in Path("...").read_text(). The
        # constructor is the receiver, and its arguments carry the literal that decides
        # whether this is an ordinary read or a credential read.
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call):
            inner = call.func.value
            origin = _resolve(_dotted(inner.func), module)
            method = call.func.attr
            if origin in PATH_RECEIVERS:
                if method in WRITE_RECEIVER_METHODS:
                    return "write", f"{origin}.{method}", None
                if method in READ_RECEIVER_METHODS:
                    action = "sensitive" if _is_credential_path(inner) else "read"
                    return action, f"{origin}.{method}", None
            if origin in EXTERNAL_RECEIVERS:
                return "external", f"{origin}.{method}", None
        # Otherwise a method on an expression result. Only evidence if the chain roots at
        # a name this module resolves; a call on a parameter or literal is not.
        if root is not None and (root in module.bindings or root in origins):
            return None, None, "UNRESOLVED_CALLEE"
        return None, None, None

    if _is_instance_state_call(call):
        # self.session.post(...): the receiver lives on the instance, which this analyzer
        # does not track. Reporting no effect here would publish an outbound call as read.
        return None, None, "UNRESOLVED_CALLEE"

    qualified = _resolve(spelled, module)
    if qualified is None:  # pragma: no cover - _resolve returns None only for empty input
        return None, None, None

    if qualified in _DYNAMIC_SYMBOLS or spelled in _DYNAMIC_SYMBOLS:
        constant_target = _constant_str(call.args[1]) if len(call.args) > 1 else None
        if spelled in {"getattr", "vars"} and constant_target is not None:
            return None, None, None
        return None, None, "DYNAMIC_DISPATCH"

    if spelled == "open" and "open" not in module.bindings:
        action, reason = _open_class(call)
        return action, "open", reason

    is_process_launch = qualified.startswith("subprocess.") or qualified in {
        "os.system",
        "os.popen",
    }
    if is_process_launch and qualified in SENSITIVE_SYMBOLS:
        # Shelling out to curl or scp is egress; anything else is privileged execution.
        return _subprocess_class(call), qualified, None

    if qualified in SENSITIVE_SYMBOLS:
        return "sensitive", qualified, None
    if qualified in _ENVIRON_READERS or qualified in _ENVIRON_BULK:
        return (
            ("sensitive", qualified, None)
            if _env_is_secret(call, qualified)
            else (None, None, None)
        )
    if qualified in EXTERNAL_SYMBOLS:
        return "external", qualified, None
    if qualified in WRITE_SYMBOLS:
        return "write", qualified, None
    if qualified in READ_SYMBOLS:
        action = "sensitive" if _is_credential_path(call) else "read"
        return action, qualified, None

    sql = _sql_class(call)
    if sql is not None:
        return sql, f"{sql}_sql_statement", None

    # Receiver-based resolution: the origin, never the bare attribute, is the evidence.
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        tracked = origins.get(call.func.value.id)
        if tracked is not None:
            origin, constructor = tracked
            if origin in EXTERNAL_RECEIVERS:
                return "external", f"{origin}.{call.func.attr}", None
            if origin in PATH_RECEIVERS:
                if call.func.attr in WRITE_RECEIVER_METHODS:
                    return "write", f"{origin}.{call.func.attr}", None
                if call.func.attr in READ_RECEIVER_METHODS:
                    credential = _is_credential_path(call) or _is_credential_path(constructor)
                    return (
                        "sensitive" if credential else "read",
                        f"{origin}.{call.func.attr}",
                        None,
                    )

    if isinstance(call.func, ast.Attribute) and call.func.attr in DB_EXECUTE_METHODS:
        # A recognised execute whose query is not a literal cannot be classified.
        return None, None, "NONLITERAL_ARGUMENT"

    if qualified in EXTERNAL_RECEIVERS or qualified in PATH_RECEIVERS:
        # Constructing a recognised receiver is not itself an effect; its methods are.
        return None, None, None

    # A call into a third-party package the catalog does not describe could do anything.
    # Treating it as harmless would let an unrecognised HTTP client publish as `read`.
    # Standard-library calls outside the catalog stay benign, or nearly every tool that
    # formats a string or logs a line would be refused and `unknown` would lose meaning.
    origin_root = qualified.split(".", 1)[0]
    imported_roots = {binding.split(".", 1)[0] for binding in module.bindings.values()}
    if origin_root in imported_roots and origin_root not in sys.stdlib_module_names:
        return None, None, "UNRESOLVED_CALLEE"

    return None, None, None


def _lexical_pii_tokens(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: list[str] = [argument.arg for argument in function.args.args]
    for node in ast.walk(function):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.append(node.value)
    found: set[str] = set()
    for name in names:
        compact = name.casefold().replace("_", "").replace("-", "")
        for token in PII_TOKENS:
            if token in compact:
                found.add(token)
    return found


def _collect_signals(
    tool: DiscoveredTool,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    module: _Module,
    via: tuple[str, ...],
    depth: int,
    visited: set[str],
) -> None:
    """Walk one function, recording signals and following module-local helpers."""

    if len(visited) > MAX_REACHABLE_FUNCTIONS_PER_TOOL:
        tool.reasons.add("BUDGET_EXHAUSTED")
        tool.budget_state = "exhausted"
        return

    # Module-level bindings are the fallback; the function's own bindings win over them.
    origins = dict(module.module_origins)
    origins.update(_scope_origins(function.body, module))
    dynamic = _dynamic_locals(function, module)
    shadowed = _local_names(function)

    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        action, symbol, reason = _classify_call(node, module, origins, dynamic)
        if reason:
            tool.reasons.add(reason)
        if action and symbol:
            tool.signals.append(EffectSignal(action, symbol, module.path, node.lineno, via))
            continue
        if depth >= MAX_CALL_DEPTH:
            continue
        # Follow a call into a module-local helper so effects one hop away still count.
        spelled = _dotted(node.func)
        if spelled and "." not in spelled and spelled not in module.bindings:
            if spelled in shadowed:
                # The caller binds this name itself -- a parameter or a local. Whatever
                # runs is supplied from outside, so following a module function of the
                # same name would invent a call path that does not exist.
                tool.reasons.add("UNRESOLVED_CALLEE")
                continue
            if spelled not in module.functions:
                continue
            if spelled in visited:
                continue
            visited.add(spelled)
            _collect_signals(
                tool, module.functions[spelled], module, (*via, spelled), depth + 1, visited
            )

    if module.wildcard_import:
        tool.reasons.add("UNRESOLVED_CALLEE")

    pii = _lexical_pii_tokens(function)
    behavioural = {signal.action_class for signal in tool.signals}
    # A name that looks like personal data is not, on its own, an effect. It may only
    # push a tool to unknown, never assign it a class.
    lexical_only = bool(pii) and not behavioural
    if lexical_only and (pii & HIGH_SPECIFICITY_PII_TOKENS or len(pii) >= 2):
        tool.reasons.add("LEXICAL_ONLY")


def _decorator_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef, module: _Module
) -> list[tuple[str | None, ast.AST]]:
    resolved: list[tuple[str | None, ast.AST]] = []
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        resolved.append((_resolve(_dotted(target), module), decorator))
    return resolved


def _tool_name_from_decorator(decorator: ast.AST, fallback: str) -> str:
    if isinstance(decorator, ast.Call):
        positional = _constant_str(decorator.args[0]) if decorator.args else None
        if positional:
            return positional
        keyword = _keyword(decorator, "name")
        named = _constant_str(keyword) if keyword is not None else None
        if named:
            return named
    return fallback


def _discover_decorated_tools(module: _Module) -> list[DiscoveredTool]:
    discovered: list[DiscoveredTool] = []
    for function in [*module.functions.values(), *module.methods]:
        for qualified, decorator in _decorator_names(function, module):
            framework: str | None = None
            if qualified in LANGCHAIN_TOOL_DECORATORS:
                framework = "langchain_tool_decorator"
            elif qualified and qualified.endswith(".tool"):
                # FastMCP and similar: @<server>.tool(). The receiver is a local object,
                # so this is recorded as a lower-confidence framework, never as proof.
                framework = "server_tool_decorator"
            elif qualified and qualified.endswith(".call_tool"):
                framework = "mcp_call_tool"
            if framework is None:
                continue
            discovered.append(
                DiscoveredTool(
                    _tool_name_from_decorator(decorator, function.name),
                    framework,
                    module.path,
                    function.lineno,
                )
            )
            break
    return discovered


def _discover_factory_tools(module: _Module) -> list[DiscoveredTool]:
    discovered: list[DiscoveredTool] = []
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = _resolve(_dotted(node.func), module)
        if qualified not in STRUCTURED_TOOL_FACTORIES:
            continue
        keyword = _keyword(node, "name")
        target = _keyword(node, "func") or _keyword(node, "fn") or _keyword(node, "coroutine")
        fallback = target.id if isinstance(target, ast.Name) else "unnamed_tool"
        tool = DiscoveredTool(
            _constant_str(keyword) or fallback,
            "structured_tool_factory",
            module.path,
            node.lineno,
        )
        if not isinstance(target, ast.Name) or target.id not in module.functions:
            tool.reasons.add("BODY_UNAVAILABLE")
        discovered.append(tool)
    return discovered


def _bound_tool_names(module: _Module) -> set[str]:
    """Names passed in a ``tools=[...]`` list to a recognised agent constructor."""

    bound: set[str] = set()
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = _resolve(_dotted(node.func), module)
        candidates: list[ast.AST] = []
        if qualified in AGENT_TOOL_BINDERS:
            candidates.extend(node.args)
        keyword = _keyword(node, "tools")
        if keyword is not None:
            candidates.append(keyword)
        for candidate in candidates:
            if isinstance(candidate, ast.List):
                for element in candidate.elts:
                    if isinstance(element, ast.Name):
                        bound.add(element.id)
    return bound


def analyze_sources(
    collection: SourceCollection,
) -> tuple[list[DiscoveredTool], list[dict[str, str]]]:
    """Discover tools across *collection* and classify each one's observed effects.

    Returns the discovered tools and a list of parse problems, both ordered
    deterministically so the same tree always produces the same artifact.
    """

    modules: list[_Module] = []
    problems: list[dict[str, str]] = []

    for source in collection.files:
        try:
            tree = ast.parse(source.text, filename=source.relative_path)
        except SyntaxError as error:
            problems.append(
                {"file": source.relative_path, "reason": f"syntax_error_line_{error.lineno or 0}"}
            )
            continue
        if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES_PER_MODULE:
            problems.append({"file": source.relative_path, "reason": "module_exceeds_node_budget"})
            continue
        modules.append(_index_module(source.relative_path, tree))

    tools: list[DiscoveredTool] = []
    for module in modules:
        candidates = _discover_decorated_tools(module) + _discover_factory_tools(module)
        bound = _bound_tool_names(module)
        for name in sorted(bound):
            if name in module.functions and not any(
                tool.file == module.path and tool.name == name for tool in candidates
            ):
                candidates.append(
                    DiscoveredTool(
                        name, "bound_plain_function", module.path, module.functions[name].lineno
                    )
                )

        for tool in candidates:
            function = module.functions.get(tool.name)
            if function is None:
                function = next(
                    (
                        candidate
                        for candidate in module.methods
                        if candidate.lineno == tool.line or candidate.name == tool.name
                    ),
                    None,
                )
            if function is None:
                # A renamed tool still resolves through the function it decorated.
                function = next(
                    (
                        candidate
                        for candidate in module.functions.values()
                        if candidate.lineno == tool.line
                    ),
                    None,
                )
            if function is None:
                tool.reasons.add("BODY_UNAVAILABLE")
            else:
                _collect_signals(tool, function, module, (tool.name,), 0, {tool.name})
            tools.append(tool)

    tools.sort(key=lambda tool: (tool.name, tool.file, tool.line))
    for tool in tools:
        tool.signals.sort(key=lambda signal: (signal.file, signal.line, signal.symbol))
    problems.sort(key=lambda problem: problem["file"])
    return tools, problems
