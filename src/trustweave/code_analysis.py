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
    RESULT_CONSTRUCTORS,
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

# Path classmethods that return a Path, so the receiver survives the call.
PATH_CONSTRUCTORS: Final[frozenset[str]] = frozenset({"home", "cwd", "resolve", "absolute"})

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
# Pseudo-origin for a local bound directly to os.environ.
_ENVIRON_ORIGIN: Final[str] = "os.environ"
# Sentinel: a resolved call the catalog has no entry for.
_UNRECOGNIZED: Final[str] = "\x00unrecognized"
_DYNAMIC_SYMBOLS: Final[frozenset[str]] = frozenset(
    {"eval", "exec", "getattr", "globals", "importlib.import_module", "vars"}
)

LANGCHAIN_TOOL_DECORATORS: Final[frozenset[str]] = frozenset(
    {"langchain_core.tools.tool", "langchain.tools.tool", "langchain.agents.tool"}
)
# Semantic Kernel registers a plugin method with a decorator carrying the exposed name.
SEMANTIC_KERNEL_DECORATORS: Final[frozenset[str]] = frozenset(
    {
        "semantic_kernel.functions.kernel_function",
        "semantic_kernel.functions.kernel_function_decorator.kernel_function",
        "semantic_kernel.kernel_function",
        "semantic_kernel.skill_definition.sk_function",
    }
)
# LangChain's class-based tools. The exposed name is a class attribute and the behaviour is
# in `_run` or `_arun`, so neither the decorator nor the factory path discovers them.
BASE_TOOL_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "langchain_core.tools.BaseTool",
        "langchain_core.tools.base.BaseTool",
        "langchain.tools.BaseTool",
        "langchain.tools.base.BaseTool",
    }
)
BASE_TOOL_BODY_METHODS: Final[tuple[str, ...]] = ("_run", "run", "_arun", "arun")

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
    # The Python symbol that implements the tool, when the registered name differs from it.
    # `StructuredTool.from_function(func=summarize_bucket_object, name="object_summary")`
    # exposes one name to the model and is implemented by another, and a reviewer checking
    # the effects needs the second to find the code.
    implementation: str | None = None
    signals: list[EffectSignal] = field(default_factory=list)
    reasons: set[str] = field(default_factory=set)
    budget_state: str = "complete"
    # A call that resolved to a real symbol the catalog does not describe. It is not a
    # refusal on its own: it only matters when an unseen effect could outrank what was
    # observed.
    unrecognized_calls: int = 0

    def proposed_action_class(self) -> str:
        """Return the highest-precedence observed class, or ``unknown`` if refused."""

        observed = {signal.action_class for signal in self.signals}
        highest = next(
            (candidate for candidate in ACTION_CLASS_PRECEDENCE if candidate in observed),
            "read",
        )
        # Nothing outranks the top of the precedence order. Once a credential read or an
        # arbitrary process launch has actually been observed, no unresolved call elsewhere
        # in the tool can make the answer worse, so refusing would discard a finding rather
        # than protect against one. The same exemption already applies to unplaced calls
        # below; this extends it to the refusal reasons for the same reason.
        if highest == ACTION_CLASS_PRECEDENCE[0]:
            return highest
        if self.reasons:
            return UNKNOWN_ACTION_CLASS
        if self.unrecognized_calls and highest != ACTION_CLASS_PRECEDENCE[0]:
            # Something in the reachable set could not be placed, and an unseen effect
            # could outrank what was observed. Answering here would turn a gap in the
            # catalog into a benign verdict, which is the one direction a security review
            # must never fail in.
            return UNKNOWN_ACTION_CLASS
        return highest

    def confidence(self) -> str:
        if self.reasons:
            return "review"
        return "review" if self.proposed_action_class() == UNKNOWN_ACTION_CLASS else "high"


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
    # Receivers a class stores on self, keyed by the owning class then the attribute.
    # `self.client = httpx.Client()` in __init__ is how real tools hold a client, and
    # refusing every self.* call rather than resolving it published egress as read.
    self_origins: dict[str, dict[str, str]] = field(default_factory=dict)
    # Which class each discovered method belongs to, so self.* resolves per class.
    method_owner: dict[str, str] = field(default_factory=dict)
    # Attributes bound directly to an imported symbol rather than to a constructed
    # receiver, keyed by the owning class then the attribute.
    self_symbols: dict[str, dict[str, str]] = field(default_factory=dict)


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
            source_module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    wildcard = True
                    continue
                bindings[alias.asname or alias.name] = (
                    f"{source_module}.{alias.name}" if source_module else alias.name
                )

    # Only module-level functions may be reached by a bare name. Indexing class methods
    # and nested functions here would let `Class.send` satisfy a call to an imported
    # `send`, and would let a method body be attributed to an unrelated caller.
    methods: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    self_origins: dict[str, dict[str, str]] = {}
    self_symbols: dict[str, dict[str, str]] = {}
    method_owner: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            functions.setdefault(node.name, node)
        elif isinstance(node, ast.ClassDef):
            own = [
                child
                for child in node.body
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
            ]
            methods.extend(own)
            for child in own:
                method_owner[f"{child.name}:{child.lineno}"] = node.name
            stored: dict[str, str] = {}
            aliased: dict[str, str] = {}
            for inner in ast.walk(node):
                if isinstance(inner, ast.Assign) and isinstance(
                    inner.value, ast.Name | ast.Attribute
                ):
                    # `self._shell = os.system`: the attribute is the symbol itself, not a
                    # constructed receiver, and calling it is calling that symbol.
                    for target in inner.targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id in _INSTANCE_RECEIVERS
                        ):
                            aliased[target.attr] = _dotted(inner.value) or ""
                if not isinstance(inner, ast.Assign) or not isinstance(inner.value, ast.Call):
                    continue
                for target in inner.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id in _INSTANCE_RECEIVERS
                    ):
                        stored[target.attr] = _dotted(inner.value.func) or ""
            if stored:
                self_origins[node.name] = stored
            if aliased:
                self_symbols[node.name] = aliased

    indexed = _Module(
        path,
        tree,
        bindings,
        functions,
        wildcard,
        methods=methods,
        self_symbols=self_symbols,
        self_origins={
            owner: {attr: _resolve_raw(spelled, bindings) for attr, spelled in stored.items()}
            for owner, stored in self_origins.items()
        },
        method_owner=method_owner,
    )
    indexed.module_origins = _scope_origins(tree.body, indexed)
    return indexed


def _resolve_raw(name: str | None, bindings: dict[str, str]) -> str:
    """Rewrite a dotted spelling through import bindings, without a _Module."""

    if not name:
        return ""
    head, _, tail = name.partition(".")
    target = bindings.get(head)
    if target is None:
        return name
    return f"{target}.{tail}" if tail else target


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


def _instance_attribute(call: ast.Call) -> str | None:
    """Return the ``self.<attr>`` name a call is reached through, if any."""

    current: ast.AST = call.func
    while isinstance(current, ast.Attribute):
        if isinstance(current.value, ast.Name) and current.value.id in _INSTANCE_RECEIVERS:
            return current.attr
        current = current.value
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
            # Only a call that selects behaviour at runtime makes the bound name opaque.
            # Treating every unresolved constructor as dispatch refused ordinary local
            # classes and cost far more recall than it bought.
            spelled = _dotted(node.value.func)
            resolved = _resolve(spelled, module)
            opaque = spelled in _DYNAMIC_SYMBOLS or resolved in _DYNAMIC_SYMBOLS
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


def _symbol_aliases(scope: ast.AST, module: _Module) -> dict[str, str]:
    """Local names bound directly to an imported symbol.

    `runner = sp.run` followed by `runner(argv)` is an ordinary way to write a call, and
    reading the second line as an unresolvable callee reports arbitrary process launch as no
    effect at all -- the most dangerous class, published as silence.

    Only a direct name or attribute binding counts. Anything computed stays with
    `_dynamic_locals`, and a name bound twice to different symbols is dropped rather than
    resolved to whichever assignment came last.
    """

    aliases: dict[str, str] = {}
    rebound: set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(node.value, ast.Name | ast.Attribute):
            continue
        qualified = _resolve(_dotted(node.value), module)
        if qualified is None or "." not in qualified:
            continue
        if target.id in aliases and aliases[target.id] != qualified:
            rebound.add(target.id)
        aliases[target.id] = qualified
    for name in rebound:
        aliases.pop(name, None)
    return aliases


def _path_segments(value: ast.expr) -> list[ast.expr]:
    """Constant string parts of a path expression, including `/` composition.

    `home = Path.home()` then `home / ".ssh" / "id_rsa"` puts the part that decides whether
    this is an ordinary read or a credential read in the composition rather than in the
    constructor. Recording only the constructor's arguments read the private key as an
    ordinary file.
    """

    return [
        node
        for node in ast.walk(value)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def _local_instances(scope: ast.AST, module: _Module) -> dict[str, str]:
    """Locals bound to an instance of a class this module defines.

    `store = ContactStore(dsn)` then `store.forget(id)` puts the effect one hop away in a
    method of a class written in the same file. Not following it left the tool with no
    observed effect at all, and a tool with no effects is classified read -- so a database
    delete was published as a benign read rather than as unknown.
    """

    classes = {node.name for node in module.tree.body if isinstance(node, ast.ClassDef)}
    found: dict[str, str] = {}
    rebound: set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(node.value, ast.Call):
            continue
        constructed = _dotted(node.value.func)
        if constructed not in classes:
            continue
        if target.id in found and found[target.id] != constructed:
            rebound.add(target.id)
        found[target.id] = constructed
    for name in rebound:
        found.pop(name, None)
    return found


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


def _scope_origins(
    scope_body: list[ast.stmt],
    module: _Module,
    self_attributes: dict[str, str] | None = None,
) -> dict[str, tuple[str, ast.Call]]:
    """Track receiver constructors bound directly in one statement list.

    Only assignments at this level count. Walking the whole tree would let a binding
    inside an unrelated function decide what a name means here, which silently changes
    another tool's classification.
    """

    self_attributes = self_attributes or {}
    origins: dict[str, tuple[str, ast.Call]] = {}
    ambiguous: set[str] = set()

    def _bind(name: str, qualified: str, call: ast.Call) -> None:
        if name in origins and origins[name][0] != qualified:
            # Rebound to a different receiver: neither reading is safe to assume.
            ambiguous.add(name)
        origins[name] = (qualified, call)

    def _receiver_of(value: ast.expr) -> str | None:
        """Return the receiver origin a value carries, through the ways it can be passed on."""

        # `root = Path.home() / ".notes"`: path composition keeps the receiver.
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
            return _receiver_of(value.left) or _receiver_of(value.right)
        # `chat = self._client.chat.completions`: an attribute reached through a stored
        # receiver still belongs to that receiver.
        if isinstance(value, ast.Attribute):
            if _resolve(_dotted(value), module) == "os.environ":
                # `env = os.environ` then `env.get(...)` is still an environment read.
                return _ENVIRON_ORIGIN
            current: ast.AST = value
            while isinstance(current, ast.Attribute):
                if (
                    isinstance(current.value, ast.Name)
                    and current.value.id in _INSTANCE_RECEIVERS
                    and current.attr in self_attributes
                ):
                    return self_attributes[current.attr]
                current = current.value
            if isinstance(current, ast.Name) and current.id in origins:
                return origins[current.id][0]
            return None
        if not isinstance(value, ast.Call):
            # `with client as session`: the manager is a name already tracked above.
            if isinstance(value, ast.Name) and value.id in origins:
                return origins[value.id][0]
            return None
        qualified = _resolve(_dotted(value.func), module)
        if qualified in EXTERNAL_RECEIVERS or qualified in PATH_RECEIVERS:
            return qualified
        # `Path.home()` and `Path.cwd()` return the receiver they are called on.
        if isinstance(value.func, ast.Attribute):
            base = _resolve(_dotted(value.func.value), module)
            if base in PATH_RECEIVERS and value.func.attr in PATH_CONSTRUCTORS:
                return base
            if base in EXTERNAL_RECEIVERS:
                return base
        # `async with session.get(url) as response`: the receiver is the caller.
        root = _root_name(value.func)
        if root is not None and root in origins:
            return origins[root][0]
        return _receiver_of(value.func) if isinstance(value.func, ast.Attribute) else None

    for statement in scope_body:
        if isinstance(statement, ast.Assign):
            origin = _receiver_of(statement.value)
            if origin is not None:
                call = (
                    statement.value
                    if isinstance(statement.value, ast.Call)
                    else ast.Call(
                        func=ast.Name(id=origin),
                        args=_path_segments(statement.value),
                        keywords=[],
                    )
                )
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        _bind(target.id, origin, call)
            continue
        if isinstance(statement, ast.With | ast.AsyncWith):
            # A context manager keeps the receiver's identity; losing it here made an
            # HTTP client used as `with client as session` look like an untracked local.
            for item in statement.items:
                origin = _receiver_of(item.context_expr)
                if origin is None or not isinstance(item.optional_vars, ast.Name):
                    continue
                call = (
                    item.context_expr
                    if isinstance(item.context_expr, ast.Call)
                    else ast.Call(func=ast.Name(id=origin), args=[], keywords=[])
                )
                _bind(item.optional_vars.id, origin, call)
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


def _environ_class(
    call: ast.Call, symbol: str, literals: dict[str, ast.expr] | None = None
) -> tuple[str | None, str | None, str | None]:
    """Classify one environment read, refusing when the key decides the answer.

    A literal key can be judged against the secret-name vocabulary. A key supplied at
    runtime cannot: the same call reads a log path or a private key depending on its
    caller, so answering would turn a credential read into a benign one.
    """

    if symbol.rsplit(".", 1)[-1] in {"items", "copy", "values"} or qualified_is_bulk(symbol):
        return "sensitive", symbol, None
    argument = call.args[0] if call.args else None
    # A helper that takes the variable name as a parameter is still reading a named
    # variable; the name is simply one frame up. Without this a secret read moved into a
    # one-line helper became unclassifiable.
    if isinstance(argument, ast.Name) and literals and argument.id in literals:
        argument = literals[argument.id]
    key = _constant_str(argument) if argument is not None else None
    if key is None:
        return None, None, "NONLITERAL_ARGUMENT"
    tokens = {token for token in key.casefold().replace("-", "_").split("_") if token}
    if tokens & SECRET_ENV_TOKENS:
        return "sensitive", symbol, None
    return None, None, None


def qualified_is_bulk(symbol: str) -> bool:
    return symbol in _ENVIRON_BULK


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
    self_attributes: dict[str, str] | None = None,
    aliases: dict[str, str] | None = None,
    self_aliases: dict[str, str] | None = None,
    literals: dict[str, ast.expr] | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Return (action_class, symbol, refusal_reason) for one call site."""

    self_attributes = self_attributes or {}
    spelled = _dotted(call.func)
    # A bare name bound to an imported symbol is that symbol.
    if isinstance(call.func, ast.Name) and call.func.id not in dynamic:
        spelled = (aliases or {}).get(call.func.id, spelled)
    # So is an instance attribute bound to one: `self._shell = os.system` in __init__ makes
    # `self._shell(...)` a shell invocation, and refusing it reports that as no effect.
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in _INSTANCE_RECEIVERS
    ):
        bound = _resolve((self_aliases or {}).get(call.func.attr, ""), module)
        if bound and "." in bound:
            spelled = bound
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

    # `handle = anthropic.Anthropic()` then `handle.messages.create(...)`. The receiver is
    # known, but the method sits behind an attribute chain, and reading only the first level
    # left the call resolving to nothing at all -- neither an effect nor a refusal. Every
    # LLM and cloud SDK is shaped this way, so egress published as silence.
    if root is not None and root in origins and isinstance(call.func, ast.Attribute):
        receiver, constructor = origins[root]
        method = call.func.attr
        if receiver in EXTERNAL_RECEIVERS:
            return "external", f"{receiver}.{method}", None
        if receiver in PATH_RECEIVERS:
            if method in WRITE_RECEIVER_METHODS:
                return "write", f"{receiver}.{method}", None
            if method in READ_RECEIVER_METHODS:
                action = "sensitive" if _is_credential_path(constructor) else "read"
                return action, f"{receiver}.{method}", None

    if _is_instance_state_call(call):
        # self.client.post(...). Resolve it when the class stored a known receiver on that
        # attribute; refuse only when the attribute's origin is genuinely unknown, since
        # reporting no effect here would publish an outbound call as read.
        attribute = _instance_attribute(call)
        origin = self_attributes.get(attribute or "")
        method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        if origin in EXTERNAL_RECEIVERS:
            return "external", f"{origin}.{method}", None
        if origin in PATH_RECEIVERS:
            if method in WRITE_RECEIVER_METHODS:
                return "write", f"{origin}.{method}", None
            if method in READ_RECEIVER_METHODS:
                return "read", f"{origin}.{method}", None
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
        open_action, open_reason = _open_class(call)
        return open_action, "open", open_reason

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
        return _environ_class(call, qualified, literals)
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
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and (origins.get(call.func.value.id) or ("", None))[0] == _ENVIRON_ORIGIN
        and call.func.attr in {"get", "setdefault", "items", "copy", "values"}
    ):
        return _environ_class(call, f"os.environ.{call.func.attr}", literals)

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
        if qualified in RESULT_CONSTRUCTORS:
            # Wrapping a return value is not an effect, and must not outrank one.
            return None, None, None
        return _UNRECOGNIZED, None, None

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
    literals: dict[str, ast.expr] | None = None,
    inherited: dict[str, tuple[str, ast.Call]] | None = None,
) -> None:
    """Walk one function, recording signals and following module-local helpers."""

    if len(visited) > MAX_REACHABLE_FUNCTIONS_PER_TOOL:
        tool.reasons.add("BUDGET_EXHAUSTED")
        tool.budget_state = "exhausted"
        return

    owner = module.method_owner.get(f"{function.name}:{function.lineno}")
    self_attributes = module.self_origins.get(owner or "", {})
    self_aliases = module.self_symbols.get(owner or "", {})
    # Module-level bindings are the fallback; the function's own bindings win over them.
    origins = dict(module.module_origins)
    # Receivers the caller handed over, before the callee's own bindings, which win.
    origins.update(inherited or {})
    origins.update(_scope_origins(function.body, module, self_attributes))
    dynamic = _dynamic_locals(function, module)
    aliases = _symbol_aliases(function, module)
    instances = _local_instances(function, module)
    shadowed = _local_names(function)

    decorator_nodes = {
        id(inner) for decorator in function.decorator_list for inner in ast.walk(decorator)
    }
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or id(node) in decorator_nodes:
            # A decorator registers the tool with a framework. It is not behaviour the tool
            # performs, and classifying it made every decorated tool refuse on its own
            # registration call.
            continue
        action, symbol, reason = _classify_call(
            node, module, origins, dynamic, self_attributes, aliases, self_aliases, literals
        )
        if reason:
            tool.reasons.add(reason)
        if action == _UNRECOGNIZED:
            tool.unrecognized_calls += 1
            continue
        if action and symbol:
            tool.signals.append(EffectSignal(action, symbol, module.path, node.lineno, via))
            continue
        if depth >= MAX_CALL_DEPTH:
            continue
        # A call on an instance of a class this module defines is one hop, like a helper.
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in instances
        ):
            owning = instances[node.func.value.id]
            method = next(
                (
                    candidate
                    for candidate in module.methods
                    if candidate.name == node.func.attr
                    and module.method_owner.get(f"{candidate.name}:{candidate.lineno}") == owning
                ),
                None,
            )
            key = f"{owning}.{node.func.attr}"
            if method is not None and key not in visited:
                visited.add(key)
                _collect_signals(tool, method, module, (*via, node.func.attr), depth + 1, visited)
            continue
        # A call to a sibling method of the same class is one hop, exactly like a module
        # helper. Not following it left every effect reached through `self._invoke`
        # invisible, which is how a shell invocation two hops down read as no effect.
        if (
            owner is not None
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in _INSTANCE_RECEIVERS
        ):
            sibling = next(
                (
                    candidate
                    for candidate in module.methods
                    if candidate.name == node.func.attr
                    and module.method_owner.get(f"{candidate.name}:{candidate.lineno}") == owner
                ),
                None,
            )
            key = f"{owner}.{node.func.attr}"
            if sibling is not None and key not in visited:
                visited.add(key)
                _collect_signals(tool, sibling, module, (*via, node.func.attr), depth + 1, visited)
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
            helper = module.functions[spelled]
            # Constants the caller supplies are bound to the helper's parameters, so a
            # decision that depends on a literal is still decidable one frame down.
            passed: dict[str, ast.expr] = {
                parameter.arg: argument
                for parameter, argument in zip(helper.args.args, node.args, strict=False)
                if isinstance(argument, ast.Constant)
            }
            # A receiver created in one function and handed to another keeps its identity.
            # `session = ClientSession()`, then `_collect(session, symbol)`, then
            # `session.get(url)` is how async clients are written, and losing the receiver
            # at the call boundary reported the egress as an unresolvable callee.
            handed: dict[str, tuple[str, ast.Call]] = {
                parameter.arg: origins[argument.id]
                for parameter, argument in zip(helper.args.args, node.args, strict=False)
                if isinstance(argument, ast.Name) and argument.id in origins
            }
            _collect_signals(
                tool, helper, module, (*via, spelled), depth + 1, visited, passed, handed
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
            elif qualified in SEMANTIC_KERNEL_DECORATORS:
                framework = "semantic_kernel_decorator"
            elif qualified and qualified.endswith(".tool"):
                # FastMCP and similar: @<server>.tool(). The receiver is a local object,
                # so this is recorded as a lower-confidence framework, never as proof.
                framework = "server_tool_decorator"
            elif qualified and qualified.endswith(".call_tool"):
                framework = "mcp_call_tool"
            if framework is None:
                continue
            registered = _tool_name_from_decorator(decorator, function.name)
            discovered.append(
                DiscoveredTool(
                    registered,
                    framework,
                    module.path,
                    function.lineno,
                    implementation=function.name if registered != function.name else None,
                )
            )
            break
    return discovered


def _class_attribute_string(node: ast.ClassDef, attribute: str) -> str | None:
    """The literal string a class assigns to *attribute*, annotated or not."""

    for child in node.body:
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            target, value = child.target.id, child.value
        elif (
            isinstance(child, ast.Assign)
            and len(child.targets) == 1
            and isinstance(child.targets[0], ast.Name)
        ):
            target, value = child.targets[0].id, child.value
        else:
            continue
        if target == attribute and value is not None:
            return _constant_str(value)
    return None


def _discover_class_tools(module: _Module) -> list[DiscoveredTool]:
    """LangChain tools written as a BaseTool subclass rather than a decorated function.

    The tool is located at its `_run` body rather than at the class statement, so the
    existing body resolution reaches the code that actually performs the effect. Without
    this the whole class is invisible: the effects it performs are never attributed to any
    tool, and a reviewer reading the discovery artifact sees a smaller tool surface than the
    agent really exposes.
    """

    discovered: list[DiscoveredTool] = []
    for node in module.tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        if not any(_resolve(_dotted(base), module) in BASE_TOOL_CLASSES for base in node.bases):
            continue
        methods = {
            child.name: child
            for child in node.body
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        body = next((methods[name] for name in BASE_TOOL_BODY_METHODS if name in methods), None)
        discovered.append(
            DiscoveredTool(
                _class_attribute_string(node, "name") or node.name,
                "langchain_base_tool_subclass",
                module.path,
                body.lineno if body is not None else node.lineno,
                implementation=node.name,
            )
        )
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
        # A factory may be handed a free function or a bound method. `func=summarize` names
        # a module function; `coroutine=_instance.rotate_logs` names a method, and reading
        # only the first form declared the second body unavailable and analysed nothing.
        if isinstance(target, ast.Name):
            implementation = target.id
        elif isinstance(target, ast.Attribute):
            implementation = target.attr
        else:
            implementation = None
        reachable = implementation is not None and (
            implementation in module.functions
            or any(method.name == implementation for method in module.methods)
        )
        tool = DiscoveredTool(
            _constant_str(keyword) or implementation or "unnamed_tool",
            "structured_tool_factory",
            module.path,
            node.lineno,
            implementation=implementation,
        )
        if not reachable:
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
        candidates = (
            _discover_decorated_tools(module)
            + _discover_class_tools(module)
            + _discover_factory_tools(module)
        )
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
            function = module.functions.get(tool.implementation or tool.name) or (
                module.functions.get(tool.name)
            )
            if function is None:
                function = next(
                    (
                        candidate
                        for candidate in module.methods
                        if candidate.lineno == tool.line
                        or candidate.name == (tool.implementation or tool.name)
                        or candidate.name == tool.name
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
