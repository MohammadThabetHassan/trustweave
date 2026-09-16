"""How an effect reaches a tool through a receiver, one shape per case.

An agent rarely calls `requests.get` on the line that matters. It builds a client and
calls a method on it, or stores the client on `self` in `__init__`, or binds a symbol to
an attribute, or chains through a sub-object the SDK exposes. Each of those is a separate
branch of `_classify_call`, and mutation testing found them to be the least asserted part
of the module: 74 survivors in that one function, most of them in the receiver branches.

Every case here asserts the resolved symbol as well as the class, because the symbol is
what tells a reviewer where to look, and a corrupted one is invisible to a test that only
checks the class.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustweave import code_catalog as catalog
from trustweave.code_analysis import analyze_sources
from trustweave.code_sources import collect_python_sources

TOOL_IMPORT = "from langchain_core.tools import tool"
CREDENTIAL_PATH = "/home/agent/.ssh/id_rsa"
ORDINARY_PATH = "/var/lib/agent/notes.txt"


def _single_tool(tmp_path: Path, source: str):
    (tmp_path / "agent.py").write_text(source, encoding="utf-8")
    tools, _ = analyze_sources(collect_python_sources(tmp_path))
    assert len(tools) == 1, [tool.name for tool in tools]
    return tools[0]


def _signal_for(tool, symbol: str):
    matching = [signal for signal in tool.signals if signal.symbol == symbol]
    assert matching, (
        f"no signal resolved {symbol!r}; got {[(s.action_class, s.symbol) for s in tool.signals]}"
    )
    return matching[0]


def _module_of(symbol: str) -> str:
    parts = symbol.split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else parts[0]


# ---------------------------------------------------------------------------------------
# Shape 1: the method is called straight on the constructor
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("receiver", sorted(catalog.EXTERNAL_RECEIVERS))
def test_a_method_on_a_constructor_resolves_through_the_constructor(
    tmp_path: Path, receiver: str
) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        f"import {_module_of(receiver)}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe an inline constructor."""\n'
        f"    return {receiver}().send(value)\n"
    )
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, f"{receiver}.send")

    assert signal.action_class == "external"
    assert tool.proposed_action_class() == "external"


def test_an_inline_path_read_of_a_credential_is_sensitive(tmp_path: Path) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe an inline credential read."""\n'
        f"    return Path({CREDENTIAL_PATH!r}).read_text()\n"
    )
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, "pathlib.Path.read_text")

    assert signal.action_class == "sensitive"
    assert tool.proposed_action_class() == "sensitive"


def test_an_inline_path_read_of_an_ordinary_file_is_a_read(tmp_path: Path) -> None:
    """The control: the literal in the constructor has to be what decides it."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe an inline ordinary read."""\n'
        f"    return Path({ORDINARY_PATH!r}).read_text()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.read_text").action_class == "read"


def test_an_inline_path_write_is_a_write_whatever_the_path(tmp_path: Path) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe an inline write."""\n'
        f"    Path({CREDENTIAL_PATH!r}).write_text(value)\n"
        "    return value\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.write_text").action_class == "write"


# ---------------------------------------------------------------------------------------
# Shape 2: a local receiver, with the method behind an attribute chain
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("receiver", sorted(catalog.EXTERNAL_RECEIVERS))
def test_a_method_behind_an_attribute_chain_still_resolves(tmp_path: Path, receiver: str) -> None:
    """`handle.messages.create(...)` is how every LLM and cloud SDK is shaped."""

    source = (
        f"{TOOL_IMPORT}\n"
        f"import {_module_of(receiver)}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a chained receiver."""\n'
        f"    handle = {receiver}()\n"
        "    return handle.messages.create(prompt=value)\n"
    )
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, f"{receiver}.create")

    assert signal.action_class == "external"
    assert tool.proposed_action_class() == "external"


@pytest.mark.parametrize("method", sorted(catalog.READ_RECEIVER_METHODS))
def test_a_local_path_receiver_carries_the_credential_decision(tmp_path: Path, method: str) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a local path receiver."""\n'
        f"    key = Path({CREDENTIAL_PATH!r})\n"
        f"    key.{method}()\n"
        "    return value\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, f"pathlib.Path.{method}").action_class == "sensitive"


# ---------------------------------------------------------------------------------------
# Shape 3: the receiver is stored on self in __init__
# ---------------------------------------------------------------------------------------


def _class_source(constructor: str, body: str, *, preamble: str) -> str:
    return (
        f"{TOOL_IMPORT}\n"
        f"{preamble}\n"
        "\n\n"
        "class Agent:\n"
        "    def __init__(self) -> None:\n"
        f"        self.handle = {constructor}\n"
        "\n"
        "    @tool\n"
        "    def probe(self, value: str) -> str:\n"
        '        """Probe a stored receiver."""\n'
        f"{body}"
    )


@pytest.mark.parametrize("receiver", sorted(catalog.EXTERNAL_RECEIVERS))
def test_a_receiver_stored_on_self_resolves_for_a_method_call(
    tmp_path: Path, receiver: str
) -> None:
    source = _class_source(
        f"{receiver}()",
        "        return self.handle.send(value)\n",
        preamble=f"import {_module_of(receiver)}",
    )
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, f"{receiver}.send")

    assert signal.action_class == "external"
    assert tool.proposed_action_class() == "external"


def test_a_credential_path_stored_on_self_is_sensitive_when_read(tmp_path: Path) -> None:
    """The constructor ran in __init__, so only the indexed class says it is a credential."""

    source = _class_source(
        f"Path({CREDENTIAL_PATH!r})",
        "        return self.handle.read_text()\n",
        preamble="from pathlib import Path",
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.read_text").action_class == "sensitive"
    assert tool.proposed_action_class() == "sensitive"


def test_an_ordinary_path_stored_on_self_stays_a_read(tmp_path: Path) -> None:
    source = _class_source(
        f"Path({ORDINARY_PATH!r})",
        "        return self.handle.read_text()\n",
        preamble="from pathlib import Path",
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.read_text").action_class == "read"
    assert tool.proposed_action_class() == "read"


def test_a_credential_path_stored_on_self_is_a_write_when_written(tmp_path: Path) -> None:
    source = _class_source(
        f"Path({CREDENTIAL_PATH!r})",
        "        self.handle.write_text(value)\n        return value\n",
        preamble="from pathlib import Path",
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.write_text").action_class == "write"


def test_a_call_on_an_unknown_self_attribute_is_refused_rather_than_reported_benign(
    tmp_path: Path,
) -> None:
    """Reporting no effect here would publish an outbound call as a read."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "class Agent:\n"
        "    def __init__(self, handle) -> None:\n"
        "        self.handle = handle\n"
        "\n"
        "    @tool\n"
        "    def probe(self, value: str) -> str:\n"
        '        """Probe an unknown stored receiver."""\n'
        "        return self.handle.post(value)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert tool.confidence() == "review"
    assert "UNRESOLVED_CALLEE" in tool.reasons


# ---------------------------------------------------------------------------------------
# Shape 4: an attribute bound to the symbol itself
# ---------------------------------------------------------------------------------------


SELF_BOUND_SYMBOLS = ("os.system", "subprocess.run", "shutil.rmtree")


@pytest.mark.parametrize("symbol", SELF_BOUND_SYMBOLS)
def test_an_attribute_bound_to_a_symbol_is_that_symbol_when_called(
    tmp_path: Path, symbol: str
) -> None:
    """`self._shell = os.system` in __init__ makes `self._shell(...)` a shell call."""

    source = (
        f"{TOOL_IMPORT}\n"
        f"import {_module_of(symbol)}\n"
        "\n\n"
        "class Agent:\n"
        "    def __init__(self) -> None:\n"
        f"        self._run = {symbol}\n"
        "\n"
        "    @tool\n"
        "    def probe(self, value: str) -> str:\n"
        '        """Probe an aliased attribute."""\n'
        "        return str(self._run(value))\n"
    )
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, symbol)

    assert signal.symbol == symbol
    assert signal.action_class in catalog.ACTION_CLASS_PRECEDENCE
    assert tool.proposed_action_class() == signal.action_class


def test_the_four_receiver_shapes_agree_on_one_credential_read(tmp_path: Path) -> None:
    """The shapes must not disagree: that asymmetry is what made a secret read benign.

    All four spell the same operation -- read a private key -- and a reviewer choosing
    between them is choosing a style, not a risk.
    """

    shapes = {
        "inline constructor": (
            "from pathlib import Path\n\n\n"
            f"{TOOL_IMPORT}\n\n\n"
            "@tool\n"
            "def probe(value: str) -> str:\n"
            '    """Doc."""\n'
            f"    return Path({CREDENTIAL_PATH!r}).read_text()\n"
        ),
        "local receiver": (
            "from pathlib import Path\n\n\n"
            f"{TOOL_IMPORT}\n\n\n"
            "@tool\n"
            "def probe(value: str) -> str:\n"
            '    """Doc."""\n'
            f"    key = Path({CREDENTIAL_PATH!r})\n"
            "    return key.read_text()\n"
        ),
        "stored on self": _class_source(
            f"Path({CREDENTIAL_PATH!r})",
            "        return self.handle.read_text()\n",
            preamble="from pathlib import Path",
        ),
        "builtin open": (
            f"{TOOL_IMPORT}\n\n\n"
            "@tool\n"
            "def probe(value: str) -> str:\n"
            '    """Doc."""\n'
            f"    with open({CREDENTIAL_PATH!r}) as handle:\n"
            "        return handle.read()\n"
        ),
    }

    verdicts = {}
    for label, source in shapes.items():
        directory = tmp_path / label.replace(" ", "_")
        directory.mkdir()
        verdicts[label] = _single_tool(directory, source).proposed_action_class()

    assert set(verdicts.values()) == {"sensitive"}, verdicts


# ---------------------------------------------------------------------------------------
# Shapes the classification benchmark caught, each one an effect reported as benign
# ---------------------------------------------------------------------------------------


def test_a_stored_receiver_is_reached_through_an_attribute_chain(tmp_path: Path) -> None:
    """`self.client.chat.completions.create(...)` is how every LLM SDK is written."""

    source = _class_source(
        "openai.OpenAI()",
        "        return self.handle.chat.completions.create(prompt=value)\n",
        preamble="import openai",
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "openai.OpenAI.create").action_class == "external"
    assert tool.proposed_action_class() == "external"


def test_an_attribute_taken_from_a_constructor_keeps_the_constructor_as_receiver(
    tmp_path: Path,
) -> None:
    """`self.chat = Chat(...).chat` takes a sub-object; the receiver is still the client."""

    source = _class_source(
        "openai.OpenAI().chat",
        "        return self.handle.completions.create(prompt=value)\n",
        preamble="import openai",
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "openai.OpenAI.create").action_class == "external"


def test_calling_a_sibling_method_is_still_followed_not_classified(tmp_path: Path) -> None:
    """A bare `self.method()` must stay a traversal step, not a receiver call."""

    source = (
        f"{TOOL_IMPORT}\n"
        "import requests\n"
        "\n\n"
        "class Agent:\n"
        "    def _fetch(self, value: str) -> str:\n"
        "        return requests.get(value).text\n"
        "\n"
        "    @tool\n"
        "    def probe(self, value: str) -> str:\n"
        '        """Probe a sibling call."""\n'
        "        return self._fetch(value)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "requests.get").action_class == "external"


def test_a_module_level_instance_aliased_to_a_local_is_followed(tmp_path: Path) -> None:
    """`STORE = ContactStore(...)` then `store = STORE` is how a shared handle is reached."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "class ContactStore:\n"
        "    def __init__(self, dsn):\n"
        "        self._dsn = dsn\n"
        "\n"
        "    def forget(self, cursor):\n"
        "        cursor.execute('DELETE FROM contacts WHERE id = 1')\n"
        "        return cursor.rowcount\n"
        "\n\n"
        "STORE = ContactStore('/srv/crm/contacts.db')\n"
        "\n\n"
        "@tool\n"
        "def probe(cursor) -> str:\n"
        '    """Probe a module-level singleton."""\n'
        "    store = STORE\n"
        "    return str(store.forget(cursor))\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "write"


def test_a_body_that_only_raises_not_implemented_is_refused(tmp_path: Path) -> None:
    """The real routine is bound elsewhere, so no effect here is not evidence of none."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Archive a batch and return a receipt."""\n'
        "    raise NotImplementedError('bound at deploy time')\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert "BODY_UNAVAILABLE" in tool.reasons


def test_a_body_that_raises_conditionally_is_not_treated_as_absent(tmp_path: Path) -> None:
    """Only a body that does nothing else counts; a guard clause is ordinary code."""

    source = (
        f"{TOOL_IMPORT}\n"
        "import requests\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a guard clause."""\n'
        "    if not value:\n"
        "        raise NotImplementedError('empty')\n"
        "    return requests.get(value).text\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "external"
    assert "BODY_UNAVAILABLE" not in tool.reasons


# ---------------------------------------------------------------------------------------
# Reading the environment by subscript, which is the ordinary spelling
# ---------------------------------------------------------------------------------------


def _environ_source(expression: str, *, preamble: str = "import os") -> str:
    return (
        f"{TOOL_IMPORT}\n"
        f"{preamble}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe an environment read."""\n'
        f"    return {expression}\n"
    )


def test_a_secret_read_by_subscript_is_sensitive(tmp_path: Path) -> None:
    """`os.environ["DB_PASSWORD"]` is the common spelling and was not seen at all."""

    tool = _single_tool(tmp_path, _environ_source("os.environ['DB_PASSWORD']"))

    assert tool.proposed_action_class() == "sensitive"


def test_a_secret_read_by_subscript_through_an_imported_name_is_sensitive(
    tmp_path: Path,
) -> None:
    tool = _single_tool(
        tmp_path, _environ_source("environ['API_KEY']", preamble="from os import environ")
    )

    assert tool.proposed_action_class() == "sensitive"


def test_a_benign_environment_name_read_by_subscript_stays_a_read(tmp_path: Path) -> None:
    tool = _single_tool(tmp_path, _environ_source("os.environ['LOG_PATH']"))

    assert tool.proposed_action_class() == "read"


def test_an_environment_key_chosen_at_runtime_is_refused(tmp_path: Path) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "import os\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str) -> str:\n"
        '    """Probe a runtime key."""\n'
        "    return os.environ[name]\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert "NONLITERAL_ARGUMENT" in tool.reasons


@pytest.mark.parametrize(
    "expression",
    [
        "str({'a': 1}['a'])",
        "value.split(',')[0]",
        "str(list(value)[0])",
    ],
)
def test_an_ordinary_subscript_is_not_an_environment_read(tmp_path: Path, expression: str) -> None:
    """The rule keys on os.environ; every other subscript must stay invisible to it."""

    tool = _single_tool(tmp_path, _environ_source(expression, preamble=""))

    assert tool.proposed_action_class() == "read"
    assert tool.reasons == set()


# ---------------------------------------------------------------------------------------
# The credential store travels from its constructor, like a network client
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("receiver", sorted(catalog.SENSITIVE_RECEIVERS))
def test_a_credential_store_receiver_makes_its_methods_sensitive(
    tmp_path: Path, receiver: str
) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        f"import {_module_of(receiver)}\n"
        "\n\n"
        "@tool\n"
        "def probe(user: str) -> str:\n"
        '    """Probe a credential store."""\n'
        f"    backend = {receiver}()\n"
        "    return backend.get_password('corp-sso', user)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, f"{receiver}.get_password").action_class == "sensitive"
    assert tool.proposed_action_class() == "sensitive"


def test_a_credential_store_stored_on_self_is_sensitive(tmp_path: Path) -> None:
    source = _class_source(
        "keyring.get_keyring()",
        "        return self.handle.get_password('corp-sso', value)\n",
        preamble="import keyring",
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "sensitive"


@pytest.mark.parametrize(
    "symbol",
    ["keyring.get_password", "keyring.get_credential", "keyring.delete_password"],
)
def test_a_direct_credential_store_call_is_sensitive(tmp_path: Path, symbol: str) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "import keyring\n"
        "\n\n"
        "@tool\n"
        "def probe(user: str) -> str:\n"
        '    """Probe a direct credential call."""\n'
        f"    return {symbol}('corp-sso', user)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "sensitive"


def test_the_credential_store_catalogue_is_disjoint_from_the_network_one() -> None:
    """A receiver must yield one class, so the two tables must not overlap."""

    assert not (catalog.SENSITIVE_RECEIVERS & catalog.EXTERNAL_RECEIVERS)
    assert not (catalog.SENSITIVE_RECEIVERS & catalog.PATH_RECEIVERS)


# ---------------------------------------------------------------------------------------
# Shape 6: the path is composed with `/` at the call site
# ---------------------------------------------------------------------------------------


def test_a_composed_path_write_is_a_write(tmp_path: Path) -> None:
    """`(BASE / name).write_text(body)` was read/high with no signal at all.

    `_dotted` and `_root_name` both stop at a `BinOp`, so the whole composed spelling fell
    through to silence, and a tool that writes a file was published as a benign read.
    """

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n"
        "BASE = Path('/srv/notes')\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str, body: str) -> str:\n"
        '    """Probe a composed write."""\n'
        "    (BASE / name).write_text(body)\n"
        "    return name\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.write_text").action_class == "write"
    assert tool.proposed_action_class() == "write"
    assert tool.confidence() == "high"


def test_a_composed_path_unlink_is_a_write(tmp_path: Path) -> None:
    """The same loss crossed the delete boundary, not only the credential one."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str) -> str:\n"
        '    """Probe a composed delete."""\n'
        "    (Path('/srv/data') / name).unlink()\n"
        "    return name\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.unlink").action_class == "write"
    assert tool.proposed_action_class() == "write"


def test_a_composed_credential_read_is_sensitive(tmp_path: Path) -> None:
    """A token spanning a separator only matches once the segments are joined in order."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe() -> str:\n"
        '    """Probe a composed credential read."""\n'
        "    return (Path.home() / '.aws' / 'credentials').read_text()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.read_text").action_class == "sensitive"
    assert tool.proposed_action_class() == "sensitive"


def test_a_composed_read_of_an_ordinary_file_stays_a_read(tmp_path: Path) -> None:
    """The control: composition must not make every read sensitive."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str) -> str:\n"
        '    """Probe a composed ordinary read."""\n'
        "    return (Path('/var/lib/agent') / name).read_text()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.read_text").action_class == "read"
    assert tool.proposed_action_class() == "read"


def test_a_composed_path_bound_to_a_name_agrees_with_the_inline_spelling(
    tmp_path: Path,
) -> None:
    """Binding the composition first must reach the same class as composing at the call."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe() -> str:\n"
        '    """Probe a bound composition."""\n'
        "    target = Path.home() / '.ssh' / 'id_rsa'\n"
        "    return target.read_text()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.read_text").action_class == "sensitive"


def test_a_credential_path_spelled_as_a_keyword_is_sensitive(tmp_path: Path) -> None:
    """`open(file=...)` was an ordinary read while the positional spelling was sensitive."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe() -> str:\n"
        '    """Probe a keyword-spelled credential read."""\n'
        f"    with open(file={CREDENTIAL_PATH!r}) as handle:\n"
        "        return handle.read()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "open").action_class == "sensitive"
    assert tool.proposed_action_class() == "sensitive"


def test_an_ordinary_path_spelled_as_a_keyword_stays_a_read(tmp_path: Path) -> None:
    """The control: the keyword lookup must read the path, not every keyword value."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe() -> str:\n"
        '    """Probe a keyword-spelled ordinary read."""\n'
        f"    with open(file={ORDINARY_PATH!r}, mode='r') as handle:\n"
        "        return handle.read()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "open").action_class == "read"


# ---------------------------------------------------------------------------------------
# Shape 7: the receiver is bound one block deeper, or inherited from an outer scope
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("opener", "closer"),
    [
        ("    try:", "    except ImportError:\n        return ''"),
        ("    if value:", "    else:\n        return ''"),
        ("    for _ in range(1):", "    else:\n        return ''"),
    ],
    ids=["try", "if", "for"],
)
def test_a_receiver_bound_inside_a_block_keeps_its_origin(
    tmp_path: Path, opener: str, closer: str
) -> None:
    """A client built inside `try`/`if`/`for` was read/high with no signal at all.

    `_scope_origins` read only the flat statement list, so a receiver bound one block
    deeper never entered `origins` and every later call on it fell through to silence --
    which is published as the benign floor class.
    """

    source = (
        f"{TOOL_IMPORT}\n"
        "import httpx\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a nested receiver."""\n'
        f"{opener}\n"
        "        client = httpx.Client()\n"
        f"{closer}\n"
        "    return client.get(value).text\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "httpx.Client.get").action_class == "external"
    assert tool.proposed_action_class() == "external"
    assert tool.confidence() == "high"


def test_a_module_level_receiver_bound_inside_a_block_keeps_its_origin(
    tmp_path: Path,
) -> None:
    """The optional-dependency idiom: `try: CLIENT = httpx.Client()` at module scope."""

    source = (
        f"{TOOL_IMPORT}\n"
        "import httpx\n"
        "\n"
        "try:\n"
        "    CLIENT = httpx.Client()\n"
        "except ImportError:\n"
        "    CLIENT = None\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a module-level nested receiver."""\n'
        "    return CLIENT.get(value).text\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "httpx.Client.get").action_class == "external"
    assert tool.proposed_action_class() == "external"


def test_a_module_level_path_survives_being_derived_into_a_local(tmp_path: Path) -> None:
    """`target = CACHE_DIR / name` then `target.write_text(body)` was read/high, no signal.

    The inherited origin was discarded the moment the body derived a name from it, so a
    tool that writes a file argued a correct `write` declaration was too strict.
    """

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n"
        "CACHE_DIR = Path('/var/lib/agent/cache')\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str, body: str) -> str:\n"
        '    """Probe an inherited path."""\n'
        "    target = CACHE_DIR / (name + '.md')\n"
        "    target.write_text(body)\n"
        "    return name\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.write_text").action_class == "write"
    assert tool.proposed_action_class() == "write"


def test_a_credential_read_inside_a_block_is_still_sensitive(tmp_path: Path) -> None:
    """The worst direction: nesting downgraded a private-key read to storage.read."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a nested credential read."""\n'
        "    if value:\n"
        f"        key = Path({CREDENTIAL_PATH!r})\n"
        "        return key.read_text()\n"
        "    return ''\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.read_text").action_class == "sensitive"
    assert tool.proposed_action_class() == "sensitive"


def test_a_receiver_built_by_the_factory_is_visible_to_the_tool_it_registers(
    tmp_path: Path,
) -> None:
    """A handler registered inside a factory sees the client the factory built.

    Origins were computed from the tool's own body only, so the shape every MCP reference
    server is written in published its egress as a benign read.
    """

    source = (
        "import httpx\n"
        "from mcp.server import Server\n"
        "\n"
        "server = Server('probe')\n"
        "\n\n"
        "async def serve() -> None:\n"
        "    client = httpx.Client()\n"
        "\n"
        "    @server.call_tool()\n"
        "    async def probe(value: str) -> str:\n"
        '        """Probe a receiver built by the factory."""\n'
        "        return client.get(value).text\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "httpx.Client.get").action_class == "external"
    assert tool.proposed_action_class() == "external"


# ---------------------------------------------------------------------------------------
# Shape 8: the file handle and the archive handle
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["w", "wb", "a", "x"], ids=["w", "wb", "a", "x"])
def test_a_path_opened_for_writing_is_a_write(tmp_path: Path, mode: str) -> None:
    """`Path(p).open("w")` was read/high with no signal: `open` was in no method table."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str, body: str) -> str:\n"
        '    """Probe a path opened for writing."""\n'
        f"    with Path('/var/notes').joinpath(name).open({mode!r}) as handle:\n"
        "        handle.write(body)\n"
        "    return name\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.open").action_class == "write"
    assert tool.proposed_action_class() == "write"


def test_a_path_opened_for_reading_stays_a_read(tmp_path: Path) -> None:
    """The control: the mode is at args[0] here, not args[1] as for the builtin."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str) -> str:\n"
        '    """Probe a path opened for reading."""\n'
        f"    with Path({ORDINARY_PATH!r}).open('r', encoding='utf-8') as handle:\n"
        "        return handle.read()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.open").action_class == "read"
    assert tool.proposed_action_class() == "read"


def test_a_credential_path_opened_for_reading_is_sensitive(tmp_path: Path) -> None:
    """The path is in the constructor, so the credential decision travels with it."""

    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe() -> str:\n"
        '    """Probe a credential path opened for reading."""\n'
        f"    handle = Path({CREDENTIAL_PATH!r}).open('r')\n"
        "    return str(handle)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "pathlib.Path.open").action_class == "sensitive"


@pytest.mark.parametrize("spelling", ["io.open", "codecs.open"], ids=["io", "codecs"])
def test_every_spelling_of_the_builtin_open_is_judged_by_its_mode(
    tmp_path: Path, spelling: str
) -> None:
    """`io.open` and `codecs.open` are the builtin, and both published a write as read."""

    source = (
        f"{TOOL_IMPORT}\n"
        f"import {spelling.split('.')[0]}\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str, body: str) -> str:\n"
        '    """Probe an aliased open."""\n'
        f"    with {spelling}(name, 'w') as handle:\n"
        "        handle.write(body)\n"
        "    return name\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, spelling).action_class == "write"
    assert tool.proposed_action_class() == "write"


def test_importing_open_from_io_does_not_disable_mode_analysis(tmp_path: Path) -> None:
    """One `from io import open` made every open in the file a benign read.

    The rule dispatched on the bare token and skipped when the module bound that name, so
    the import that makes no difference at runtime disabled the analysis entirely.
    """

    source = (
        f"{TOOL_IMPORT}\n"
        "from io import open\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str, body: str) -> str:\n"
        '    """Probe a shadowed open."""\n'
        "    with open(name, 'w') as handle:\n"
        "        handle.write(body)\n"
        "    return name\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "io.open").action_class == "write"
    assert tool.proposed_action_class() == "write"


@pytest.mark.parametrize(
    ("receiver", "constructor"),
    [("zipfile.ZipFile", "zipfile.ZipFile(name)"), ("tarfile.open", "tarfile.open(name)")],
    ids=["zipfile", "tarfile"],
)
def test_extracting_an_archive_is_a_write(tmp_path: Path, receiver: str, constructor: str) -> None:
    """`z.extractall(dest)` was read/high with no signal, while `shutil.unpack_archive` was
    already catalogued as a write. An archive names its own member paths, so extraction
    writes wherever the archive says."""

    source = (
        f"{TOOL_IMPORT}\n"
        f"import {receiver.split('.')[0]}\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str, destination: str) -> str:\n"
        '    """Probe an archive extraction."""\n'
        f"    with {constructor} as bundle:\n"
        "        bundle.extractall(destination)\n"
        "    return destination\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, f"{receiver}.extractall").action_class == "write"
    assert tool.proposed_action_class() == "write"
    assert tool.confidence() == "high"


def test_reading_an_archives_member_list_is_a_read(tmp_path: Path) -> None:
    """The control: the family must not make every archive handle a write."""

    source = (
        f"{TOOL_IMPORT}\n"
        "import zipfile\n"
        "\n\n"
        "@tool\n"
        "def probe(name: str) -> str:\n"
        '    """Probe an archive listing."""\n'
        "    bundle = zipfile.ZipFile(name)\n"
        "    return str(bundle.namelist())\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "zipfile.ZipFile.namelist").action_class == "read"
    assert tool.proposed_action_class() == "read"


@pytest.mark.parametrize(
    "binding",
    [
        "    client, tries = httpx.Client(), 0\n    return client.get(value).text\n",
        "    return (client := httpx.Client()).get(value).text\n",
        "    client = httpx.Client() if value else httpx.Client(verify=False)\n"
        "    return client.get(value).text\n",
    ],
    ids=["tuple", "walrus", "conditional"],
)
def test_a_receiver_bound_by_an_unusual_shape_keeps_its_origin(
    tmp_path: Path, binding: str
) -> None:
    """Tuple unpacking, the walrus and a conditional all produced `read`/high, no signal.

    `_scope_origins` read a single `ast.Name` target and nothing else, so three ordinary
    ways of binding a client lost the receiver and every call on it fell to the floor class.
    """

    source = (
        f"{TOOL_IMPORT}\nimport httpx\n\n\n@tool\ndef probe(value: str) -> str:\n"
        '    """Probe an unusual binding."""\n' + binding
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "httpx.Client.get").action_class == "external"
    assert tool.proposed_action_class() == "external"
    assert tool.confidence() == "high"


def test_a_conditional_whose_arms_build_different_receivers_is_refused(tmp_path: Path) -> None:
    """One arm builds a client and the other a path, so neither reading is safe to assume."""

    source = (
        f"{TOOL_IMPORT}\n"
        "import httpx\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe disagreeing arms."""\n'
        "    handle = httpx.Client() if value else Path(value)\n"
        "    return str(handle.get(value))\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert tool.confidence() == "review"
    assert "UNRESOLVED_CALLEE" in tool.reasons


def test_a_credential_path_named_by_the_codecs_keyword_is_sensitive(tmp_path: Path) -> None:
    """`codecs.open` names its path `filename`, not `file`."""

    source = (
        f"{TOOL_IMPORT}\n"
        "import codecs\n"
        "\n\n"
        "@tool\n"
        "def probe() -> str:\n"
        '    """Probe a keyword-spelled credential read."""\n'
        f"    with codecs.open(filename={CREDENTIAL_PATH!r}, mode='r') as handle:\n"
        "        return handle.read()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _signal_for(tool, "codecs.open").action_class == "sensitive"
