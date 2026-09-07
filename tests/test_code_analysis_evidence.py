"""The evidence the analyzer emits, asserted for every symbol it claims to recognise.

`tests/test_code_analysis.py` covers the detection rules one behaviour at a time and
asserts the class a tool is proposed. It almost never asserts the *evidence*: across its
46 cases, a signal's `symbol` and `line` are never checked. Mutation testing showed what
that costs -- 331 survivors in `code_analysis.py`, the largest family being action-class
and symbol string literals that no assertion reads, so replacing `"read"` with `"READ"` or
a resolved symbol with a corrupted one changed nothing any test could see.

These tests drive the catalogue itself. Every symbol the analyzer says it recognises gets
a tool built around it, and the whole signal is asserted: the action class, the resolved
symbol, the file, the line, and the propagation chain. Adding a symbol to
`code_catalog.py` therefore adds a case here automatically, and a symbol that stops being
recognised fails rather than silently degrading a review to `unknown`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustweave import code_catalog as catalog
from trustweave.code_analysis import analyze_sources
from trustweave.code_sources import collect_python_sources

TOOL_IMPORT = "from langchain_core.tools import tool"


def _analyze(tmp_path: Path, source: str):
    (tmp_path / "agent.py").write_text(source, encoding="utf-8")
    return analyze_sources(collect_python_sources(tmp_path))


def _single_tool(tmp_path: Path, source: str):
    tools, _ = _analyze(tmp_path, source)
    assert len(tools) == 1, [tool.name for tool in tools]
    return tools[0]


def _importable_module(symbol: str) -> str:
    """The module an `import` statement must name for *symbol* to resolve."""
    parts = symbol.split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else parts[0]


def _direct_call_source(symbol: str) -> tuple[str, int]:
    """Source calling *symbol* once, with the line the call lands on.

    The line is derived rather than written down, so a change to the preamble cannot
    silently turn a line assertion into a check of the wrong line.
    """

    lines = [
        TOOL_IMPORT,
        f"import {_importable_module(symbol)}",
        "",
        "",
        "@tool",
        "def probe(value: str) -> str:",
        '    """Probe one catalogued symbol."""',
        f"    return {symbol}(value)",
    ]
    return "\n".join(lines) + "\n", len(lines)


def _signal_for(tool, symbol: str):
    matching = [signal for signal in tool.signals if signal.symbol == symbol]
    assert matching, (
        f"no signal resolved {symbol!r}; got {[(s.action_class, s.symbol) for s in tool.signals]}"
    )
    assert len(matching) == 1, f"{symbol!r} produced {len(matching)} signals"
    return matching[0]


CATALOGUED_SYMBOLS = sorted(
    [(symbol, "external") for symbol in catalog.EXTERNAL_SYMBOLS]
    + [(symbol, "write") for symbol in catalog.WRITE_SYMBOLS]
    + [(symbol, "sensitive") for symbol in catalog.SENSITIVE_SYMBOLS]
    + [(symbol, "read") for symbol in catalog.READ_SYMBOLS]
)


@pytest.mark.parametrize(
    ("symbol", "expected_class"), CATALOGUED_SYMBOLS, ids=[s for s, _ in CATALOGUED_SYMBOLS]
)
def test_a_catalogued_symbol_yields_exactly_its_documented_evidence(
    tmp_path: Path, symbol: str, expected_class: str
) -> None:
    """Class, resolved symbol, file, line and propagation chain, all four asserted."""

    source, call_line = _direct_call_source(symbol)
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, symbol)

    assert signal.action_class == expected_class
    assert signal.symbol == symbol
    assert signal.file == "agent.py"
    assert signal.line == call_line
    assert signal.via == ("probe",)


@pytest.mark.parametrize(
    ("symbol", "expected_class"), CATALOGUED_SYMBOLS, ids=[s for s, _ in CATALOGUED_SYMBOLS]
)
def test_a_catalogued_symbol_decides_the_proposed_class_and_capability(
    tmp_path: Path, symbol: str, expected_class: str
) -> None:
    """A single observed effect must reach the proposal, not stop at the signal list."""

    source, _ = _direct_call_source(symbol)
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == expected_class
    assert tool.confidence() == "high"
    assert tool.reasons == set()
    assert tool.unrecognized_calls == 0


def test_every_catalogued_symbol_is_covered_by_these_cases() -> None:
    """The parametrisation must track the catalogue rather than a copy of it."""

    covered = {symbol for symbol, _ in CATALOGUED_SYMBOLS}
    expected = (
        set(catalog.EXTERNAL_SYMBOLS)
        | set(catalog.WRITE_SYMBOLS)
        | set(catalog.SENSITIVE_SYMBOLS)
        | set(catalog.READ_SYMBOLS)
    )
    assert covered == expected
    assert len(CATALOGUED_SYMBOLS) == len(expected)


# ---------------------------------------------------------------------------------------
# Receivers: the class travels from the constructor to the method called on it
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("receiver", sorted(catalog.EXTERNAL_RECEIVERS))
def test_an_external_receiver_carries_its_class_to_a_method_call(
    tmp_path: Path, receiver: str
) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        f"import {_importable_module(receiver)}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one catalogued receiver."""\n'
        f"    handle = {receiver}()\n"
        "    return handle.send(value)\n"
    )
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, f"{receiver}.send")

    assert signal.action_class == "external"
    # The constructor is on line 8 of the generated source and the method call on line 9.
    assert signal.line == 9
    assert signal.via == ("probe",)
    assert tool.proposed_action_class() == "external"


@pytest.mark.parametrize("method", sorted(catalog.WRITE_RECEIVER_METHODS))
def test_a_path_write_method_is_recorded_as_a_write(tmp_path: Path, method: str) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one catalogued path write."""\n'
        "    target = Path(value)\n"
        f"    target.{method}()\n"
        "    return value\n"
    )
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, f"pathlib.Path.{method}")

    assert signal.action_class == "write"
    assert tool.proposed_action_class() == "write"


@pytest.mark.parametrize("method", sorted(catalog.READ_RECEIVER_METHODS))
def test_a_path_read_method_is_recorded_as_a_read(tmp_path: Path, method: str) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "from pathlib import Path\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one catalogued path read."""\n'
        "    target = Path(value)\n"
        f"    target.{method}()\n"
        "    return value\n"
    )
    tool = _single_tool(tmp_path, source)
    signal = _signal_for(tool, f"pathlib.Path.{method}")

    assert signal.action_class == "read"
    assert tool.proposed_action_class() == "read"


# ---------------------------------------------------------------------------------------
# Token tables: the argument decides the class, not the callee alone
# ---------------------------------------------------------------------------------------


def _subprocess_source(command: str) -> str:
    return (
        f"{TOOL_IMPORT}\n"
        "import subprocess\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one catalogued command."""\n'
        f"    subprocess.run([{command!r}, value])\n"
        "    return value\n"
    )


@pytest.mark.parametrize("command", sorted(catalog.EGRESS_COMMANDS))
def test_an_egress_command_makes_a_subprocess_external(tmp_path: Path, command: str) -> None:
    tool = _single_tool(tmp_path, _subprocess_source(command))
    signal = _signal_for(tool, "subprocess.run")

    assert signal.action_class == "external"
    assert tool.proposed_action_class() == "external"


def test_a_command_outside_the_egress_table_is_not_external(tmp_path: Path) -> None:
    """The egress table must decide the class, not merely appear to."""

    tool = _single_tool(tmp_path, _subprocess_source("echo"))
    signal = _signal_for(tool, "subprocess.run")

    assert signal.action_class != "external"


@pytest.mark.parametrize("token", sorted(catalog.SECRET_ENV_TOKENS))
def test_a_secret_environment_name_is_sensitive(tmp_path: Path, token: str) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "import os\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one catalogued environment name."""\n'
        f"    return os.environ.get({('service_' + token).upper()!r}, value)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "sensitive"


@pytest.mark.parametrize("token", sorted(catalog.BENIGN_ENV_TOKENS))
def test_a_benign_environment_name_is_not_sensitive(tmp_path: Path, token: str) -> None:
    """The benign table has to exclude, otherwise every getenv would read as a secret."""

    source = (
        f"{TOOL_IMPORT}\n"
        "import os\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one catalogued benign name."""\n'
        f"    return os.environ.get({token.upper()!r}, value)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() != "sensitive"


@pytest.mark.parametrize("token", sorted(catalog.CREDENTIAL_PATH_TOKENS))
def test_a_credential_path_read_is_sensitive_rather_than_a_read(tmp_path: Path, token: str) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one catalogued credential path."""\n'
        f"    with open({('/home/agent/' + token)!r}) as handle:\n"
        "        return handle.read()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "sensitive"


@pytest.mark.parametrize("suffix", sorted(catalog.CREDENTIAL_PATH_SUFFIXES))
def test_a_credential_suffix_is_sensitive_rather_than_a_read(tmp_path: Path, suffix: str) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one catalogued credential suffix."""\n'
        f"    with open({('/etc/agent/client' + suffix)!r}) as handle:\n"
        "        return handle.read()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "sensitive"


def _sql_source(statement: str) -> str:
    """A recognised execute whose query is a literal, on a cursor handed to the tool."""

    return (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(cursor) -> str:\n"
        '    """Probe one catalogued SQL verb."""\n'
        f"    cursor.execute({statement!r})\n"
        "    return 'ok'\n"
    )


@pytest.mark.parametrize("token", sorted(catalog.SQL_WRITE_TOKENS))
def test_a_sql_write_verb_is_recorded_as_a_write(tmp_path: Path, token: str) -> None:
    tool = _single_tool(tmp_path, _sql_source(f"{token} FROM records"))
    signal = _signal_for(tool, "write_sql_statement")

    assert signal.action_class == "write"
    assert tool.proposed_action_class() == "write"


@pytest.mark.parametrize("token", sorted(catalog.SQL_READ_TOKENS))
def test_a_sql_read_verb_is_recorded_as_a_read(tmp_path: Path, token: str) -> None:
    tool = _single_tool(tmp_path, _sql_source(f"{token} FROM records"))
    signal = _signal_for(tool, "read_sql_statement")

    assert signal.action_class == "read"
    assert tool.proposed_action_class() == "read"


def test_a_sql_statement_that_is_not_a_literal_is_refused_rather_than_guessed(
    tmp_path: Path,
) -> None:
    """The refusal is the point: an unread query must not be reported as a benign read."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(cursor, statement: str) -> str:\n"
        '    """Probe a non-literal query."""\n'
        "    cursor.execute(statement)\n"
        "    return 'ok'\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert tool.confidence() == "review"
    assert "NONLITERAL_ARGUMENT" in tool.reasons


# ---------------------------------------------------------------------------------------
# Precedence: which of several observed effects reaches the proposal
# ---------------------------------------------------------------------------------------


PRECEDENCE_SYMBOLS = {
    "sensitive": "subprocess.run",
    "external": "requests.get",
    "write": "shutil.rmtree",
    "read": "json.load",
}


@pytest.mark.parametrize("expected", catalog.ACTION_CLASS_PRECEDENCE)
def test_the_highest_precedence_observed_class_is_the_one_proposed(
    tmp_path: Path, expected: str
) -> None:
    """A tool showing several effects is proposed at the top of the precedence order."""

    order = list(catalog.ACTION_CLASS_PRECEDENCE)
    present = order[order.index(expected) :]
    calls = "\n".join(f"    {PRECEDENCE_SYMBOLS[name]}(value)" for name in present)
    source = (
        f"{TOOL_IMPORT}\n"
        "import json\nimport requests\nimport shutil\nimport subprocess\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe the precedence order."""\n'
        f"{calls}\n"
        "    return value\n"
    )
    tool = _single_tool(tmp_path, source)

    observed = {signal.action_class for signal in tool.signals}
    assert observed == set(present), f"expected {set(present)}, saw {observed}"
    assert tool.proposed_action_class() == expected


def test_the_precedence_order_is_the_one_the_catalogue_publishes() -> None:
    """A reordering here would silently change every multi-effect proposal."""

    assert catalog.ACTION_CLASS_PRECEDENCE == ("sensitive", "external", "write", "read")


def test_each_action_class_maps_to_exactly_one_capability() -> None:
    assert dict(catalog.CAPABILITY_BY_ACTION_CLASS) == {
        "sensitive": "process.privileged",
        "external": "network.egress",
        "write": "storage.write",
        "read": "storage.read",
    }
    assert set(catalog.CAPABILITY_BY_ACTION_CLASS) == set(catalog.ACTION_CLASS_PRECEDENCE)
