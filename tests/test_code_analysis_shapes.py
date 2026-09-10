"""Input shapes the analyzer handles, and that nothing asserted.

The two test files beside this one cover *what* the analyzer decides: which class a
catalogued symbol yields, and how an effect travels through a receiver. This one covers
the shapes of the source it decides over -- how an import was spelled, whether an argument
was passed by keyword, what a malformed file produces, where the traversal budget stops.

Mutation testing is what identified them. The analyzer resolves `import urllib.request as
ur` by splitting the dotted name, reads `open(path, mode="w")` by looking up a keyword, and
reports a syntax error with the line it failed on, and none of those had an assertion, so
corrupting the separator, the keyword name, or the reason string changed nothing any test
could see.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustweave import code_catalog as catalog
from trustweave.code_analysis import (
    MAX_CALL_DEPTH,
    MAX_REACHABLE_FUNCTIONS_PER_TOOL,
    analyze_sources,
)
from trustweave.code_sources import collect_python_sources

TOOL_IMPORT = "from langchain_core.tools import tool"


def _analyze(tmp_path: Path, source: str):
    (tmp_path / "agent.py").write_text(source, encoding="utf-8")
    return analyze_sources(collect_python_sources(tmp_path))


def _single_tool(tmp_path: Path, source: str):
    tools, _ = _analyze(tmp_path, source)
    assert len(tools) == 1, [tool.name for tool in tools]
    return tools[0]


def _symbols(tool) -> list[str]:
    return sorted(signal.symbol for signal in tool.signals)


# ---------------------------------------------------------------------------------------
# However the import was spelled, the symbol resolves to its canonical dotted name
# ---------------------------------------------------------------------------------------

IMPORT_SPELLINGS = {
    "plain": "import urllib.request",
    "aliased dotted module": "import urllib.request as ur",
    "from-import": "from urllib.request import urlopen",
    "from-import aliased": "from urllib.request import urlopen as fetch",
}
CALL_SPELLINGS = {
    "plain": "urllib.request.urlopen",
    "aliased dotted module": "ur.urlopen",
    "from-import": "urlopen",
    "from-import aliased": "fetch",
}


@pytest.mark.parametrize("spelling", sorted(IMPORT_SPELLINGS))
def test_an_import_resolves_to_the_canonical_symbol_however_it_was_spelled(
    tmp_path: Path, spelling: str
) -> None:
    """Splitting the dotted name is how the binding is built, and it was unasserted."""

    source = (
        f"{TOOL_IMPORT}\n"
        f"{IMPORT_SPELLINGS[spelling]}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe one import spelling."""\n'
        f"    return {CALL_SPELLINGS[spelling]}(value)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert _symbols(tool) == ["urllib.request.urlopen"]
    assert tool.proposed_action_class() == "external"


def test_a_dotted_module_keeps_its_full_path_in_the_symbol(tmp_path: Path) -> None:
    """`urllib.request` must not be truncated to `urllib`, nor left as the alias."""

    tool = _single_tool(
        tmp_path,
        f"{TOOL_IMPORT}\n"
        "import urllib.request as ur\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a dotted alias."""\n'
        "    return ur.urlopen(value)\n",
    )
    symbol = _symbols(tool)[0]

    assert symbol == "urllib.request.urlopen"
    assert not symbol.startswith("ur.")
    assert symbol.count(".") == 2


# ---------------------------------------------------------------------------------------
# `open` reads its mode whether it was passed by position or by keyword
# ---------------------------------------------------------------------------------------


def _open_source(argument: str) -> str:
    return (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe an open call."""\n'
        f"    handle = open('/var/lib/agent/notes.txt'{argument})\n"
        "    handle.write(value)\n"
        "    return value\n"
    )


@pytest.mark.parametrize("flag", ["w", "a", "x", "r+"])
def test_a_writing_mode_is_a_write_by_position(tmp_path: Path, flag: str) -> None:
    assert _single_tool(tmp_path, _open_source(f", {flag!r}")).proposed_action_class() == "write"


@pytest.mark.parametrize("flag", ["w", "a", "x", "r+"])
def test_a_writing_mode_is_a_write_by_keyword(tmp_path: Path, flag: str) -> None:
    """The keyword name is looked up by string, so corrupting it silently loses the mode."""

    tool = _single_tool(tmp_path, _open_source(f", mode={flag!r}"))

    assert tool.proposed_action_class() == "write"


def test_a_reading_mode_stays_a_read_by_keyword(
    tmp_path: Path,
) -> None:
    tools, _ = _analyze(
        tmp_path,
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a reading open."""\n'
        "    with open('/var/lib/agent/notes.txt', mode='r') as handle:\n"
        "        return handle.read()\n",
    )

    assert tools[0].proposed_action_class() == "read"


def test_an_absent_mode_is_a_read(tmp_path: Path) -> None:
    tools, _ = _analyze(
        tmp_path,
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a default open."""\n'
        "    with open('/var/lib/agent/notes.txt') as handle:\n"
        "        return handle.read()\n",
    )

    assert tools[0].proposed_action_class() == "read"


def test_a_mode_chosen_at_runtime_is_refused_rather_than_guessed(tmp_path: Path) -> None:
    """Answering here would call a write a read whenever the caller passed 'w'."""

    tool = _single_tool(
        tmp_path,
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str, mode: str) -> str:\n"
        '    """Probe a runtime mode."""\n'
        "    handle = open('/var/lib/agent/notes.txt', mode)\n"
        "    return handle.read()\n",
    )

    assert "NONLITERAL_ARGUMENT" in tool.reasons
    assert tool.confidence() == "review"


# ---------------------------------------------------------------------------------------
# A file the analyzer cannot parse is reported, with the line it failed on
# ---------------------------------------------------------------------------------------


def test_a_syntax_error_names_the_file_and_the_line(tmp_path: Path) -> None:
    tools, refusals = _analyze(tmp_path, "def broken(:\n    pass\n")

    assert tools == []
    assert refusals == [{"file": "agent.py", "reason": "syntax_error_line_1"}]


def test_the_reported_line_is_the_line_that_failed(tmp_path: Path) -> None:
    """A constant line number would satisfy a test that only checked the prefix."""

    tools, refusals = _analyze(
        tmp_path,
        "def fine():\n    return 1\n\n\ndef broken(:\n    pass\n",
    )

    assert tools == []
    assert refusals == [{"file": "agent.py", "reason": "syntax_error_line_5"}]


def test_one_unparsable_file_does_not_stop_the_others(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text(
        f"{TOOL_IMPORT}\n"
        "import requests\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe."""\n'
        "    return requests.get(value).text\n",
        encoding="utf-8",
    )

    tools, refusals = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.name for tool in tools] == ["probe"]
    assert [refusal["file"] for refusal in refusals] == ["broken.py"]


# ---------------------------------------------------------------------------------------
# The traversal budget, at its exact boundary
# ---------------------------------------------------------------------------------------


def _breadth_source(helpers: int) -> str:
    defined = "".join(
        f"def helper{index}(value):\n    return value\n\n\n" for index in range(helpers)
    )
    called = "".join(f"    helper{index}(value)\n" for index in range(helpers))
    return (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        f"{defined}"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe the traversal budget."""\n'
        f"{called}"
        "    return value\n"
    )


def test_a_tool_just_under_the_budget_is_analyzed_completely(tmp_path: Path) -> None:
    tool = _single_tool(tmp_path, _breadth_source(MAX_REACHABLE_FUNCTIONS_PER_TOOL - 1))

    assert tool.budget_state == "complete"


def test_a_tool_at_the_budget_reports_the_budget_exhausted(tmp_path: Path) -> None:
    """The boundary is exact: one more reachable function stops the traversal."""

    tool = _single_tool(tmp_path, _breadth_source(MAX_REACHABLE_FUNCTIONS_PER_TOOL))

    assert tool.budget_state == "exhausted"


def test_the_budget_is_the_published_constant(tmp_path: Path) -> None:
    """Moving the limit silently would change what a review covers without saying so."""

    assert MAX_REACHABLE_FUNCTIONS_PER_TOOL == 64


# ---------------------------------------------------------------------------------------
# A name bound twice to different receivers is not evidence for either
# ---------------------------------------------------------------------------------------


def test_a_name_rebound_to_a_different_receiver_yields_no_receiver_effect(
    tmp_path: Path,
) -> None:
    """Which object the later call reaches depends on the path taken, so neither is claimed."""

    tool = _single_tool(
        tmp_path,
        f"{TOOL_IMPORT}\n"
        "import requests\n"
        "import sqlite3\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a rebound name."""\n'
        "    handle = requests.Session()\n"
        "    handle = sqlite3.connect(value)\n"
        "    return str(handle)\n",
    )

    assert not [signal for signal in tool.signals if signal.symbol.startswith("requests.")]


def test_a_name_bound_twice_to_the_same_receiver_still_resolves(tmp_path: Path) -> None:
    """The conflict rule must key on the receiver, not on merely being assigned twice."""

    tool = _single_tool(
        tmp_path,
        f"{TOOL_IMPORT}\n"
        "import requests\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a repeated binding."""\n'
        "    handle = requests.Session()\n"
        "    handle = requests.Session()\n"
        "    return handle.post(value).text\n",
    )

    assert _symbols(tool) == ["requests.Session.post"]
    assert tool.proposed_action_class() == "external"


# ---------------------------------------------------------------------------------------
# A mode bound to a local is still a literal
# ---------------------------------------------------------------------------------------


def _mode_source(binding: str) -> str:
    return (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(path: str, event: str) -> str:\n"
        '    """Probe a bound mode."""\n'
        f"{binding}"
        "    open('/var/lib/agent/notes.txt', mode).write(event)\n"
        "    return path\n"
    )


@pytest.mark.parametrize("flag", ["w", "a", "x", "r+"])
def test_a_writing_mode_bound_to_a_local_is_still_a_write(tmp_path: Path, flag: str) -> None:
    """Refusing here treated an ordinary local as though the value came from outside."""

    tool = _single_tool(tmp_path, _mode_source(f"    mode = {flag!r}\n"))

    assert tool.proposed_action_class() == "write"
    assert tool.reasons == set()


def test_a_reading_mode_bound_to_a_local_is_still_a_read(tmp_path: Path) -> None:
    tool = _single_tool(tmp_path, _mode_source("    mode = 'r'\n"))

    assert tool.proposed_action_class() == "read"


def test_a_conditional_mode_whose_arms_agree_is_decided(tmp_path: Path) -> None:
    """`"a" if event else "a+"` can only ever be an append, so the class is the same."""

    tool = _single_tool(tmp_path, _mode_source("    mode = 'a' if event else 'a+'\n"))

    assert tool.proposed_action_class() == "write"


def test_a_conditional_mode_whose_arms_disagree_is_refused(tmp_path: Path) -> None:
    """One path reads and the other writes, so answering either way would be a guess."""

    tool = _single_tool(tmp_path, _mode_source("    mode = 'r' if event else 'w'\n"))

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert "NONLITERAL_ARGUMENT" in tool.reasons


def test_a_mode_rebound_to_a_different_literal_is_refused(tmp_path: Path) -> None:
    """Which assignment wins depends on the path taken, so neither is claimed."""

    tool = _single_tool(tmp_path, _mode_source("    mode = 'r'\n    mode = 'w'\n"))

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS


def test_a_mode_taken_from_a_parameter_is_still_refused(tmp_path: Path) -> None:
    """The caller decides it, so both readings stay open."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(path: str, mode: str) -> str:\n"
        '    """Probe a caller-supplied mode."""\n'
        "    return open('/var/lib/agent/notes.txt', mode).read()\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert "NONLITERAL_ARGUMENT" in tool.reasons


# ---------------------------------------------------------------------------------------
# A method on the result of another call
# ---------------------------------------------------------------------------------------


def _chain_source(expression: str, *, preamble: str) -> str:
    return (
        f"{TOOL_IMPORT}\n"
        f"{preamble}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a chained call."""\n'
        f"    return str({expression})\n"
    )


@pytest.mark.parametrize("link", sorted(catalog.PATH_PRESERVING_METHODS - {"relative_to"}))
def test_a_path_chain_keeps_its_receiver_through_each_link(tmp_path: Path, link: str) -> None:
    """`Path(p).expanduser().resolve().stat()` is one read of one path."""

    argument = "'x'" if link in {"joinpath", "with_name", "with_suffix", "with_stem"} else ""
    tool = _single_tool(
        tmp_path,
        _chain_source(
            f"Path(value).{link}({argument}).read_text()", preamble="from pathlib import Path"
        ),
    )

    assert tool.proposed_action_class() == "read"
    assert tool.reasons == set()


def test_a_credential_read_survives_a_path_chain(tmp_path: Path) -> None:
    tool = _single_tool(
        tmp_path,
        _chain_source(
            "Path('/home/agent/.ssh/id_rsa').expanduser().resolve().read_text()",
            preamble="from pathlib import Path",
        ),
    )

    assert tool.proposed_action_class() == "sensitive"


@pytest.mark.parametrize("symbol", ["json.dumps", "hashlib.new", "base64.b64encode"])
def test_a_method_on_a_computed_value_is_not_an_effect(tmp_path: Path, symbol: str) -> None:
    """It cannot read or write anything, so refusing on it says nothing true."""

    module = symbol.split(".")[0]
    tool = _single_tool(
        tmp_path, _chain_source(f"{symbol}(value).__class__", preamble=f"import {module}")
    )

    assert tool.proposed_action_class() == "read"
    assert "UNRESOLVED_CALLEE" not in tool.reasons


def test_a_database_handle_is_plumbing_and_the_statement_decides(tmp_path: Path) -> None:
    """`connect(dsn).cursor()` hands back a handle; the SQL is what has the effect."""

    source = (
        f"{TOOL_IMPORT}\n"
        "import sqlite3\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a database handle."""\n'
        "    cursor = sqlite3.connect('/srv/app.db').cursor()\n"
        "    cursor.execute('UPDATE tickets SET priority = 1')\n"
        "    return value\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "write"
    assert tool.reasons == set()


def test_a_statement_held_in_a_module_constant_is_still_a_literal(tmp_path: Path) -> None:
    """A query defined once at the top of the file is the ordinary way to write this."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "QUERY = 'SELECT sku FROM sales WHERE region = ?'\n"
        "\n\n"
        "@tool\n"
        "def probe(cursor, region: str) -> str:\n"
        '    """Probe a module-level query."""\n'
        "    cursor.execute(QUERY, (region,))\n"
        "    return 'ok'\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "read"


def test_a_statement_built_at_runtime_is_still_refused(tmp_path: Path) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(cursor, statement: str) -> str:\n"
        '    """Probe a runtime query."""\n'
        "    cursor.execute(statement)\n"
        "    return 'ok'\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS


# ---------------------------------------------------------------------------------------
# Running caller-supplied code is a finding, not an inability to make one
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", ["eval(expression)", "exec(expression)"])
def test_running_caller_supplied_code_is_sensitive(tmp_path: Path, spelling: str) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(expression: str) -> str:\n"
        '    """Probe dynamic execution."""\n'
        f"    return str({spelling})\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "sensitive"
    assert tool.confidence() == "high"


def test_compiling_a_caller_supplied_string_before_running_it_is_still_sensitive(
    tmp_path: Path,
) -> None:
    """Wrapping the source in `compile` does not make the execution any less arbitrary."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(expression: str) -> str:\n"
        '    """Probe a compiled expression."""\n'
        "    return str(eval(compile(expression, '<agent>', 'eval')))\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "sensitive"


def test_a_constant_expression_is_not_reported_as_arbitrary_execution(
    tmp_path: Path,
) -> None:
    """Nothing the caller controls reaches it, so the finding would be about nothing."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a constant expression."""\n'
        "    return str(eval('1 + 1'))\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() != "sensitive"


def test_a_dynamic_lookup_is_still_a_refusal_not_an_execution_finding(
    tmp_path: Path,
) -> None:
    """`getattr` selects a symbol rather than running code, so the old reading stands."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "@tool\n"
        "def probe(handler, name: str) -> str:\n"
        '    """Probe a dynamic lookup."""\n'
        "    return str(getattr(handler, name)())\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert "DYNAMIC_DISPATCH" in tool.reasons


# ---------------------------------------------------------------------------------------
# The call-depth budget, which stops the traversal and must say so
# ---------------------------------------------------------------------------------------


def _depth_source(depth: int) -> str:
    """A tool whose only effect sits *depth* frames below it."""

    chain = "".join(
        f"def hop{index}(value):\n    return hop{index + 1}(value)\n\n\n" for index in range(depth)
    )
    chain += (
        f"def hop{depth}(value):\n    import requests\n    return requests.get(value).text\n\n\n"
    )
    return (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        f"{chain}"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe the call-depth budget."""\n'
        "    return hop0(value)\n"
    )


def test_an_effect_within_the_depth_budget_is_reported(tmp_path: Path) -> None:
    tool = _single_tool(tmp_path, _depth_source(MAX_CALL_DEPTH - 1))

    assert tool.proposed_action_class() == "external"
    assert tool.budget_state == "complete"
    assert tool.reasons == set()


@pytest.mark.parametrize("beyond", [0, 1, 2])
def test_an_effect_past_the_depth_budget_is_refused_not_called_a_read(
    tmp_path: Path, beyond: int
) -> None:
    """The traversal stops, and saying nothing published an outbound call as no effect.

    Before this the tool was reported `read` at high confidence with `budget_state`
    still `complete`, which is the one direction a security review must not fail in.
    """

    tool = _single_tool(tmp_path, _depth_source(MAX_CALL_DEPTH + beyond))

    assert tool.proposed_action_class() == catalog.UNKNOWN_ACTION_CLASS
    assert tool.confidence() == "review"
    assert tool.budget_state == "exhausted"
    assert "BUDGET_EXHAUSTED" in tool.reasons


def test_a_call_at_the_limit_with_nothing_to_follow_is_not_reported_as_exhausted(
    tmp_path: Path,
) -> None:
    """Only a call the traversal would have followed counts, or every tool would refuse."""

    source = (
        f"{TOOL_IMPORT}\n"
        "\n\n"
        "def hop0(value):\n"
        "    return hop1(value)\n"
        "\n\n"
        "def hop1(value):\n"
        "    return hop2(value)\n"
        "\n\n"
        "def hop2(value):\n"
        "    return str(len(value))\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a chain that ends in computation."""\n'
        "    return hop0(value)\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.budget_state == "complete"
    assert tool.proposed_action_class() == "read"


def test_a_shallow_tool_is_unaffected_by_the_depth_rule(tmp_path: Path) -> None:
    source = (
        f"{TOOL_IMPORT}\n"
        "import requests\n"
        "\n\n"
        "@tool\n"
        "def probe(value: str) -> str:\n"
        '    """Probe a direct call."""\n'
        "    return requests.get(value).text\n"
    )
    tool = _single_tool(tmp_path, source)

    assert tool.proposed_action_class() == "external"
    assert tool.budget_state == "complete"


def test_the_depth_budget_is_the_published_constant() -> None:
    assert MAX_CALL_DEPTH == 3
