"""Detection rules for the local source analyzer, one behaviour per case."""

from __future__ import annotations

from pathlib import Path

import pytest

from trustweave.code_analysis import analyze_sources
from trustweave.code_sources import collect_python_sources
from trustweave.models import ValidationError

TOOL_PREAMBLE = "from langchain_core.tools import tool\n\n\n"


def _analyze(tmp_path: Path, body: str, *, preamble: str = TOOL_PREAMBLE) -> list:
    (tmp_path / "agent.py").write_text(preamble + body, encoding="utf-8")
    tools, _ = analyze_sources(collect_python_sources(tmp_path))
    return tools


def _one(tmp_path: Path, body: str, *, preamble: str = TOOL_PREAMBLE):
    tools = _analyze(tmp_path, body, preamble=preamble)
    assert len(tools) == 1, [tool.name for tool in tools]
    return tools[0]


# ---------------------------------------------------------------------------------------
# external
# ---------------------------------------------------------------------------------------


def test_a_session_receiver_carries_the_class_to_its_methods(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef push(payload: str) -> str:\n"
        '    """Send through a session."""\n'
        "    client = requests.Session()\n"
        "    client.post('https://example.invalid', data=payload)\n"
        "    return 'ok'\n",
        preamble="import requests\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "external"


def test_shelling_out_to_a_transfer_tool_is_egress_not_local_execution(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef fetch(url: str) -> str:\n"
        '    """Fetch with curl."""\n'
        "    subprocess.run(['/usr/bin/curl', url], check=False)\n"
        "    return 'ok'\n",
        preamble="import subprocess\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "external"


# ---------------------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ("open('out.txt', 'w').write(data)", "write"),
        ("open('in.txt').read()", "read"),
        ("open('in.txt', 'rb').read()", "read"),
        ("open('out.txt', 'a').write(data)", "write"),
    ],
)
def test_open_is_classified_by_its_literal_mode(tmp_path: Path, call: str, expected: str) -> None:
    tool = _one(
        tmp_path,
        f"@tool\ndef touch_file(data: str) -> str:\n"
        f'    """Touch a file."""\n'
        f"    {call}\n"
        f"    return 'ok'\n",
    )

    assert tool.proposed_action_class() == expected


def test_a_path_receiver_write_is_a_write(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef save(data: str) -> str:\n"
        '    """Save a file."""\n'
        "    target = Path('out.txt')\n"
        "    target.write_text(data)\n"
        "    return 'ok'\n",
        preamble="from pathlib import Path\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "write"


@pytest.mark.parametrize(
    ("statement", "expected"),
    [("SELECT 1", "read"), ("INSERT INTO t VALUES (1)", "write"), ("DROP TABLE t", "write")],
)
def test_a_literal_query_is_classified_by_its_leading_keyword(
    tmp_path: Path, statement: str, expected: str
) -> None:
    tool = _one(
        tmp_path,
        f"@tool\ndef run(cursor) -> str:\n"
        f'    """Run a fixed statement."""\n'
        f'    cursor.execute("{statement}")\n'
        f"    return 'ok'\n",
    )

    assert tool.proposed_action_class() == expected


# ---------------------------------------------------------------------------------------
# sensitive
# ---------------------------------------------------------------------------------------


def test_reading_a_secret_environment_variable_is_sensitive(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef authenticate() -> str:\n"
        '    """Read a token."""\n'
        "    return os.getenv('SERVICE_API_TOKEN')\n",
        preamble="import os\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "sensitive"


def test_reading_a_configuration_environment_variable_is_not_sensitive(tmp_path: Path) -> None:
    """LOG_PATH names a location, not a credential; treating it as one trains noise."""

    tool = _one(
        tmp_path,
        '@tool\ndef where() -> str:\n    """Read a path."""\n    return os.getenv(\'LOG_PATH\')\n',
        preamble="import os\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() != "sensitive"


def test_reading_a_credential_path_is_sensitive(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef load_key() -> str:\n"
        '    """Read a private key."""\n'
        "    return Path('~/.ssh/id_rsa').read_text()\n",
        preamble="from pathlib import Path\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "sensitive"


def test_sensitive_outranks_every_other_observed_class(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef combined(data: str) -> str:\n"
        '    """Do several things at once."""\n'
        "    requests.get('https://example.invalid')\n"
        "    open('out.txt', 'w').write(data)\n"
        "    subprocess.run(['/bin/true'], check=False)\n"
        "    return 'ok'\n",
        preamble="import requests\nimport subprocess\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "sensitive"


# ---------------------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------------------


def test_a_wildcard_import_degrades_resolution_and_is_reported(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef opaque(value: str) -> str:\n"
        '    """Call something that may have been star-imported."""\n'
        "    return helper(value)\n",
        preamble="from os.path import *\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "unknown"
    assert "UNRESOLVED_CALLEE" in tool.reasons


def test_a_dynamic_attribute_lookup_is_refused(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef call_it(name: str, target) -> str:\n"
        '    """Resolve a method by name at runtime."""\n'
        "    return getattr(target, name)()\n",
    )

    assert "DYNAMIC_DISPATCH" in tool.reasons


def test_a_factory_tool_without_a_locatable_body_is_reported(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain_core.tools import StructuredTool\n\n"
        "external = StructuredTool.from_function(name='remote', func=imported_callable)\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].name == "remote"
    assert "BODY_UNAVAILABLE" in tools[0].reasons


def test_a_plain_function_bound_into_a_tools_list_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "import requests\n\n\n"
        "def lookup(term):\n"
        "    return requests.get('https://example.invalid', params={'q': term})\n\n\n"
        "agent = build(tools=[lookup])\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.name for tool in tools] == ["lookup"]
    assert tools[0].proposed_action_class() == "external"


def test_a_function_that_is_never_bound_as_a_tool_is_not_discovered(tmp_path: Path) -> None:
    """Enumerating every public function would inflate the manifest with non-tools."""

    (tmp_path / "agent.py").write_text(
        "import requests\n\n\ndef helper(term):\n"
        "    return requests.get('https://example.invalid')\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools == []


def test_a_recursive_helper_chain_terminates(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "def left(value):\n    return right(value)\n\n\n"
        "def right(value):\n    return left(value)\n\n\n"
        "@tool\ndef loop(value: str) -> str:\n"
        '    """Enter a cycle."""\n'
        "    return left(value)\n",
    )

    assert tool.proposed_action_class() in {"read", "unknown"}


# ---------------------------------------------------------------------------------------
# intake
# ---------------------------------------------------------------------------------------


def test_a_single_module_may_be_analyzed_directly(tmp_path: Path) -> None:
    module = tmp_path / "solo.py"
    module.write_text(
        TOOL_PREAMBLE + '@tool\ndef noop() -> str:\n    """Do nothing."""\n    return \'\'\n',
        encoding="utf-8",
    )

    collection = collect_python_sources(module)

    assert [source.relative_path for source in collection.files] == ["solo.py"]


def test_a_non_python_file_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    target.write_text("not source", encoding="utf-8")

    with pytest.raises(ValidationError):
        collect_python_sources(target)


def test_a_missing_path_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        collect_python_sources(tmp_path / "absent")


def test_vendored_directories_are_not_analyzed(tmp_path: Path) -> None:
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "vendored.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text("y = 2\n", encoding="utf-8")

    collection = collect_python_sources(tmp_path)

    assert [source.relative_path for source in collection.files] == ["agent.py"]


def test_a_file_that_is_not_utf8_is_skipped_with_a_reason(tmp_path: Path) -> None:
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe\x00invalid")

    collection = collect_python_sources(tmp_path)

    assert [skipped.reason for skipped in collection.skipped] == ["file_is_not_utf8"]


# ---------------------------------------------------------------------------------------
# framework shapes and naming
# ---------------------------------------------------------------------------------------


def test_a_fastmcp_style_decorator_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "mcp = FastMCP('synthetic')\n\n\n"
        "@mcp.tool()\n"
        "def ping(value: str) -> str:\n"
        '    """Answer a ping."""\n'
        "    return value\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [(tool.name, tool.framework) for tool in tools] == [("ping", "server_tool_decorator")]


def test_a_low_level_mcp_call_tool_handler_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n\n"
        "server = Server('synthetic')\n\n\n"
        "@server.call_tool()\n"
        "async def dispatch(name: str, arguments: dict) -> str:\n"
        '    """Handle any declared tool."""\n'
        "    return name\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.framework for tool in tools] == ["mcp_call_tool"]


@pytest.mark.parametrize(
    ("decorator", "expected"),
    [
        ("@tool('renamed_positional')", "renamed_positional"),
        ("@tool(name='renamed_keyword')", "renamed_keyword"),
        ("@tool", "original"),
    ],
)
def test_a_decorator_may_rename_the_discovered_tool(
    tmp_path: Path, decorator: str, expected: str
) -> None:
    tool = _one(
        tmp_path,
        f"{decorator}\ndef original(value: str) -> str:\n"
        f'    """Return the value."""\n'
        f"    return value\n",
    )

    assert tool.name == expected


def test_a_string_command_shelled_out_is_still_classified(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef sync(target: str) -> str:\n"
        '    """Sync via a shell string."""\n'
        "    subprocess.run('rsync -a /src /dst', shell=True, check=False)\n"
        "    return target\n",
        preamble="import subprocess\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "external"


def test_a_private_key_suffix_is_treated_as_a_credential(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef load_cert() -> str:\n"
        '    """Read a certificate."""\n'
        "    handle = Path('service.pem')\n"
        "    return handle.read_text()\n",
        preamble="from pathlib import Path\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "sensitive"


def test_a_client_built_from_a_factory_keeps_its_origin(tmp_path: Path) -> None:
    tool = _one(
        tmp_path,
        "@tool\ndef upload(key: str) -> str:\n"
        '    """Upload through a constructed client."""\n'
        "    client = boto3.client('s3')\n"
        "    client.put_object(Bucket='b', Key=key)\n"
        "    return key\n",
        preamble="import boto3\n" + TOOL_PREAMBLE,
    )

    assert tool.proposed_action_class() == "external"


def test_a_module_that_does_not_parse_is_reported_and_skipped(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def oops(:\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text(
        TOOL_PREAMBLE + '@tool\ndef ok() -> str:\n    """Fine."""\n    return \'\'\n',
        encoding="utf-8",
    )
    tools, problems = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.name for tool in tools] == ["ok"]
    assert [problem["file"] for problem in problems] == ["broken.py"]


# ---------------------------------------------------------------------------------------
# Scope correctness. Each of these reproduced a confident wrong answer before the fix.
# ---------------------------------------------------------------------------------------


def test_an_unrelated_functions_binding_cannot_erase_a_tools_receiver(tmp_path: Path) -> None:
    """A later helper reusing the name `client` once made an HTTP tool report read/high."""

    (tmp_path / "agent.py").write_text(
        "import requests\n"
        "from pathlib import Path\n" + TOOL_PREAMBLE + "@tool\n"
        "def exfiltrate(payload: str) -> str:\n"
        '    """Send data out."""\n'
        "    client = requests.Session()\n"
        "    client.post('https://example.invalid', data=payload)\n"
        "    return 'ok'\n\n\n"
        "def unrelated_helper(name):\n"
        "    client = Path(name)\n"
        "    return client.read_text()\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.proposed_action_class() for tool in tools] == ["external"]


def test_calling_a_parameter_never_borrows_a_same_named_function_body(tmp_path: Path) -> None:
    """This once published a fabricated shutil.rmtree signal and a fake call path."""

    (tmp_path / "agent.py").write_text(
        "import shutil\n" + TOOL_PREAMBLE + "def cleanup(path):\n"
        "    shutil.rmtree(path)\n\n\n"
        "@tool\n"
        "def report(cleanup) -> str:\n"
        '    """cleanup is a parameter, not the module function."""\n'
        "    cleanup('nothing')\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "unknown"
    assert tools[0].signals == []


def test_a_class_method_cannot_satisfy_a_call_to_an_imported_name(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from mylib import send\n" + TOOL_PREAMBLE + "class Client:\n"
        "    def send(self, target):\n"
        "        import shutil\n"
        "        shutil.rmtree(target)\n\n\n"
        "@tool\n"
        "def relay(value: str) -> str:\n"
        '    """Calls the imported send."""\n'
        "    return send(value)\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert not [signal for signal in tools[0].signals if signal.action_class == "write"]


def test_a_client_held_on_self_is_refused_rather_than_reported_as_read(tmp_path: Path) -> None:
    """An outbound POST through self.session once published as read with high confidence."""

    (tmp_path / "agent.py").write_text(
        "import requests\n" + TOOL_PREAMBLE + "class Client:\n"
        "    def __init__(self):\n"
        "        self.session = requests.Session()\n\n"
        "    @tool\n"
        "    def exfiltrate(self, payload: str) -> str:\n"
        '        """Send data out."""\n'
        "        self.session.post('https://example.invalid', data=payload)\n"
        "        return 'ok'\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.name for tool in tools] == ["exfiltrate"], "class-based tools must be discovered"
    assert tools[0].proposed_action_class() == "unknown"
    assert "UNRESOLVED_CALLEE" in tools[0].reasons


def test_an_unrecognised_third_party_call_is_refused_but_stdlib_stays_read(
    tmp_path: Path,
) -> None:
    """Unknown third-party code could do anything; stdlib formatting could not."""

    (tmp_path / "third_party.py").write_text(
        "import mylib\n" + TOOL_PREAMBLE + "@tool\n"
        "def relay(value: str) -> str:\n"
        '    """Hand off to an unrecognised package."""\n'
        "    return mylib.dispatch(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "std.py").write_text(
        "import re\n" + TOOL_PREAMBLE + "@tool\n"
        "def clean(value: str) -> str:\n"
        '    """Normalise with the standard library."""\n'
        "    return re.sub('a', 'b', value)\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))
    by_name = {tool.name: tool for tool in tools}

    assert by_name["relay"].proposed_action_class() == "unknown"
    assert by_name["clean"].proposed_action_class() == "read"


# ---------------------------------------------------------------------------------------
# Safe fallback: an unrecognised call must not become a benign verdict
# ---------------------------------------------------------------------------------------


def test_an_unrecognised_call_blocks_a_benign_verdict(tmp_path: Path) -> None:
    """`read` is what the analyzer says when it recognised everything and saw no effect.

    If part of the reachable set could not be placed, an unseen effect could outrank what
    was observed, so answering would turn a gap in the catalog into a benign result.
    """

    (tmp_path / "agent.py").write_text(
        "import mylib\n" + TOOL_PREAMBLE + "@tool\n"
        "def relay(value: str) -> str:\n"
        '    """Hand off to a package the catalog does not describe."""\n'
        "    return mylib.dispatch(value)\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "unknown"
    assert tools[0].confidence() == "review"


def test_an_unrecognised_call_cannot_lower_a_sensitive_verdict(tmp_path: Path) -> None:
    """Nothing outranks sensitive, so an unplaceable call alongside it changes nothing."""

    (tmp_path / "agent.py").write_text(
        "import mylib\nimport subprocess\n" + TOOL_PREAMBLE + "@tool\n"
        "def run(value: str) -> str:\n"
        '    """Launch a process and also call an unknown package."""\n'
        "    subprocess.run(['/bin/true'], check=False)\n"
        "    return mylib.dispatch(value)\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "sensitive"


def test_a_receiver_kept_through_a_context_manager_is_still_tracked(tmp_path: Path) -> None:
    """`with client as session` once lost the receiver and published egress as read."""

    (tmp_path / "agent.py").write_text(
        "import httpx\n" + TOOL_PREAMBLE + "@tool\n"
        "def fetch(path: str) -> str:\n"
        '    """Fetch through a client used as a context manager."""\n'
        "    client = httpx.Client(base_url='https://example.invalid')\n"
        "    with client as session:\n"
        "        return session.get(path).text\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "external"


def test_an_async_context_manager_receiver_is_tracked(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "import aiohttp\n" + TOOL_PREAMBLE + "@tool\n"
        "async def fetch(url: str) -> str:\n"
        '    """Fetch through an async client session."""\n'
        "    async with aiohttp.ClientSession() as session:\n"
        "        async with session.get(url) as response:\n"
        "            return await response.text()\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "external"


def test_a_decorator_is_registration_and_never_counts_as_behaviour(tmp_path: Path) -> None:
    """Classifying `@mcp.tool()` made every decorated tool refuse on its own registration."""

    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "mcp = FastMCP('synthetic')\n\n\n"
        "@mcp.tool()\n"
        "def summarize(text: str) -> str:\n"
        '    """Pure formatting."""\n'
        "    return text.strip().upper()\n",
        encoding="utf-8",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.proposed_action_class() for tool in tools] == ["read"]
    assert tools[0].reasons == set()
