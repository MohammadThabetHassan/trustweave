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
