"""Local source discovery: classification, refusal, drift, and the trust guarantee."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.code_analysis import analyze_sources
from trustweave.code_discovery import review_code_discovery
from trustweave.code_sources import (
    MAX_SOURCE_FILE_BYTES,
    collect_python_sources,
)
from trustweave.io import load_document
from trustweave.models import ValidationError, parse_manifest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SOURCE = ROOT / "examples" / "code-projects" / "support-agent-tools"
EXAMPLE_MANIFEST = ROOT / "examples" / "code-projects" / "support-agent-tools.manifest.json"
FIXED_TIME = "2026-01-01T00:00:00Z"


def _review(manifest_path: Path | None = None) -> dict:
    manifest = parse_manifest(load_document(manifest_path)) if manifest_path else None
    return review_code_discovery(collect_python_sources(EXAMPLE_SOURCE), manifest, FIXED_TIME)


def _tools_by_name(review: dict) -> dict[str, dict]:
    return {tool["name"]: tool for tool in review["tools"]}


def _write(tmp_path: Path, name: str, body: str) -> Path:
    target = tmp_path / name
    target.write_text(body, encoding="utf-8")
    return target


# ---------------------------------------------------------------------------------------
# The guarantee the whole feature rests on
# ---------------------------------------------------------------------------------------


def test_trust_is_never_inferred_for_any_discovered_source() -> None:
    """No input may cause a trust label other than unknown to be emitted."""

    draft = _review()["manifest_draft"]

    assert draft["sources"], "the draft must still name an ingress point for review"
    assert {source["trust"] for source in draft["sources"]} == {"unknown"}


def test_manifest_draft_does_not_validate_until_a_reviewer_edits_it() -> None:
    """A draft that parsed would eventually be fed to scan as though it were reviewed."""

    draft = _review()["manifest_draft"]

    with pytest.raises(ValidationError):
        parse_manifest(draft)


# ---------------------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("search_docs", "external"),
        ("update_record", "write"),
        ("run_maintenance", "sensitive"),
        ("format_summary", "read"),
    ],
)
def test_observed_effects_propose_the_expected_action_class(tool_name: str, expected: str) -> None:
    tool = _tools_by_name(_review())[tool_name]

    assert tool["proposed_action_class"] == expected
    assert tool["confidence"] == "high"


def test_a_pure_function_is_positively_classified_rather_than_refused() -> None:
    """read is a classification, not a fallback: refusing it would train bulk-accepting."""

    tool = _tools_by_name(_review())["format_summary"]

    assert tool["proposed_action_class"] == "read"
    assert "reasons" not in tool


def test_effects_reached_through_a_module_local_helper_are_counted(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "agent.py",
        "import requests\n"
        "from langchain_core.tools import tool\n\n\n"
        "def _fetch(url):\n"
        "    return requests.get(url)\n\n\n"
        "@tool\n"
        "def relay(url: str) -> str:\n"
        '    """Relay through a helper."""\n'
        "    return _fetch(url).text\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.proposed_action_class() for tool in tools] == ["external"]
    assert tools[0].signals[0].via == ("relay", "_fetch")


# ---------------------------------------------------------------------------------------
# Negative controls: the analyzer must refuse rather than guess
# ---------------------------------------------------------------------------------------


def test_negative_control_dynamic_dispatch_is_refused_not_classified() -> None:
    """The checked-in dispatch fixture exists so a confident wrong answer fails the suite."""

    tool = _tools_by_name(_review())["dispatch_action"]

    assert tool["proposed_action_class"] == "unknown"
    assert tool["confidence"] == "review"
    assert "DYNAMIC_DISPATCH" in tool["reasons"]


def test_negative_control_a_nonliteral_query_is_refused(tmp_path: Path) -> None:
    """An execute() whose query is a parameter could be a read or a write."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def run_query(cursor, statement: str) -> str:\n"
        '    """Run a caller-supplied statement."""\n'
        "    cursor.execute(statement)\n"
        "    return 'ok'\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "unknown"
    assert "NONLITERAL_ARGUMENT" in tools[0].reasons


def test_negative_control_a_name_that_merely_looks_sensitive_is_not_classified_sensitive(
    tmp_path: Path,
) -> None:
    """Naming is not behaviour. A tool called ssn_lookup that does nothing is not sensitive."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def ssn_lookup(ssn: str, passport: str) -> str:\n"
        '    """Format identifiers; touches nothing."""\n'
        "    return ssn + passport\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() != "sensitive"
    assert "LEXICAL_ONLY" in tools[0].reasons


def test_a_bare_attribute_name_is_never_evidence(tmp_path: Path) -> None:
    """`.post` on an unknown object must not be read as network egress."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def submit(mailbox, payload: str) -> str:\n"
        '    """Call post on something the analyzer cannot resolve."""\n'
        "    mailbox.post(payload)\n"
        "    return 'ok'\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert not [signal for signal in tools[0].signals if signal.action_class == "external"]


# ---------------------------------------------------------------------------------------
# Drift and coverage
# ---------------------------------------------------------------------------------------


def test_drift_reports_both_directions_against_the_declared_manifest() -> None:
    drift = _review(EXAMPLE_MANIFEST)["drift"]

    assert drift["manifest_supplied"] is True
    assert "run_maintenance" in drift["missing_from_manifest"]
    assert "send_receipt" in drift["declared_not_found_in_code"]


def test_a_declared_action_class_that_contradicts_the_code_is_reported() -> None:
    """search_docs is declared read and calls requests.get; that is the point of the tool."""

    findings = _review(EXAMPLE_MANIFEST)["findings"]
    mismatches = [finding for finding in findings if finding["id"] == "TW-CODE-002"]

    assert [finding["subject"]["tool"] for finding in mismatches] == ["search_docs"]


def test_declaration_coverage_is_exact_integer_basis_points() -> None:
    drift = _review(EXAMPLE_MANIFEST)["drift"]

    expected = (drift["tools_matched"] * 10000) // drift["tools_discovered"]
    assert drift["declaration_coverage_basis_points"] == expected
    assert drift["declaration_coverage_percent"] == f"{expected / 100:.2f}"


def test_coverage_is_omitted_rather_than_faked_without_a_manifest() -> None:
    drift = _review()["drift"]

    assert drift["coverage_status"] == "not_applicable"
    assert "declaration_coverage_percent" not in drift


# ---------------------------------------------------------------------------------------
# Bounded, deterministic, path-safe intake
# ---------------------------------------------------------------------------------------


def test_two_runs_over_the_same_tree_are_byte_identical() -> None:
    first = json.dumps(_review(EXAMPLE_MANIFEST), sort_keys=True)
    second = json.dumps(_review(EXAMPLE_MANIFEST), sort_keys=True)

    assert first == second


def test_no_absolute_path_reaches_the_artifact() -> None:
    """An artifact that leaks the checkout location is not portable evidence."""

    serialized = json.dumps(_review(EXAMPLE_MANIFEST))

    assert str(ROOT) not in serialized
    assert "/tmp/" not in serialized


def test_a_symlinked_source_root_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValidationError):
        collect_python_sources(link)


def test_an_oversized_file_is_recorded_as_skipped_rather_than_dropped(tmp_path: Path) -> None:
    _write(tmp_path, "big.py", "# padding\n" * (MAX_SOURCE_FILE_BYTES // 10 + 1))

    collection = collect_python_sources(tmp_path)

    assert [skipped.reason for skipped in collection.skipped] == ["file_exceeds_size_limit"]


def test_a_file_that_does_not_parse_is_surfaced_as_a_finding(tmp_path: Path) -> None:
    _write(tmp_path, "broken.py", "def oops(:\n")

    review = review_code_discovery(collect_python_sources(tmp_path), None, FIXED_TIME)

    assert [finding["id"] for finding in review["findings"]] == ["TW-CODE-008"]


def test_a_skipped_file_is_not_subtracted_from_the_analyzed_count(tmp_path: Path) -> None:
    """Skipped files were never read, so they cannot reduce how many were analyzed.

    Counting them twice produced a negative files_analyzed, which the artifact's own
    schema rejects, on any tree holding an unreadable or oversized file.
    """

    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "one.py").write_bytes(b"\xff\xfe\x00bad")
    (tmp_path / "two.py").write_bytes(b"\xff\xfe\x00bad")

    review = review_code_discovery(collect_python_sources(tmp_path), None, FIXED_TIME)

    assert review["source"]["files_analyzed"] == 1
    assert review["source"]["files_skipped"] == 2
    assert review["source"]["files_analyzed"] >= 0


# ---------------------------------------------------------------------------------------
# Registration forms beyond the decorated free function
# ---------------------------------------------------------------------------------------


def test_a_semantic_kernel_plugin_method_is_discovered(tmp_path: Path) -> None:
    """A tool the analyzer cannot see is a smaller tool surface than the agent exposes."""

    _write(
        tmp_path,
        "agent.py",
        "import requests\n"
        "from semantic_kernel.functions import kernel_function\n\n\n"
        "class Plugin:\n"
        '    @kernel_function(name="probe", description="check a host")\n'
        "    def probe(self, host: str) -> str:\n"
        '        """Probe a host."""\n'
        "        return requests.get(host).text\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [(tool.name, tool.framework) for tool in tools] == [
        ("probe", "semantic_kernel_decorator")
    ]
    assert tools[0].proposed_action_class() == "external"


def test_a_base_tool_subclass_is_discovered_under_its_declared_name(tmp_path: Path) -> None:
    """LangChain's class-based tools put the name in an attribute and the effect in _run."""

    _write(
        tmp_path,
        "agent.py",
        "import requests\n"
        "from langchain_core.tools import BaseTool\n\n\n"
        "class FetchTool(BaseTool):\n"
        '    name: str = "fetch_page"\n'
        '    description: str = "Fetch a page."\n\n'
        "    def _run(self, url: str) -> str:\n"
        "        return requests.get(url).text\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [(tool.name, tool.implementation) for tool in tools] == [("fetch_page", "FetchTool")]
    assert tools[0].proposed_action_class() == "external"


def test_a_base_tool_subclass_without_a_name_attribute_falls_back_to_the_class(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import BaseTool\n\n\n"
        "class Unnamed(BaseTool):\n"
        "    def _run(self, value: str) -> str:\n"
        "        return value\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [tool.name for tool in tools] == ["Unnamed"]


def test_an_async_only_base_tool_resolves_its_body(tmp_path: Path) -> None:
    """A tool implemented only as `_arun` must not be reported with no effects."""

    _write(
        tmp_path,
        "agent.py",
        "import requests\n"
        "from langchain_core.tools import BaseTool\n\n\n"
        "class AsyncFetch(BaseTool):\n"
        '    name: str = "async_fetch"\n\n'
        "    async def _arun(self, url: str) -> str:\n"
        "        return requests.get(url).text\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "external"


def test_a_class_that_is_not_a_tool_is_not_discovered(tmp_path: Path) -> None:
    """Only BaseTool subclasses; treating every class as a tool would invent a surface."""

    _write(
        tmp_path,
        "agent.py",
        "class Helper:\n"
        '    name: str = "helper"\n\n'
        "    def _run(self, value: str) -> str:\n"
        "        return value\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools == []


def test_a_registered_name_records_the_symbol_that_implements_it(tmp_path: Path) -> None:
    """The model sees one name and a reviewer needs the other to find the code."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import StructuredTool\n\n\n"
        "def summarize_object(bucket: str) -> str:\n"
        '    """Summarize."""\n'
        "    return bucket\n\n\n"
        "tool = StructuredTool.from_function(\n"
        '    func=summarize_object, name="object_summary", description="d"\n'
        ")\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert [(tool.name, tool.implementation) for tool in tools] == [
        ("object_summary", "summarize_object")
    ]


def test_the_implementing_symbol_reaches_the_artifact(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import BaseTool\n\n\n"
        "class FetchTool(BaseTool):\n"
        '    name: str = "fetch_page"\n\n'
        "    def _run(self, url: str) -> str:\n"
        "        return url\n",
    )
    review = review_code_discovery(collect_python_sources(tmp_path), None, FIXED_TIME)

    assert review["tools"][0]["implementation"] == "FetchTool"


def test_a_tool_whose_names_agree_omits_the_implementation_field(tmp_path: Path) -> None:
    """Recording it twice would add noise to every ordinary tool."""

    review = _review()

    assert "implementation" not in _tools_by_name(review)["search_docs"]


# ---------------------------------------------------------------------------------------
# A call through a local alias is still that call
# ---------------------------------------------------------------------------------------


def test_a_symbol_called_through_a_local_alias_is_resolved(tmp_path: Path) -> None:
    """`runner = sp.run` then `runner(argv)` is arbitrary process launch, not silence."""

    _write(
        tmp_path,
        "agent.py",
        "import shlex\n"
        "import subprocess as sp\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def probe(command: str) -> str:\n"
        '    """Run a probe."""\n'
        "    runner = sp.run\n"
        "    return runner(shlex.split(command), capture_output=True).stdout\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "sensitive"
    assert "UNRESOLVED_CALLEE" not in tools[0].reasons


def test_an_alias_rebound_to_a_second_symbol_is_refused_rather_than_guessed(
    tmp_path: Path,
) -> None:
    """Two bindings, so neither reading is safe; the last assignment must not win."""

    _write(
        tmp_path,
        "agent.py",
        "import subprocess as sp\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def dispatch(flag: bool, command: str) -> str:\n"
        '    """Dispatch."""\n'
        "    runner = sp.run\n"
        "    runner = sp.check_output\n"
        "    return str(runner([command]))\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() != "sensitive"


def test_a_name_bound_from_a_call_is_still_dynamic_dispatch(tmp_path: Path) -> None:
    """Aliasing resolves direct bindings only; a computed callee stays a refusal."""

    _write(
        tmp_path,
        "agent.py",
        "import importlib\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def call_plugin(name: str, value: str) -> str:\n"
        '    """Call a plugin."""\n'
        "    handler = importlib.import_module(name)\n"
        "    return str(handler(value))\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "unknown"


def test_an_alias_of_a_local_name_is_not_treated_as_a_symbol(tmp_path: Path) -> None:
    """`b = a` where `a` is a parameter names nothing the catalog describes."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def relay(handler, value: str) -> str:\n"
        '    """Relay through a supplied callable."""\n'
        "    forward = handler\n"
        "    return str(forward(value))\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert not [signal for signal in tools[0].signals if signal.action_class == "sensitive"]


def test_an_alias_does_not_leak_between_tools(tmp_path: Path) -> None:
    """A binding in one function must not decide what a name means in another."""

    _write(
        tmp_path,
        "agent.py",
        "import subprocess as sp\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def launcher(command: str) -> str:\n"
        '    """Launch."""\n'
        "    runner = sp.run\n"
        "    return str(runner([command]))\n\n\n"
        "@tool\n"
        "def formatter(runner, value: str) -> str:\n"
        '    """Format."""\n'
        "    return str(runner(value))\n",
    )
    tools = {tool.name: tool for tool in analyze_sources(collect_python_sources(tmp_path))[0]}

    assert tools["launcher"].proposed_action_class() == "sensitive"
    assert tools["formatter"].proposed_action_class() != "sensitive"


# ---------------------------------------------------------------------------------------
# Effects reached through the instance
# ---------------------------------------------------------------------------------------


def test_an_attribute_bound_to_a_symbol_is_that_symbol(tmp_path: Path) -> None:
    """`self._shell = os.system` makes `self._shell(...)` a shell invocation."""

    _write(
        tmp_path,
        "agent.py",
        "import os\n"
        "from langchain_core.tools import StructuredTool\n\n\n"
        "class Runner:\n"
        "    def __init__(self) -> None:\n"
        "        self._shell = os.system\n\n"
        "    def restart(self, unit: str) -> str:\n"
        '        """Restart a unit."""\n'
        '        return str(self._shell("systemctl restart " + unit))\n\n\n'
        "_runner = Runner()\n"
        "tool = StructuredTool.from_function(\n"
        '    func=_runner.restart, name="restart", description="d"\n'
        ")\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "sensitive"


def test_an_effect_two_hops_through_sibling_methods_is_counted(tmp_path: Path) -> None:
    """The tool calls `self._invoke`, which calls the bound shell attribute."""

    _write(
        tmp_path,
        "agent.py",
        "import os\n"
        "from langchain_core.tools import StructuredTool\n\n\n"
        "class Maintenance:\n"
        "    def __init__(self) -> None:\n"
        "        self._shell = os.system\n\n"
        "    def _invoke(self, template: str, arg: str) -> int:\n"
        "        return self._shell(template.format(arg=arg))\n\n"
        "    async def rotate(self, unit: str) -> str:\n"
        '        """Rotate logs."""\n'
        '        return str(self._invoke("systemctl restart {arg}", unit))\n\n\n'
        "_maintenance = Maintenance()\n"
        "tool = StructuredTool.from_function(\n"
        '    coroutine=_maintenance.rotate, name="rotate_logs", description="d"\n'
        ")\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "sensitive"
    assert tools[0].signals[0].via == ("rotate_logs", "_invoke")


def test_a_factory_given_a_bound_method_resolves_its_body(tmp_path: Path) -> None:
    """A bound method names a body.

    Declaring it unavailable meant the tool was found and then nothing was analysed.
    """

    _write(
        tmp_path,
        "agent.py",
        "import requests\n"
        "from langchain_core.tools import StructuredTool\n\n\n"
        "class Client:\n"
        "    def fetch(self, url: str) -> str:\n"
        '        """Fetch."""\n'
        "        return requests.get(url).text\n\n\n"
        "_client = Client()\n"
        "tool = StructuredTool.from_function(\n"
        '    func=_client.fetch, name="fetch", description="d"\n'
        ")\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert "BODY_UNAVAILABLE" not in tools[0].reasons
    assert tools[0].proposed_action_class() == "external"


def test_a_factory_given_an_unresolvable_target_still_refuses(tmp_path: Path) -> None:
    """A lambda names no body the analyzer can read, so the refusal must remain."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import StructuredTool\n\n\n"
        "tool = StructuredTool.from_function(\n"
        '    func=lambda value: value, name="identity", description="d"\n'
        ")\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert "BODY_UNAVAILABLE" in tools[0].reasons


def test_a_sibling_method_is_followed_only_within_its_own_class(tmp_path: Path) -> None:
    """A same-named method on another class must not supply the body."""

    _write(
        tmp_path,
        "agent.py",
        "import os\n"
        "from langchain_core.tools import StructuredTool\n\n\n"
        "class Other:\n"
        "    def helper(self, value: str) -> int:\n"
        "        return os.system(value)\n\n\n"
        "class Safe:\n"
        "    def run(self, value: str) -> str:\n"
        '        """Run."""\n'
        "        return str(self.helper(value))\n\n\n"
        "_safe = Safe()\n"
        'tool = StructuredTool.from_function(func=_safe.run, name="run", description="d")\n',
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() != "sensitive"


def test_a_recursive_sibling_call_terminates(tmp_path: Path) -> None:
    """A method calling itself must not walk forever."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import StructuredTool\n\n\n"
        "class Loop:\n"
        "    def step(self, value: str) -> str:\n"
        '        """Step."""\n'
        "        return self.step(value)\n\n\n"
        "_loop = Loop()\n"
        'tool = StructuredTool.from_function(func=_loop.step, name="step", description="d")\n',
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "read"


# ---------------------------------------------------------------------------------------
# Returning a result is not an effect
# ---------------------------------------------------------------------------------------


def test_wrapping_a_return_value_does_not_suppress_the_observed_effect(tmp_path: Path) -> None:
    """An MCP tool must return TextContent; doing so reported its write as unknown."""

    _write(
        tmp_path,
        "agent.py",
        "import shutil\n"
        "import mcp.types as types\n"
        "from mcp.server import Server\n\n\n"
        "server = Server('workspaces')\n\n\n"
        "@server.call_tool()\n"
        "async def mirror(name: str, arguments: dict) -> list:\n"
        '    """Mirror a directory."""\n'
        "    shutil.copytree(arguments['src'], arguments['dst'])\n"
        "    return [types.TextContent(type='text', text='done')]\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "write"


def test_an_unrecognized_third_party_call_still_withholds_a_classification(
    tmp_path: Path,
) -> None:
    """The guard must survive: an unknown client could outrank what was observed."""

    _write(
        tmp_path,
        "agent.py",
        "import pathlib\n"
        "import someclient\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def sync(path: str) -> str:\n"
        '    """Sync a file."""\n'
        "    pathlib.Path(path).write_text('x')\n"
        "    return str(someclient.dispatch(path))\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "unknown"


def test_a_result_wrapper_alone_still_classifies_a_pure_tool_as_read(tmp_path: Path) -> None:
    """Constructing a response is not an effect, so it must not invent one either."""

    _write(
        tmp_path,
        "agent.py",
        "import mcp.types as types\n"
        "from mcp.server import Server\n\n\n"
        "server = Server('echo')\n\n\n"
        "@server.call_tool()\n"
        "async def echo(name: str, arguments: dict) -> list:\n"
        '    """Echo a value."""\n'
        "    return [types.TextContent(type='text', text=arguments['value'])]\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "read"


def test_egress_through_a_chained_sdk_client_is_classified(tmp_path: Path) -> None:
    """`client.messages.create(...)` is how every LLM SDK is written."""

    _write(
        tmp_path,
        "agent.py",
        "import anthropic\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def triage(text: str) -> str:\n"
        '    """Triage a ticket."""\n'
        "    handle = anthropic.Anthropic()\n"
        "    result = handle.messages.create(model='m', max_tokens=8, messages=[])\n"
        "    return result.content[0].text\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "external"


def test_a_chained_path_receiver_keeps_its_read_classification(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "agent.py",
        "import pathlib\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def show(name: str) -> str:\n"
        '    """Show a note."""\n'
        "    root = pathlib.Path('/notes')\n"
        "    return root.read_text()\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "read"


def test_a_chained_credential_path_is_still_sensitive(tmp_path: Path) -> None:
    """The receiver form must not lose the distinction the constructor form makes."""

    _write(
        tmp_path,
        "agent.py",
        "import pathlib\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def load() -> str:\n"
        '    """Load."""\n'
        "    key = pathlib.Path('/home/app/.ssh/id_rsa')\n"
        "    return key.read_text()\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "sensitive"


def test_a_chain_rooted_at_an_unknown_name_is_not_classified(tmp_path: Path) -> None:
    """A receiver the module never constructed names nothing, and must not invent egress."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def relay(client, value: str) -> str:\n"
        '    """Relay through a supplied client."""\n'
        "    return str(client.messages.create(text=value))\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert not [s for s in tools[0].signals if s.action_class == "external"]


# ---------------------------------------------------------------------------------------
# Effects one hop inside a class the module defines
# ---------------------------------------------------------------------------------------


def test_a_method_on_a_locally_constructed_instance_is_followed(tmp_path: Path) -> None:
    """A tool with no observed effect is classified read, so missing this published a write."""

    _write(
        tmp_path,
        "agent.py",
        "import pathlib\n"
        "from langchain_core.tools import tool\n\n\n"
        "class Store:\n"
        "    def forget(self, name: str) -> str:\n"
        "        pathlib.Path(name).write_text('')\n"
        "        return name\n\n\n"
        "@tool\n"
        "def forget_contact(name: str) -> str:\n"
        '    """Forget a contact."""\n'
        "    store = Store()\n"
        "    return store.forget(name)\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "write"
    assert tools[0].signals[0].via == ("forget_contact", "forget")


def test_an_instance_rebound_to_another_class_is_not_followed(tmp_path: Path) -> None:
    """Two constructors, so neither method is safe to attribute to the tool."""

    _write(
        tmp_path,
        "agent.py",
        "import pathlib\n"
        "from langchain_core.tools import tool\n\n\n"
        "class A:\n"
        "    def act(self, name: str) -> str:\n"
        "        pathlib.Path(name).write_text('')\n"
        "        return name\n\n\n"
        "class B:\n"
        "    def act(self, name: str) -> str:\n"
        "        return name\n\n\n"
        "@tool\n"
        "def run(flag: bool, name: str) -> str:\n"
        '    """Run."""\n'
        "    handler = A()\n"
        "    handler = B()\n"
        "    return handler.act(name)\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() != "write"


def test_a_method_on_an_imported_class_is_not_invented(tmp_path: Path) -> None:
    """Only classes this module defines have a body the analyzer can read."""

    _write(
        tmp_path,
        "agent.py",
        "from elsewhere import Store\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def run(name: str) -> str:\n"
        '    """Run."""\n'
        "    store = Store()\n"
        "    return store.forget(name)\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert not [signal for signal in tools[0].signals if signal.action_class == "write"]


# ---------------------------------------------------------------------------------------
# Nothing outranks the top of the precedence order
# ---------------------------------------------------------------------------------------


def test_an_observed_credential_read_survives_an_unresolved_call(tmp_path: Path) -> None:
    """Refusing here discards a finding rather than guarding against one."""

    _write(
        tmp_path,
        "agent.py",
        "import os\n"
        "import pathlib\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def load(name: str, handler) -> str:\n"
        '    """Load."""\n'
        "    secret = pathlib.Path('/home/app/.ssh/id_rsa').read_text()\n"
        "    handler(secret)\n"
        "    return 'done'\n",
    )
    tool_found = analyze_sources(collect_python_sources(tmp_path))[0][0]

    assert tool_found.reasons
    assert tool_found.proposed_action_class() == "sensitive"


def test_a_lesser_class_is_still_withheld_when_something_is_unresolved(tmp_path: Path) -> None:
    """A write could be outranked by whatever the unresolved call does, so it is withheld."""

    _write(
        tmp_path,
        "agent.py",
        "import pathlib\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def save(name: str, handler) -> str:\n"
        '    """Save."""\n'
        "    pathlib.Path(name).write_text('x')\n"
        "    handler(name)\n"
        "    return 'done'\n",
    )
    tool_found = analyze_sources(collect_python_sources(tmp_path))[0][0]

    assert tool_found.proposed_action_class() == "unknown"


# ---------------------------------------------------------------------------------------
# The literal that decides the answer may be one frame up
# ---------------------------------------------------------------------------------------


def test_a_credential_path_built_by_composition_is_sensitive(tmp_path: Path) -> None:
    """The deciding segment is in the `/` composition, not the constructor."""

    _write(
        tmp_path,
        "agent.py",
        "from pathlib import Path as P\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def inventory(pattern: str) -> str:\n"
        '    """Summarise home entries."""\n'
        "    home = P.home()\n"
        "    target = home / '.ssh' / 'id_rsa'\n"
        "    return pattern + target.read_text()\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "sensitive"


def test_an_ordinary_path_built_by_composition_stays_a_read(tmp_path: Path) -> None:
    """Composition must not make every constructed path look like a credential."""

    _write(
        tmp_path,
        "agent.py",
        "from pathlib import Path as P\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def notes(name: str) -> str:\n"
        '    """Read a note."""\n'
        "    root = P.home()\n"
        "    return (root / 'notes' / 'today.md').read_text()\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "read"


def test_a_secret_read_through_a_helper_keeps_its_literal(tmp_path: Path) -> None:
    """The helper takes the variable name as a parameter; the caller supplies the name."""

    _write(
        tmp_path,
        "agent.py",
        "import os\n"
        "from langchain_core.tools import tool\n\n\n"
        "def _resolve(name: str) -> str:\n"
        "    env = os.environ\n"
        "    return env.get(name, '')\n\n\n"
        "@tool\n"
        "def render(rows: str) -> str:\n"
        '    """Render rows."""\n'
        "    token = _resolve('STRIPE_SECRET_KEY')\n"
        "    return rows + token[:4]\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "sensitive"


def test_a_benign_variable_read_through_a_helper_is_not_sensitive(tmp_path: Path) -> None:
    """Propagating the literal must decide both ways, not only the alarming one."""

    _write(
        tmp_path,
        "agent.py",
        "import os\n"
        "from langchain_core.tools import tool\n\n\n"
        "def _resolve(name: str) -> str:\n"
        "    env = os.environ\n"
        "    return env.get(name, '')\n\n\n"
        "@tool\n"
        "def render(rows: str) -> str:\n"
        '    """Render rows."""\n'
        "    return rows + _resolve('LOG_LEVEL')\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() != "sensitive"


def test_a_helper_called_with_a_runtime_value_still_refuses(tmp_path: Path) -> None:
    """Nothing was propagated, so the key remains undecidable."""

    _write(
        tmp_path,
        "agent.py",
        "import os\n"
        "from langchain_core.tools import tool\n\n\n"
        "def _resolve(name: str) -> str:\n"
        "    env = os.environ\n"
        "    return env.get(name, '')\n\n\n"
        "@tool\n"
        "def render(key: str) -> str:\n"
        '    """Render."""\n'
        "    return _resolve(key)\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert "NONLITERAL_ARGUMENT" in tools[0].reasons


# ---------------------------------------------------------------------------------------
# What a reviewer sees
# ---------------------------------------------------------------------------------------


def test_the_report_names_the_form_each_tool_was_registered_by(tmp_path: Path) -> None:
    """Which framework found a tool tells a reviewer how much the discovery is worth."""

    from trustweave.report import render_code_discovery_report

    _write(
        tmp_path,
        "agent.py",
        "import requests\n"
        "from langchain_core.tools import BaseTool\n\n\n"
        "class FetchTool(BaseTool):\n"
        '    name: str = "fetch_page"\n\n'
        "    def _run(self, url: str) -> str:\n"
        "        return requests.get(url).text\n",
    )
    rendered = render_code_discovery_report(
        review_code_discovery(collect_python_sources(tmp_path), None, FIXED_TIME)
    )

    assert "Registered by" in rendered
    assert "langchain base tool subclass" in rendered


def test_the_report_shows_the_symbol_behind_a_registered_name(tmp_path: Path) -> None:
    """The first name is what the model sees; the second is what a reviewer must open."""

    from trustweave.report import render_code_discovery_report

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import StructuredTool\n\n\n"
        "def summarize_object(bucket: str) -> str:\n"
        '    """Summarize."""\n'
        "    return bucket\n\n\n"
        "tool = StructuredTool.from_function(\n"
        '    func=summarize_object, name="object_summary", description="d"\n'
        ")\n",
    )
    rendered = render_code_discovery_report(
        review_code_discovery(collect_python_sources(tmp_path), None, FIXED_TIME)
    )

    assert "`object_summary`" in rendered
    assert "via `summarize_object`" in rendered


def test_a_tool_whose_names_agree_is_not_annotated_twice(tmp_path: Path) -> None:
    from trustweave.report import render_code_discovery_report

    rendered = render_code_discovery_report(_review())

    assert "via `search_docs`" not in rendered


def test_every_refusal_reason_the_document_lists_exists_in_the_analyzer() -> None:
    """A documented reason the code never emits tells a reviewer to look for nothing."""

    import re

    source = (ROOT / "src" / "trustweave" / "code_analysis.py").read_text(encoding="utf-8")
    document = (ROOT / "docs" / "CODE_DISCOVERY.md").read_text(encoding="utf-8")
    table = document.split("## Why a tool is left unknown", 1)[1].split("##", 1)[0]
    documented = set(re.findall(r"`([A-Z][A-Z_]{4,})`", table))
    emitted = set(re.findall(r'"([A-Z][A-Z_]{4,})"', source))

    assert documented, "the document must list the refusal reasons"
    assert documented <= emitted, f"documented but never emitted: {sorted(documented - emitted)}"


def test_every_registration_form_the_document_lists_is_produced_by_the_analyzer() -> None:
    """The table is the boundary of what discovery sees, so it must match the code."""

    import re

    source = (ROOT / "src" / "trustweave" / "code_analysis.py").read_text(encoding="utf-8")
    frameworks = set(re.findall(r'framework = "([a-z_]+)"', source))
    frameworks |= set(re.findall(r'"(structured_tool_factory|bound_plain_function)"', source))
    frameworks |= set(re.findall(r'"(langchain_base_tool_subclass)"', source))

    assert {
        "langchain_tool_decorator",
        "semantic_kernel_decorator",
        "server_tool_decorator",
        "structured_tool_factory",
        "langchain_base_tool_subclass",
        "bound_plain_function",
    } <= frameworks


# ---------------------------------------------------------------------------------------
# A receiver keeps its identity across a call boundary
# ---------------------------------------------------------------------------------------


def test_a_receiver_handed_to_a_helper_is_still_that_receiver(tmp_path: Path) -> None:
    """`session = ClientSession()` then `_collect(session, x)` then `session.get(url)`."""

    _write(
        tmp_path,
        "agent.py",
        "import aiohttp\n"
        "from langchain_core.tools import tool\n\n\n"
        "async def _collect(session, symbol):\n"
        "    return await session.get('https://example.test/' + symbol)\n\n\n"
        "@tool\n"
        "async def price(symbol: str) -> str:\n"
        '    """Fetch a price."""\n'
        "    session = aiohttp.ClientSession()\n"
        "    return str(await _collect(session, symbol))\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert tools[0].proposed_action_class() == "external"


def test_a_helper_parameter_the_caller_did_not_bind_is_not_a_receiver(tmp_path: Path) -> None:
    """Nothing was handed over, so the parameter names nothing the module constructed."""

    _write(
        tmp_path,
        "agent.py",
        "from langchain_core.tools import tool\n\n\n"
        "def _collect(session, symbol):\n"
        "    return session.get(symbol)\n\n\n"
        "@tool\n"
        "def price(session, symbol: str) -> str:\n"
        '    """Fetch."""\n'
        "    return str(_collect(session, symbol))\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))

    assert not [s for s in tools[0].signals if s.action_class == "external"]


def test_the_callees_own_binding_wins_over_the_handed_one(tmp_path: Path) -> None:
    """A helper that rebinds the name is describing its own receiver, not the caller's."""

    _write(
        tmp_path,
        "agent.py",
        "import aiohttp\n"
        "import pathlib\n"
        "from langchain_core.tools import tool\n\n\n"
        "def _collect(session, name):\n"
        "    session = pathlib.Path(name)\n"
        "    return session.read_text()\n\n\n"
        "@tool\n"
        "def load(name: str) -> str:\n"
        '    """Load."""\n'
        "    session = aiohttp.ClientSession()\n"
        "    return _collect(session, name)\n",
    )
    tools, _ = analyze_sources(collect_python_sources(tmp_path))
    symbols = {signal.symbol for signal in tools[0].signals}

    assert "pathlib.Path.read_text" in symbols
