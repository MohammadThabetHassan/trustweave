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
