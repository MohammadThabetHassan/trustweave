"""The discovery artifact's published shape, enforced rather than assumed.

`trustweave.dev/code-discovery/v1alpha1` is a published contract with a JSON schema in the
package, and nothing validated an emitted artifact against it. Mutation testing showed the
consequence: renaming `location` to `LOCATION`, or `schema_version` to `SCHEMA_VERSION`,
passed the whole suite. Consumers read these key names, so the names are the contract.

The schema constrains the top level and the source, summary, drift and manifest_draft
sections. It does not constrain the shape of a tool entry, so those keys are asserted here
directly rather than left to the schema.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from trustweave.code_discovery import review_code_discovery
from trustweave.code_sources import collect_python_sources
from trustweave.io import load_document
from trustweave.models import parse_manifest
from trustweave.schema_catalog import read_schema

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SOURCE = ROOT / "examples" / "code-projects" / "support-agent-tools"
EXAMPLE_MANIFEST = ROOT / "examples" / "code-projects" / "support-agent-tools.manifest.json"
FIXED_TIME = "2026-01-01T00:00:00Z"


def _review(with_manifest: bool) -> dict[str, Any]:
    manifest = parse_manifest(load_document(EXAMPLE_MANIFEST)) if with_manifest else None
    return review_code_discovery(collect_python_sources(EXAMPLE_SOURCE), manifest, FIXED_TIME)


def _validate(document: dict[str, Any]) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    # Read through the package rather than off the filesystem: the mutation sandbox
    # runs against a copied tree where a path relative to the repo root does not hold.
    jsonschema.validate(document, json.loads(read_schema("code-discovery-v1alpha1.schema.json")))


# ---------------------------------------------------------------------------------------
# The emitted artifact satisfies its own published schema
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("with_manifest", [False, True], ids=["no-manifest", "with-manifest"])
def test_the_emitted_artifact_validates_against_its_schema(with_manifest: bool) -> None:
    _validate(_review(with_manifest))


def test_the_schema_rejects_a_renamed_top_level_section() -> None:
    """`additionalProperties: false` is what makes the key names binding, so prove it holds."""

    jsonschema = pytest.importorskip("jsonschema")
    document = _review(False)
    document["SUMMARY"] = document.pop("summary")

    with pytest.raises(jsonschema.ValidationError):
        _validate(document)


def test_the_schema_rejects_a_renamed_manifest_draft_field() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    document = _review(False)
    draft = document["manifest_draft"]
    draft["NAME"] = draft.pop("name")

    with pytest.raises(jsonschema.ValidationError):
        _validate(document)


def test_the_schema_rejects_a_renamed_source_field() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    document = _review(False)
    source = document["source"]
    source["ROOT_NAME"] = source.pop("root_name")

    with pytest.raises(jsonschema.ValidationError):
        _validate(document)


# ---------------------------------------------------------------------------------------
# A tool entry's keys, which the schema does not constrain
# ---------------------------------------------------------------------------------------


def _tool_named(document: dict[str, Any], name: str) -> dict[str, Any]:
    matching = [tool for tool in document["tools"] if tool["name"] == name]
    assert len(matching) == 1, f"expected one {name}"
    return matching[0]


def test_a_classified_tool_entry_carries_exactly_the_documented_keys() -> None:
    tool = _tool_named(_review(False), "search_docs")

    assert set(tool) == {
        "name",
        "framework",
        "location",
        "proposed_action_class",
        "confidence",
        "budget_state",
        "signals",
        "proposed_capabilities",
    }
    assert set(tool["location"]) == {"file", "line"}


def test_a_refused_tool_entry_adds_its_reasons() -> None:
    tool = _tool_named(_review(False), "dispatch_action")

    assert "reasons" in tool
    assert tool["reasons"] == sorted(tool["reasons"])
    assert "proposed_capabilities" not in tool, "unknown maps to no capability"


def test_a_signal_carries_exactly_the_documented_keys() -> None:
    tool = _tool_named(_review(False), "run_maintenance")

    assert tool["signals"], "this tool is expected to have observed effects"
    for signal in tool["signals"]:
        assert set(signal) == {"action_class", "symbol", "file", "line", "via"}


def test_a_line_number_is_emitted_as_a_string() -> None:
    """SARIF and the report both consume it as text; an int here changes the artifact."""

    tool = _tool_named(_review(False), "search_docs")

    assert isinstance(tool["location"]["line"], str)
    assert tool["location"]["line"].isdigit()
    for signal in tool["signals"]:
        assert isinstance(signal["line"], str)


def test_declared_membership_appears_only_when_a_manifest_was_supplied() -> None:
    """Without a declaration there is nothing to be declared in, so the key is absent."""

    assert "declared_in_manifest" not in _tool_named(_review(False), "search_docs")
    assert _tool_named(_review(True), "search_docs")["declared_in_manifest"] is True


def test_a_tool_absent_from_the_manifest_is_marked_as_such() -> None:
    assert _tool_named(_review(True), "run_maintenance")["declared_in_manifest"] is False


# ---------------------------------------------------------------------------------------
# The summary counts, which are arithmetic on the tool list
# ---------------------------------------------------------------------------------------


def test_the_summary_counts_partition_the_discovered_tools() -> None:
    """classified + unknown must equal discovered, or the summary contradicts the tools."""

    document = _review(False)
    summary = document["summary"]
    tools = document["tools"]
    unknown = [tool for tool in tools if tool["proposed_action_class"] == "unknown"]

    assert summary["tools_discovered"] == len(tools)
    assert summary["tools_unknown"] == len(unknown)
    assert summary["tools_classified"] == len(tools) - len(unknown)
    assert summary["review_findings"] == len(document["findings"])


def test_a_review_with_findings_is_marked_for_review() -> None:
    document = _review(False)

    assert document["findings"], "this example is expected to raise at least one finding"
    assert document["summary"]["status"] == "review_required"


def test_a_review_with_no_findings_is_marked_clear(tmp_path: Path) -> None:
    """The exact word matters: `clear` is what a caller checks for."""

    (tmp_path / "agent.py").write_text(
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def widen(rows: str) -> str:\n"
        '    """Widen rows."""\n'
        "    return rows.strip()\n",
        encoding="utf-8",
    )
    document = review_code_discovery(collect_python_sources(tmp_path), None, FIXED_TIME)

    assert document["findings"] == []
    assert document["summary"]["status"] == "clear"


def test_a_file_that_failed_to_parse_is_excluded_from_the_analyzed_count(
    tmp_path: Path,
) -> None:
    """It was read and rejected, so counting it as analyzed overstates the review."""

    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def oops(:\n", encoding="utf-8")

    document = review_code_discovery(collect_python_sources(tmp_path), None, FIXED_TIME)

    assert document["source"]["files_analyzed"] == 1
    assert [finding["id"] for finding in document["findings"]] == ["TW-CODE-008"]


def test_the_artifact_records_when_it_was_generated_in_normalised_form() -> None:
    """The Z suffix is normalised to an explicit offset, so two runs compare byte for byte."""

    assert _review(False)["generated_at"] == "2026-01-01T00:00:00+00:00"
