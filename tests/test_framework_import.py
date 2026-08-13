from __future__ import annotations

from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.framework_import import normalize_framework_declaration
from trustweave.io import load_document, read_json
from trustweave.models import ValidationError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples" / "frameworks"


@pytest.mark.parametrize(
    ("framework", "filename", "expected_summary"),
    [
        (
            "langgraph",
            "langgraph.json",
            {"entry_count": 2, "agent_count": 0, "task_count": 0, "graph_count": 2},
        ),
        (
            "openai-agents",
            "openai-agents-descriptor.json",
            {"entry_count": 2, "agent_count": 2, "task_count": 0, "graph_count": 0},
        ),
        (
            "crewai",
            "crewai-crew.json",
            {"entry_count": 4, "agent_count": 2, "task_count": 2, "graph_count": 0},
        ),
    ],
)
def test_framework_imports_are_deterministic_and_static(
    framework: str, filename: str, expected_summary: dict[str, int]
) -> None:
    document = load_document(FIXTURES / filename)

    first = normalize_framework_declaration(framework, document)
    second = normalize_framework_declaration(framework, document)

    assert first == second
    assert first["summary"] == expected_summary
    assert "did not import Python modules" in first["limits"][0]
    assert "does not infer TrustWeave action classes" in first["limits"][1]


def test_framework_import_rejects_unknown_framework_duplicate_agents_and_unknown_task_agent() -> (
    None
):
    with pytest.raises(ValidationError, match="Unsupported framework"):
        normalize_framework_declaration("unknown", {})
    with pytest.raises(ValidationError, match="duplicate name"):
        normalize_framework_declaration(
            "openai-agents", {"agents": [{"name": "same"}, {"name": "same"}]}
        )
    with pytest.raises(ValidationError, match="unknown agent"):
        normalize_framework_declaration(
            "crewai",
            {"agents": [{"name": "known"}], "tasks": [{"name": "task", "agent": "missing"}]},
        )


def test_cli_framework_import_writes_local_inventory(tmp_path: Path) -> None:
    assert (
        main(
            [
                "framework-import",
                "--framework",
                "langgraph",
                "--input",
                str(FIXTURES / "langgraph.json"),
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    inventory = read_json(tmp_path / "framework-inventory.json")
    assert inventory["framework"] == "langgraph"
    assert inventory["summary"]["graph_count"] == 2
