from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.chain import review_declared_chains
from trustweave.cli import main
from trustweave.models import ValidationError


def _document(nodes: list[dict[str, object]], edges: list[dict[str, str]]) -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
        "name": "declared-chain",
        "nodes": nodes,
        "edges": edges,
    }


def _unsafe_nodes() -> list[dict[str, object]]:
    return [
        {"id": "inbox", "kind": "source", "trust": "untrusted"},
        {"id": "records", "kind": "data", "classification": "confidential"},
        {"id": "email", "kind": "tool", "action_class": "external"},
    ]


def test_chain_manifest_rejects_incompatible_node_fields() -> None:
    document = _document(_unsafe_nodes(), [])
    source = document["nodes"][0]
    assert isinstance(source, dict)
    source["action_class"] = "external"
    with pytest.raises(ValidationError, match="not valid for source"):
        review_declared_chains(document)

    document = _document(_unsafe_nodes(), [])
    data = document["nodes"][1]
    assert isinstance(data, dict)
    data.pop("classification")
    with pytest.raises(ValidationError, match="classification is required"):
        review_declared_chains(document)


def test_chain_review_reports_only_explicitly_declared_unsafe_path() -> None:
    review = review_declared_chains(
        _document(
            _unsafe_nodes(),
            [{"from": "inbox", "to": "records"}, {"from": "records", "to": "email"}],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert [item["id"] for item in review["findings"]] == ["TW-CHAIN-001", "TW-CHAIN-002"]
    assert review["findings"][0]["subject"] == {"path": ["inbox", "records", "email"]}


def test_chain_review_respects_declared_fail_closed_approval_and_reports_incomplete_sanitizer() -> (
    None
):
    nodes = _unsafe_nodes() + [
        {"id": "approval", "kind": "approval", "fail_closed": True},
        {"id": "redactor", "kind": "sanitizer", "covers_classifications": ["internal"]},
    ]
    review = review_declared_chains(
        _document(
            nodes,
            [
                {"from": "inbox", "to": "records"},
                {"from": "records", "to": "approval"},
                {"from": "approval", "to": "redactor"},
                {"from": "redactor", "to": "email"},
            ],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert [item["id"] for item in review["findings"]] == ["TW-CHAIN-001", "TW-CHAIN-003"]


def test_chain_check_cli_writes_local_json_and_markdown(tmp_path: Path) -> None:
    input_path = tmp_path / "chain.json"
    input_path.write_text(
        json.dumps(
            _document(
                _unsafe_nodes(),
                [{"from": "inbox", "to": "records"}, {"from": "records", "to": "email"}],
            )
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "artifacts"
    assert main(["chain-check", "--input", str(input_path), "--output-dir", str(output_dir)]) == 0
    assert (output_dir / "chain-review.json").is_file()
    assert "TW-CHAIN-001" in (output_dir / "chain-review.md").read_text(encoding="utf-8")


def test_chain_traversal_terminates_at_declared_external_action() -> None:
    review = review_declared_chains(
        _document(
            _unsafe_nodes(),
            [
                {"from": "inbox", "to": "records"},
                {"from": "records", "to": "email"},
                {"from": "email", "to": "records"},
            ],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert review["paths"] == [{"identity": ["inbox", "records", "email"]}]


def test_chain_review_handles_cycles_and_reports_budget_limits() -> None:
    cyclic = review_declared_chains(
        _document(
            _unsafe_nodes(),
            [
                {"from": "inbox", "to": "records"},
                {"from": "records", "to": "email"},
                {"from": "email", "to": "records"},
            ],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert cyclic["paths"] == [{"identity": ["inbox", "records", "email"]}]

    budgeted = review_declared_chains(
        _document(_unsafe_nodes(), []),
        generated_at="2026-08-13T00:00:00+00:00",
        max_nodes=2,
    )
    assert budgeted["findings"][0]["id"] == "TW-CHAIN-004"
