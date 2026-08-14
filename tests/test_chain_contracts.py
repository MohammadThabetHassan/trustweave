"""Fail-closed declared-chain contract coverage."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from trustweave.chain import render_chain_review, review_declared_chains
from trustweave.models import ValidationError

ROOT = Path(__file__).resolve().parents[1]


def _chain() -> dict[str, Any]:
    return {
        "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
        "name": "coverage-chain",
        "nodes": [
            {"id": "source", "kind": "source", "trust": "untrusted"},
            {"id": "data", "kind": "data", "classification": "confidential"},
            {"id": "tool", "kind": "tool", "action_class": "read"},
            {"id": "sink", "kind": "sink", "action_class": "external"},
        ],
        "edges": [
            {"from": "source", "to": "data"},
            {"from": "data", "to": "tool"},
            {"from": "tool", "to": "sink"},
        ],
    }


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda document: document.update({"schema_version": "unsupported"}), "schema_version"),
        (lambda document: document.update({"name": ""}), "name"),
        (lambda document: document["nodes"][0].pop("trust"), "trust is required"),
        (lambda document: document["nodes"][1].pop("classification"), "classification is required"),
        (lambda document: document["nodes"][2].pop("action_class"), "action_class is required"),
        (
            lambda document: document["nodes"].append({"id": "approval", "kind": "approval"}),
            "fail_closed is required",
        ),
        (
            lambda document: document["nodes"].append({"id": "san", "kind": "sanitizer"}),
            "covers_classifications is required",
        ),
        (
            lambda document: document["nodes"][0].update({"fail_closed": True}),
            "fail_closed is not valid for source",
        ),
        (
            lambda document: document["nodes"][0].update(
                {"covers_classifications": ["restricted"]}
            ),
            "covers_classifications is not valid for source",
        ),
        (
            lambda document: document["nodes"][1].update({"action_class": "read"}),
            "not valid for data",
        ),
        (
            lambda document: document["nodes"][1].update({"trust": "untrusted"}),
            "trust is not valid for data",
        ),
        (
            lambda document: document["nodes"][2].update({"classification": "confidential"}),
            "classification is not valid for tool",
        ),
        (
            lambda document: document["nodes"][3].update({"fail_closed": True}),
            "fail_closed is not valid for sink",
        ),
        (
            lambda document: document["nodes"].append(
                {"id": "approval", "kind": "approval", "fail_closed": True, "trust": "trusted"}
            ),
            "trust is not valid for approval",
        ),
        (
            lambda document: document["nodes"].append(
                {
                    "id": "sanitizer",
                    "kind": "sanitizer",
                    "covers_classifications": ["confidential"],
                    "classification": "confidential",
                }
            ),
            "classification is not valid for sanitizer",
        ),
        (
            lambda document: document["nodes"].append(
                {
                    "id": "duplicate-coverage",
                    "kind": "sanitizer",
                    "covers_classifications": ["confidential", "confidential"],
                }
            ),
            "must not contain duplicate classifications",
        ),
        (
            lambda document: document["nodes"].append({"id": "output", "kind": "output"}),
            "kind must be one of",
        ),
        (
            lambda document: document["nodes"].append(dict(document["nodes"][0])),
            "duplicate id",
        ),
        (
            lambda document: document["edges"].append({"from": "source", "to": "unknown"}),
            "unknown declared node",
        ),
    ],
)
def test_chain_manifest_rejects_invalid_node_kind_contracts(mutate: object, message: str) -> None:
    document = copy.deepcopy(_chain())
    assert callable(mutate)
    mutate(document)

    with pytest.raises(ValidationError, match=message):
        review_declared_chains(document)


def test_chain_manifest_schema_rejects_incompatible_node_kind_fields() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "chain-manifest-v1alpha1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)

    invalid_data = _chain()
    invalid_data["nodes"][1]["trust"] = "untrusted"
    invalid_output = _chain()
    invalid_output["nodes"].append({"id": "output", "kind": "output"})

    assert list(validator.iter_errors(invalid_data))
    assert list(validator.iter_errors(invalid_output))


def test_chain_renderer_reports_absence_of_external_paths_and_findings() -> None:
    document = _chain()
    document["nodes"][3]["action_class"] = "read"

    rendered = render_chain_review(review_declared_chains(document))

    assert (
        "No path from an explicitly declared untrusted source reached an external action."
        in rendered
    )
    assert "No reviewer-facing findings were produced" in rendered


def test_chain_review_schema_validates_real_output_and_rejects_shallow_mutations() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "chain-review-v1alpha1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    review = review_declared_chains(_chain(), generated_at="2026-08-14T00:00:00+00:00", max_paths=1)

    validator.validate(review)
    malformed = copy.deepcopy(review)
    malformed["paths"] = [{}]
    malformed["summary"] = {"paths": "not-an-integer"}

    assert list(validator.iter_errors(malformed))
