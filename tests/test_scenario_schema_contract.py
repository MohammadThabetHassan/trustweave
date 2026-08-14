"""Strict public schema regressions for synthetic scenario packs."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_scenario_pack_schema_rejects_empty_scenario_object() -> None:
    """Scenario-pack schemas must require every scenario's decision-contract fields."""

    schema = json.loads(
        (ROOT / "schemas" / "scenario-pack-v1alpha1.schema.json").read_text(encoding="utf-8")
    )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "schema_version": "trustweave.dev/v1alpha1",
                "name": "example",
                "scenarios": [{}],
            },
            schema,
        )
