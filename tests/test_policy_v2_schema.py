from __future__ import annotations

import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def test_policy_v1alpha2_schema_accepts_the_versioned_contract_shape() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "policy-v1alpha2.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(
        {
            "schema_version": "trustweave.dev/policy/v1alpha2",
            "name": "example",
            "default_decision": "deny",
            "classification_taxonomy": ["public", "restricted"],
            "rules": [],
        },
        schema,
    )
