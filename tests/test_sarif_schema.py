"""Conformance checks against the pinned official SARIF 2.1.0 schema."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from jsonschema import Draft4Validator

from trustweave.sarif import build_sarif

ROOT = Path(__file__).resolve().parents[1]
SARIF_SCHEMA = ROOT / "schemas" / "external" / "sarif-schema-2.1.0.json"
SARIF_SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"


def test_generated_sarif_validates_against_the_pinned_official_schema() -> None:
    """The local exporter remains conformant without network access at validation time."""

    schema_bytes = SARIF_SCHEMA.read_bytes()
    assert sha256(schema_bytes).hexdigest() == SARIF_SCHEMA_SHA256
    schema = json.loads(schema_bytes)
    Draft4Validator.check_schema(schema)
    exported = build_sarif(
        {
            "policy": (
                "artifacts/policy-review.json",
                {
                    "schema_version": "trustweave.dev/policy-review/v1alpha1",
                    "findings": [
                        {
                            "id": "TW-POL-004",
                            "severity": "review",
                            "message": "Approval control is not declared.",
                        }
                    ],
                },
            )
        }
    )

    errors = sorted(
        Draft4Validator(schema).iter_errors(exported), key=lambda error: str(error.path)
    )

    assert errors == []
