from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = "a" * 64


@pytest.mark.parametrize(
    ("filename", "document"),
    [
        (
            "risk-baseline.schema.json",
            {
                "schema_version": "trustweave.dev/risk-baseline/v1alpha1",
                "baseline": [
                    {
                        "fingerprint": FINGERPRINT,
                        "reason": "Reviewed locally.",
                        "expires_at": "2027-01-01T00:00:00+00:00",
                    }
                ],
            },
        ),
        (
            "risk-suppressions.schema.json",
            {
                "schema_version": "trustweave.dev/risk-suppressions/v1alpha1",
                "suppressions": [
                    {
                        "fingerprint": FINGERPRINT,
                        "reason": "Temporarily scoped.",
                        "expires_at": "2027-01-01T00:00:00+00:00",
                    }
                ],
            },
        ),
    ],
)
def test_risk_lifecycle_schemas_validate_required_entries(
    filename: str, document: dict[str, object]
) -> None:
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    jsonschema.validate(document, schema)
    collection = "baseline" if "baseline" in document else "suppressions"
    invalid = {**document, collection: [{"fingerprint": FINGERPRINT}]}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(invalid, schema)


def test_risk_review_schema_accepts_generated_review_shape() -> None:
    schema = json.loads((ROOT / "schemas" / "risk-review.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(
        {
            "schema_version": "trustweave.dev/risk-review/v1alpha1",
            "findings": [],
            "summary": {},
            "limits": ["Local evidence only."],
        },
        schema,
    )
