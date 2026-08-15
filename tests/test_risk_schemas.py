from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from trustweave.risk import review_risks

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


def test_risk_review_schema_requires_generated_lifecycle_summary_shape() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "risk-review-v1alpha2.schema.json").read_text(encoding="utf-8")
    )
    review = review_risks([], reviewed_at="2026-08-14T00:00:00+00:00")
    jsonschema.validate(review, schema)

    invalid = {**review, "summary": {}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(invalid, schema)


def test_risk_review_schema_accepts_generated_v3_normalized_finding() -> None:
    """Strict risk schemas must cover every emitted normalized finding field."""

    schema = json.loads(
        (ROOT / "schemas" / "risk-review-v1alpha2.schema.json").read_text(encoding="utf-8")
    )
    review = review_risks(
        [
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "policy": "support-policy",
                "findings": [
                    {
                        "id": "TW-POL-004",
                        "severity": "high",
                        "message": "A declared control requires review.",
                        "subject": {"source": "customer_request", "tool": "lookup"},
                    }
                ],
            }
        ],
        reviewed_at="2026-08-14T00:00:00+00:00",
    )
    jsonschema.validate(review, schema)
