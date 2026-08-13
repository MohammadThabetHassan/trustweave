from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import EXIT_REVIEW, EXIT_SUCCESS, main
from trustweave.models import ValidationError
from trustweave.risk import (
    RISK_BASELINE_SCHEMA_VERSION,
    RISK_SUPPRESSIONS_SCHEMA_VERSION,
    normalize_findings,
    review_risks,
    should_fail,
)


@pytest.fixture
def review_artifact() -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "review",
                "message": "An approval control must be reviewed.",
            }
        ],
    }


def test_findings_have_stable_fingerprints_and_legacy_review_severity_is_normalized(
    review_artifact: dict[str, object],
) -> None:
    first = normalize_findings(review_artifact)
    second = normalize_findings(json.loads(json.dumps(review_artifact)))

    assert first == second
    assert first[0].severity == "medium"
    assert len(first[0].fingerprint) == 64


def test_baseline_and_suppression_expiry_are_enforced(
    review_artifact: dict[str, object],
) -> None:
    fingerprint = normalize_findings(review_artifact)[0].fingerprint
    baseline = {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [
            {
                "fingerprint": fingerprint,
                "reason": "Accepted until the approval-control rollout completes.",
                "expires_at": "2026-09-01T00:00:00+00:00",
            }
        ],
    }
    clear = review_risks(
        [review_artifact], baseline_document=baseline, reviewed_at="2026-08-13T00:00:00+00:00"
    )
    assert clear["findings"][0]["risk_state"] == "baselined"
    assert clear["summary"]["status"] == "clear"
    assert not should_fail(clear, "medium")

    baseline["baseline"][0]["expires_at"] = "2026-08-01T00:00:00+00:00"
    expired = review_risks(
        [review_artifact], baseline_document=baseline, reviewed_at="2026-08-13T00:00:00+00:00"
    )
    assert expired["findings"][0]["risk_state"] == "expired_baseline"
    assert should_fail(expired, "medium")

    suppressions = {
        "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
        "suppressions": [
            {
                "fingerprint": fingerprint,
                "reason": "Temporary local review exemption with an explicit expiry.",
                "expires_at": "2026-09-01T00:00:00+00:00",
            }
        ],
    }
    suppressed = review_risks(
        [review_artifact],
        suppressions_document=suppressions,
        reviewed_at="2026-08-13T00:00:00+00:00",
    )
    assert suppressed["findings"][0]["risk_state"] == "suppressed"


def test_risk_contract_rejects_missing_reason_duplicate_or_invalid_expiry(
    review_artifact: dict[str, object],
) -> None:
    fingerprint = normalize_findings(review_artifact)[0].fingerprint
    malformed = {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [{"fingerprint": fingerprint, "expires_at": "not-a-date"}],
    }
    with pytest.raises(ValidationError, match="unknown field|reason"):
        review_risks(
            [review_artifact], baseline_document=malformed, reviewed_at="2026-08-13T00:00:00+00:00"
        )


def test_risk_check_cli_writes_review_and_applies_fail_on(tmp_path: Path) -> None:
    artifact_path = tmp_path / "policy-review.json"
    artifact_path.write_text(
        json.dumps(
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [
                    {"id": "TW-POL-004", "severity": "review", "message": "Review required."}
                ],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "risk-review.json"
    arguments = [
        "--generated-at",
        "2026-08-13T00:00:00+00:00",
        "risk-check",
        "--input",
        str(artifact_path),
        "--output",
        str(output_path),
    ]
    assert main([*arguments, "--fail-on", "high"]) == EXIT_SUCCESS
    assert main([*arguments, "--fail-on", "medium"]) == EXIT_REVIEW
    assert json.loads(output_path.read_text(encoding="utf-8"))["summary"]["new"] == 1
