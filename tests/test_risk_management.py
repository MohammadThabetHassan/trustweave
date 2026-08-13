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
    markdown = (tmp_path / "risk-review.md").read_text(encoding="utf-8")
    assert "# TrustWeave Local Risk Review" in markdown
    assert "| new | medium | `TW-POL-004`" in markdown


def test_risk_review_accepts_bundle_diff_signals_and_preserves_input_paths() -> None:
    diff = {
        "schema_version": "trustweave.dev/bundle-diff/v1alpha1",
        "head": {"agent": "support-agent"},
        "signals": [
            {
                "id": "TW-DIFF-003",
                "severity": "review",
                "message": "Tool lookup gained a sensitive capability.",
                "subject": {"tool": "lookup", "capabilities": ["customer-record.export"]},
            }
        ],
    }

    review = review_risks(
        [diff],
        reviewed_at="2026-08-13T00:00:00+00:00",
        artifact_paths=["artifacts/bundle-diff.json"],
    )
    finding = review["findings"][0]
    assert finding["evidence_kind"] == "configuration_difference"
    assert finding["severity"] == "medium"
    assert finding["source_artifact_paths"] == ["artifacts/bundle-diff.json"]


def test_semantic_fingerprints_ignore_wording_but_preserve_distinct_subjects() -> None:
    first = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [{"id": "TW-POL-004", "severity": "review", "message": "First wording."}],
    }
    wording_update = {
        **first,
        "findings": [{"id": "TW-POL-004", "severity": "review", "message": "Second wording."}],
    }
    assert (
        normalize_findings(first)[0].fingerprint
        == normalize_findings(wording_update)[0].fingerprint
    )

    first_diff = {
        "schema_version": "trustweave.dev/bundle-diff/v1alpha1",
        "head": {"agent": "support-agent"},
        "signals": [
            {
                "id": "TW-DIFF-003",
                "severity": "review",
                "message": "Capability changed.",
                "subject": {"tool": "lookup"},
            }
        ],
    }
    second_diff = {
        **first_diff,
        "signals": [
            {
                "id": "TW-DIFF-003",
                "severity": "review",
                "message": "Capability changed.",
                "subject": {"tool": "export"},
            }
        ],
    }
    assert (
        normalize_findings(first_diff)[0].fingerprint
        != normalize_findings(second_diff)[0].fingerprint
    )


def test_risk_review_deduplicates_exact_semantic_findings_deterministically() -> None:
    artifact = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [{"id": "TW-POL-004", "severity": "review", "message": "Review A."}],
    }
    review = review_risks(
        [artifact, artifact],
        reviewed_at="2026-08-13T00:00:00+00:00",
        artifact_paths=["one.json", "two.json"],
    )
    assert review["summary"]["findings"] == 1
    assert review["findings"][0]["source_artifact_paths"] == ["one.json", "two.json"]


def test_risk_review_rejects_unsupported_artifact_contract() -> None:
    with pytest.raises(ValidationError, match="unsupported for risk review"):
        review_risks(
            [{"schema_version": "trustweave.dev/unknown/v1", "findings": []}],
            reviewed_at="2026-08-13T00:00:00+00:00",
        )


def test_risk_review_rejects_malformed_collections_subjects_and_conflicting_decisions() -> None:
    malformed_diff = {
        "schema_version": "trustweave.dev/bundle-diff/v1alpha1",
        "signals": "not-a-list",
    }
    with pytest.raises(ValidationError, match="artifact.signals must be a list"):
        review_risks([malformed_diff], reviewed_at="2026-08-13T00:00:00+00:00")

    malformed_subject = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "review",
                "message": "Review.",
                "subject": {"tool": 1},
            }
        ],
    }
    with pytest.raises(ValidationError, match="subject.tool"):
        review_risks([malformed_subject], reviewed_at="2026-08-13T00:00:00+00:00")

    artifact = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [{"id": "TW-POL-004", "severity": "review", "message": "Review."}],
    }
    fingerprint = normalize_findings(artifact)[0].fingerprint
    baseline = {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [
            {
                "fingerprint": fingerprint,
                "reason": "Reviewed baseline.",
                "expires_at": "2026-09-01T00:00:00+00:00",
            }
        ],
    }
    suppressions = {
        "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
        "suppressions": [
            {
                "fingerprint": fingerprint,
                "reason": "Conflicting suppression.",
                "expires_at": "2026-09-01T00:00:00+00:00",
            }
        ],
    }
    with pytest.raises(ValidationError, match="conflict"):
        review_risks(
            [artifact],
            baseline_document=baseline,
            suppressions_document=suppressions,
            reviewed_at="2026-08-13T00:00:00+00:00",
        )


def test_risk_normalization_derives_safe_legacy_subjects_and_selects_deterministic_wording() -> (
    None
):
    trace = {
        "schema_version": "trustweave.dev/trace-review/v1alpha1",
        "agent": "support-agent",
        "policy": "support-policy",
        "findings": [{"id": "TW-TRACE-001", "severity": "review", "message": "Trace A."}],
    }
    mcp = {
        "schema_version": "trustweave.dev/mcp-profile-review/v1alpha1",
        "profile": {"name": "support-profile"},
        "findings": [{"id": "TW-MCP-001", "severity": "review", "message": "MCP A."}],
    }
    assert normalize_findings(trace)[0].subject == {
        "agent": "support-agent",
        "policy": "support-policy",
    }
    assert normalize_findings(mcp)[0].subject == {"profile": "support-profile"}

    first = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [{"id": "TW-POL-004", "severity": "review", "message": "Zulu wording."}],
    }
    second = {
        **first,
        "findings": [{"id": "TW-POL-004", "severity": "review", "message": "Alpha wording."}],
    }
    review = review_risks(
        [first, second], reviewed_at="2026-08-13T00:00:00+00:00", artifact_paths=["a", "b"]
    )
    assert review["summary"]["findings"] == 1
    assert review["findings"][0]["message"] == "Alpha wording."


def test_risk_review_rejects_misaligned_paths_and_invalid_subject_collection() -> None:
    artifact = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [{"id": "TW-POL-004", "severity": "review", "message": "Review."}],
    }
    with pytest.raises(ValidationError, match="align"):
        review_risks([artifact], reviewed_at="2026-08-13T00:00:00+00:00", artifact_paths=["a", "b"])
    malformed_subject = {
        **artifact,
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "review",
                "message": "Review.",
                "subject": {"tools": ["one", 2]},
            }
        ],
    }
    with pytest.raises(ValidationError, match="only strings"):
        review_risks([malformed_subject], reviewed_at="2026-08-13T00:00:00+00:00")
