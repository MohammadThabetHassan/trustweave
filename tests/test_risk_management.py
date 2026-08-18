from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

import trustweave.risk as risk_module
from trustweave.cli import EXIT_REVIEW, EXIT_SUCCESS, main
from trustweave.io import canonical_json
from trustweave.models import ValidationError
from trustweave.risk import (
    RISK_BASELINE_SCHEMA_VERSION,
    RISK_REVIEW_SCHEMA_VERSION,
    RISK_SUPPRESSIONS_SCHEMA_VERSION,
    create_baseline,
    normalize_findings,
    review_risks,
    should_fail,
    validate_decision_document,
)


def _decision_entry(
    finding: object,
    *,
    reason: str = "Explicit temporary local decision.",
    expires_at: str = "2026-09-01T00:00:00+00:00",
    accepted_severity: str | None = None,
) -> dict[str, str]:
    normalized = finding
    assert hasattr(normalized, "as_dict")
    document = normalized.as_dict()
    return {
        "fingerprint": str(document["fingerprint"]),
        "fingerprint_schema_version": "trustweave/fingerprint/v3",
        "rule_id": str(document["id"]),
        "subject_digest": sha256(canonical_json(document["subject"]).encode("utf-8")).hexdigest(),
        "accepted_severity": accepted_severity or str(document["severity"]),
        "reason": reason,
        "owner": "security-review",
        "created_at": "2026-08-14T00:00:00+00:00",
        "expires_at": expires_at,
    }


def _orphaned_decision(fingerprint: str) -> dict[str, str]:
    return {
        "fingerprint": fingerprint,
        "fingerprint_schema_version": "trustweave/fingerprint/v3",
        "rule_id": "TW-ORPHAN-001",
        "subject_digest": "a" * 64,
        "accepted_severity": "low",
        "reason": "Explicit orphaned local decision.",
        "owner": "security-review",
        "created_at": "2026-08-14T00:00:00+00:00",
        "expires_at": "2026-09-01T00:00:00+00:00",
    }


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


def test_risk_normalization_rejects_invalid_subjects_and_severities() -> None:
    artifact = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "findings": [{"id": "TW-RISK-001", "severity": "invalid", "message": "Test."}],
    }
    with pytest.raises(ValidationError, match="must be one of"):
        normalize_findings(artifact)

    artifact["findings"][0]["severity"] = "high"
    artifact["findings"][0]["subject"] = {"path": ["valid", 1]}
    with pytest.raises(ValidationError, match="only strings"):
        normalize_findings(artifact)


def test_baseline_and_suppression_expiry_are_enforced(
    review_artifact: dict[str, object],
) -> None:
    normalized = normalize_findings(review_artifact)[0]
    baseline = {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [
            _decision_entry(
                normalized,
                reason="Accepted until the approval-control rollout completes.",
            )
        ],
    }
    clear = review_risks(
        [review_artifact], baseline_document=baseline, reviewed_at="2026-08-15T00:00:00+00:00"
    )
    assert clear["findings"][0]["risk_state"] == "baselined"
    assert clear["summary"]["status"] == "clear"
    assert not should_fail(clear, "medium")

    baseline["baseline"][0]["expires_at"] = "2026-08-14T12:00:00+00:00"
    expired = review_risks(
        [review_artifact], baseline_document=baseline, reviewed_at="2026-08-15T00:00:00+00:00"
    )
    assert expired["findings"][0]["risk_state"] == "expired_baseline"
    assert should_fail(expired, "medium")

    suppressions = {
        "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
        "suppressions": [
            _decision_entry(
                normalized,
                reason="Temporary local review exemption with an explicit expiry.",
            )
        ],
    }
    suppressed = review_risks(
        [review_artifact],
        suppressions_document=suppressions,
        reviewed_at="2026-08-15T00:00:00+00:00",
    )
    assert suppressed["findings"][0]["risk_state"] == "suppressed"


def test_future_created_decision_does_not_apply_to_earlier_review(
    review_artifact: dict[str, object],
) -> None:
    """A decision cannot become applicable before its recorded creation instant."""

    normalized = normalize_findings(review_artifact)[0]
    entry = _decision_entry(normalized)
    entry["created_at"] = "2027-01-01T00:00:00+00:00"
    entry["expires_at"] = "2027-02-01T00:00:00+00:00"
    review = review_risks(
        [review_artifact],
        baseline_document={"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [entry]},
        reviewed_at="2026-08-15T00:00:00+00:00",
    )

    assert review["schema_version"] == "trustweave.dev/risk-review/v1alpha2"
    assert review["findings"][0]["risk_state"] == "not_yet_applicable_baseline"
    assert review["summary"]["not_yet_applicable_baseline"] == 1
    assert review["summary"]["status"] == "review_required"

    suppressed = review_risks(
        [review_artifact],
        suppressions_document={
            "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
            "suppressions": [entry],
        },
        reviewed_at="2026-08-15T00:00:00+00:00",
    )
    assert suppressed["findings"][0]["risk_state"] == "not_yet_applicable_suppression"
    assert suppressed["summary"]["not_yet_applicable_suppression"] == 1
    assert suppressed["summary"]["status"] == "review_required"


def test_baseline_does_not_mask_severity_escalation() -> None:
    """A severity-independent fingerprint must not make severity acceptance indefinite."""

    low = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "low",
                "message": "A low-severity local condition requires review.",
                "subject": {"source": "customer_request", "tool": "lookup"},
            }
        ],
    }
    critical = {
        **low,
        "findings": [{**low["findings"][0], "severity": "critical"}],
    }
    normalized_low = normalize_findings(low)[0]
    baseline = {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [
            _decision_entry(
                normalized_low,
                reason="Accepted only while the finding is low severity.",
                accepted_severity="low",
            )
        ],
    }

    review = review_risks(
        [critical],
        baseline_document=baseline,
        reviewed_at="2026-08-14T00:00:00+00:00",
    )

    assert review["findings"][0]["risk_state"] == "severity_escalated_baseline"
    assert review["summary"]["severity_escalated_baseline"] == 1
    assert review["summary"]["status"] == "review_required"
    assert should_fail(review, "critical")


def test_risk_review_reports_orphaned_local_decisions(
    review_artifact: dict[str, object],
) -> None:
    normalized = normalize_findings(review_artifact)[0]
    orphaned = "a" * 64
    review = review_risks(
        [review_artifact],
        baseline_document={
            "schema_version": RISK_BASELINE_SCHEMA_VERSION,
            "baseline": [
                _decision_entry(normalized, reason="Known local review decision."),
                _orphaned_decision(orphaned),
            ],
        },
        suppressions_document={
            "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
            "suppressions": [_orphaned_decision("b" * 64)],
        },
        reviewed_at="2026-08-13T00:00:00+00:00",
    )

    assert review["summary"]["orphaned_baseline"] == 1
    assert review["summary"]["orphaned_suppressions"] == 1
    assert review["orphaned_decisions"] == {
        "baseline": [orphaned],
        "suppressions": ["b" * 64],
    }


def test_risk_contract_rejects_missing_reason_duplicate_or_invalid_expiry(
    review_artifact: dict[str, object],
) -> None:
    fingerprint = normalize_findings(review_artifact)[0].fingerprint
    malformed = {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [{"fingerprint": fingerprint, "expires_at": "not-a-date"}],
    }
    with pytest.raises(ValidationError, match="fingerprint_schema_version"):
        review_risks(
            [review_artifact], baseline_document=malformed, reviewed_at="2026-08-13T00:00:00+00:00"
        )


def test_risk_lifecycle_rejects_missing_time_misaligned_paths_conflicts_and_invalid_decision_kind(
    review_artifact: dict[str, object],
) -> None:
    normalized = normalize_findings(review_artifact)[0]
    decision = {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [_decision_entry(normalized)],
    }
    with pytest.raises(ValidationError, match="reviewed_at must be supplied"):
        review_risks([review_artifact])
    with pytest.raises(ValidationError, match="align one-to-one"):
        review_risks(
            [review_artifact],
            reviewed_at="2026-08-14T00:00:00+00:00",
            artifact_paths=[],
        )
    with pytest.raises(ValidationError, match="conflict"):
        review_risks(
            [review_artifact],
            baseline_document=decision,
            suppressions_document={
                "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
                "suppressions": [_decision_entry(normalized, reason="Conflicting local decision.")],
            },
            reviewed_at="2026-08-14T00:00:00+00:00",
        )
    with pytest.raises(ValidationError, match="decision_kind"):
        validate_decision_document(decision, "unsupported")


def test_v1alpha2_decisions_fail_closed_on_mismatch_expiry_escalation_and_legacy_contracts(
    review_artifact: dict[str, object],
) -> None:
    """Decision identity, severity, expiry, and legacy semantics all remain reviewer-visible."""

    normalized = normalize_findings(review_artifact)[0]
    accepted = _decision_entry(normalized, accepted_severity="medium")
    baseline = {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [accepted]}
    assert (
        review_risks(
            [review_artifact], baseline_document=baseline, reviewed_at="2026-08-15T00:00:00+00:00"
        )["findings"][0]["risk_state"]
        == "baselined"
    )

    mismatched = {**accepted, "rule_id": "TW-POL-999"}
    assert (
        review_risks(
            [review_artifact],
            baseline_document={
                "schema_version": RISK_BASELINE_SCHEMA_VERSION,
                "baseline": [mismatched],
            },
            reviewed_at="2026-08-15T00:00:00+00:00",
        )["findings"][0]["risk_state"]
        == "new"
    )

    expired = {**accepted, "expires_at": "2026-08-14T12:00:00+00:00"}
    assert (
        review_risks(
            [review_artifact],
            suppressions_document={
                "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
                "suppressions": [expired],
            },
            reviewed_at="2026-08-15T00:00:00+00:00",
        )["findings"][0]["risk_state"]
        == "expired_suppression"
    )

    invalid_rule_id = {**accepted, "rule_id": "BAD"}
    with pytest.raises(ValidationError, match="rule_id"):
        validate_decision_document(
            {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [invalid_rule_id]},
            "baseline",
        )

    with pytest.raises(ValidationError, match="requires explicit migration"):
        validate_decision_document(
            {"schema_version": "trustweave.dev/risk-baseline/v1alpha1", "baseline": []},
            "baseline",
        )


def test_create_baseline_binds_command_provenance_and_optional_reference() -> None:
    artifact = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "high",
                "message": "A declared condition requires review.",
                "subject": {"tool": "lookup"},
            }
        ],
    }
    review = review_risks([artifact], reviewed_at="2026-08-14T00:00:00+00:00")
    baseline = create_baseline(
        review,
        "Explicit review decision.",
        "2026-09-01T00:00:00+00:00",
        owner="security-review",
        created_at="2026-08-14T00:00:00+00:00",
        reference="TICKET-42",
    )
    assert baseline["baseline"][0]["reference"] == "TICKET-42"
    assert baseline["baseline"][0]["accepted_severity"] == "high"


def test_create_baseline_rejects_invalid_provenance_and_incomplete_active_findings() -> None:
    base = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-14T00:00:00+00:00",
        "findings": [
            {
                "fingerprint": "a" * 64,
                "fingerprint_schema_version": "trustweave/fingerprint/v3",
                "id": "TW-POL-004",
                "severity": "high",
                "subject": {"tool": "lookup"},
                "risk_state": "new",
            }
        ],
    }
    arguments = {
        "owner": "security-review",
        "created_at": "2026-08-14T00:00:00+00:00",
    }
    with pytest.raises(ValidationError, match="schema_version"):
        create_baseline(
            {**base, "schema_version": "invalid"},
            "Reason.",
            "2026-09-01T00:00:00+00:00",
            **arguments,
        )
    with pytest.raises(ValidationError, match="must not precede"):
        create_baseline(
            base,
            "Reason.",
            "2026-09-01T00:00:00+00:00",
            owner="security-review",
            created_at="2026-08-13T00:00:00+00:00",
        )
    incomplete = {**base, "findings": [{**base["findings"][0], "subject": {}}]}
    with pytest.raises(ValidationError, match="must bind"):
        create_baseline(incomplete, "Reason.", "2026-09-01T00:00:00+00:00", **arguments)
    inactive = {**base, "findings": [{**base["findings"][0], "risk_state": "baselined"}]}
    assert (
        create_baseline(inactive, "Reason.", "2026-09-01T00:00:00+00:00", **arguments)["baseline"]
        == []
    )
    invalid_fingerprint = {**base, "findings": [{**base["findings"][0], "fingerprint": "z"}]}
    with pytest.raises(ValidationError, match="SHA-256"):
        create_baseline(invalid_fingerprint, "Reason.", "2026-09-01T00:00:00+00:00", **arguments)
    invalid_version = {
        **base,
        "findings": [{**base["findings"][0], "fingerprint_schema_version": "unknown"}],
    }
    with pytest.raises(ValidationError, match="fingerprint_schema_version"):
        create_baseline(invalid_version, "Reason.", "2026-09-01T00:00:00+00:00", **arguments)


def test_risk_gate_rejects_invalid_severity_and_supports_none(
    review_artifact: dict[str, object],
) -> None:
    review = review_risks([review_artifact], reviewed_at="2026-08-14T00:00:00+00:00")
    assert not should_fail(review, "none")
    assert should_fail({"findings": [{"risk_state": "new", "severity": "info"}]}, "review")
    assert should_fail(
        {"findings": [{"risk_state": "expired_baseline", "severity": "low"}]}, "review"
    )
    assert not should_fail(
        {"findings": [{"risk_state": "baselined", "severity": "info"}]}, "review"
    )
    with pytest.raises(ValidationError, match="fail_on"):
        should_fail(review, "invalid")


def test_baseline_creation_rejects_expiry_before_review_timestamp() -> None:
    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-14T12:00:00+00:00",
        "findings": [{"fingerprint": "a" * 64, "risk_state": "new"}],
    }

    with pytest.raises(ValidationError, match="later than created_at"):
        create_baseline(
            review,
            "Explicit local reviewer decision.",
            "2026-08-14T11:59:59+00:00",
            owner="security-review",
            created_at="2026-08-14T12:00:00+00:00",
        )


def test_baseline_create_and_decision_validation_commands_are_explicit_and_local(
    tmp_path: Path,
) -> None:
    review_path = tmp_path / "risk-review.json"
    review_path.write_text(
        json.dumps(
            {
                "schema_version": RISK_REVIEW_SCHEMA_VERSION,
                "generated_at": "2026-08-14T00:00:00+00:00",
                "findings": [
                    {
                        "fingerprint": "a" * 64,
                        "fingerprint_schema_version": "trustweave/fingerprint/v3",
                        "id": "TW-POL-004",
                        "severity": "high",
                        "subject": {"tool": "lookup"},
                        "risk_state": "new",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    baseline_path = tmp_path / "baseline.json"
    assert (
        main(
            [
                "--generated-at",
                "2026-08-14T00:00:00+00:00",
                "baseline",
                "create",
                "--review",
                str(review_path),
                "--reason",
                "Explicit local reviewer decision.",
                "--expires-at",
                "2026-09-01T00:00:00+00:00",
                "--owner",
                "security-review",
                "--output",
                str(baseline_path),
            ]
        )
        == EXIT_SUCCESS
    )
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    entry = baseline["baseline"][0]
    assert entry["fingerprint"] == "a" * 64
    assert entry["fingerprint_schema_version"] == "trustweave/fingerprint/v3"
    assert entry["accepted_severity"] == "high"
    assert entry["owner"] == "security-review"
    assert entry["created_at"] == "2026-08-14T00:00:00+00:00"
    assert entry["expires_at"] == "2026-09-01T00:00:00+00:00"
    assert main(["baseline", "validate", "--input", str(baseline_path)]) == EXIT_SUCCESS

    suppressions_path = tmp_path / "suppressions.json"
    suppressions_path.write_text(
        json.dumps(
            {
                "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
                "suppressions": [],
            }
        ),
        encoding="utf-8",
    )
    assert main(["suppressions", "validate", "--input", str(suppressions_path)]) == EXIT_SUCCESS


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
    normalized = normalize_findings(artifact)[0]
    baseline = {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [_decision_entry(normalized, reason="Reviewed baseline.")],
    }
    suppressions = {
        "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
        "suppressions": [_decision_entry(normalized, reason="Conflicting suppression.")],
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


def test_risk_normalization_preserves_ordered_chain_path_identity() -> None:
    forward = {
        "schema_version": "trustweave.dev/chain-review/v1alpha1",
        "findings": [
            {
                "id": "TW-CHAIN-001",
                "severity": "high",
                "message": "A declared path requires review.",
                "subject": {"path": ["source", "data", "sink"]},
            }
        ],
    }
    reverse = {
        **forward,
        "findings": [
            {
                **forward["findings"][0],
                "subject": {"path": ["sink", "data", "source"]},
            }
        ],
    }

    normalized_forward = normalize_findings(forward)[0]
    normalized_reverse = normalize_findings(reverse)[0]

    assert normalized_forward.subject == {"path": ("source", "data", "sink")}
    assert normalized_reverse.subject == {"path": ("sink", "data", "source")}
    assert normalized_forward.fingerprint != normalized_reverse.fingerprint


def test_normalized_risk_finding_subject_is_deeply_immutable() -> None:
    artifact = {
        "schema_version": "trustweave.dev/chain-review/v1alpha1",
        "findings": [
            {
                "id": "TW-CHAIN-001",
                "severity": "high",
                "message": "A declared path requires review.",
                "subject": {"path": ["source", "data", "sink"]},
            }
        ],
    }

    normalized = normalize_findings(artifact)[0]
    artifact["findings"][0]["subject"]["path"].append("mutated")

    assert normalized.as_dict()["subject"] == {"path": ["source", "data", "sink"]}
    with pytest.raises(TypeError):
        normalized.subject["path"] = ("mutated",)


def test_risk_deduplication_retains_highest_severity_independent_of_wording_and_order() -> None:
    """Equivalent findings must retain the most severe observed review state."""

    low = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "low",
                "message": "Alpha wording must not downgrade the finding.",
                "subject": {"source": "customer_request", "tool": "lookup"},
            }
        ],
    }
    critical = {
        **low,
        "findings": [
            {
                **low["findings"][0],
                "severity": "critical",
                "message": "Zulu wording records the critical condition.",
            }
        ],
    }

    first = review_risks(
        [low, critical],
        reviewed_at="2026-08-14T00:00:00+00:00",
        artifact_paths=["low.json", "critical.json"],
    )
    second = review_risks(
        [critical, low],
        reviewed_at="2026-08-14T00:00:00+00:00",
        artifact_paths=["critical.json", "low.json"],
    )

    assert first == second
    assert first["findings"][0]["severity"] == "critical"
    assert first["findings"][0]["source_artifact_paths"] == ["critical.json", "low.json"]
    assert should_fail(first, "critical")


def test_risk_deduplication_aggregates_paths_and_selects_equal_severity_presentation() -> None:
    """Deduplication keeps every artifact path and deterministically selects tied text."""

    base = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "critical",
                "message": "Zulu message.",
                "title": "Zulu title.",
                "rationale": "Zulu rationale.",
                "remediation": "Zulu remediation.",
                "subject": {"source": "customer_request", "tool": "lookup"},
            }
        ],
    }
    selected = {
        **base,
        "findings": [
            {
                **base["findings"][0],
                "message": "Alpha message.",
                "title": "Alpha title.",
                "rationale": "Alpha rationale.",
                "remediation": "Alpha remediation.",
            }
        ],
    }
    legacy_review = {
        **base,
        "findings": [{**base["findings"][0], "severity": "review"}],
    }

    first = review_risks(
        [base, selected, legacy_review],
        reviewed_at="2026-08-14T00:00:00+00:00",
        artifact_paths=["shared.json", "different.json", "shared.json"],
    )
    second = review_risks(
        [legacy_review, selected, base],
        reviewed_at="2026-08-14T00:00:00+00:00",
        artifact_paths=["shared.json", "different.json", "shared.json"],
    )

    finding = first["findings"][0]
    assert first == second
    assert canonical_json(first) == canonical_json(second)
    assert finding["severity"] == "critical"
    assert finding["title"] == "Alpha title."
    assert finding["message"] == "Alpha message."
    assert finding["rationale"] == "Alpha rationale."
    assert finding["remediation"] == "Alpha remediation."
    assert finding["source_artifact_paths"] == ["different.json", "shared.json"]


def test_risk_deduplication_rejects_contradictory_stable_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fingerprint collision cannot silently discard a different stable subject."""

    first = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "high",
                "message": "First finding.",
                "subject": {"tool": "lookup"},
            }
        ],
    }
    contradictory = {
        **first,
        "findings": [{**first["findings"][0], "subject": {"tool": "export"}}],
    }
    monkeypatch.setattr(risk_module, "_fingerprint", lambda *_: "a" * 64)

    with pytest.raises(ValidationError, match="contradictory stable metadata"):
        review_risks(
            [first, contradictory],
            reviewed_at="2026-08-14T00:00:00+00:00",
        )


def test_v3_fingerprints_preserve_identity_across_severity_changes() -> None:
    """Severity is review state, not the stable identity of the affected finding."""

    low = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "low",
                "message": "A local policy condition requires review.",
                "subject": {"source": "customer_request", "tool": "lookup"},
            }
        ],
    }
    high = {
        **low,
        "findings": [{**low["findings"][0], "severity": "high"}],
    }

    normalized_low = normalize_findings(low)[0]
    normalized_high = normalize_findings(high)[0]
    assert normalized_low.fingerprint == normalized_high.fingerprint
    assert normalized_low.severity == "low"
    assert normalized_high.severity == "high"


def test_risk_review_reports_fingerprint_matched_decisions_with_incompatible_identity(
    review_artifact: dict[str, object],
) -> None:
    """A decision that collides on fingerprint must be visible rather than silently discarded."""

    normalized = normalize_findings(review_artifact)[0]
    mismatched_baseline = {**_decision_entry(normalized), "rule_id": "TW-POL-999"}
    mismatched_suppression = {
        **_decision_entry(normalized),
        "subject_digest": "f" * 64,
    }

    baseline_review = review_risks(
        [review_artifact],
        baseline_document={
            "schema_version": RISK_BASELINE_SCHEMA_VERSION,
            "baseline": [mismatched_baseline],
        },
        reviewed_at="2026-08-15T00:00:00+00:00",
    )
    suppression_review = review_risks(
        [review_artifact],
        suppressions_document={
            "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
            "suppressions": [mismatched_suppression],
        },
        reviewed_at="2026-08-15T00:00:00+00:00",
    )

    assert baseline_review["findings"][0]["risk_state"] == "new"
    assert suppression_review["findings"][0]["risk_state"] == "new"
    assert baseline_review["mismatched_decisions"] == {
        "baseline": [
            {
                "fingerprint": normalized.fingerprint,
                "mismatches": ["rule_id"],
            }
        ],
        "suppressions": [],
    }
    assert suppression_review["mismatched_decisions"] == {
        "baseline": [],
        "suppressions": [
            {
                "fingerprint": normalized.fingerprint,
                "mismatches": ["subject_digest"],
            }
        ],
    }
    assert baseline_review["summary"]["mismatched_baseline"] == 1
    assert suppression_review["summary"]["mismatched_suppressions"] == 1


def test_risk_review_preserves_absolute_artifact_paths_with_spaces_for_schema_parity() -> None:
    """The review schema must accept the runtime's literal local artifact provenance path."""

    artifact = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "high",
                "message": "A declared control requires review.",
                "subject": {"tool": "lookup"},
            }
        ],
    }
    review = review_risks(
        [artifact],
        reviewed_at="2026-08-15T00:00:00+00:00",
        artifact_paths=["/workspace/release artifacts/policy review.json"],
    )

    assert review["findings"][0]["source_artifact_paths"] == [
        "/workspace/release artifacts/policy review.json"
    ]


def test_risk_review_preserves_decision_lifecycle_metadata_and_exact_summary(
    review_artifact: dict[str, object],
) -> None:
    """Applied and unusable reviewer decisions remain distinguishable local evidence."""

    normalized = normalize_findings(review_artifact)[0]
    accepted = _decision_entry(
        normalized,
        reason="Accepted local baseline for a bounded declared approval review.",
        expires_at="2026-09-01T00:00:00+00:00",
    )
    applied = review_risks(
        [review_artifact],
        baseline_document={"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [accepted]},
        reviewed_at="2026-08-15T00:00:00+00:00",
        artifact_paths=["/workspace/release artifacts/policy review.json"],
    )

    finding = applied["findings"][0]
    assert applied["schema_version"] == RISK_REVIEW_SCHEMA_VERSION
    assert finding["risk_state"] == "baselined"
    assert finding["reason"] == accepted["reason"]
    assert finding["expires_at"] == accepted["expires_at"]
    assert finding["source_artifact_paths"] == ["/workspace/release artifacts/policy review.json"]
    assert applied["summary"] == {
        "findings": 1,
        "new": 0,
        "baselined": 1,
        "suppressed": 0,
        "expired_baseline": 0,
        "expired_suppression": 0,
        "not_yet_applicable_baseline": 0,
        "not_yet_applicable_suppression": 0,
        "severity_escalated_baseline": 0,
        "severity_escalated_suppression": 0,
        "orphaned_baseline": 0,
        "orphaned_suppressions": 0,
        "mismatched_baseline": 0,
        "mismatched_suppressions": 0,
        "active_by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "status": "clear",
    }
    assert not should_fail(applied, "review")

    expired = {
        **accepted,
        "created_at": "2026-08-01T00:00:00+00:00",
        "expires_at": "2026-08-14T00:00:00+00:00",
    }
    expired_review = review_risks(
        [review_artifact],
        baseline_document={"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [expired]},
        reviewed_at="2026-08-15T00:00:00+00:00",
    )
    assert expired_review["findings"][0]["risk_state"] == "expired_baseline"
    assert expired_review["findings"][0]["reason"] == accepted["reason"]
    assert expired_review["summary"]["expired_baseline"] == 1
    assert should_fail(expired_review, "review")

    future = {
        **accepted,
        "created_at": "2026-08-16T00:00:00+00:00",
        "expires_at": "2026-09-01T00:00:00+00:00",
    }
    future_review = review_risks(
        [review_artifact],
        baseline_document={"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [future]},
        reviewed_at="2026-08-15T00:00:00+00:00",
    )
    assert future_review["findings"][0]["risk_state"] == "not_yet_applicable_baseline"
    assert "reason" not in future_review["findings"][0]
    assert future_review["summary"]["not_yet_applicable_baseline"] == 1
    assert should_fail(future_review, "review")

    mismatch = {**accepted, "rule_id": "TW-POL-999"}
    mismatch_review = review_risks(
        [review_artifact],
        baseline_document={"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [mismatch]},
        reviewed_at="2026-08-15T00:00:00+00:00",
    )
    assert mismatch_review["findings"][0]["risk_state"] == "new"
    assert mismatch_review["mismatched_decisions"] == {
        "baseline": [{"fingerprint": accepted["fingerprint"], "mismatches": ["rule_id"]}],
        "suppressions": [],
    }
    assert mismatch_review["summary"]["mismatched_baseline"] == 1

    suppression = _decision_entry(
        normalized,
        reason="Temporary local suppression while a declared exception is reviewed.",
    )
    suppressed_review = review_risks(
        [review_artifact],
        suppressions_document={
            "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
            "suppressions": [suppression],
        },
        reviewed_at="2026-08-15T00:00:00+00:00",
    )
    assert suppressed_review["findings"][0]["risk_state"] == "suppressed"
    assert suppressed_review["findings"][0]["reason"] == suppression["reason"]
    assert suppressed_review["summary"]["suppressed"] == 1


@pytest.mark.parametrize(
    ("parameter", "message"),
    [
        ("reason", "baseline.reason must be a non-empty string"),
        ("owner", "baseline.owner must be a non-empty string"),
        ("created_at", "baseline.created_at must be an ISO 8601 timestamp"),
        ("expires_at", "baseline.expires_at must include a UTC offset"),
        ("reference", "baseline.reference must be a non-empty string"),
    ],
)
def test_baseline_creation_preserves_exact_lifecycle_field_diagnostics(
    parameter: str, message: str
) -> None:
    """Baseline command inputs retain their documented field-level validation diagnostics."""

    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-14T00:00:00+00:00",
        "findings": [],
    }
    arguments: dict[str, object] = {
        "review": review,
        "reason": "Explicit review decision.",
        "expires_at": "2026-09-01T00:00:00+00:00",
        "owner": "security-review",
        "created_at": "2026-08-14T00:00:00+00:00",
        "reference": "TICKET-42",
    }
    invalid_values: dict[str, object] = {
        "reason": None,
        "owner": "",
        "created_at": "not-a-timestamp",
        "expires_at": "2026-09-01T00:00:00",
        "reference": "",
    }
    arguments[parameter] = invalid_values[parameter]

    with pytest.raises(ValidationError) as error:
        create_baseline(**arguments)
    assert str(error.value) == message


def test_baseline_creation_deduplicates_active_fingerprints_and_normalizes_metadata() -> None:
    """One local decision entry binds each active fingerprint with normalized provenance fields."""

    finding = {
        "fingerprint": "a" * 64,
        "fingerprint_schema_version": "trustweave/fingerprint/v3",
        "id": "TW-POL-004",
        "severity": "high",
        "subject": {"tool": "lookup", "source": "customer"},
        "risk_state": "new",
    }
    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-14T00:00:00+00:00",
        "findings": [finding, dict(finding)],
    }

    baseline = create_baseline(
        review,
        "  Explicit review decision.  ",
        "2026-09-01T00:00:00Z",
        owner="  security-review  ",
        created_at="2026-08-14T00:00:00Z",
        reference="  TICKET-42  ",
    )

    assert baseline == {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": [
            {
                "fingerprint": "a" * 64,
                "fingerprint_schema_version": "trustweave/fingerprint/v3",
                "rule_id": "TW-POL-004",
                "subject_digest": (
                    "6e3a3401ac246fb8882b3e82fca71a46c4069c311262c406a57dd20fef71ddd0"
                ),
                "accepted_severity": "high",
                "reason": "Explicit review decision.",
                "owner": "security-review",
                "created_at": "2026-08-14T00:00:00+00:00",
                "expires_at": "2026-09-01T00:00:00+00:00",
                "reference": "TICKET-42",
            }
        ],
    }


def test_should_fail_preserves_active_state_threshold_matrix_and_exact_invalid_gate() -> None:
    """Only active lifecycle states participate in each ordered severity gate."""

    review = {
        "findings": [
            {"risk_state": "new", "severity": "high"},
            {"risk_state": "severity_escalated_baseline", "severity": "medium"},
            {"risk_state": "baselined", "severity": "critical"},
            {"risk_state": "suppressed", "severity": "low"},
        ]
    }

    assert should_fail(review, "none") is False
    assert should_fail(review, "critical") is False
    assert should_fail(review, "high") is True
    assert should_fail(review, "medium") is True
    assert should_fail(review, "low") is True
    assert should_fail(review, "info") is True
    assert should_fail(review, "review") is True

    with pytest.raises(ValidationError) as invalid_gate_error:
        should_fail(review, "urgent")
    assert str(invalid_gate_error.value) == (
        "fail_on must be one of ['critical', 'high', 'medium', 'low', 'info', 'review'] or none"
    )


def test_should_fail_validates_review_finding_paths_and_skips_resolved_entries() -> None:
    """Severity gating retains exact indexed diagnostics and continues past resolved findings."""

    with pytest.raises(ValidationError) as missing_findings_error:
        should_fail({}, "high")
    assert str(missing_findings_error.value) == "risk_review.findings must be a list"

    with pytest.raises(ValidationError) as malformed_finding_error:
        should_fail({"findings": [None]}, "high")
    assert str(malformed_finding_error.value) == "risk_review.findings[0] must be an object"

    with pytest.raises(ValidationError) as missing_state_error:
        should_fail({"findings": [{"severity": "high"}]}, "high")
    assert str(missing_state_error.value) == (
        "risk_review.findings[0].risk_state must be a non-empty string"
    )

    with pytest.raises(ValidationError) as missing_severity_error:
        should_fail({"findings": [{"risk_state": "new"}]}, "high")
    assert str(missing_severity_error.value) == (
        "risk_review.findings[0].severity must be a non-empty string"
    )

    resolved_before_active = {
        "findings": [
            {"risk_state": "baselined", "severity": "critical"},
            {"risk_state": "new", "severity": "high"},
        ]
    }
    assert should_fail(resolved_before_active, "high") is True


def test_baseline_creation_rejects_expiry_equal_to_created_at() -> None:
    """A reviewer decision must have a strictly future expiry rather than a zero-length lifetime."""

    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-14T12:00:00+00:00",
        "findings": [],
    }

    with pytest.raises(ValidationError, match="later than created_at"):
        create_baseline(
            review,
            "Explicit local reviewer decision.",
            "2026-08-14T12:00:00+00:00",
            owner="security-review",
            created_at="2026-08-14T12:00:00+00:00",
        )


def test_risk_review_treats_expiry_equal_to_review_time_as_expired(
    review_artifact: dict[str, object],
) -> None:
    """A decision expires at its recorded expiry instant and cannot apply through that boundary."""

    normalized = normalize_findings(review_artifact)[0]
    entry = _decision_entry(normalized, expires_at="2026-08-15T00:00:00+00:00")
    review = review_risks(
        [review_artifact],
        baseline_document={"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [entry]},
        reviewed_at="2026-08-15T00:00:00+00:00",
    )

    assert review["findings"][0]["risk_state"] == "expired_baseline"
    assert review["summary"]["expired_baseline"] == 1
    assert should_fail(review, "review")


@pytest.mark.parametrize("fingerprint", ("a" * 63, "z" * 64))
def test_baseline_creation_rejects_every_invalid_fingerprint_form(fingerprint: str) -> None:
    """Both SHA-256 length and hexadecimal alphabet are public decision-identity requirements."""

    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-14T00:00:00+00:00",
        "findings": [
            {
                "fingerprint": fingerprint,
                "fingerprint_schema_version": "trustweave/fingerprint/v3",
                "id": "TW-POL-004",
                "severity": "high",
                "subject": {"tool": "lookup"},
                "risk_state": "new",
            }
        ],
    }

    with pytest.raises(ValidationError, match="SHA-256"):
        create_baseline(
            review,
            "Explicit local reviewer decision.",
            "2026-09-01T00:00:00+00:00",
            owner="security-review",
            created_at="2026-08-14T00:00:00+00:00",
        )


def test_baseline_creation_retains_every_distinct_active_fingerprint() -> None:
    """Baseline generation must not stop after the first active finding with a distinct identity."""

    findings = [
        {
            "fingerprint": character * 64,
            "fingerprint_schema_version": "trustweave/fingerprint/v3",
            "id": f"TW-POL-00{index}",
            "severity": "high",
            "subject": {"tool": f"lookup-{index}"},
            "risk_state": "new",
        }
        for index, character in ((1, "a"), (2, "b"))
    ]
    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-14T00:00:00+00:00",
        "findings": findings,
    }

    baseline = create_baseline(
        review,
        "Explicit local reviewer decision.",
        "2026-09-01T00:00:00+00:00",
        owner="security-review",
        created_at="2026-08-14T00:00:00+00:00",
    )

    assert [entry["fingerprint"] for entry in baseline["baseline"]] == ["a" * 64, "b" * 64]


def test_risk_review_reports_exact_counts_for_multiple_active_severities() -> None:
    """The public severity summary counts each active finding once in its exact severity bucket."""

    artifact = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "high",
                "message": "A high local condition requires review.",
                "subject": {"tool": "lookup"},
            },
            {
                "id": "TW-POL-005",
                "severity": "low",
                "message": "A low local condition requires review.",
                "subject": {"tool": "archive"},
            },
        ],
    }

    review = review_risks([artifact], reviewed_at="2026-08-15T00:00:00+00:00")

    assert review["summary"]["active_by_severity"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 1,
        "info": 0,
    }
    assert review["summary"]["findings"] == 2
    assert review["summary"]["new"] == 2
    assert should_fail(review, "high")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("subject_digest", "a" * 63, "subject_digest must be a SHA-256 hex digest"),
        ("subject_digest", "z" * 64, "subject_digest must be a SHA-256 hex digest"),
        ("accepted_severity", "review", "accepted_severity must be one of"),
        ("created_at", "not-a-timestamp", "created_at must be an ISO 8601 timestamp"),
        ("expires_at", "2026-08-14T00:00:00", "expires_at must include a UTC offset"),
    ],
)
def test_v1alpha2_decision_validation_rejects_each_identity_and_lifecycle_boundary(
    review_artifact: dict[str, object], field: str, value: str, message: str
) -> None:
    """Decision documents fail closed for every declared identity and lifecycle field boundary."""

    entry = _decision_entry(normalize_findings(review_artifact)[0])
    entry[field] = value
    document = {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [entry]}

    with pytest.raises(ValidationError, match=message):
        validate_decision_document(document, "baseline")


def test_v1alpha2_decision_validation_rejects_duplicate_fingerprint_entries(
    review_artifact: dict[str, object],
) -> None:
    """One decision collection cannot contain multiple reviewer records for one fingerprint."""

    entry = _decision_entry(normalize_findings(review_artifact)[0])
    document = {
        "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
        "suppressions": [entry, dict(entry)],
    }

    with pytest.raises(ValidationError) as error:
        validate_decision_document(document, "suppressions")
    assert (
        str(error.value) == f"suppressions contains duplicate fingerprint: {entry['fingerprint']}"
    )


def test_v1alpha2_decision_validation_rejects_expiry_equal_to_creation(
    review_artifact: dict[str, object],
) -> None:
    """A decision cannot have an empty duration even when both timestamps are well formed."""

    entry = _decision_entry(normalize_findings(review_artifact)[0])
    entry["expires_at"] = entry["created_at"]
    document = {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [entry]}

    with pytest.raises(ValidationError) as error:
        validate_decision_document(document, "baseline")
    assert str(error.value) == "baseline[0].expires_at must be later than created_at"


def test_baseline_creation_skips_inactive_findings_before_later_active_evidence() -> None:
    """Inactive historical findings do not prevent later active evidence from being baselined."""

    inactive = {
        "fingerprint": "a" * 64,
        "fingerprint_schema_version": "trustweave/fingerprint/v3",
        "id": "TW-POL-004",
        "severity": "high",
        "subject": {"tool": "lookup"},
        "risk_state": "baselined",
    }
    active = {
        "fingerprint": "b" * 64,
        "fingerprint_schema_version": "trustweave/fingerprint/v3",
        "id": "TW-POL-005",
        "severity": "low",
        "subject": {"tool": "archive"},
        "risk_state": "new",
    }
    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-18T00:00:00+00:00",
        "findings": [inactive, active],
    }

    baseline = create_baseline(
        review,
        "Explicit local reviewer decision.",
        "2026-09-01T00:00:00+00:00",
        owner="security-review",
        created_at="2026-08-18T00:00:00+00:00",
    )

    assert [entry["fingerprint"] for entry in baseline["baseline"]] == ["b" * 64]
    assert baseline["baseline"][0]["rule_id"] == "TW-POL-005"
    assert baseline["baseline"][0]["accepted_severity"] == "low"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "fingerprint",
            "a" * 63,
            "risk_review.findings[0].fingerprint must be a SHA-256 hex digest",
        ),
        (
            "fingerprint",
            "z" * 64,
            "risk_review.findings[0].fingerprint must be a SHA-256 hex digest",
        ),
        (
            "fingerprint_schema_version",
            "unknown",
            "risk_review.findings[0].fingerprint_schema_version must be trustweave/fingerprint/v3",
        ),
        ("severity", "review", "risk_review.findings[0].severity must be one of"),
        ("subject", {}, "risk_review.findings[0].subject must bind a v1alpha2 decision"),
        ("id", "", "risk_review.findings[0].id must be a non-empty string"),
    ],
)
def test_baseline_creation_preserves_exact_active_finding_diagnostics(
    field: str, value: object, message: str
) -> None:
    """Active review findings must retain all v1alpha2 decision identity inputs before output."""

    finding: dict[str, object] = {
        "fingerprint": "a" * 64,
        "fingerprint_schema_version": "trustweave/fingerprint/v3",
        "id": "TW-POL-004",
        "severity": "high",
        "subject": {"tool": "lookup"},
        "risk_state": "new",
    }
    finding[field] = value
    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-18T00:00:00+00:00",
        "findings": [finding],
    }

    with pytest.raises(ValidationError) as error:
        create_baseline(
            review,
            "Explicit local reviewer decision.",
            "2026-09-01T00:00:00+00:00",
            owner="security-review",
            created_at="2026-08-18T00:00:00+00:00",
        )
    assert str(error.value).startswith(message)


def test_decision_document_validates_optional_reviewer_reference(
    review_artifact: dict[str, object],
) -> None:
    """A recorded reviewer reference is optional but, when supplied, must be meaningful text."""

    entry = _decision_entry(normalize_findings(review_artifact)[0])
    entry["reference"] = 42  # type: ignore[assignment]

    with pytest.raises(ValidationError) as error:
        validate_decision_document(
            {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [entry]}, "baseline"
        )
    assert str(error.value) == "baseline[0].reference must be a non-empty string"


@pytest.mark.parametrize(
    ("document", "expected_message"),
    [
        (
            {"schema_version": "invalid", "baseline": []},
            "baseline.schema_version must be trustweave.dev/risk-baseline/v1alpha2",
        ),
        (
            {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": {}, "extra": True},
            "baseline: unknown field 'extra'",
        ),
        (
            {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": {}},
            "baseline must be a list",
        ),
        (
            {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": ["invalid"]},
            "baseline[0] must be an object",
        ),
    ],
)
def test_decision_document_validation_reports_exact_document_paths(
    document: dict[str, object], expected_message: str
) -> None:
    """Malformed decision documents cannot lose their reviewer-visible diagnostics."""

    with pytest.raises(ValidationError) as error:
        validate_decision_document(document, "baseline")
    assert str(error.value) == expected_message


def test_legacy_artifact_fallback_subjects_preserve_declared_identity_fields() -> None:
    """Risk fingerprints retain stable identity for every supported legacy review family."""

    artifacts = (
        (
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "policy": "support-policy",
                "findings": [{"id": "TW-POL-001", "severity": "low", "message": "Policy."}],
            },
            {"policy": "support-policy"},
        ),
        (
            {
                "schema_version": "trustweave.dev/trace-review/v1alpha1",
                "agent": "support-agent",
                "policy": "support-policy",
                "findings": [{"id": "TW-TRACE-001", "severity": "low", "message": "Trace."}],
            },
            {"agent": "support-agent", "policy": "support-policy"},
        ),
        (
            {
                "schema_version": "trustweave.dev/mcp-profile-review/v1alpha1",
                "profile": {"name": "support-profile"},
                "findings": [{"id": "TW-MCP-001", "severity": "low", "message": "Profile."}],
            },
            {"profile": "support-profile"},
        ),
        (
            {
                "schema_version": "trustweave.dev/bundle-diff/v1alpha1",
                "head": {"agent": "candidate-agent"},
                "signals": [{"id": "TW-DIFF-001", "severity": "low", "message": "Delta."}],
            },
            {"agent": "candidate-agent", "legacy_message": "Delta."},
        ),
    )

    subjects = [normalize_findings(artifact)[0].as_dict()["subject"] for artifact, _ in artifacts]

    assert subjects == [expected for _, expected in artifacts]
    assert len({normalize_findings(artifact)[0].fingerprint for artifact, _ in artifacts}) == len(
        artifacts
    )


def test_risk_normalization_preserves_optional_reviewer_text_and_fingerprint_material() -> None:
    """Normalized evidence binds its public evidence kind and reviewer-facing optional text."""

    artifact = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": "support-policy",
        "findings": [
            {
                "id": "TW-POL-042",
                "severity": "high",
                "message": "Approval is required before escalation.",
                "subject": {"tool": "lookup"},
                "title": "Approval boundary",
                "rationale": "External impact requires an explicit approval control.",
                "remediation": "Add a fail-closed approval step.",
            }
        ],
    }

    normalized = normalize_findings(artifact)[0]
    expected_material = {
        "fingerprint_schema_version": "trustweave/fingerprint/v3",
        "evidence_kind": "declared_configuration",
        "id": "TW-POL-042",
        "subject": {"tool": "lookup"},
    }

    assert normalized.evidence_kind == "declared_configuration"
    assert normalized.title == "Approval boundary"
    assert normalized.rationale == "External impact requires an explicit approval control."
    assert normalized.remediation == "Add a fail-closed approval step."
    assert (
        normalized.fingerprint
        == sha256(canonical_json(expected_material).encode("utf-8")).hexdigest()
    )


@pytest.mark.parametrize(
    ("artifact", "message"),
    [
        (
            {"schema_version": "", "findings": []},
            "artifact.schema_version must be a non-empty string",
        ),
        (
            {"schema_version": "trustweave.dev/policy-review/v1alpha1", "findings": {}},
            "artifact.findings must be a list",
        ),
        (
            {"schema_version": "trustweave.dev/policy-review/v1alpha1", "findings": ["bad"]},
            "artifact.findings[0] must be an object",
        ),
        (
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [{"id": "", "severity": "low", "message": "Message."}],
            },
            "artifact.findings[0].id must be a non-empty string",
        ),
        (
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [{"id": "TW-POL-001", "severity": "", "message": "Message."}],
            },
            "artifact.findings[0].severity must be a non-empty string",
        ),
        (
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [{"id": "TW-POL-001", "severity": "low", "message": ""}],
            },
            "artifact.findings[0].message must be a non-empty string",
        ),
        (
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [
                    {"id": "TW-POL-001", "severity": "low", "message": "Message.", "title": ""}
                ],
            },
            "artifact.findings[0].title must be a non-empty string",
        ),
        (
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [
                    {"id": "TW-POL-001", "severity": "low", "message": "Message.", "rationale": ""}
                ],
            },
            "artifact.findings[0].rationale must be a non-empty string",
        ),
        (
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [
                    {
                        "id": "TW-POL-001",
                        "severity": "low",
                        "message": "Message.",
                        "remediation": "",
                    }
                ],
            },
            "artifact.findings[0].remediation must be a non-empty string",
        ),
    ],
)
def test_risk_normalization_reports_exact_malformed_artifact_paths(
    artifact: dict[str, object], message: str
) -> None:
    """Malformed supported evidence retains exact field paths for automated remediation."""

    with pytest.raises(ValidationError) as error:
        normalize_findings(artifact)
    assert str(error.value) == message


def test_risk_review_preserves_exact_boundary_and_conflict_diagnostics(
    review_artifact: dict[str, object],
) -> None:
    """Risk orchestration retains exact provenance, decision, and review-time diagnostics."""

    normalized = normalize_findings(review_artifact)[0]
    entry = _decision_entry(normalized)
    baseline = {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [entry]}
    suppressions = {"schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION, "suppressions": [entry]}

    with pytest.raises(ValidationError) as error:
        review_risks([review_artifact], reviewed_at="invalid")
    assert str(error.value) == "reviewed_at must be an ISO 8601 timestamp"

    with pytest.raises(ValidationError) as error:
        review_risks([], reviewed_at="2026-08-15T00:00:00+00:00", artifact_paths=["artifact.json"])
    assert str(error.value) == "artifact_paths must align one-to-one with artifacts"

    with pytest.raises(ValidationError) as error:
        review_risks(
            [review_artifact],
            reviewed_at="2026-08-15T00:00:00+00:00",
            artifact_paths=[""],
        )
    assert str(error.value) == "artifact_paths[0] must be a non-empty string"

    with pytest.raises(ValidationError) as error:
        review_risks(
            [review_artifact],
            baseline_document=baseline,
            suppressions_document=suppressions,
            reviewed_at="2026-08-15T00:00:00+00:00",
        )
    assert str(error.value) == (
        "baseline and suppressions conflict for fingerprint: " + normalized.fingerprint
    )

    with pytest.raises(ValidationError) as error:
        review_risks(
            [review_artifact],
            baseline_document={
                "schema_version": "trustweave.dev/risk-baseline/v1alpha1",
                "baseline": [],
            },
            reviewed_at="2026-08-15T00:00:00+00:00",
        )
    assert str(error.value) == (
        "baseline.schema_version trustweave.dev/risk-baseline/v1alpha1 requires explicit migration "
        "to trustweave.dev/risk-baseline/v1alpha2"
    )

    with pytest.raises(ValidationError) as error:
        review_risks(
            [review_artifact],
            suppressions_document={
                "schema_version": "trustweave.dev/risk-suppressions/v1alpha1",
                "suppressions": [],
            },
            reviewed_at="2026-08-15T00:00:00+00:00",
        )
    assert str(error.value) == (
        "suppressions.schema_version trustweave.dev/risk-suppressions/v1alpha1 requires "
        "explicit migration to trustweave.dev/risk-suppressions/v1alpha2"
    )


def test_risk_review_counts_severity_escalated_suppressions(
    review_artifact: dict[str, object],
) -> None:
    """A suppression cannot mask a finding that became more severe than it accepted."""

    entry = _decision_entry(normalize_findings(review_artifact)[0], accepted_severity="low")
    review = review_risks(
        [review_artifact],
        suppressions_document={
            "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
            "suppressions": [entry],
        },
        reviewed_at="2026-08-15T00:00:00+00:00",
    )

    assert review["findings"][0]["risk_state"] == "severity_escalated_suppression"
    assert review["summary"]["severity_escalated_suppression"] == 1


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("artifact.json", True),
        ("a" * 4096, True),
        ("a" * 4097, False),
        ("artifact\x00.json", False),
        ("artifact\x7f.json", False),
    ],
)
def test_risk_artifact_paths_enforce_exact_control_and_length_boundaries(
    value: str, valid: bool
) -> None:
    """Risk provenance paths reject every control character and values beyond 4,096 characters."""

    if valid:
        assert risk_module._artifact_path(value, "artifact_path") == value
    else:
        with pytest.raises(ValidationError) as error:
            risk_module._artifact_path(value, "artifact_path")
        assert str(error.value) == (
            "artifact_path must be at most 4096 characters without control characters"
        )


def _strict_baseline_entry() -> dict[str, str]:
    return {
        "fingerprint": "a" * 64,
        "fingerprint_schema_version": risk_module.FINGERPRINT_SCHEMA_VERSION,
        "rule_id": "TW-STRICT-001",
        "subject_digest": "b" * 64,
        "accepted_severity": "medium",
        "reason": "Explicit bounded local decision.",
        "owner": "alice",
        "created_at": "2026-08-14T00:00:00+00:00",
        "expires_at": "2026-09-01T00:00:00+00:00",
        "reference": "SEC-123",
    }


def test_risk_decision_entries_preserve_identity_and_reject_non_hex_digests() -> None:
    """Reviewer decisions retain full identity fields and accept only lowercase SHA-256 digests."""

    entry = _strict_baseline_entry()
    document = {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [entry]}
    decisions = risk_module._decision_entries(
        document,
        RISK_BASELINE_SCHEMA_VERSION,
        risk_module.LEGACY_RISK_BASELINE_SCHEMA_VERSION,
        "baseline",
    )
    decision = decisions[entry["fingerprint"]]
    assert decision.fingerprint == "a" * 64
    assert decision.owner == "alice"
    assert decision.reference == "SEC-123"
    assert decision.subject_digest == "b" * 64

    invalid_cases = (
        ("fingerprint", "a" * 63, "baseline[0].fingerprint must be a SHA-256 hex digest"),
        ("fingerprint", "X" * 64, "baseline[0].fingerprint must be a SHA-256 hex digest"),
        ("subject_digest", "X" * 64, "baseline[0].subject_digest must be a SHA-256 hex digest"),
    )
    for field, value, message in invalid_cases:
        malformed = _strict_baseline_entry()
        malformed[field] = value
        with pytest.raises(ValidationError) as error:
            risk_module._decision_entries(
                {"schema_version": RISK_BASELINE_SCHEMA_VERSION, "baseline": [malformed]},
                RISK_BASELINE_SCHEMA_VERSION,
                risk_module.LEGACY_RISK_BASELINE_SCHEMA_VERSION,
                "baseline",
            )
        assert str(error.value) == message


def test_risk_reviewer_selection_key_is_complete_and_stable() -> None:
    """Equal-severity findings deterministically select reviewer-facing text.

    The selection must not vary with input order.
    """

    complete = risk_module.CanonicalFinding(
        artifact_schema_version="trustweave.dev/policy-review/v1alpha1",
        evidence_kind="declared_configuration",
        identifier="TW-SELECT-001",
        severity="high",
        message="Stable message.",
        subject={"policy": "support"},
        fingerprint="c" * 64,
        title="Stable title.",
        rationale="Stable rationale.",
        remediation="Stable remediation.",
    )
    absent_optional = risk_module.CanonicalFinding(
        artifact_schema_version="trustweave.dev/policy-review/v1alpha1",
        evidence_kind="declared_configuration",
        identifier="TW-SELECT-002",
        severity="high",
        message="Stable message.",
        subject={"policy": "support"},
        fingerprint="d" * 64,
    )

    assert risk_module._reviewer_selection_key(complete) == (
        risk_module.SEVERITY_RANK["high"],
        "Stable title.",
        "Stable message.",
        "Stable rationale.",
        "Stable remediation.",
    )
    assert risk_module._reviewer_selection_key(absent_optional) == (
        risk_module.SEVERITY_RANK["high"],
        "",
        "Stable message.",
        "",
        "",
    )


def test_baseline_creation_preserves_exact_lifecycle_and_lowercase_fingerprint_contracts() -> None:
    """Baseline creation fails closed on stale creation, non-later expiry, and uppercase digests."""

    review = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "generated_at": "2026-08-14T12:00:00+00:00",
        "findings": [
            {
                "fingerprint": "a" * 64,
                "fingerprint_schema_version": risk_module.FINGERPRINT_SCHEMA_VERSION,
                "id": "TW-BASELINE-STRICT",
                "severity": "high",
                "subject": {"tool": "lookup"},
                "risk_state": "new",
            }
        ],
    }
    common = {"owner": "security-review", "created_at": "2026-08-14T12:00:00+00:00"}

    with pytest.raises(ValidationError) as error:
        create_baseline(
            review,
            "Explicit local reviewer decision.",
            "2026-08-14T12:00:00+00:00",
            **common,
        )
    assert str(error.value) == "baseline.expires_at must be later than created_at"

    with pytest.raises(ValidationError) as error:
        create_baseline(
            review,
            "Explicit local reviewer decision.",
            "2026-09-01T00:00:00+00:00",
            owner="security-review",
            created_at="2026-08-13T00:00:00+00:00",
        )
    assert str(error.value) == "baseline.created_at must not precede review timestamp"

    uppercase = {**review, "findings": [{**review["findings"][0], "fingerprint": "X" + "0" * 63}]}
    with pytest.raises(ValidationError) as error:
        create_baseline(
            uppercase, "Explicit local reviewer decision.", "2026-09-01T00:00:00+00:00", **common
        )
    assert str(error.value) == "risk_review.findings[0].fingerprint must be a SHA-256 hex digest"


def test_risk_timestamp_and_normalization_preserve_strict_utc_and_schema_diagnostics() -> None:
    """Risk parsing normalizes Z timestamps and preserves schema diagnostics."""

    timestamp = risk_module._timestamp("2020-01-01T00:00:00Z", "timestamp")
    assert timestamp.isoformat() == "2020-01-01T00:00:00+00:00"

    with pytest.raises(ValidationError) as error:
        normalize_findings({"schema_version": "unsupported", "findings": []})
    assert str(error.value) == (
        "artifact.schema_version 'unsupported' is unsupported for risk review; supported schemas: "
        + ", ".join(sorted(risk_module._ARTIFACT_CONTRACTS))
    )

    with pytest.raises(ValidationError) as error:
        normalize_findings(
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [{"id": "TW-RISK-TYPE", "severity": 1, "message": "Type boundary."}],
            }
        )
    assert str(error.value) == "artifact.findings[0].severity must be a non-empty string"


def test_risk_review_requires_explicit_review_time_and_orders_conflict_fingerprints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Risk orchestration rejects implicit time and renders multi-fingerprint conflicts stably."""

    with pytest.raises(ValidationError) as error:
        review_risks([], reviewed_at=None)
    assert str(error.value) == "reviewed_at must be supplied by the application boundary"

    decisions = iter(({"b": object(), "a": object()}, {"a": object(), "b": object()}))
    monkeypatch.setattr(risk_module, "_decision_entries", lambda *_args: next(decisions))
    with pytest.raises(ValidationError) as error:
        review_risks([], reviewed_at="2026-08-18T00:00:00+00:00")
    assert str(error.value) == "baseline and suppressions conflict for fingerprint: a, b"


def test_risk_review_preserves_first_equal_finding_and_rejects_metadata_conflicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fingerprint de-duplication must retain first equal findings but reject identity conflicts."""

    first = risk_module.CanonicalFinding(
        artifact_schema_version="trustweave.dev/policy-review/v1alpha1",
        evidence_kind="declared_configuration",
        identifier="TW-TIE-001",
        severity="high",
        message="Stable reviewer text.",
        subject={"policy": "support"},
        fingerprint="a" * 64,
    )
    equal_second = risk_module.CanonicalFinding(
        artifact_schema_version="trustweave.dev/policy-review/v1alpha1",
        evidence_kind="declared_configuration",
        identifier="TW-TIE-001",
        severity="high",
        message="Stable reviewer text.",
        subject={"policy": "support"},
        fingerprint="a" * 64,
    )
    selected: list[risk_module.CanonicalFinding] = []
    monkeypatch.setattr(risk_module, "normalize_findings", lambda _artifact: (first, equal_second))
    monkeypatch.setattr(
        risk_module,
        "_status_for",
        lambda finding, *_args: selected.append(finding) or ("new", None, None),
    )

    review_risks([{}], reviewed_at="2026-08-18T00:00:00+00:00")
    assert selected == [first]
    assert selected[0] is first

    contradictory = risk_module.CanonicalFinding(
        artifact_schema_version="trustweave.dev/policy-review/v1alpha1",
        evidence_kind="declared_configuration",
        identifier="TW-TIE-002",
        severity="high",
        message="Stable reviewer text.",
        subject={"policy": "support"},
        fingerprint="a" * 64,
    )
    monkeypatch.setattr(risk_module, "normalize_findings", lambda _artifact: (first, contradictory))
    with pytest.raises(ValidationError) as error:
        review_risks([{}], reviewed_at="2026-08-18T00:00:00+00:00")
    assert (
        str(error.value) == "risk findings with one fingerprint have contradictory stable metadata"
    )


def test_risk_timestamp_preserves_invalid_value_path_and_utc_singleton_identity() -> None:
    """Risk timestamps retain invalid-input paths and normalized UTC identity."""

    with pytest.raises(ValidationError) as error:
        risk_module._timestamp(None, "reviewed_at")
    assert str(error.value) == "reviewed_at must be a non-empty string"

    normalized = risk_module._timestamp("2026-08-18T04:00:00+04:00", "reviewed_at")
    assert normalized.isoformat() == "2026-08-18T00:00:00+00:00"
    assert normalized.tzinfo is risk_module.UTC


def test_risk_status_marks_a_suppression_expiring_at_review_time_as_expired() -> None:
    """Expiry is inclusive at the review boundary so stale suppressions cannot remain active."""

    finding = risk_module.CanonicalFinding(
        artifact_schema_version="trustweave.dev/policy-review/v1alpha1",
        evidence_kind="declared_configuration",
        identifier="TW-EXPIRY-BOUNDARY",
        severity="high",
        message="A review-time boundary fixture.",
        subject={"policy": "support"},
        fingerprint="a" * 64,
    )
    reviewed_at = risk_module._timestamp("2026-08-18T00:00:00+00:00", "reviewed_at")
    decision = risk_module.RiskDecision(
        fingerprint=finding.fingerprint,
        accepted_severity="high",
        reason="The reviewer decision has reached its expiry boundary.",
        owner="security-review",
        created_at=risk_module._timestamp("2026-08-17T00:00:00+00:00", "created_at"),
        expires_at=reviewed_at,
        rule_id=finding.identifier,
        subject_digest=risk_module._subject_digest(finding.subject),
    )

    assert risk_module._status_for(finding, {}, {finding.fingerprint: decision}, reviewed_at) == (
        "expired_suppression",
        decision.reason,
        decision.expires_at.isoformat(),
    )


def test_risk_helpers_preserve_legacy_subject_metadata_and_decision_diagnostics() -> None:
    """Risk helpers retain stable legacy identity and explicit decision-validation diagnostics."""

    assert risk_module._fallback_subject({}, "trustweave.dev/bundle-diff/v1alpha1", "legacy") == {
        "legacy_message": "legacy"
    }
    finding = risk_module.CanonicalFinding(
        artifact_schema_version="trustweave.dev/policy-review/v1alpha1",
        evidence_kind="declared_configuration",
        identifier="TW-STABLE-METADATA",
        severity="high",
        message="Stable metadata fixture.",
        subject={"policy": "support"},
        fingerprint="b" * 64,
    )
    assert risk_module._stable_metadata(finding) == (
        "trustweave.dev/policy-review/v1alpha1",
        "declared_configuration",
        "TW-STABLE-METADATA",
        canonical_json({"subject": {"policy": "support"}}),
    )

    with pytest.raises(ValidationError) as error:
        risk_module._stable_subject({1: "invalid"}, "subject")
    assert str(error.value) == "subject: subject keys must be strings"

    with pytest.raises(ValidationError) as error:
        validate_decision_document(
            {
                "schema_version": risk_module.LEGACY_RISK_SUPPRESSIONS_SCHEMA_VERSION,
                "suppressions": [],
            },
            "suppressions",
        )
    assert str(error.value) == (
        "suppressions.schema_version trustweave.dev/risk-suppressions/v1alpha1 requires explicit "
        "migration to trustweave.dev/risk-suppressions/v1alpha2"
    )

    with pytest.raises(ValidationError) as error:
        validate_decision_document({}, "unsupported")
    assert str(error.value) == "decision_kind must be baseline or suppressions"
