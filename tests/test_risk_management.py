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

    assert review["findings"][0]["risk_state"] == "new"
    assert review["summary"]["status"] == "review_required"

    suppressed = review_risks(
        [review_artifact],
        suppressions_document={
            "schema_version": RISK_SUPPRESSIONS_SCHEMA_VERSION,
            "suppressions": [entry],
        },
        reviewed_at="2026-08-15T00:00:00+00:00",
    )
    assert suppressed["findings"][0]["risk_state"] == "new"
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

    assert review["findings"][0]["risk_state"] == "new"
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
                "schema_version": "trustweave.dev/risk-review/v1alpha1",
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
