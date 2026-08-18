from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.models import ValidationError
from trustweave.risk import review_risks
from trustweave.sarif import SARIF_SCHEMA_URI, SARIF_VERSION, build_sarif


def _review_documents() -> dict[str, tuple[str, dict[str, object]]]:
    return {
        "trace": (
            "artifacts/trace-review.json",
            {
                "schema_version": "trustweave.dev/trace-review/v1alpha1",
                "findings": [
                    {
                        "id": "TW-TRACE-004",
                        "severity": "review",
                        "message": "Declared trace call evaluates to deny.",
                    }
                ],
            },
        ),
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
        ),
        "diff": (
            "artifacts/bundle-diff.json",
            {
                "schema_version": "trustweave.dev/bundle-diff/v1alpha1",
                "signals": [
                    {
                        "id": "TW-DIFF-003",
                        "severity": "review",
                        "message": "Sensitive tool capability growth requires review.",
                    }
                ],
            },
        ),
        "mcp": (
            "artifacts/mcp-profile-review.json",
            {
                "schema_version": "trustweave.dev/mcp-profile-review/v1alpha1",
                "findings": [
                    {
                        "id": "TW-MCP-001",
                        "severity": "review",
                        "message": "MCP profile does not match a declared tool.",
                    }
                ],
            },
        ),
    }


def test_sarif_export_is_deterministic_and_preserves_review_artifact_locations() -> None:
    reviews = _review_documents()

    first = build_sarif(reviews)
    second = build_sarif(reviews)

    assert first == second
    assert first["$schema"] == SARIF_SCHEMA_URI
    assert first["version"] == SARIF_VERSION
    run = first["runs"][0]
    assert run["tool"]["driver"]["name"] == "TrustWeave"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "TW-DIFF-003",
        "TW-MCP-001",
        "TW-POL-004",
        "TW-TRACE-004",
    ]
    assert [result["ruleId"] for result in run["results"]] == [
        "TW-DIFF-003",
        "TW-MCP-001",
        "TW-POL-004",
        "TW-TRACE-004",
    ]
    assert all(result["level"] == "warning" for result in run["results"])
    assert {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in run["results"]
    } == {
        "artifacts/bundle-diff.json",
        "artifacts/mcp-profile-review.json",
        "artifacts/policy-review.json",
        "artifacts/trace-review.json",
    }
    assert all("trustweave/v1" in result["partialFingerprints"] for result in run["results"])


def test_sarif_export_rejects_missing_or_invalid_review_inputs() -> None:
    with pytest.raises(ValidationError, match="At least one TrustWeave review artifact"):
        build_sarif({})

    invalid = _review_documents()
    invalid["policy"] = (
        "artifacts/policy-review.json",
        {"schema_version": "trustweave.dev/policy-review/v1alpha0", "findings": []},
    )
    with pytest.raises(ValidationError, match="policy review must use"):
        build_sarif(invalid)


def test_cli_sarif_writes_a_local_json_artifact(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy-review.json"
    diff_path = tmp_path / "bundle-diff.json"
    output_path = tmp_path / "trustweave.sarif"
    documents = _review_documents()
    policy_path.write_text(json.dumps(documents["policy"][1]), encoding="utf-8")
    diff_path.write_text(json.dumps(documents["diff"][1]), encoding="utf-8")

    assert (
        main(
            [
                "sarif",
                "--policy-review",
                str(policy_path),
                "--diff",
                str(diff_path),
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    exported = json.loads(output_path.read_text(encoding="utf-8"))
    assert exported["version"] == SARIF_VERSION
    assert [result["ruleId"] for result in exported["runs"][0]["results"]] == [
        "TW-DIFF-003",
        "TW-POL-004",
    ]


def test_cli_sarif_requires_at_least_one_review_artifact(tmp_path: Path) -> None:
    assert main(["sarif", "--output", str(tmp_path / "trustweave.sarif")]) == 2


def test_sarif_exports_only_active_risk_findings_with_their_canonical_fingerprint() -> None:
    active_fingerprint = "a" * 64
    risk_review = {
        "schema_version": "trustweave.dev/risk-review/v1alpha1",
        "findings": [
            {
                "id": "TW-POL-004",
                "severity": "high",
                "message": "Approval control is not declared.",
                "fingerprint": active_fingerprint,
                "risk_state": "new",
            },
            {
                "id": "TW-POL-005",
                "severity": "medium",
                "message": "A documented baseline remains in effect.",
                "fingerprint": "b" * 64,
                "risk_state": "baselined",
            },
        ],
    }

    exported = build_sarif({"risk": ("artifacts/risk-review.json", risk_review)})
    result = exported["runs"][0]["results"]
    assert len(result) == 1
    assert result[0]["ruleId"] == "TW-POL-004"
    assert result[0]["level"] == "error"
    assert result[0]["partialFingerprints"] == {"trustweave/risk-v1": active_fingerprint}


def test_sarif_deduplicates_raw_chain_and_derived_risk_findings() -> None:
    chain_review = {
        "schema_version": "trustweave.dev/chain-review/v1alpha1",
        "findings": [
            {
                "id": "TW-CHAIN-001",
                "severity": "high",
                "message": "Declared path reaches an external action with sensitive data.",
                "subject": {"path": ["source", "records", "external"]},
            }
        ],
        "paths": [{"identity": ["source", "records", "external"]}],
        "summary": {"status": "review_required"},
        "limits": ["Local declared-chain analysis only."],
    }
    risk_review = review_risks(
        [chain_review],
        reviewed_at="2026-08-14T00:00:00+00:00",
        artifact_paths=["artifacts/chain-review.json"],
    )

    exported = build_sarif(
        {
            "chain": ("artifacts/chain-review.json", chain_review),
            "risk": ("artifacts/risk-review.json", risk_review),
        }
    )

    results = exported["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "TW-CHAIN-001"
    assert results[0]["locations"] == [
        {"physicalLocation": {"artifactLocation": {"uri": "artifacts/chain-review.json"}}},
        {"physicalLocation": {"artifactLocation": {"uri": "artifacts/risk-review.json"}}},
    ]
    assert results[0]["properties"]["trustweaveSourceKinds"] == ["chain", "risk"]


def test_cli_sarif_accepts_active_risk_review(tmp_path: Path) -> None:
    risk_path = tmp_path / "risk-review.json"
    output_path = tmp_path / "trustweave.sarif"
    risk_path.write_text(
        json.dumps(
            {
                "schema_version": "trustweave.dev/risk-review/v1alpha1",
                "findings": [
                    {
                        "id": "TW-POL-004",
                        "severity": "high",
                        "message": "Approval control is not declared.",
                        "fingerprint": "c" * 64,
                        "risk_state": "expired_baseline",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                "sarif",
                "--risk-review",
                str(risk_path),
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    exported = json.loads(output_path.read_text(encoding="utf-8"))
    assert exported["runs"][0]["results"][0]["partialFingerprints"] == {
        "trustweave/risk-v1": "c" * 64
    }


def test_sarif_unknown_declared_signal_uses_note_fallback_and_stable_result_identity() -> None:
    """Uncatalogued declared signals retain their message and receive the safe SARIF note level."""

    reviews = {
        "policy": (
            "artifacts/custom-policy-review.json",
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [
                    {
                        "id": "TW-CUSTOM-001",
                        "severity": "unrecognized",
                        "message": "A custom local signal requires an explicit reviewer decision.",
                    }
                ],
            },
        )
    }

    exported = build_sarif(reviews)
    run = exported["runs"][0]
    assert run["tool"]["driver"]["rules"] == [
        {
            "id": "TW-CUSTOM-001",
            "name": "tw_custom_001",
            "shortDescription": {"text": "TrustWeave TW-CUSTOM-001 review signal"},
            "fullDescription": {
                "text": "A custom local signal requires an explicit reviewer decision."
            },
            "defaultConfiguration": {"level": "note"},
        }
    ]
    assert run["results"] == [
        {
            "ruleId": "TW-CUSTOM-001",
            "level": "note",
            "message": {
                "text": "[policy] A custom local signal requires an explicit reviewer decision."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "artifacts/custom-policy-review.json"}
                    }
                }
            ],
            "partialFingerprints": {
                "trustweave/v1": sha256(
                    "\0".join(
                        (
                            "policy",
                            "TW-CUSTOM-001",
                            "A custom local signal requires an explicit reviewer decision.",
                            "artifacts/custom-policy-review.json",
                        )
                    ).encode("utf-8")
                ).hexdigest()
            },
            "properties": {"trustweaveSourceKinds": ["policy"]},
        }
    ]


@pytest.mark.parametrize(
    ("artifact_uri", "finding", "message"),
    [
        (
            "",
            {"id": "TW-POL-004", "severity": "high", "message": "Review."},
            "policy artifact URI must be a non-empty string",
        ),
        (
            "artifacts/policy.json",
            {"id": "", "severity": "high", "message": "Review."},
            "policy.findings[0].id must be a non-empty string",
        ),
        (
            "artifacts/policy.json",
            {"id": "TW-POL-004", "severity": "high", "message": ""},
            "policy.findings[0].message must be a non-empty string",
        ),
        (
            "artifacts/policy.json",
            {"id": "TW-POL-004", "severity": "", "message": "Review."},
            "policy.findings[0].severity must be a non-empty string",
        ),
    ],
)
def test_sarif_rejects_empty_public_artifact_and_finding_fields(
    artifact_uri: str, finding: dict[str, str], message: str
) -> None:
    """SARIF conversion fails closed before emitting incomplete reviewer-facing evidence."""

    reviews = {
        "policy": (
            artifact_uri,
            {"schema_version": "trustweave.dev/policy-review/v1alpha1", "findings": [finding]},
        )
    }

    with pytest.raises(ValidationError) as error:
        build_sarif(reviews)
    assert str(error.value) == message


def test_sarif_rejects_active_risk_findings_without_a_canonical_fingerprint() -> None:
    """Active risk output must retain its lifecycle fingerprint when converted to SARIF."""

    reviews = {
        "risk": (
            "artifacts/risk-review.json",
            {
                "schema_version": "trustweave.dev/risk-review/v1alpha2",
                "findings": [
                    {
                        "id": "TW-POL-004",
                        "severity": "high",
                        "message": "Approval control is not declared.",
                        "risk_state": "new",
                    }
                ],
            },
        )
    }

    with pytest.raises(ValidationError) as error:
        build_sarif(reviews)
    assert str(error.value) == "risk.findings[0].fingerprint must be a non-empty string"


def test_sarif_canonical_result_order_uses_rule_message_uri_and_fallback_fingerprint() -> None:
    """Same-rule raw findings retain distinct fallback identities and canonical result ordering."""

    reviews = {
        "policy": (
            "artifacts/z-policy.json",
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": [
                    {"id": "TW-ORDER-001", "severity": "low", "message": "Zulu finding."},
                    {"id": "TW-ORDER-001", "severity": "low", "message": "Alpha finding."},
                ],
            },
        ),
        "trace": (
            "artifacts/a-trace.json",
            {
                "schema_version": "trustweave.dev/trace-review/v1alpha1",
                "findings": [
                    {"id": "TW-ORDER-001", "severity": "low", "message": "Alpha finding."}
                ],
            },
        ),
    }

    results = build_sarif(reviews)["runs"][0]["results"]

    assert [
        (
            result["ruleId"],
            result["message"]["text"],
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        for result in results
    ] == [
        ("TW-ORDER-001", "[policy] Alpha finding.", "artifacts/z-policy.json"),
        ("TW-ORDER-001", "[policy] Zulu finding.", "artifacts/z-policy.json"),
        ("TW-ORDER-001", "[trace] Alpha finding.", "artifacts/a-trace.json"),
    ]
    assert len({next(iter(result["partialFingerprints"].values())) for result in results}) == 3
