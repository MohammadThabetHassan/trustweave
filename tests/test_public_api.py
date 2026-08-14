from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave import api

ROOT = Path(__file__).resolve().parents[1]


def test_public_api_exports_only_documented_data_only_services() -> None:
    assert api.__all__ == sorted(api.__all__)
    for name in api.__all__:
        assert hasattr(api, name)

    manifest = api.parse_manifest(
        json.loads((ROOT / "examples" / "support-agent.manifest.json").read_text(encoding="utf-8"))
    )
    policy = api.parse_policy(
        json.loads((ROOT / "policies" / "default-policy.json").read_text(encoding="utf-8"))
    )
    bundle = api.build_bundle(manifest, policy, generated_at="2026-08-13T00:00:00+00:00")
    assert bundle["schema_version"] == "trustweave.dev/bundle/v1alpha1"
    assert bundle["summary"]["deny"] == 2


def test_local_review_result_is_deeply_immutable_and_defensively_copied() -> None:
    document: dict[str, object] = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "findings": [{"id": "TW-TEST-001", "subject": {"flow": ["source", "tool"]}}],
        "summary": {"counts": {"review": 1}},
        "limits": ["Local evidence only."],
    }

    result = api.LocalReviewResult.from_document(document)
    findings = document["findings"]
    summary = document["summary"]
    assert isinstance(findings, list)
    assert isinstance(summary, dict)
    first_finding = findings[0]
    assert isinstance(first_finding, dict)
    first_finding["id"] = "TW-MUTATED"
    summary["counts"] = {"review": 0}

    assert result.findings[0]["id"] == "TW-TEST-001"
    assert result.summary["counts"]["review"] == 1
    with pytest.raises(TypeError):
        result.findings[0]["id"] = "TW-MUTATED"


def test_typed_local_review_result_preserves_only_existing_local_evidence() -> None:
    result = api.LocalReviewResult.from_document(
        {
            "schema_version": "trustweave.dev/policy-review/v1alpha1",
            "findings": [{"id": "TW-TEST-001"}],
            "summary": {"status": "clear"},
            "limits": ["Local evidence only."],
        }
    )
    assert result.schema_version == "trustweave.dev/policy-review/v1alpha1"
    assert result.findings[0]["id"] == "TW-TEST-001"
    with pytest.raises(api.ValidationError, match="findings"):
        api.LocalReviewResult.from_document(
            {
                "schema_version": "trustweave.dev/policy-review/v1alpha1",
                "findings": "not-a-list",
                "summary": {},
                "limits": [],
            }
        )
