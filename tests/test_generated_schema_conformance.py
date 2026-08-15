"""Regression coverage for generated TrustWeave artifact schema conformance."""

from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError

from trustweave.chain import review_declared_chains
from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation
from trustweave.findings import finding
from trustweave.io import load_document, write_json
from trustweave.models import parse_manifest, parse_policy
from trustweave.risk import review_risks

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
LEGACY_BUNDLE_SCHEMA = ROOT / "schemas" / "agent-security-bundle-v1alpha1.schema.json"
CURRENT_BUNDLE_SCHEMA = ROOT / "schemas" / "agent-security-bundle-v1alpha2.schema.json"
ATTESTATION_SCHEMA = ROOT / "schemas" / "attestation-v1alpha3.schema.json"
FINDING_SCHEMA = ROOT / "schemas" / "finding-v1alpha1.schema.json"
RISK_REVIEW_SCHEMA = ROOT / "schemas" / "risk-review-v1alpha2.schema.json"


def test_real_generated_bundle_conforms_to_its_published_schema() -> None:
    """A generated bundle must be accepted by its exact checked-in JSON Schema."""

    bundle = build_bundle(
        parse_manifest(load_document(MANIFEST)),
        parse_policy(load_document(POLICY)),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert bundle["schema_version"] == "trustweave.dev/bundle/v1alpha2"
    schema = load_document(CURRENT_BUNDLE_SCHEMA)

    Draft202012Validator(schema).validate(bundle)


def test_bundle_schema_accepts_runtime_display_manifest_name() -> None:
    """A bounded human-readable manifest display name remains schema-valid in evidence."""

    manifest_document = dict(load_document(MANIFEST))
    manifest_document["name"] = "Customer Support Agent"
    bundle = build_bundle(
        parse_manifest(manifest_document),
        parse_policy(load_document(POLICY)),
        generated_at="2026-08-13T00:00:00+00:00",
    )

    Draft202012Validator(load_document(CURRENT_BUNDLE_SCHEMA)).validate(bundle)


def test_historical_v1alpha1_bundle_remains_schema_valid_without_v1alpha2_policy_fields() -> None:
    """The historical version retains its original policy-only shape and no v1alpha2 fields."""

    bundle = build_bundle(
        parse_manifest(load_document(MANIFEST)),
        parse_policy(load_document(POLICY)),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    bundle["schema_version"] = "trustweave.dev/bundle/v1alpha1"
    bundle.pop("limits")
    policy = bundle["policy"]
    assert isinstance(policy, dict)
    policy.pop("classification_taxonomy")
    policy.pop("approval_control")
    for rule in policy["rules"]:
        assert isinstance(rule, dict)
        for field in (
            "source_identifiers",
            "tool_identifiers",
            "purpose_tags",
            "source_data_classification_at_least",
            "source_data_classification_at_most",
            "required_controls",
        ):
            rule.pop(field)

    Draft202012Validator(load_document(LEGACY_BUNDLE_SCHEMA)).validate(bundle)


def test_bundle_schema_rejects_unknown_top_level_field() -> None:
    """Strict bundle schemas must not accept unversioned output extensions."""

    bundle = build_bundle(
        parse_manifest(load_document(MANIFEST)),
        parse_policy(load_document(POLICY)),
    )
    bundle["unexpected"] = True

    with pytest.raises(JsonSchemaValidationError, match="Additional properties"):
        Draft202012Validator(load_document(CURRENT_BUNDLE_SCHEMA)).validate(bundle)


def test_real_v1alpha3_attestation_conforms_to_its_published_schema(tmp_path: Path) -> None:
    """An emitted local v1alpha3 integrity statement must satisfy its exact schema."""

    bundle_path = write_json(
        tmp_path / "bundle.json",
        build_bundle(
            parse_manifest(load_document(MANIFEST)),
            parse_policy(load_document(POLICY)),
            generated_at="2026-08-13T00:00:00+00:00",
        ),
    )
    test_results_path = write_json(
        tmp_path / "tests.json",
        {"schema_version": "trustweave.dev/test-results/v1alpha1", "summary": {"status": "passed"}},
    )
    attestation = build_attestation(
        bundle_path,
        test_results_path,
        source_revision="test-revision",
        generated_at="2026-08-13T00:00:00+00:00",
    )

    Draft202012Validator(load_document(ATTESTATION_SCHEMA)).validate(attestation)


def test_real_chain_findings_conform_to_the_canonical_finding_schema() -> None:
    """Path-bearing chain observations must use the shared embedded finding contract."""

    review = review_declared_chains(
        {
            "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
            "name": "real-chain-finding",
            "nodes": [
                {"id": "untrusted", "kind": "source", "trust": "untrusted"},
                {"id": "sensitive", "kind": "data", "classification": "confidential"},
                {"id": "external", "kind": "sink", "action_class": "external"},
            ],
            "edges": [
                {"from": "untrusted", "to": "sensitive"},
                {"from": "sensitive", "to": "external"},
            ],
        },
        generated_at="2026-08-14T00:00:00+00:00",
    )
    validator = Draft202012Validator(load_document(FINDING_SCHEMA))

    assert review["findings"]
    for emitted in review["findings"]:
        validator.validate(emitted)


def test_emitted_canonical_finding_conforms_to_its_published_schema() -> None:
    """Embedded canonical findings inherit their version from the containing artifact."""

    emitted = finding(
        "TW-TEST-001",
        "review",
        "A local declared-evidence observation.",
        "declared_configuration",
        subject={"source": "customer_message", "tool": "send_mock_email"},
    )

    Draft202012Validator(load_document(FINDING_SCHEMA)).validate(emitted)


def test_risk_review_schema_accepts_runtime_absolute_artifact_paths_with_spaces() -> None:
    """Published risk-review validation preserves bounded literal local provenance paths."""

    review = review_risks(
        [
            {
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
        ],
        reviewed_at="2026-08-15T00:00:00+00:00",
        artifact_paths=["/workspace/release artifacts/policy review.json"],
    )

    Draft202012Validator(load_document(RISK_REVIEW_SCHEMA)).validate(review)


def test_bundle_schema_rejects_placeholder_nested_contracts() -> None:
    """Bundle schemas must not permit generic nested objects in emitted evidence fields."""

    bundle = build_bundle(
        parse_manifest(load_document(MANIFEST)),
        parse_policy(load_document(POLICY)),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    bundle["manifest"] = {}

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(load_document(CURRENT_BUNDLE_SCHEMA)).validate(bundle)


def test_current_risk_review_schema_accepts_bundle_diff_v1alpha2_findings() -> None:
    """Risk normalization keeps current bundle-diff evidence schema-valid through v1alpha2."""

    review = review_risks(
        [
            {
                "schema_version": "trustweave.dev/bundle-diff/v1alpha2",
                "signals": [
                    {
                        "id": "TW-DIFF-001",
                        "severity": "review",
                        "message": "A current bundle diff requires review.",
                        "subject": {"tool": "archive"},
                    }
                ],
            }
        ],
        reviewed_at="2026-08-15T00:00:00+00:00",
    )

    Draft202012Validator(load_document(RISK_REVIEW_SCHEMA)).validate(review)
