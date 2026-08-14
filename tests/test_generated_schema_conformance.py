"""Regression coverage for generated TrustWeave artifact schema conformance."""

from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError

from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation
from trustweave.findings import finding
from trustweave.io import load_document, write_json
from trustweave.models import parse_manifest, parse_policy

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
SCHEMA = ROOT / "schemas" / "agent-security-bundle-v1alpha1.schema.json"
ATTESTATION_SCHEMA = ROOT / "schemas" / "attestation-v1alpha3.schema.json"
FINDING_SCHEMA = ROOT / "schemas" / "finding-v1alpha1.schema.json"


def test_real_generated_bundle_conforms_to_its_published_schema() -> None:
    """A generated bundle must be accepted by its exact checked-in JSON Schema."""

    bundle = build_bundle(
        parse_manifest(load_document(MANIFEST)),
        parse_policy(load_document(POLICY)),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    schema = load_document(SCHEMA)

    Draft202012Validator(schema).validate(bundle)


def test_bundle_schema_rejects_unknown_top_level_field() -> None:
    """Strict bundle schemas must not accept unversioned output extensions."""

    bundle = build_bundle(
        parse_manifest(load_document(MANIFEST)),
        parse_policy(load_document(POLICY)),
    )
    bundle["unexpected"] = True

    with pytest.raises(JsonSchemaValidationError, match="Additional properties"):
        Draft202012Validator(load_document(SCHEMA)).validate(bundle)


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
