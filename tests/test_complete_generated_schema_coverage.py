"""Conformance tests for every versioned generated TrustWeave artifact schema."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError

from trustweave.diff import diff_bundles
from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation
from trustweave.framework_import import normalize_framework_declaration
from trustweave.io import load_document, write_json
from trustweave.mcp_import import build_manifest_scaffold, normalize_mcp_tools_list
from trustweave.mcp_profile import parse_mcp_profile, review_mcp_profile
from trustweave.models import parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.scenarios import parse_scenarios, run_scenarios
from trustweave.statement import build_unsigned_statement
from trustweave.trace_review import review_trace

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
FIXED_TIME = "2026-08-15T00:00:00+00:00"


def _validate(schema_name: str, artifact: dict[str, Any]) -> None:
    Draft202012Validator(load_document(ROOT / "schemas" / schema_name)).validate(artifact)


def _manifest_and_policy() -> tuple[Any, Any]:
    return parse_manifest(load_document(MANIFEST)), parse_policy(load_document(POLICY))


def test_policy_review_and_synthetic_results_conform_to_published_schemas() -> None:
    """Policy analysis artifacts use strict contracts, including optional coverage data."""

    _, policy = _manifest_and_policy()
    policy_review = review_policy(policy, generated_at=FIXED_TIME, include_coverage=True)
    test_results = run_scenarios(
        policy,
        parse_scenarios(load_document(ROOT / "scenarios" / "default-scenarios.json")),
        generated_at=FIXED_TIME,
    )

    _validate("policy-review-v1alpha1.schema.json", policy_review)
    _validate("test-results-v1alpha1.schema.json", test_results)


@pytest.mark.parametrize(
    ("schema_name", "artifact_factory"),
    [
        (
            "bundle-diff-v1alpha3.schema.json",
            lambda: _bundle_diff(),
        ),
        (
            "trace-review-v1alpha1.schema.json",
            lambda: _trace_review(),
        ),
        (
            "mcp-profile-review-v1alpha1.schema.json",
            lambda: _mcp_profile_review(),
        ),
        (
            "mcp-tool-inventory-v1alpha1.schema.json",
            lambda: _mcp_tool_inventory(),
        ),
        (
            "mcp-manifest-scaffold-v1alpha1.schema.json",
            lambda: _mcp_manifest_scaffold(),
        ),
        (
            "framework-inventory-v1alpha1.schema.json",
            lambda: _framework_inventory(),
        ),
    ],
)
def test_real_generated_artifacts_conform_to_their_published_schemas(
    schema_name: str, artifact_factory: Any
) -> None:
    """Every supported local generator has an exact published structural contract."""

    artifact = artifact_factory()

    _validate(schema_name, artifact)
    artifact["unexpected"] = True
    with pytest.raises(JsonSchemaValidationError, match="Additional properties"):
        _validate(schema_name, artifact)


def test_unsigned_statement_conforms_to_its_published_schema(tmp_path: Path) -> None:
    """The unsigned local statement keeps the attestation integrity envelope schema-valid."""

    manifest, policy = _manifest_and_policy()
    bundle_path = write_json(
        tmp_path / "bundle.json", build_bundle(manifest, policy, generated_at=FIXED_TIME)
    )
    test_results_path = write_json(
        tmp_path / "test-results.json",
        run_scenarios(
            policy,
            parse_scenarios(load_document(ROOT / "scenarios" / "default-scenarios.json")),
            generated_at=FIXED_TIME,
        ),
    )
    statement = build_unsigned_statement(
        build_attestation(
            bundle_path,
            test_results_path,
            source_revision="schema-coverage",
            generated_at=FIXED_TIME,
        )
    )

    _validate("unsigned-statement-v1alpha1.schema.json", statement)


def _bundle_diff() -> dict[str, Any]:
    manifest, policy = _manifest_and_policy()
    bundle = build_bundle(manifest, policy, generated_at=FIXED_TIME)
    return diff_bundles(bundle, bundle, generated_at=FIXED_TIME)


def _trace_review() -> dict[str, Any]:
    manifest, policy = _manifest_and_policy()
    return review_trace(
        manifest,
        policy,
        load_document(ROOT / "examples" / "traces" / "clear-support-trace.json"),
        generated_at=FIXED_TIME,
    )


def _mcp_profile_review() -> dict[str, Any]:
    manifest, _ = _manifest_and_policy()
    profile = parse_mcp_profile(
        load_document(ROOT / "examples" / "mcp-profiles" / "clear-support-profile.json")
    )
    return review_mcp_profile(profile, manifest, generated_at=FIXED_TIME)


def _mcp_tool_inventory() -> dict[str, Any]:
    return normalize_mcp_tools_list(
        load_document(ROOT / "examples" / "mcp-tools" / "support-tools-list.json")
    )


def _mcp_manifest_scaffold() -> dict[str, Any]:
    return build_manifest_scaffold(_mcp_tool_inventory())


def _framework_inventory() -> dict[str, Any]:
    return normalize_framework_declaration(
        "langgraph",
        load_document(ROOT / "examples" / "frameworks" / "langgraph.json"),
    )
