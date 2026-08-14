from __future__ import annotations

import json
import tomllib
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trustweave import __version__
from trustweave.cli import main
from trustweave.engine import build_bundle, evaluate_flow, evaluate_manifest
from trustweave.evidence import build_attestation, verify_attestation
from trustweave.io import load_document, read_json, write_json
from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.provenance import stable_document_hash
from trustweave.scenarios import parse_scenarios, run_scenarios

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
SCENARIOS = ROOT / "scenarios" / "default-scenarios.json"


def test_import_version_matches_declared_project_version() -> None:
    with (ROOT / "pyproject.toml").open("rb") as project_file:
        metadata = tomllib.load(project_file)

    assert __version__ == metadata["project"]["version"]


def test_example_manifest_and_policy_produce_expected_boundary_decisions() -> None:
    manifest = parse_manifest(load_document(MANIFEST))
    policy = parse_policy(load_document(POLICY))

    findings = evaluate_manifest(manifest, policy)

    assert [finding.decision for finding in findings] == [
        "allow",
        "deny",
        "require_approval",
        "deny",
    ]
    assert [finding.rule_id for finding in findings] == ["TW-001", None, "TW-002", "TW-004"]
    assert [finding.rationale for finding in findings] == [
        "Authenticated synthetic requests may invoke declared read-only retrieval paths.",
        "No policy rule matched this declared path; the default decision was applied.",
        (
            "Confidential synthetic records may influence an external mock action only with "
            "explicit human review."
        ),
        "Untrusted retrieved content must not cause outbound or business-impacting actions.",
    ]


def test_unmatched_declared_path_returns_explicit_default_rationale() -> None:
    manifest = parse_manifest(load_document(MANIFEST))
    policy = parse_policy(load_document(POLICY))
    conditional_source = next(
        source for source in manifest.sources if source.trust == "conditional"
    )
    read_tool = next(tool for tool in manifest.tools if tool.action_class == "read")

    finding = evaluate_flow(manifest.flows[0], conditional_source, read_tool, policy)

    assert finding.decision == "deny"
    assert finding.rule_id is None
    assert finding.rationale == (
        "No policy rule matched this declared path; the default decision was applied."
    )


def test_scenarios_pass_against_example_policy() -> None:
    policy = parse_policy(load_document(POLICY))
    scenarios = parse_scenarios(load_document(SCENARIOS))

    results = run_scenarios(policy, scenarios)

    assert results["summary"] == {"total": 5, "passed": 5, "failed": 0, "status": "passed"}


def test_manifest_rejects_unknown_flow_source() -> None:
    document = dict(load_document(MANIFEST))
    flows = list(document["flows"])
    invalid_flow = dict(flows[0])
    invalid_flow["source"] = "missing_source"
    flows[0] = invalid_flow
    document["flows"] = flows

    with pytest.raises(ValidationError, match="unknown source"):
        parse_manifest(document)


def test_bundle_contains_summary_and_explicit_limits() -> None:
    manifest = parse_manifest(load_document(MANIFEST))
    policy = parse_policy(load_document(POLICY))

    bundle = build_bundle(manifest, policy, generated_at="2026-08-13T00:00:00+00:00")

    assert bundle["schema_version"] == "trustweave.dev/bundle/v1alpha1"
    generated_at = datetime.fromisoformat(bundle["generated_at"])
    assert generated_at.tzinfo == UTC
    assert bundle["manifest"] == manifest.as_dict()
    assert bundle["policy"] == {
        "schema_version": policy.schema_version,
        "name": policy.name,
        "default_decision": policy.default_decision,
        "rules": [
            {
                key: list(value) if isinstance(value, tuple) else value
                for key, value in asdict(rule).items()
            }
            for rule in policy.rules
        ],
    }
    assert [finding["decision"] for finding in bundle["findings"]] == [
        "allow",
        "deny",
        "require_approval",
        "deny",
    ]
    assert bundle["summary"] == {"allow": 1, "deny": 2, "require_approval": 1}
    assert bundle["limits"] == [
        "The bundle reflects declared architecture only; it does not discover or execute tools.",
        (
            "The bundle applies deterministic local rules; it does not establish security "
            "of a deployed system."
        ),
        (
            "No model output, credential, network traffic, or external system was analyzed "
            "to create this bundle."
        ),
    ]


def test_builders_are_pure_and_stable_hashes_exclude_volatile_provenance() -> None:
    manifest = parse_manifest(load_document(MANIFEST))
    policy = parse_policy(load_document(POLICY))

    stable_bundle = build_bundle(manifest, policy)
    assert "generated_at" not in stable_bundle
    assert stable_bundle == build_bundle(manifest, policy)

    first = build_bundle(manifest, policy, generated_at="2026-08-13T00:00:00+00:00")
    second = build_bundle(manifest, policy, generated_at="2026-08-13T00:00:01+00:00")
    assert stable_document_hash(first) == stable_document_hash(second)


def test_attestation_detects_tampering(tmp_path: Path) -> None:
    manifest = parse_manifest(load_document(MANIFEST))
    policy = parse_policy(load_document(POLICY))
    bundle_path = write_json(
        tmp_path / "agent-security-bundle.json",
        build_bundle(manifest, policy, generated_at="2026-08-13T00:00:00+00:00"),
    )
    results_path = write_json(
        tmp_path / "security-test-results.json",
        run_scenarios(
            policy,
            parse_scenarios(load_document(SCENARIOS)),
            generated_at="2026-08-13T00:00:00+00:00",
        ),
    )

    attestation = build_attestation(
        bundle_path,
        results_path,
        source_revision="test-revision",
        generated_at="2026-08-13T00:00:00+00:00",
    )
    valid, _ = verify_attestation(attestation)
    assert valid

    tampered = json.loads(json.dumps(attestation))
    tampered["predicate"]["source_revision"] = "tampered"
    valid, reason = verify_attestation(tampered)
    assert not valid
    assert "does not match" in reason


def test_cli_end_to_end_writes_and_verifies_artifacts(tmp_path: Path) -> None:
    assert (
        main(
            [
                "scan",
                "--manifest",
                str(MANIFEST),
                "--policy",
                str(POLICY),
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "test",
                "--policy",
                str(POLICY),
                "--scenarios",
                str(SCENARIOS),
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert main(["attest", "--source-revision", "test", "--output-dir", str(tmp_path)]) == 0
    assert main(["report", "--output-dir", str(tmp_path)]) == 0
    assert main(["verify", "--attestation", str(tmp_path / "attestation.json")]) == 0
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "TrustWeave Security Evidence Report" in report
    assert "require_approval" in report
    assert read_json(tmp_path / "security-test-results.json")["summary"]["status"] == "passed"
