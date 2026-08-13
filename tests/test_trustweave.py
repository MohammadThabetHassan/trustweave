from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from trustweave import __version__
from trustweave.cli import main
from trustweave.engine import build_bundle, evaluate_manifest
from trustweave.evidence import build_attestation, verify_attestation
from trustweave.io import load_document, read_json, write_json
from trustweave.models import ValidationError, parse_manifest, parse_policy
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
    assert findings[-1].rule_id == "TW-004"


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

    bundle = build_bundle(manifest, policy)

    assert bundle["summary"] == {"allow": 1, "deny": 2, "require_approval": 1}
    assert len(bundle["limits"]) == 3


def test_attestation_detects_tampering(tmp_path: Path) -> None:
    manifest = parse_manifest(load_document(MANIFEST))
    policy = parse_policy(load_document(POLICY))
    bundle_path = write_json(
        tmp_path / "agent-security-bundle.json", build_bundle(manifest, policy)
    )
    results_path = write_json(
        tmp_path / "security-test-results.json",
        run_scenarios(policy, parse_scenarios(load_document(SCENARIOS))),
    )

    attestation = build_attestation(bundle_path, results_path, source_revision="test-revision")
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
