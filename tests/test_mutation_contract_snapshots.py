"""Exact deterministic artifact snapshots for mutation-sensitive public contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from trustweave.chain import render_chain_review, review_declared_chains
from trustweave.cli import main
from trustweave.diff import diff_bundles
from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation
from trustweave.findings import parse_finding
from trustweave.io import canonical_json, load_document, write_json
from trustweave.mcp_profile import parse_mcp_profile, review_mcp_profile
from trustweave.models import parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.risk import review_risks
from trustweave.sarif import build_sarif
from trustweave.scenarios import parse_scenarios, run_scenarios

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "mutation-contracts"
MANIFEST_PATH = ROOT / "examples" / "support-agent.manifest.json"
POLICY_PATH = ROOT / "policies" / "default-policy.json"
FIXED_TIME = "2026-08-15T00:00:00+00:00"


def _snapshot(name: str, value: dict[str, Any]) -> None:
    """Compare a public deterministic artifact with its checked-in canonical fixture."""

    assert canonical_json(value) + "\n" == (FIXTURES / f"{name}.json").read_text(encoding="utf-8")


def _manifest_and_policy() -> tuple[Any, Any]:
    return parse_manifest(load_document(MANIFEST_PATH)), parse_policy(load_document(POLICY_PATH))


def test_core_generated_artifacts_match_deterministic_contract_snapshots() -> None:
    """Core scan, test, policy-review, diff, and chain outputs retain exact public semantics."""

    manifest, policy = _manifest_and_policy()
    bundle = build_bundle(manifest, policy, generated_at=FIXED_TIME)
    _snapshot("bundle", bundle)
    _snapshot(
        "scenarios",
        run_scenarios(
            policy,
            parse_scenarios(load_document(ROOT / "scenarios" / "default-scenarios.json")),
            generated_at=FIXED_TIME,
        ),
    )
    policy_artifact = review_policy(policy, generated_at=FIXED_TIME, include_coverage=True)
    _snapshot("policy-review", policy_artifact)
    _snapshot("bundle-diff", diff_bundles(bundle, bundle, generated_at=FIXED_TIME))
    chain_review = review_declared_chains(
        {
            "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
            "name": "mutation-chain",
            "nodes": [
                {"id": "inbox", "kind": "source", "trust": "untrusted"},
                {"id": "records", "kind": "data", "classification": "confidential"},
                {"id": "email", "kind": "sink", "action_class": "external"},
            ],
            "edges": [
                {"from": "inbox", "to": "records"},
                {"from": "records", "to": "email"},
            ],
        },
        generated_at=FIXED_TIME,
    )
    _snapshot("chain-review", chain_review)
    _snapshot("chain-review-render", {"report": render_chain_review(chain_review)})


def test_review_and_sarif_artifacts_match_deterministic_contract_snapshots() -> None:
    """Risk, MCP, findings, and SARIF output retain exact local evidence fields and limits."""

    manifest, policy = _manifest_and_policy()
    policy_artifact = review_policy(policy, generated_at=FIXED_TIME, include_coverage=True)
    risk_artifact = review_risks(
        [policy_artifact],
        reviewed_at=FIXED_TIME,
        artifact_paths=["artifacts/policy-review.json"],
    )
    _snapshot("risk-review", risk_artifact)
    profile = parse_mcp_profile(
        load_document(ROOT / "examples" / "mcp-profiles" / "clear-support-profile.json")
    )
    _snapshot("mcp-profile-review", review_mcp_profile(profile, manifest, generated_at=FIXED_TIME))
    parsed_finding = parse_finding(
        {
            "id": "TW-SNAPSHOT-001",
            "severity": "high",
            "message": "A declared snapshot finding requires local review.",
            "evidence_kind": "declared_configuration",
            "subject": {"source": "customer_request", "tool": "archive"},
            "rationale": "Snapshot contract coverage.",
            "remediation": "Review the declared local boundary.",
        }
    )
    _snapshot("finding", parsed_finding.as_dict())
    _snapshot(
        "sarif",
        build_sarif(
            {
                "policy": ("artifacts/policy-review.json", policy_artifact),
                "risk": ("artifacts/risk-review.json", risk_artifact),
            }
        ),
    )


def test_full_ci_run_matches_deterministic_contract_snapshot(tmp_path: Path) -> None:
    """The configured local coordinator preserves every staged public artifact.

    Fixed provenance makes every rendered output safe for exact contract comparison.
    """

    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    root = ROOT
    manifest = root / "examples" / "support-agent.manifest.json"
    policy = root / "policies" / "default-policy.json"
    scenarios = root / "scenarios" / "default-scenarios.json"
    trace = root / "examples" / "traces" / "clear-support-trace.json"
    chain_manifest = root / "examples" / "chains" / "safe-sanitized-external.chain.json"
    mcp_profile = root / "examples" / "mcp-profiles" / "clear-support-profile.json"
    config.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{manifest.as_posix()}"\n'
        f'policy = "{policy.as_posix()}"\n'
        f'scenarios = "{scenarios.as_posix()}"\n'
        f'trace = "{trace.as_posix()}"\n'
        f'chain_manifest = "{chain_manifest.as_posix()}"\n'
        f'mcp_profile = "{mcp_profile.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'sarif_output = "sarif/trustweave.sarif"\n'
        'failure_threshold = "none"\n'
        'enabled_stages = ["validate", "scan", "scenarios", "policy_review", "policy_coverage", '
        '"trace_review", "mcp_profile_review", "chain_review", "risk", "sarif", "attestation", '
        '"report", "summary"]\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    arguments = [
        "--generated-at",
        FIXED_TIME,
        "ci",
        "--config",
        str(config),
        "--source-revision",
        "mutation-contract-snapshot",
        "--quiet",
    ]
    assert main(arguments) == 0
    files = {
        path.relative_to(output_dir).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(output_dir.rglob("*"))
        if path.is_file()
    }
    _snapshot("ci-artifacts", {"files": files})


def test_attestation_matches_deterministic_contract_snapshot(tmp_path: Path) -> None:
    """The local v1alpha3 integrity envelope is deterministic for fixed evidence and provenance."""

    manifest, policy = _manifest_and_policy()
    bundle_path = write_json(
        tmp_path / "bundle.json", build_bundle(manifest, policy, generated_at=FIXED_TIME)
    )
    results_path = write_json(
        tmp_path / "results.json",
        run_scenarios(
            policy,
            parse_scenarios(load_document(ROOT / "scenarios" / "default-scenarios.json")),
            generated_at=FIXED_TIME,
        ),
    )
    _snapshot(
        "attestation",
        build_attestation(
            bundle_path,
            results_path,
            source_revision="mutation-contract-snapshot",
            generated_at=FIXED_TIME,
            bundle_name="bundle.json",
            test_results_name="results.json",
        ),
    )


def test_all_supported_ci_stages_match_deterministic_contract_snapshot(tmp_path: Path) -> None:
    """Every configured local stage preserves deterministic artifacts and decision inputs.

    This includes diff and risk-decision paths that the core successful CI snapshot does not select.
    """

    manifest, policy = _manifest_and_policy()
    generated_bundle = build_bundle(manifest, policy, generated_at=FIXED_TIME)
    base_bundle = write_json(tmp_path / "base-bundle.json", generated_bundle)
    candidate_bundle = write_json(tmp_path / "candidate-bundle.json", generated_bundle)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        '{"schema_version":"trustweave.dev/risk-baseline/v1alpha2","baseline":[]}',
        encoding="utf-8",
    )
    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(
        '{"schema_version":"trustweave.dev/risk-suppressions/v1alpha2","suppressions":[]}',
        encoding="utf-8",
    )
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    scenarios = ROOT / "scenarios" / "default-scenarios.json"
    trace = ROOT / "examples" / "traces" / "clear-support-trace.json"
    mcp_profile = ROOT / "examples" / "mcp-profiles" / "clear-support-profile.json"
    chain_manifest = ROOT / "examples" / "chains" / "safe-sanitized-external.chain.json"
    stages = (
        "validate",
        "scan",
        "scenarios",
        "policy_review",
        "policy_coverage",
        "diff",
        "trace_review",
        "mcp_profile_review",
        "chain_review",
        "risk",
        "sarif",
        "attestation",
        "report",
        "summary",
    )
    stage_list = ", ".join(f'"{stage}"' for stage in stages)
    config.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{MANIFEST_PATH.as_posix()}"\n'
        f'policy = "{POLICY_PATH.as_posix()}"\n'
        f'scenarios = "{scenarios.as_posix()}"\n'
        f'baseline_bundle = "{base_bundle.as_posix()}"\n'
        f'candidate_bundle = "{candidate_bundle.as_posix()}"\n'
        f'trace = "{trace.as_posix()}"\n'
        f'mcp_profile = "{mcp_profile.as_posix()}"\n'
        f'chain_manifest = "{chain_manifest.as_posix()}"\n'
        f'risk_baseline = "{baseline.as_posix()}"\n'
        f'suppressions = "{suppressions.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'sarif_output = "nested reports/trustweave.sarif"\n'
        'failure_threshold = "none"\n'
        f"enabled_stages = [{stage_list}]\n"
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                FIXED_TIME,
                "ci",
                "--config",
                str(config),
                "--source-revision",
                "mutation-contract-snapshot",
                "--coverage",
                "--quiet",
            ]
        )
        == 0
    )
    files = {
        path.relative_to(output_dir).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(output_dir.rglob("*"))
        if path.is_file()
    }
    _snapshot("ci-all-stages-artifacts", {"files": files})
