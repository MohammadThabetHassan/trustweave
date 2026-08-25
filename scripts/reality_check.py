#!/usr/bin/env python3
"""Validate that TrustWeave documentation and local repository contracts are real and connected."""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import venv
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from trustweave.cli import _parser
from trustweave.cli import main as cli_main
from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation
from trustweave.findings import finding
from trustweave.io import load_document, write_json
from trustweave.models import parse_manifest, parse_policy
from trustweave.rules import RULES

try:
    import yaml
except ImportError as error:  # pragma: no cover - CI installs the optional dev dependency.
    raise SystemExit("PyYAML is required for repository reality checks.") from error

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)\s]+)(?:\s+[^)]*)?\)")
PINNED_ACTION = re.compile(r"^\s*uses:\s+[A-Za-z0-9._/-]+@[0-9a-f]{40}(?:\s+#\s+\S+)?\s*$")
PUBLIC_ASSETS = (
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "CODE_OF_CONDUCT.md",
    "GOVERNANCE.md",
    "LICENSE",
    "CITATION.cff",
    ".github/CODEOWNERS",
    "docs/SUPPLY_CHAIN.md",
    "docs/ASSURANCE.md",
    "docs/COMPATIBILITY.md",
    "docs/SUPPORT_POLICY.md",
    "docs/adr/ADR-0005-PACKAGE-RELEASE-PROVENANCE.md",
    "docs/GOLDEN_EVIDENCE.md",
    "docs/CONTROL_TRACEABILITY.md",
    "docs/DISTRIBUTION_ASSURANCE.md",
    "docs/RESOURCE_BOUNDS.md",
    "docs/PACKAGE_PROVENANCE.md",
    "docs/archive/RELEASE_CANDIDATE_0.3.1.md",
    "docs/archive/GITHUB_GOVERNANCE_DECISION.md",
    "docs/EXTERNAL_ASSESSMENT.md",
    "docs/SAFE_EXTERNAL_REPRODUCTION.md",
    "docs/EXTERNAL_COMMUNICATION_CHECKLIST.md",
    "docs/evaluation/EVALUATION_CHARTER.md",
    "docs/evaluation/REVIEWER_PROTOCOL.md",
    "docs/evaluation/DATA_MINIMIZATION_POLICY.md",
    "docs/evaluation/CONFLICTS_AND_LIMITATIONS.md",
    "docs/evaluation/STATUS.md",
    "docs/evaluation/CORPUS_LIFECYCLE.md",
    "docs/evaluation/REVIEWER_QUICKSTART.md",
    "docs/evaluation/ARTIFACT_ARCHIVE_READINESS.md",
    "docs/evaluation/artifact-allowlist.json",
    "docs/COMMUNITY_FEEDBACK.md",
    "docs/ISSUE_TRIAGE.md",
    "docs/site/EVALUATION.md",
    "docs/site/CURRENT_EVIDENCE.md",
    "examples/evaluation-corpus/corpus.json",
    "examples/evaluation-corpus/reviewer-packet/README.md",
    "examples/evaluation-corpus/reviewer-packet/FEEDBACK_TEMPLATE.md",
    "examples/evaluation-corpus/reviewer-packet/OUTREACH_INVITATION_DRAFT.md",
    "examples/evaluation-corpus/reviewer-packet/RESULT_RECORD_TEMPLATE.md",
    "scripts/run_evaluation_corpus.py",
    "scripts/build_evaluation_artifact.py",
)
REQUIRED_ISSUE_FORMS = (
    ".github/ISSUE_TEMPLATE/01-bug-report.yml",
    ".github/ISSUE_TEMPLATE/02-feature-request.yml",
    ".github/ISSUE_TEMPLATE/03-evaluation-feedback.yml",
)
REQUIRED_README_MARKERS = (
    "python -m pip install --upgrade trustweave",
    "python -m trustweave --help",
    "[Developer integration routes](docs/site/INTEGRATIONS.md)",
    "[SUPPORT.md](SUPPORT.md)",
    "[SECURITY.md](SECURITY.md)",
    "[CONTRIBUTING.md](CONTRIBUTING.md)",
    "docs/evaluation/EVALUATION_CHARTER.md",
    "docs/site/CURRENT_EVIDENCE.md",
    "## How the local evidence workflow fits together",
    "### Example policy decision matrix",
    "**first matching rule wins**",
)
ADVERSARIAL_SCENARIO_PATH = ROOT / "scenarios" / "adversarial-scenarios.json"
QUALITY_GUIDE_PATH = ROOT / "docs" / "QUALITY.md"
MUTATION_RECORD_PATH = ROOT / "docs" / "MUTATION_TESTING.md"
REPRODUCIBILITY_RECORD_PATH = ROOT / "docs" / "REPRODUCIBILITY.md"
RELEASE_REPRODUCIBILITY_HELPER_PATH = ROOT / "scripts" / "verify_release_reproducibility.py"
ASSURANCE_CONTRACT_HELPER_PATH = ROOT / "scripts" / "verify_assurance_contracts.py"
GOLDEN_EVIDENCE_HELPER_PATH = ROOT / "scripts" / "verify_golden_evidence.py"
TRACEABILITY_HELPER_PATH = ROOT / "scripts" / "verify_control_traceability.py"
DISTRIBUTION_ASSURANCE_HELPER_PATH = ROOT / "scripts" / "verify_distribution_artifacts.py"
PACKAGE_PROVENANCE_HELPER_PATH = ROOT / "scripts" / "verify_package_provenance_controls.py"
RULE_PRODUCER_PATHS = (
    ROOT / "src" / "trustweave" / "chain.py",
    ROOT / "src" / "trustweave" / "diff.py",
    ROOT / "src" / "trustweave" / "mcp_profile.py",
    ROOT / "src" / "trustweave" / "policy_review.py",
    ROOT / "src" / "trustweave" / "trace_review.py",
)
RULE_IDENTIFIER = re.compile(r'"(TW-[A-Z0-9-]+)"')
MUTATION_RECORD_MARKERS = (
    "`mutmut 3.7.0`",
    "6,691 generated mutants; 6,565 killed; 126 survived; 0 without a selected test; "
    "0 timed out; 0 suspicious.",
    "98.12% killed (`6,565 / 6,691`)",
    "Linux with fork support",
    "**95% mutation threshold** for the measured high-risk scope",
    "126 classified survivors",
    "0 untriaged survivors",
    "126 equivalent mutations",
    "0 defensive mutations",
    "0 mutations marked `needs_regression`",
    "release-blocking quality check",
)
GENERATED_ARTIFACT_SCHEMA_CONTRACTS: dict[str, tuple[str, str]] = {
    "agent-security-bundle-v1alpha2.schema.json": (
        "trustweave.dev/bundle/v1alpha2",
        "src/trustweave/bundles.py",
    ),
    "attestation-v1alpha3.schema.json": (
        "trustweave.dev/attestation/v1alpha3",
        "src/trustweave/evidence.py",
    ),
    "bundle-diff-v1alpha3.schema.json": (
        "trustweave.dev/bundle-diff/v1alpha3",
        "src/trustweave/diff.py",
    ),
    "chain-review-v1alpha1.schema.json": (
        "trustweave.dev/chain-review/v1alpha1",
        "src/trustweave/chain.py",
    ),
    "ci-summary-v1alpha1.schema.json": (
        "trustweave.dev/ci-summary/v1alpha1",
        "src/trustweave/commands/ci.py",
    ),
    "framework-inventory-v1alpha1.schema.json": (
        "trustweave.dev/framework-inventory/v1alpha1",
        "src/trustweave/framework_import.py",
    ),
    "mcp-manifest-scaffold-v1alpha1.schema.json": (
        "trustweave.dev/mcp-manifest-scaffold/v1alpha1",
        "src/trustweave/mcp_import.py",
    ),
    "mcp-profile-review-v1alpha1.schema.json": (
        "trustweave.dev/mcp-profile-review/v1alpha1",
        "src/trustweave/mcp_profile.py",
    ),
    "mcp-tool-inventory-v1alpha1.schema.json": (
        "trustweave.dev/mcp-tool-inventory/v1alpha1",
        "src/trustweave/mcp_import.py",
    ),
    "policy-explanation-v1alpha1.schema.json": (
        "trustweave.dev/policy-explanation/v1alpha1",
        "src/trustweave/engine.py",
    ),
    "policy-review-v1alpha1.schema.json": (
        "trustweave.dev/policy-review/v1alpha1",
        "src/trustweave/policy_review.py",
    ),
    "risk-baseline-v1alpha2.schema.json": (
        "trustweave.dev/risk-baseline/v1alpha2",
        "src/trustweave/risk.py",
    ),
    "risk-review-v1alpha2.schema.json": (
        "trustweave.dev/risk-review/v1alpha2",
        "src/trustweave/risk.py",
    ),
    "test-results-v1alpha1.schema.json": (
        "trustweave.dev/test-results/v1alpha1",
        "src/trustweave/scenarios.py",
    ),
    "trace-review-v1alpha1.schema.json": (
        "trustweave.dev/trace-review/v1alpha1",
        "src/trustweave/trace_review.py",
    ),
    "unsigned-statement-v1alpha1.schema.json": (
        "trustweave.dev/unsigned-statement/v1alpha1",
        "src/trustweave/statement.py",
    ),
}
CURRENT_CONTRACT_DOCUMENTATION: dict[str, tuple[str, ...]] = {
    "README.md": (
        "trustweave.dev/bundle/v1alpha2",
        "trustweave/fingerprint/v3",
        "95% branch coverage",
        "--bundle artifacts/agent-security-bundle.json",
        "checks only the statement’s internal consistency",
    ),
    "docs/CLI_REFERENCE.md": (
        "trustweave/fingerprint/v3",
        "trustweave.dev/risk-review/v1alpha2",
        "risk-baseline/v1alpha2",
        "Recommended exact-file verification",
        "statement-only result does not establish",
    ),
    "docs/CONFIGURATION.md": (
        "baseline_bundle",
        "candidate_bundle",
        "sarif_output",
        "chain_review",
    ),
    "docs/QUALITY.md": (
        "95% branch coverage",
        "exact survivor-identifier parity",
        "zero `needs_regression` classifications",
    ),
    "docs/SCHEMA_AND_COMPATIBILITY.md": (
        "trustweave.dev/bundle/v1alpha2",
        "trustweave.dev/bundle-diff/v1alpha3",
        "trustweave.dev/risk-review/v1alpha2",
        "agent-security-bundle-v1alpha2.schema.json",
        "bundle-diff-v1alpha3.schema.json",
        "risk-review-v1alpha2.schema.json",
    ),
    "docs/RISK_MANAGEMENT.md": (
        "trustweave/fingerprint/v3",
        "not_yet_applicable_baseline",
        "risk-review/v1alpha2",
    ),
    "docs/site/SCHEMAS.md": (
        "trustweave.dev/bundle/v1alpha2",
        "trustweave.dev/bundle-diff/v1alpha3",
        "trustweave.dev/risk-review/v1alpha2",
    ),
    "docs/site/CURRENT_EVIDENCE.md": (
        "0.3.1",
        "0.3.0",
        "98.12%",
        "not yet collected",
        "does **not** establish",
    ),
    "docs/evaluation/CORPUS_LIFECYCLE.md": (
        "trustweave.dev/evaluation-corpus/v1alpha1",
        "TW-EVAL-001",
        "python scripts/run_evaluation_corpus.py --check",
        "independent evaluation result",
    ),
    "docs/site/EVALUATION.md": (
        "twelve checked-in synthetic cases",
        "not yet collected",
        "attack prevention",
    ),
    "docs/evaluation/REVIEWER_QUICKSTART.md": (
        "python scripts/run_evaluation_corpus.py --check",
        "python scripts/run_evaluation_corpus.py --verify",
        "cannot establish source authenticity",
        "must not be described as a study response",
    ),
    "docs/evaluation/ARTIFACT_ARCHIVE_READINESS.md": (
        "A durable archive URL or DOI has not yet been recorded.",
        "SHA-256",
        "human maintainer has reviewed it",
        "python scripts/build_evaluation_artifact.py",
        "performs no network request, upload, archive-service action",
    ),
    "docs/ISSUE_TRIAGE.md": (
        "must not be processed through a public issue",
        "not an independently collected reviewer-study result",
        "automatic merge",
    ),
    "docs/archive/MAINTAINER_HANDOFF.md": (
        "Evaluation corpus and feedback status:",
        "Public Issue Triage Procedure",
    ),
    "docs/archive/GITHUB_GOVERNANCE_DECISION.md": (
        "Current observed baseline",
        "Choose one maintenance profile",
        "Do not claim a branch-protection rule",
    ),
    "docs/EXTERNAL_ASSESSMENT.md": (
        "manual only",
        "no claim",
        "Published externally by this workflow: no",
    ),
    "docs/archive/RELEASE_CANDIDATE_0.3.1.md": (
        "Prepared source candidate; not published.",
        "The last observed public package release is `0.3.0`",
        "TrustWeave 0.3.1 is released",
    ),
    "docs/SAFE_EXTERNAL_REPRODUCTION.md": (
        "It is a reproducibility path, not a security test",
        "Do not point it at a live agent",
        "It cannot support",
    ),
    "docs/EXTERNAL_COMMUNICATION_CHECKLIST.md": (
        "not an authorization to publish or contact anyone",
        "No result is framed as a certification",
        "A successful CI job, prepared document, public issue, or synthetic test result",
    ),
    "examples/evaluation-corpus/reviewer-packet/README.md": (
        "prepared, not yet executed",
        "Participation is optional.",
        "does not establish runtime enforcement",
    ),
}
MUTATION_SOURCE_SCOPE = [
    "src/trustweave/engine.py",
    "src/trustweave/models.py",
    "src/trustweave/policy_predicates.py",
    "src/trustweave/policy_review.py",
    "src/trustweave/chain.py",
    "src/trustweave/findings.py",
    "src/trustweave/risk.py",
    "src/trustweave/evidence.py",
    "src/trustweave/config.py",
    "src/trustweave/schema_catalog.py",
    "src/trustweave/sarif.py",
    "src/trustweave/commands/ci.py",
    "src/trustweave/bundle_policy.py",
    "src/trustweave/policy_weakening.py",
]
REPRODUCIBILITY_RECORD_MARKERS = (
    "Clean-checkout staged-CI release verification",
    "scripts/verify_release_reproducibility.py",
    "must not depend on a tracked root `trustweave.toml`",
    "safe-sanitized-external.chain.json",
    "Both ten-file output trees have exactly the same relative paths and byte content",
    "Each generated v1alpha3 attestation",
    "does not prove reproducibility across operating systems",
)
CHANGELOG_VERSION_HEADING = re.compile(r"^## \[([^\]]+)\]", re.MULTILINE)


def _declared_project_version() -> str | None:
    """Return the package version from the build metadata, if structurally valid."""

    with (ROOT / "pyproject.toml").open("rb") as project_file:
        project = tomllib.load(project_file)
    version = project.get("project", {}).get("version")
    return version if isinstance(version, str) and version else None


def _check_schema_resource_synchronization() -> list[str]:
    """Require published schemas and packaged schema resources to remain byte-identical."""

    failures: list[str] = []
    source_schemas = {path.name: path for path in (ROOT / "schemas").glob("*.schema.json")}
    packaged_schemas = {
        path.name: path for path in (ROOT / "src" / "trustweave" / "schemas").glob("*.schema.json")
    }
    for name in sorted(set(source_schemas) - set(packaged_schemas)):
        failures.append(f"Published schema is missing from package resources: schemas/{name}")
    for name in sorted(set(packaged_schemas) - set(source_schemas)):
        failures.append(f"Packaged schema lacks a matching published source resource: {name}")
    for name in sorted(set(source_schemas) & set(packaged_schemas)):
        if source_schemas[name].read_bytes() != packaged_schemas[name].read_bytes():
            failures.append(f"Published and packaged schema resources differ: {name}")
    return failures


def _check_generated_artifact_schema_coverage() -> list[str]:
    """Require every documented emitted artifact version to have its exact public contract."""

    failures: list[str] = []
    for schema_name, (version, producer) in sorted(GENERATED_ARTIFACT_SCHEMA_CONTRACTS.items()):
        schema_path = ROOT / "schemas" / schema_name
        producer_path = ROOT / producer
        if not schema_path.is_file():
            failures.append(f"Generated artifact lacks a published schema: schemas/{schema_name}")
            continue
        if not producer_path.is_file() or version not in producer_path.read_text(encoding="utf-8"):
            failures.append(
                f"Generated artifact schema contract is not linked to its producer: {producer}"
            )
            continue
        try:
            schema: Any = json.loads(schema_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            failures.append(f"Generated artifact schema is invalid JSON: {schema_name}: {error}")
            continue
        actual_version = schema.get("properties", {}).get("schema_version", {}).get("const")
        if actual_version != version:
            failures.append(
                f"Generated artifact schema version differs from producer contract: {schema_name}"
            )
    return failures


def _check_json_documents() -> list[str]:
    failures: list[str] = []
    for path in sorted((ROOT / "schemas").glob("*.json")):
        try:
            parsed: Any = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            failures.append(f"Invalid JSON schema {path.relative_to(ROOT)}: {error}")
            continue
        if not isinstance(parsed, dict) or "$schema" not in parsed:
            failures.append(f"Schema {path.relative_to(ROOT)} lacks a top-level $schema field")
    return failures


def _check_generated_artifact_schemas() -> list[str]:
    """Validate actual deterministic output against the public structural schemas."""

    failures: list[str] = []
    manifest = parse_manifest(load_document(ROOT / "examples" / "support-agent.manifest.json"))
    policy = parse_policy(load_document(ROOT / "policies" / "default-policy.json"))
    bundle = build_bundle(manifest, policy, generated_at="2026-08-14T00:00:00+00:00")
    emitted_finding = finding(
        "TW-REALITY-001",
        "review",
        "A local declared-evidence observation.",
        "declared_configuration",
        subject={"source": "customer_message", "tool": "send_mock_email"},
    )
    generated: list[tuple[str, dict[str, Any]]] = [
        ("agent-security-bundle-v1alpha2.schema.json", bundle),
        ("finding-v1alpha1.schema.json", emitted_finding),
    ]
    with tempfile.TemporaryDirectory(prefix="trustweave-reality-") as temporary_directory:
        temporary_path = Path(temporary_directory).resolve()
        bundle_path = write_json(temporary_path / "bundle.json", bundle)
        test_results_path = write_json(
            temporary_path / "test-results.json",
            {
                "schema_version": "trustweave.dev/test-results/v1alpha1",
                "summary": {"status": "passed"},
            },
        )
        generated.append(
            (
                "attestation-v1alpha3.schema.json",
                build_attestation(
                    bundle_path,
                    test_results_path,
                    source_revision="reality-check",
                    generated_at="2026-08-14T00:00:00+00:00",
                ),
            )
        )
        output_directory = temporary_path / "ci-artifacts"
        stages = ("scan", "scenarios", "policy_review", "attestation", "report", "summary")
        rendered_stages = ", ".join(f'"{stage}"' for stage in stages)
        config_path = temporary_path / "trustweave.toml"
        config_path.write_text(
            "[tool.trustweave]\n"
            f'manifest = "{(ROOT / "examples/support-agent.manifest.json").as_posix()}"\n'
            f'policy = "{(ROOT / "policies/default-policy.json").as_posix()}"\n'
            f'scenarios = "{(ROOT / "scenarios/default-scenarios.json").as_posix()}"\n'
            f'output_dir = "{output_directory.as_posix()}"\n'
            f"enabled_stages = [{rendered_stages}]\n"
            'failure_threshold = "none"\n'
            "reproducible = true\n",
            encoding="utf-8",
        )
        if (
            cli_main(
                [
                    "--generated-at",
                    "2026-08-14T00:00:00+00:00",
                    "ci",
                    "--config",
                    str(config_path),
                    "--source-revision",
                    "reality-check",
                    "--quiet",
                ]
            )
            != 0
        ):
            failures.append("Could not generate fixed-provenance CI summary for schema validation")
        else:
            generated.append(
                (
                    "ci-summary-v1alpha1.schema.json",
                    dict(load_document(output_directory / "ci-summary.json")),
                )
            )

    for schema_name, artifact in generated:
        schema_path = ROOT / "schemas" / schema_name
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for error in sorted(validator.iter_errors(artifact), key=lambda issue: list(issue.path)):
            location = ".".join(str(part) for part in error.path) or "<root>"
            failures.append(
                f"Generated artifact violates schemas/{schema_name} at {location}: {error.message}"
            )
    return failures


def _check_contract_examples() -> list[str]:
    """Validate tracked contract examples against their published structural schemas."""

    failures: list[str] = []
    contracts = (
        ("agent-manifest.schema.json", sorted((ROOT / "examples").glob("*.manifest.json"))),
        ("policy.schema.json", sorted((ROOT / "policies").glob("*.json"))),
        ("trace.schema.json", sorted((ROOT / "examples" / "traces").glob("*.json"))),
        (
            "mcp-profile.schema.json",
            sorted((ROOT / "examples" / "mcp-profiles").glob("*.json")),
        ),
    )
    for schema_name, examples in contracts:
        schema_path = ROOT / "schemas" / schema_name
        if not schema_path.exists():
            failures.append(f"Missing contract schema: schemas/{schema_name}")
            continue
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for example_path in examples:
            document = json.loads(example_path.read_text(encoding="utf-8"))
            errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
            for error in errors:
                location = ".".join(str(part) for part in error.path) or "<root>"
                failures.append(
                    f"Contract example {example_path.relative_to(ROOT)} violates "
                    f"schemas/{schema_name} at {location}: {error.message}"
                )
    return failures


def _check_markdown_links() -> list[str]:
    failures: list[str] = []
    for document in sorted(ROOT.rglob("*.md")):
        if any(part in {".git", "dist", "build", ".wheel-check"} for part in document.parts):
            continue
        for target in MARKDOWN_LINK.findall(document.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            relative_target = target.split("#", maxsplit=1)[0]
            if not relative_target:
                continue
            destination = (document.parent / relative_target).resolve()
            if not destination.exists():
                failures.append(
                    f"Broken local Markdown link in {document.relative_to(ROOT)}: {target}"
                )
    return failures


def _check_workflows() -> list[str]:
    failures: list[str] = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        try:
            parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            failures.append(f"Invalid workflow YAML {path.relative_to(ROOT)}: {error}")
            continue
        if not isinstance(parsed, dict) or not isinstance(parsed.get("jobs"), dict):
            failures.append(f"Workflow {path.relative_to(ROOT)} lacks a jobs mapping")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.lstrip()
            if not stripped.startswith("uses:"):
                continue
            target = stripped.removeprefix("uses:").strip()
            if target.startswith("./"):
                continue
            if not PINNED_ACTION.match(line):
                failures.append(
                    f"Workflow action is not pinned to a full commit SHA: "
                    f"{path.relative_to(ROOT)}:{line_number}"
                )
    return failures


def _check_manual_scorecard_workflow() -> list[str]:
    """Require the owner-approved assessment path to remain manual and non-publishing."""

    failures: list[str] = []
    relative_path = ".github/workflows/scorecard.yml"
    path = ROOT / relative_path
    if not path.is_file():
        return [f"Missing manual Scorecard workflow: {relative_path}"]
    try:
        workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        return [f"Invalid manual Scorecard workflow: {error}"]
    if not isinstance(workflow, dict):
        return ["Manual Scorecard workflow must be a YAML mapping"]

    triggers = workflow.get("on")
    if not isinstance(triggers, dict) or set(triggers) != {"workflow_dispatch"}:
        failures.append("Manual Scorecard workflow must use workflow_dispatch as its only trigger")
    dispatch = triggers.get("workflow_dispatch") if isinstance(triggers, dict) else None
    inputs = dispatch.get("inputs") if isinstance(dispatch, dict) else None
    reason = inputs.get("reason") if isinstance(inputs, dict) else None
    if not isinstance(reason, dict) or reason.get("required") != "true":
        failures.append("Manual Scorecard workflow requires an owner-recorded reason input")

    if workflow.get("permissions") != {"contents": "read"}:
        failures.append("Manual Scorecard workflow must use only contents: read permissions")
    jobs = workflow.get("jobs")
    analysis = jobs.get("analysis") if isinstance(jobs, dict) else None
    if not isinstance(analysis, dict):
        return failures + ["Manual Scorecard workflow lacks its analysis job"]
    if "permissions" in analysis:
        failures.append("Manual Scorecard analysis job must not add elevated permissions")
    steps = analysis.get("steps")
    if not isinstance(steps, list):
        return failures + ["Manual Scorecard analysis job lacks steps"]

    scorecard_step = next(
        (
            step
            for step in steps
            if isinstance(step, dict)
            and step.get("uses") == "ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc"
        ),
        None,
    )
    if not isinstance(scorecard_step, dict):
        failures.append("Manual Scorecard workflow lacks the expected pinned Scorecard Action")
    else:
        inputs = scorecard_step.get("with")
        if not isinstance(inputs, dict) or inputs.get("publish_results") != "false":
            failures.append("Manual Scorecard workflow must disable result publication")
        if not isinstance(inputs, dict) or inputs.get("results_format") != "sarif":
            failures.append("Manual Scorecard workflow must retain SARIF results")

    artifact_step = next(
        (
            step
            for step in steps
            if isinstance(step, dict)
            and step.get("uses")
            == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        ),
        None,
    )
    if not isinstance(artifact_step, dict):
        failures.append("Manual Scorecard workflow lacks the expected pinned artifact uploader")
    else:
        inputs = artifact_step.get("with")
        if not isinstance(inputs, dict) or inputs.get("retention-days") != "7":
            failures.append("Manual Scorecard workflow must retain results for seven days")
    return failures


def _check_ci_assets() -> list[str]:
    """Verify repository-native CI integration assets without contacting external services."""

    failures: list[str] = []
    action_path = ROOT / ".github" / "actions" / "trustweave" / "action.yml"
    if not action_path.exists():
        failures.append("Missing repository-local TrustWeave composite action")
    else:
        try:
            action = yaml.safe_load(action_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            failures.append(f"Invalid composite action YAML: {error}")
        else:
            if not isinstance(action, dict):
                failures.append("Composite action must be a YAML mapping")
            else:
                required_inputs = {
                    "manifest",
                    "policy",
                    "scenarios",
                    "output-dir",
                    "fail-on-review",
                }
                inputs = action.get("inputs")
                if not isinstance(inputs, dict) or set(inputs) != required_inputs:
                    failures.append(
                        "Composite action inputs do not match the documented local contract"
                    )
                outputs = action.get("outputs")
                expected_outputs = {"bundle", "test-results", "policy-review"}
                if not isinstance(outputs, dict) or set(outputs) != expected_outputs:
                    failures.append("Composite action must expose all generated artifact paths")
                runs = action.get("runs")
                steps = runs.get("steps") if isinstance(runs, dict) else None
                if not isinstance(runs, dict) or runs.get("using") != "composite":
                    failures.append("TrustWeave action must use supported composite metadata")
                elif not isinstance(steps, list) or not any(
                    isinstance(step, dict) and step.get("id") == "artifacts" for step in steps
                ):
                    failures.append("Composite action must publish artifact-path outputs")

    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    if not workflow_path.exists():
        failures.append("Missing CI workflow that exercises the repository-local action")
    else:
        try:
            workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            failures.append(f"Invalid CI workflow YAML: {error}")
        else:
            jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
            composite_job = jobs.get("composite-action") if isinstance(jobs, dict) else None
            steps = composite_job.get("steps") if isinstance(composite_job, dict) else None
            if not isinstance(steps, list) or not any(
                isinstance(step, dict) and step.get("uses") == "./.github/actions/trustweave"
                for step in steps
            ):
                failures.append("CI must invoke the repository-local composite action")

    dependabot_path = ROOT / ".github" / "dependabot.yml"
    if not dependabot_path.exists():
        failures.append("Missing .github/dependabot.yml")
        return failures
    try:
        dependabot = yaml.safe_load(dependabot_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        failures.append(f"Invalid Dependabot YAML: {error}")
        return failures
    updates = dependabot.get("updates") if isinstance(dependabot, dict) else None
    if not isinstance(updates, list):
        failures.append("Dependabot configuration must contain an updates list")
        return failures
    ecosystems = {entry.get("package-ecosystem") for entry in updates if isinstance(entry, dict)}
    for ecosystem in ("pip", "github-actions"):
        if ecosystem not in ecosystems:
            failures.append(f"Dependabot configuration lacks {ecosystem} updates")
    return failures


def _check_issue_templates() -> list[str]:
    failures: list[str] = []
    config_path = ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml"
    if not config_path.exists():
        return ["Missing .github/ISSUE_TEMPLATE/config.yml"]

    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        return [f"Invalid issue-template config YAML: {error}"]
    if not isinstance(config, dict):
        failures.append("Issue-template config must be a YAML mapping")
    elif config.get("blank_issues_enabled") is not False:
        failures.append("Issue-template config must disable blank public issues")

    for relative_path in REQUIRED_ISSUE_FORMS:
        path = ROOT / relative_path
        if not path.exists():
            failures.append(f"Missing required issue form: {relative_path}")
            continue
        try:
            form = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            failures.append(f"Invalid issue-form YAML {relative_path}: {error}")
            continue
        if not isinstance(form, dict):
            failures.append(f"Issue form {relative_path} must be a YAML mapping")
            continue
        for key in ("name", "description", "body"):
            if key not in form:
                failures.append(f"Issue form {relative_path} lacks required key: {key}")
        if not isinstance(form.get("name"), str) or len(form.get("name", "")) <= 3:
            failures.append(f"Issue form {relative_path} needs a name longer than three characters")
        if not isinstance(form.get("description"), str) or not form.get("description", "").strip():
            failures.append(f"Issue form {relative_path} needs a non-empty description")
        if not isinstance(form.get("body"), list) or not form.get("body"):
            failures.append(f"Issue form {relative_path} needs a non-empty body list")
    return failures


def _check_current_contract_documentation() -> list[str]:
    """Require concise maintained documentation to name the current emitted contracts."""

    failures: list[str] = []
    for relative_path, markers in CURRENT_CONTRACT_DOCUMENTATION.items():
        path = ROOT / relative_path
        if not path.is_file():
            failures.append(f"Missing current-contract documentation: {relative_path}")
            continue
        content = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                failures.append(
                    f"{relative_path} lacks current-contract documentation marker: {marker}"
                )
    return failures


def _check_public_documents() -> list[str]:
    failures: list[str] = []
    for relative_path in PUBLIC_ASSETS:
        if not (ROOT / relative_path).exists():
            failures.append(f"Missing public project asset: {relative_path}")

    readme_path = ROOT / "README.md"
    if readme_path.exists():
        readme = readme_path.read_text(encoding="utf-8")
        for marker in REQUIRED_README_MARKERS:
            if marker not in readme:
                failures.append(f"README.md lacks required public-readiness marker: {marker}")
        if "repository remains private" in readme.casefold():
            failures.append("README.md still claims that the repository remains private")
        if "remains the currently published" in readme:
            failures.append("README.md retains stale current-release wording")
        if "remains subject to owner-approved production publication" in readme:
            failures.append("README.md retains stale pre-publication wording")

    security_path = ROOT / "SECURITY.md"
    if security_path.exists():
        security = security_path.read_text(encoding="utf-8").casefold()
        if "pre-release software" in security:
            failures.append(
                "SECURITY.md still describes the released project as pre-release software"
            )
        if "report a vulnerability" not in security:
            failures.append("SECURITY.md lacks a private vulnerability-reporting route")

    project_path = ROOT / "pyproject.toml"
    release_path = ROOT / "docs" / "RELEASE.md"
    if project_path.exists() and release_path.exists():
        with project_path.open("rb") as project_file:
            project = tomllib.load(project_file)
        version = project.get("project", {}).get("version")
        if isinstance(version, str):
            release = release_path.read_text(encoding="utf-8")
            if f"TrustWeave `{version}`" not in release:
                failures.append("docs/RELEASE.md does not name the declared package version")

            citation_path = ROOT / "CITATION.cff"
            if citation_path.exists():
                try:
                    citation = yaml.safe_load(citation_path.read_text(encoding="utf-8"))
                except yaml.YAMLError as error:
                    failures.append(f"Invalid CITATION.cff YAML: {error}")
                else:
                    if not isinstance(citation, dict):
                        failures.append("CITATION.cff must be a YAML mapping")
                    elif citation.get("title") != "TrustWeave":
                        failures.append("CITATION.cff must use the TrustWeave title")
                    elif citation.get("type") != "software":
                        failures.append("CITATION.cff must identify the project as software")
                    elif citation.get("version") != version:
                        failures.append("CITATION.cff version does not match pyproject.toml")
    return failures


def _check_changelog_version_synchronization() -> list[str]:
    """Verify build metadata, public package version, and top changelog heading agree."""

    failures: list[str] = []
    version = _declared_project_version()
    if version is None:
        return ["pyproject.toml must declare a non-empty project version"]

    package_init = ROOT / "src" / "trustweave" / "__init__.py"
    try:
        module = ast.parse(package_init.read_text(encoding="utf-8"), filename=str(package_init))
    except (OSError, SyntaxError) as error:
        return [f"Could not parse public package version: {error}"]
    source_version = next(
        (
            assignment.value.value
            for assignment in module.body
            if isinstance(assignment, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in assignment.targets
            )
            and isinstance(assignment.value, ast.Constant)
            and isinstance(assignment.value.value, str)
        ),
        None,
    )
    if source_version != version:
        failures.append("src/trustweave/__init__.py version does not match pyproject.toml")

    changelog_path = ROOT / "CHANGELOG.md"
    if not changelog_path.exists():
        failures.append("Missing CHANGELOG.md")
        return failures
    headings = CHANGELOG_VERSION_HEADING.findall(changelog_path.read_text(encoding="utf-8"))
    if not headings:
        failures.append("CHANGELOG.md lacks a version heading")
    else:
        released_headings = [heading for heading in headings if heading != "Unreleased"]
        if not released_headings:
            failures.append("CHANGELOG.md lacks a released version heading")
        elif released_headings[0] != version:
            failures.append(
                "CHANGELOG.md first released version heading does not match pyproject.toml"
            )
    return failures


def _check_quality_evidence() -> list[str]:
    """Verify source-derived quality facts and the bounded mutation record."""

    failures: list[str] = []
    if not ADVERSARIAL_SCENARIO_PATH.exists():
        failures.append("Missing cited adversarial scenario library")
    elif not QUALITY_GUIDE_PATH.exists():
        failures.append("Missing docs/QUALITY.md")
    else:
        try:
            scenarios_document: Any = json.loads(
                ADVERSARIAL_SCENARIO_PATH.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError as error:
            failures.append(f"Invalid adversarial scenario library JSON: {error}")
        else:
            scenarios = (
                scenarios_document.get("scenarios")
                if isinstance(scenarios_document, dict)
                else None
            )
            if not isinstance(scenarios, list):
                failures.append("Adversarial scenario library must contain a scenarios array")
            else:
                expected_count_marker = f"all **{len(scenarios)}** cited synthetic patterns"
                quality_guide = QUALITY_GUIDE_PATH.read_text(encoding="utf-8")
                if expected_count_marker not in quality_guide:
                    failures.append(
                        "docs/QUALITY.md does not state the source-derived adversarial "
                        "scenario count"
                    )

    if not MUTATION_RECORD_PATH.exists():
        failures.append("Missing docs/MUTATION_TESTING.md")
    else:
        mutation_record = MUTATION_RECORD_PATH.read_text(encoding="utf-8")
        for marker in MUTATION_RECORD_MARKERS:
            if marker not in mutation_record:
                failures.append(f"Mutation-testing record lacks required evidence marker: {marker}")

    if not RELEASE_REPRODUCIBILITY_HELPER_PATH.is_file():
        failures.append("Missing scripts/verify_release_reproducibility.py")
    if not REPRODUCIBILITY_RECORD_PATH.exists():
        failures.append("Missing docs/REPRODUCIBILITY.md")
    else:
        reproducibility_record = REPRODUCIBILITY_RECORD_PATH.read_text(encoding="utf-8")
        for marker in REPRODUCIBILITY_RECORD_MARKERS:
            if marker not in reproducibility_record:
                failures.append(f"Reproducibility record lacks required evidence marker: {marker}")

    with (ROOT / "pyproject.toml").open("rb") as project_file:
        project = tomllib.load(project_file)
    mutation_config = project.get("tool", {}).get("mutmut")
    if not isinstance(mutation_config, dict):
        failures.append("pyproject.toml lacks a [tool.mutmut] configuration")
    elif mutation_config.get("only_mutate") != MUTATION_SOURCE_SCOPE:
        failures.append("Mutation configuration must cover the documented high-risk source scope")
    return failures


def _parser_command_names() -> tuple[str, ...]:
    """Return the current top-level command names from the authoritative CLI parser."""

    for action in _parser()._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            return tuple(sorted(choices))
    raise RuntimeError("TrustWeave CLI parser has no top-level subcommands")


def _check_installed_wheel_schema_resources() -> list[str]:
    """Verify the wheel exposes exact packaged schemas without source-tree access."""

    failures: list[str] = []
    expected_names = sorted(path.name for path in (ROOT / "schemas").glob("*.schema.json"))
    with tempfile.TemporaryDirectory(prefix="trustweave-wheel-reality-") as temporary_directory:
        temporary_path = Path(temporary_directory)
        build = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(temporary_path)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            return [f"Isolated wheel build failed: {build.stderr.strip()}"]
        wheels = sorted(temporary_path.glob("*.whl"))
        if len(wheels) != 1:
            return ["Isolated wheel build did not produce exactly one wheel"]

        environment = temporary_path / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        binary_directory = "Scripts" if sys.platform == "win32" else "bin"
        python_name = "python.exe" if sys.platform == "win32" else "python"
        command_name = "trustweave.exe" if sys.platform == "win32" else "trustweave"
        python = environment / binary_directory / python_name
        command = environment / binary_directory / command_name
        install = subprocess.run(
            [str(python), "-m", "pip", "install", "--no-index", str(wheels[0])],
            check=False,
            capture_output=True,
            text=True,
        )
        if install.returncode != 0:
            return [f"Isolated wheel installation failed: {install.stderr.strip()}"]

        listed = subprocess.run(
            [str(command), "schema", "list"], check=False, capture_output=True, text=True
        )
        if listed.returncode != 0:
            return [f"Installed-wheel schema list failed: {listed.stderr.strip()}"]
        listed_names = listed.stdout.splitlines()
        if listed_names != expected_names:
            failures.append("Installed-wheel schema list does not match packaged schema filenames")
        if expected_names:
            shown = subprocess.run(
                [str(command), "schema", "show", expected_names[0]],
                check=False,
                capture_output=True,
                text=True,
            )
            if shown.returncode != 0:
                failures.append(f"Installed-wheel schema show failed: {shown.stderr.strip()}")
            else:
                expected_schema = json.loads(
                    (ROOT / "schemas" / expected_names[0]).read_text(encoding="utf-8")
                )
                if json.loads(shown.stdout) != expected_schema:
                    failures.append(
                        "Installed-wheel schema content differs from the source contract"
                    )

        runtime = subprocess.run(
            [
                str(python),
                "-c",
                (
                    "import json, pathlib; "
                    "import trustweave, trustweave.chain, trustweave.config, "
                    "trustweave.evidence, trustweave.sarif; "
                    "print(json.dumps({'version': trustweave.__version__, "
                    "'typed': (pathlib.Path(trustweave.__file__).parent / 'py.typed').is_file()}))"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if runtime.returncode != 0:
            failures.append(
                f"Installed-wheel public package imports failed: {runtime.stderr.strip()}"
            )
        else:
            try:
                runtime_contract = json.loads(runtime.stdout)
            except json.JSONDecodeError as error:
                failures.append(f"Installed-wheel runtime contract was not JSON: {error}")
            else:
                version = _declared_project_version()
                if runtime_contract.get("version") != version:
                    failures.append("Installed-wheel package version does not match pyproject.toml")
                if runtime_contract.get("typed") is not True:
                    failures.append("Installed-wheel package is missing its py.typed marker")

        version = _declared_project_version()
        for flag in ("--version", "-V"):
            version_result = subprocess.run(
                [str(command), flag], check=False, capture_output=True, text=True
            )
            if version_result.returncode != 0:
                failures.append(
                    f"Installed-wheel CLI {flag} failed: {version_result.stderr.strip()}"
                )
            elif version_result.stdout != f"{version}\n" or version_result.stderr:
                failures.append(
                    f"Installed-wheel CLI {flag} does not emit only the declared package version"
                )

        help_result = subprocess.run(
            [str(command), "--help"], check=False, capture_output=True, text=True
        )
        if help_result.returncode != 0:
            failures.append(f"Installed-wheel CLI help failed: {help_result.stderr.strip()}")
        else:
            failures.extend(
                f"Installed-wheel CLI help lacks parser command: {command_name}"
                for command_name in _parser_command_names()
                if command_name not in help_result.stdout
            )

        module_help = subprocess.run(
            [str(python), "-m", "trustweave", "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        if module_help.returncode != 0:
            failures.append(f"Installed-wheel module CLI help failed: {module_help.stderr.strip()}")
        else:
            failures.extend(
                f"Installed-wheel module CLI help lacks parser command: {command_name}"
                for command_name in _parser_command_names()
                if command_name not in module_help.stdout
            )
    return failures


def _check_installed_wheel_runtime_contract() -> list[str]:
    """Verify the isolated wheel's executable public runtime contract."""

    return _check_installed_wheel_schema_resources()


def _check_rule_registry() -> list[str]:
    """Require all built-in producer identifiers to be documented in the shared registry."""

    failures: list[str] = []
    emitted = {
        identifier
        for path in RULE_PRODUCER_PATHS
        for identifier in RULE_IDENTIFIER.findall(path.read_text(encoding="utf-8"))
    }
    unknown = sorted(emitted - set(RULES))
    if unknown:
        failures.append(
            "Built-in finding producers emit rule IDs absent from trustweave.rules: "
            + ", ".join(unknown)
        )
    return failures


def _check_documentation_site() -> list[str]:
    """Verify generated command help and the curated documentation site are buildable."""

    generate = subprocess.run(
        [sys.executable, "scripts/generate_cli_help.py", "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if generate.returncode != 0:
        return [
            f"Generated CLI help is stale: {generate.stdout.strip() or generate.stderr.strip()}"
        ]
    rule_catalog = subprocess.run(
        [sys.executable, "scripts/generate_rule_catalog.py", "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if rule_catalog.returncode != 0:
        return [
            "Generated rule catalog is stale: "
            f"{rule_catalog.stdout.strip() or rule_catalog.stderr.strip()}"
        ]

    with tempfile.TemporaryDirectory(prefix="trustweave-docs-reality-") as temporary_directory:
        build = subprocess.run(
            [
                sys.executable,
                "-m",
                "mkdocs",
                "build",
                "--strict",
                "--site-dir",
                str(Path(temporary_directory) / "site"),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    if build.returncode != 0:
        detail = build.stderr.strip() or build.stdout.strip()
        return [f"Strict documentation-site build failed: {detail}"]
    return []


def _check_documentation_commands() -> list[str]:
    """Execute representative copy-paste documentation commands without external services."""

    failures: list[str] = []
    expected_names = sorted(path.name for path in (ROOT / "schemas").glob("*.schema.json"))
    with tempfile.TemporaryDirectory(
        prefix="trustweave-doc-command-reality-"
    ) as temporary_directory:
        temporary_path = Path(temporary_directory)
        schema_list = subprocess.run(
            ["trustweave", "schema", "list"], check=False, capture_output=True, text=True
        )
        if schema_list.returncode != 0:
            failures.append(f"Documented schema list command failed: {schema_list.stderr.strip()}")
        elif schema_list.stdout.splitlines() != expected_names:
            failures.append("Documented schema list command does not show all shipped schemas")

        if expected_names:
            schema_show = subprocess.run(
                ["trustweave", "schema", "show", expected_names[0]],
                check=False,
                capture_output=True,
                text=True,
            )
            if schema_show.returncode != 0:
                failures.append(
                    f"Documented schema show command failed: {schema_show.stderr.strip()}"
                )
            else:
                try:
                    shown_schema = json.loads(schema_show.stdout)
                except json.JSONDecodeError as error:
                    failures.append(f"Documented schema show command emitted invalid JSON: {error}")
                else:
                    expected_schema = json.loads(
                        (ROOT / "schemas" / expected_names[0]).read_text(encoding="utf-8")
                    )
                    if shown_schema != expected_schema:
                        failures.append(
                            "Documented schema show command differs from the shipped schema"
                        )

        initialized = subprocess.run(
            ["trustweave", "init", "--directory", str(temporary_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        config_path = temporary_path / "trustweave.toml"
        if initialized.returncode != 0 or not config_path.is_file():
            failures.append(
                "Documented init command did not create a local trustweave.toml template"
            )
        else:
            validated = subprocess.run(
                ["trustweave", "config", "validate", "--config", str(config_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            if validated.returncode != 0:
                failures.append(
                    f"Documented config validate command failed: {validated.stderr.strip()}"
                )
    return failures


def _check_package_provenance_controls() -> list[str]:
    """Validate configured attestation generation without making a release-time network call."""

    if not PACKAGE_PROVENANCE_HELPER_PATH.is_file():
        return ["Missing scripts/verify_package_provenance_controls.py"]
    completed = subprocess.run(
        [sys.executable, str(PACKAGE_PROVENANCE_HELPER_PATH)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return []
    detail = completed.stderr.strip() or completed.stdout.strip()
    return [f"Package provenance control validation failed: {detail}"]


def _check_distribution_assurance() -> list[str]:
    """Build and temporarily install both local distributions during repository verification."""

    if not DISTRIBUTION_ASSURANCE_HELPER_PATH.is_file():
        return ["Missing scripts/verify_distribution_artifacts.py"]
    completed = subprocess.run(
        [sys.executable, str(DISTRIBUTION_ASSURANCE_HELPER_PATH), "--allow-dirty"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return []
    detail = completed.stderr.strip() or completed.stdout.strip()
    return [f"Distribution assurance validation failed: {detail}"]


def _check_control_traceability() -> list[str]:
    """Run the source-to-control-to-test traceability validator without rewriting its guide."""

    if not TRACEABILITY_HELPER_PATH.is_file():
        return ["Missing scripts/verify_control_traceability.py"]
    completed = subprocess.run(
        [sys.executable, str(TRACEABILITY_HELPER_PATH)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return []
    detail = completed.stderr.strip() or completed.stdout.strip()
    return [f"Control traceability validation failed: {detail}"]


def _check_golden_evidence() -> list[str]:
    """Run the check-only synthetic golden corpus verifier without snapshot updates."""

    if not GOLDEN_EVIDENCE_HELPER_PATH.is_file():
        return ["Missing scripts/verify_golden_evidence.py"]
    completed = subprocess.run(
        [sys.executable, str(GOLDEN_EVIDENCE_HELPER_PATH)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return []
    detail = completed.stderr.strip() or completed.stdout.strip()
    return [f"Golden evidence validation failed: {detail}"]


def _check_assurance_contracts() -> list[str]:
    """Run the standalone assurance validator as part of repository reality evidence."""

    if not ASSURANCE_CONTRACT_HELPER_PATH.is_file():
        return ["Missing scripts/verify_assurance_contracts.py"]
    completed = subprocess.run(
        [sys.executable, str(ASSURANCE_CONTRACT_HELPER_PATH)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return []
    detail = completed.stderr.strip() or completed.stdout.strip()
    return [f"Assurance contract validation failed: {detail}"]


def _check_cli() -> list[str]:
    completed = subprocess.run(
        ["trustweave", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return [f"trustweave --help failed: {completed.stderr.strip()}"]
    return [
        f"Documented CLI command missing from help: {command}"
        for command in _parser_command_names()
        if command not in completed.stdout
    ]


def main() -> int:
    """Print actionable repository reality-check failures and return an appropriate code."""

    failures = (
        _check_schema_resource_synchronization()
        + _check_generated_artifact_schema_coverage()
        + _check_current_contract_documentation()
        + _check_json_documents()
        + _check_contract_examples()
        + _check_generated_artifact_schemas()
        + _check_installed_wheel_runtime_contract()
        + _check_markdown_links()
        + _check_workflows()
        + _check_manual_scorecard_workflow()
        + _check_ci_assets()
        + _check_issue_templates()
        + _check_public_documents()
        + _check_changelog_version_synchronization()
        + _check_quality_evidence()
        + _check_rule_registry()
        + _check_documentation_site()
        + _check_documentation_commands()
        + _check_package_provenance_controls()
        + _check_distribution_assurance()
        + _check_control_traceability()
        + _check_golden_evidence()
        + _check_assurance_contracts()
        + _check_cli()
    )
    if failures:
        print("Repository reality check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(
        "Repository reality check passed: schemas, contract examples, local documentation "
        "links, workflows, CI assets, issue forms, public documentation, release metadata, "
        "quality evidence, generated artifacts, installed-wheel runtime and schema resources, "
        "generated documentation, strict documentation-site builds, executed documentation "
        "commands, package provenance controls, distribution assurance, control traceability, "
        "golden evidence, assurance contracts, and CLI commands are connected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
