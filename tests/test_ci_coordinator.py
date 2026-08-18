"""Behavioral regressions for the configured local CI coordinator boundaries."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError

from trustweave.chain import review_declared_chains
from trustweave.cli import main
from trustweave.commands import ci as ci_command
from trustweave.commands._shared import EXIT_REVIEW
from trustweave.commands.ci import (
    CI_SUMMARY_SCHEMA_VERSION,
    _config_path,
    _fail_on_findings,
    _publish_directory,
    _render_summary,
    _required_paths,
    _selected_stages,
    _staged_sarif_path,
)
from trustweave.config import CONFIG_FILE_NAME, find_project_config, load_project_config
from trustweave.io import load_document, write_json
from trustweave.models import InputOutputError, ValidationError
from trustweave.risk import create_baseline, review_risks


def test_config_rejects_invalid_typed_values_and_discovery_bounds(tmp_path: Path) -> None:
    """Configuration remains strict for stage lists, booleans, threshold, and discovery bounds."""

    path = tmp_path / CONFIG_FILE_NAME
    cases = (
        ("enabled_stages = []\n", "between 1"),
        ('enabled_stages = ["scan", "scan"]\n', "duplicates"),
        ('enabled_stages = ["unknown"]\n', "unsupported stages"),
        ('enabled_stages = "scan"\n', "must be a list"),
        ('reproducible = "yes"\n', "must be a boolean"),
        ('failure_threshold = "urgent"\n', "must be one of"),
        ('manifest = "bad\\u0000path"\n', "null byte"),
    )
    for fragment, message in cases:
        path.write_text("[tool.trustweave]\n" + fragment, encoding="utf-8")
        with pytest.raises(ValidationError, match=message):
            load_project_config(path)

    with pytest.raises(ValidationError, match="non-negative"):
        find_project_config(tmp_path, max_parents=-1)


@pytest.mark.parametrize(
    ("config", "generated_at_source", "message"),
    [
        (
            {"enabled_stages": ("summary",), "reproducible": "true"},
            "explicit",
            "tool.trustweave.reproducible must be a boolean",
        ),
        (
            {"enabled_stages": ("summary",), "reproducible": True},
            "clock",
            "reproducible CI requires --generated-at or SOURCE_DATE_EPOCH; wall-clock provenance "
            "is not deterministic",
        ),
        (
            {
                "enabled_stages": ("summary",),
                "reproducible": False,
                "failure_threshold": 1,
                "output_dir": "artifacts",
            },
            "explicit",
            "tool.trustweave.failure_threshold must be a severity string",
        ),
    ],
)
def test_ci_handle_defense_in_depth_rejects_untyped_embedded_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, object],
    generated_at_source: str,
    message: str,
) -> None:
    """Coordinator validation remains fail-closed for an embedding caller.

    This direct boundary test covers callers that bypass configuration loading.
    """

    config_path = tmp_path / "embedded.toml"
    config_path.write_text("[tool.trustweave]\n", encoding="utf-8")
    monkeypatch.setattr(ci_command, "load_project_config", lambda _path: config)
    monkeypatch.setattr(
        ci_command,
        "configured_paths",
        lambda _config_path, _values: {"output_dir": tmp_path / "artifacts"},
    )
    args = argparse.Namespace(
        config=config_path,
        no_config_discovery=False,
        output_dir=None,
        source_revision="embedded-contract",
        coverage=False,
        exit_on_review=False,
        fail_on=None,
        quiet=True,
        format="text",
        generated_at_source=generated_at_source,
    )

    with pytest.raises(ValidationError) as error:
        ci_command.handle(args, "2026-08-15T00:00:00+00:00")
    assert str(error.value) == message


def test_ci_helper_contracts_are_deterministic_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stage selection, gating, rendering, and local path containment have stable semantics."""

    assert _selected_stages({})[:3] == ("scan", "scenarios", "policy_review")
    assert _selected_stages({"enabled_stages": ("scan", "summary")}) == ("scan", "summary")
    with pytest.raises(ValidationError, match="validated stage list"):
        _selected_stages({"enabled_stages": ["scan"]})
    assert _selected_stages({"enabled_stages": ("trace_review",)}) == ("trace_review",)

    assert _required_paths(()) == set()
    assert _required_paths(("scan", "scenarios", "chain_review")) == {
        "manifest",
        "policy",
        "scenarios",
        "chain_manifest",
    }
    staging = tmp_path / "staging"
    staging.mkdir()
    assert _staged_sarif_path({}, staging) == staging / "trustweave.sarif"
    assert _staged_sarif_path({"sarif_output": "nested/out.sarif"}, staging) == (
        staging / "nested" / "out.sarif"
    )
    with pytest.raises(ValidationError, match="local path string"):
        _staged_sarif_path({"sarif_output": 1}, staging)
    for value in (
        "../out.sarif",
        str((tmp_path / "out.sarif").resolve()),
        r"C:\\escaped.sarif",
    ):
        with pytest.raises(ValidationError, match="within the CI artifact directory"):
            _staged_sarif_path({"sarif_output": value}, staging)

    discovered = tmp_path / CONFIG_FILE_NAME
    discovered.write_text("[tool.trustweave]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert _config_path(argparse.Namespace(config=None, no_config_discovery=False)) == discovered
    explicit = argparse.Namespace(config=tmp_path / CONFIG_FILE_NAME, no_config_discovery=False)
    assert _config_path(explicit) == explicit.config
    with pytest.raises(ValidationError, match="requires an explicit"):
        _config_path(argparse.Namespace(config=None, no_config_discovery=True))
    with pytest.raises(ValidationError, match="must identify"):
        _config_path(argparse.Namespace(config="not-a-path", no_config_discovery=False))

    high_review = {"findings": [{"severity": "high"}]}
    assert _fail_on_findings(None, "high", False) is False
    assert _fail_on_findings({"findings": []}, "high", False) is False
    assert _fail_on_findings(high_review, "none", False) is False
    assert _fail_on_findings(high_review, "medium", False) is True
    assert _fail_on_findings(high_review, "critical", False) is False
    assert _fail_on_findings(high_review, "review", False) is True
    assert _fail_on_findings({"findings": [{"severity": "review"}]}, "review", False) is True
    assert _fail_on_findings({"findings": [{"severity": "low"}]}, "review", False) is True
    assert _fail_on_findings(high_review, "none", True) is True

    summary = {
        "schema_version": CI_SUMMARY_SCHEMA_VERSION,
        "status": "clear",
        "generated_at": "2026-08-14T00:00:00+00:00",
        "artifacts": ["ci-summary.json", "report.md"],
    }
    assert _render_summary(summary, "text").startswith("Wrote staged local CI evidence")
    assert '"schema_version": "trustweave.dev/ci-summary/v1alpha1"' in _render_summary(
        summary, "json"
    )
    assert "# TrustWeave Local CI Summary" in _render_summary(summary, "markdown")


@pytest.mark.parametrize(
    ("sarif_output", "message"),
    [
        (1, "tool.trustweave.sarif_output must be a local path string"),
        (
            "../escape.sarif",
            "tool.trustweave.sarif_output must remain within the CI artifact directory",
        ),
        (
            r"..\\escape.sarif",
            "tool.trustweave.sarif_output must remain within the CI artifact directory",
        ),
        (".", "tool.trustweave.sarif_output must remain within the CI artifact directory"),
        (
            "/escape.sarif",
            "tool.trustweave.sarif_output must remain within the CI artifact directory",
        ),
        (
            r"\\escape.sarif",
            "tool.trustweave.sarif_output must remain within the CI artifact directory",
        ),
        (
            "C:/escape.sarif",
            "tool.trustweave.sarif_output must remain within the CI artifact directory",
        ),
        (
            r"C:\\escape.sarif",
            "tool.trustweave.sarif_output must remain within the CI artifact directory",
        ),
        (
            "C:escape.sarif",
            "tool.trustweave.sarif_output must remain within the CI artifact directory",
        ),
        (
            r"nested\\escape.sarif",
            "tool.trustweave.sarif_output must use portable relative path separators",
        ),
    ],
)
def test_safe_sarif_path_has_exact_cross_platform_validation_errors(
    tmp_path: Path, sarif_output: object, message: str
) -> None:
    """Every portable path category has a stable fail-closed public validation error."""

    with pytest.raises(ValidationError) as error:
        _staged_sarif_path({"sarif_output": sarif_output}, tmp_path)
    assert str(error.value) == message


def test_ci_directory_publication_replaces_only_complete_staged_artifacts(tmp_path: Path) -> None:
    """The publish primitive replaces directories atomically and rejects file destinations."""

    output = tmp_path / "artifacts"
    output.mkdir()
    (output / "old.txt").write_text("old", encoding="utf-8")
    stale_backup = tmp_path / ".artifacts.previous"
    stale_backup.mkdir()
    (stale_backup / "stale.txt").write_text("stale", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "new.txt").write_text("new", encoding="utf-8")

    _publish_directory(staging, output)

    assert (output / "new.txt").read_text(encoding="utf-8") == "new"
    assert not (output / "old.txt").exists()
    assert not stale_backup.exists()
    file_destination = tmp_path / "not-a-directory"
    file_destination.write_text("file", encoding="utf-8")
    with pytest.raises(InputOutputError, match="must be a directory"):
        _publish_directory(tmp_path / "missing-staging", file_destination)

    assert EXIT_REVIEW == 1


def test_ci_selected_stage_dependencies_fail_closed_without_publication(tmp_path: Path) -> None:
    """Selected stages must state their local prerequisites and cannot publish partial output."""

    root = Path(__file__).resolve().parents[1]
    manifest = root / "examples" / "support-agent.manifest.json"
    policy = root / "policies" / "default-policy.json"
    scenarios = root / "scenarios" / "default-scenarios.json"

    def run(stages: str, name: str) -> int:
        config = tmp_path / f"{name}.toml"
        config.write_text(
            "[tool.trustweave]\n"
            f'manifest = "{manifest.as_posix()}"\n'
            f'policy = "{policy.as_posix()}"\n'
            f'scenarios = "{scenarios.as_posix()}"\n'
            f'output_dir = "{name}"\n'
            f"enabled_stages = {stages}\n"
            'failure_threshold = "none"\n',
            encoding="utf-8",
        )
        return main(["ci", "--config", str(config), "--quiet"])

    assert run('["sarif"]', "sarif-only") == 2
    assert run('["attestation"]', "attestation-only") == 2
    assert run('["report"]', "report-only") == 2
    assert run('["scenarios", "summary"]', "scenarios-only") == 0
    assert run('["policy_review"]', "policy-only") == 0
    assert (tmp_path / "scenarios-only" / "ci-summary.json").is_file()
    assert not (tmp_path / "policy-only" / "ci-summary.json").exists()


def _write_ci_config(path: Path, output_dir: Path, *, include_chain_review: bool = False) -> None:
    """Write a bounded local coordinator configuration for end-to-end regressions."""

    root = Path(__file__).resolve().parents[1]
    stages = ["scan", "scenarios", "policy_review"]
    if include_chain_review:
        stages.append("chain_review")
    stages.extend(["sarif", "attestation", "report", "summary"])
    chain_manifest = root / "examples" / "chains" / "safe-sanitized-external.chain.json"
    chain_line = f'chain_manifest = "{chain_manifest.as_posix()}"\n' if include_chain_review else ""
    rendered_stages = ", ".join(f'"{stage}"' for stage in stages)
    path.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{(root / "examples/support-agent.manifest.json").as_posix()}"\n'
        f'policy = "{(root / "policies/default-policy.json").as_posix()}"\n'
        f'scenarios = "{(root / "scenarios/default-scenarios.json").as_posix()}"\n'
        + chain_line
        + f'output_dir = "{output_dir.as_posix()}"\n'
        + f"enabled_stages = [{rendered_stages}]\n"
        + 'failure_threshold = "none"\n'
        + "reproducible = true\n",
        encoding="utf-8",
    )


def test_ci_fixed_provenance_artifacts_are_byte_identical_and_path_independent(
    tmp_path: Path,
) -> None:
    """The coordinator must not bind temporary physical paths into reproducible evidence."""

    config = tmp_path / "trustweave.toml"
    output_dir = tmp_path / "artifacts"
    _write_ci_config(config, output_dir, include_chain_review=True)
    arguments = [
        "--generated-at",
        "2026-08-14T00:00:00+00:00",
        "ci",
        "--config",
        str(config),
        "--source-revision",
        "fixed-revision",
        "--quiet",
    ]

    assert main(arguments) == 0
    first = {
        path.relative_to(output_dir).as_posix(): path.read_bytes()
        for path in sorted(output_dir.rglob("*"))
        if path.is_file()
    }
    assert main(arguments) == 0
    second = {
        path.relative_to(output_dir).as_posix(): path.read_bytes()
        for path in sorted(output_dir.rglob("*"))
        if path.is_file()
    }

    assert second == first
    evidence = b"\n".join(second.values())
    assert b".trustweave-ci-" not in evidence
    assert str(tmp_path).encode("utf-8") not in evidence


def test_ci_creates_missing_nested_output_parent_before_staging(tmp_path: Path) -> None:
    """A configured nested output directory must be safely creatable before staging begins."""

    config = tmp_path / "trustweave.toml"
    output_dir = tmp_path / "new parent" / "nested" / "artifacts"
    _write_ci_config(config, output_dir)

    assert (
        main(
            [
                "--generated-at",
                "2026-08-14T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--source-revision",
                "fixed-revision",
                "--quiet",
            ]
        )
        == 0
    )
    assert (output_dir / "ci-summary.json").is_file()


def test_reproducible_ci_requires_fixed_provenance_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Reproducible configured CI must not silently derive provenance from the wall clock."""

    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    config = tmp_path / "trustweave.toml"
    output_dir = tmp_path / "artifacts"
    _write_ci_config(config, output_dir)

    assert main(["ci", "--config", str(config), "--quiet"]) == 2
    assert capsys.readouterr().err == (
        "Validation error: reproducible CI requires --generated-at or SOURCE_DATE_EPOCH; "
        "wall-clock provenance is not deterministic\n"
    )
    assert not output_dir.exists()


def test_ci_chain_findings_drive_severity_gate_and_summary_status(tmp_path: Path) -> None:
    """Selected chain-review findings must participate in the final local CI gate."""

    chain_manifest = tmp_path / "unsafe-chain.json"
    chain_manifest.write_text(
        "{\n"
        '  "schema_version": "trustweave.dev/chain-manifest/v1alpha1",\n'
        '  "name": "unsafe-chain",\n'
        '  "nodes": [\n'
        '    {"id": "inbox", "kind": "source", "trust": "untrusted"},\n'
        '    {"id": "records", "kind": "data", "classification": "confidential"},\n'
        '    {"id": "email", "kind": "tool", "action_class": "external"}\n'
        "  ],\n"
        '  "edges": [\n'
        '    {"from": "inbox", "to": "records"},\n'
        '    {"from": "records", "to": "email"}\n'
        "  ]\n"
        "}\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'chain_manifest = "{chain_manifest.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["chain_review", "risk", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-14T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--exit-on-review",
                "--quiet",
            ]
        )
        == EXIT_REVIEW
    )
    summary = load_document(output_dir / "ci-summary.json")
    assert summary["status"] == "review_required"
    assert summary["review"] == {
        "selected_kinds": ["chain", "risk"],
        "uses_risk_lifecycle": True,
    }
    assert summary["finding_counts"] == summary["active_severity_counts"]
    assert summary["finding_counts"]["high"] > 0
    assert summary["applied_decisions"] == {
        "baselined": 0,
        "suppressed": 0,
        "expired_baseline": 0,
        "expired_suppression": 0,
    }
    assert summary["incomplete_analyses"] == []


def test_ci_baseline_lifecycle_updates_active_counts_and_gate_status(tmp_path: Path) -> None:
    """Configured matching baselines preserve findings but remove them from active CI gating."""

    generated_at = "2026-08-15T00:00:00+00:00"
    chain_document = {
        "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
        "name": "lifecycle-chain",
        "nodes": [
            {"id": "inbox", "kind": "source", "trust": "untrusted"},
            {"id": "records", "kind": "data", "classification": "confidential"},
            {"id": "email", "kind": "tool", "action_class": "external"},
        ],
        "edges": [
            {"from": "inbox", "to": "records"},
            {"from": "records", "to": "email"},
        ],
    }
    chain_manifest = write_json(tmp_path / "chain.json", chain_document)
    chain_review = review_declared_chains(chain_document, generated_at=generated_at)
    initial_risk_review = review_risks(
        [chain_review],
        reviewed_at=generated_at,
        artifact_paths=["chain-review.json"],
    )
    baseline = create_baseline(
        initial_risk_review,
        "Explicit local review decision.",
        "2026-09-01T00:00:00+00:00",
        owner="security-review",
        created_at=generated_at,
    )
    baseline_path = write_json(tmp_path / "baseline.json", baseline)
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'chain_manifest = "{chain_manifest.as_posix()}"\n'
        f'risk_baseline = "{baseline_path.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["chain_review", "risk", "summary"]\n'
        'failure_threshold = "high"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                generated_at,
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )
    summary = load_document(output_dir / "ci-summary.json")
    assert summary["status"] == "clear"
    assert summary["finding_counts"]["high"] > 0
    assert summary["active_severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "review": 0,
    }
    assert summary["applied_decisions"] == {
        "baselined": len(initial_risk_review["findings"]),
        "suppressed": 0,
        "expired_baseline": 0,
        "expired_suppression": 0,
    }


def test_ci_resolves_configured_risk_baseline_for_selected_risk_stage(tmp_path: Path) -> None:
    """Configured optional risk decisions must be resolved before the risk stage reads them."""

    root = Path(__file__).resolve().parents[1]
    baseline = tmp_path / "risk baseline.json"
    chain_manifest = root / "examples" / "chains" / "safe-sanitized-external.chain.json"
    baseline.write_text(
        '{"schema_version":"trustweave.dev/risk-baseline/v1alpha2","baseline":[]}',
        encoding="utf-8",
    )
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'chain_manifest = "{chain_manifest.as_posix()}"\n'
        f'risk_baseline = "{baseline.name}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["chain_review", "risk", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-14T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )
    assert (output_dir / "risk-review.json").is_file()


def test_ci_validate_stage_checks_declared_local_inputs(tmp_path: Path) -> None:
    """A selected validation stage cannot report success without reading declared inputs."""

    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        'manifest = "missing-manifest.json"\n'
        f'output_dir = "{(tmp_path / "artifacts").as_posix()}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n',
        encoding="utf-8",
    )

    assert main(["ci", "--config", str(config), "--quiet"]) == 3
    assert not (tmp_path / "artifacts").exists()


def test_ci_validate_stage_semantically_validates_declared_policy_and_scenarios(
    tmp_path: Path,
) -> None:
    """Declared policy and scenario inputs are validated through their typed parsers."""

    root = Path(__file__).resolve().parents[1]
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{(root / "examples/support-agent.manifest.json").as_posix()}"\n'
        f'policy = "{(root / "policies/default-policy.json").as_posix()}"\n'
        f'scenarios = "{(root / "scenarios/default-scenarios.json").as_posix()}"\n'
        f'output_dir = "{(tmp_path / "artifacts").as_posix()}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n',
        encoding="utf-8",
    )

    assert main(["ci", "--config", str(config), "--quiet"]) == 0


def test_ci_validate_stage_semantically_validates_declared_manifest(tmp_path: Path) -> None:
    """A selected validation stage must reject a parsed but semantically invalid manifest."""

    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"not": "a manifest"}', encoding="utf-8")
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{manifest.name}"\n'
        f'output_dir = "{(tmp_path / "artifacts").as_posix()}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n',
        encoding="utf-8",
    )

    assert main(["ci", "--config", str(config), "--quiet"]) == 2
    assert not (tmp_path / "artifacts").exists()


def test_ci_supports_every_configuration_accepted_stage() -> None:
    """Configuration must not advertise any local workflow stage that CI rejects."""

    from trustweave.commands.ci import CI_SUPPORTED_STAGES
    from trustweave.config import VALID_WORKFLOW_STAGES

    accepted = (
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
    assert CI_SUPPORTED_STAGES == VALID_WORKFLOW_STAGES
    assert _selected_stages({"enabled_stages": accepted}) == accepted


def test_ci_executes_all_supported_local_review_stages(tmp_path: Path) -> None:
    """Accepted configured review stages must all perform their documented local work."""

    root = Path(__file__).resolve().parents[1]
    policy = root / "policies" / "default-policy.json"
    manifest = root / "examples" / "support-agent.manifest.json"
    candidate = root / "examples" / "support-agent.candidate.manifest.json"
    base_dir = tmp_path / "base bundle"
    candidate_dir = tmp_path / "candidate bundle"
    generated_at = "2026-08-14T00:00:00+00:00"
    assert (
        main(
            [
                "--generated-at",
                generated_at,
                "scan",
                "--manifest",
                str(manifest),
                "--policy",
                str(policy),
                "--output-dir",
                str(base_dir),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--generated-at",
                generated_at,
                "scan",
                "--manifest",
                str(candidate),
                "--policy",
                str(policy),
                "--output-dir",
                str(candidate_dir),
            ]
        )
        == 0
    )

    output_dir = tmp_path / "artifacts"
    base_bundle = base_dir / "agent-security-bundle.json"
    candidate_bundle = candidate_dir / "agent-security-bundle.json"
    trace = root / "examples" / "traces" / "clear-support-trace.json"
    mcp_profile = root / "examples" / "mcp-profiles" / "clear-support-profile.json"
    chain_manifest = root / "examples" / "chains" / "safe-sanitized-external.chain.json"
    stages = (
        "validate",
        "diff",
        "trace_review",
        "mcp_profile_review",
        "chain_review",
        "risk",
        "sarif",
        "summary",
    )
    rendered_stages = ", ".join(f'"{stage}"' for stage in stages)
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{manifest.as_posix()}"\n'
        f'policy = "{policy.as_posix()}"\n'
        f'baseline_bundle = "{base_bundle.as_posix()}"\n'
        f'candidate_bundle = "{candidate_bundle.as_posix()}"\n'
        f'trace = "{trace.as_posix()}"\n'
        f'mcp_profile = "{mcp_profile.as_posix()}"\n'
        f'chain_manifest = "{chain_manifest.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        f"enabled_stages = [{rendered_stages}]\n"
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                generated_at,
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )
    assert {
        "bundle-diff.json",
        "bundle-diff.md",
        "trace-review.json",
        "trace-review.md",
        "mcp-profile-review.json",
        "mcp-profile-review.md",
        "chain-review.json",
        "chain-review.md",
        "risk-review.json",
        "risk-review.md",
        "trustweave.sarif",
        "ci-summary.json",
    }.issubset({path.name for path in output_dir.iterdir()})


def test_generated_ci_summary_conforms_to_packaged_strict_schema(tmp_path: Path) -> None:
    """CI summary output must remain a strict versioned public artifact contract."""

    config = tmp_path / "trustweave.toml"
    output_dir = tmp_path / "artifacts"
    _write_ci_config(config, output_dir)
    assert (
        main(
            [
                "--generated-at",
                "2026-08-14T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )

    root = Path(__file__).resolve().parents[1]
    schema = load_document(root / "schemas" / "ci-summary-v1alpha1.schema.json")
    summary = load_document(output_dir / "ci-summary.json")
    Draft202012Validator(schema).validate(summary)
    summary["artifacts"] = ["reports/my report.sarif"]
    Draft202012Validator(schema).validate(summary)


def test_ci_summary_schema_rejects_unknown_fields(tmp_path: Path) -> None:
    """The public CI-summary schema must fail closed for unknown artifact fields."""

    config = tmp_path / "trustweave.toml"
    output_dir = tmp_path / "artifacts"
    _write_ci_config(config, output_dir)
    assert (
        main(
            [
                "--generated-at",
                "2026-08-14T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )

    root = Path(__file__).resolve().parents[1]
    schema = load_document(root / "schemas" / "ci-summary-v1alpha1.schema.json")
    summary = dict(load_document(output_dir / "ci-summary.json"))
    summary["unexpected"] = True
    with pytest.raises(JsonSchemaValidationError, match="Additional properties"):
        Draft202012Validator(schema).validate(summary)


@pytest.mark.parametrize("bundle_field", ["baseline_bundle", "candidate_bundle"])
def test_ci_validate_stage_semantically_rejects_malformed_configured_bundle(
    tmp_path: Path, bundle_field: str
) -> None:
    """Configured diff bundles require semantic validation even when diff is not selected."""

    malformed = tmp_path / f"{bundle_field}.json"
    malformed.write_text('{"not": "a bundle"}', encoding="utf-8")
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'{bundle_field} = "{malformed.name}"\n'
        f'output_dir = "{output_dir.name}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-15T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 2
    )
    assert not output_dir.exists()


@pytest.mark.parametrize(
    "sarif_output", ["../escape.sarif", "/tmp/escape.sarif", r"..\\escape.sarif"]
)
def test_ci_validate_stage_rejects_unsafe_configured_sarif_path_before_publication(
    tmp_path: Path, sarif_output: str
) -> None:
    """Configured SARIF output paths are validated even when the SARIF stage is not selected."""

    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'sarif_output = "{sarif_output}"\n'
        f'output_dir = "{output_dir.name}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-15T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 2
    )
    assert not output_dir.exists()


def test_ci_validate_stage_accepts_nested_sarif_path_with_spaces(tmp_path: Path) -> None:
    """A safe relative nested SARIF path remains valid in a validate-only configuration."""

    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        'sarif_output = "nested reports/my report.sarif"\n'
        f'output_dir = "{output_dir.name}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-15T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )
    assert (output_dir / "ci-summary.json").is_file()


def test_ci_validate_stage_rejects_output_symlink_escape_without_publication(
    tmp_path: Path,
) -> None:
    """Validate-only runs reject an output path that traverses a symbolic link before writes."""

    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "artifact-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symbolic links are unavailable: {error}")
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        'output_dir = "artifact-link/artifacts"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-15T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 3
    )
    assert not (outside / "artifacts").exists()


def test_ci_validate_stage_preserves_existing_output_after_semantic_failure(tmp_path: Path) -> None:
    """Semantic validation fails before replacing a prior complete local artifact directory."""

    output_dir = tmp_path / "artifacts"
    output_dir.mkdir()
    prior = output_dir / "prior.json"
    prior.write_text('{"preserved": true}', encoding="utf-8")
    malformed = tmp_path / "baseline.json"
    malformed.write_text('{"not": "a bundle"}', encoding="utf-8")
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'baseline_bundle = "{malformed.name}"\n'
        f'output_dir = "{output_dir.name}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-15T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 2
    )
    assert prior.read_text(encoding="utf-8") == '{"preserved": true}'
    assert sorted(path.name for path in output_dir.iterdir()) == ["prior.json"]


@pytest.mark.parametrize(
    ("field", "filename", "contents"),
    [
        ("policy", "invalid-policy.json", '{"schema_version":"unsupported"}'),
        (
            "risk_baseline",
            "invalid-baseline.json",
            '{"schema_version":"trustweave.dev/risk-baseline/v1alpha2","baseline":[{}]}',
        ),
        (
            "suppressions",
            "invalid-suppressions.json",
            '{"schema_version":"trustweave.dev/risk-suppressions/v1alpha2","suppressions":[{}]}',
        ),
    ],
)
def test_ci_validate_stage_semantically_rejects_every_configured_decision_input(
    tmp_path: Path, field: str, filename: str, contents: str
) -> None:
    """Validate-only coordination parses every configured local decision input.

    Invalid documents fail before the coordinator creates or replaces output.
    """

    invalid_document = tmp_path / filename
    invalid_document.write_text(contents, encoding="utf-8")
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'{field} = "{invalid_document.name}"\n'
        f'output_dir = "{output_dir.name}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-15T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 2
    )
    assert not output_dir.exists()
