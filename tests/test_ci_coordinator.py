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
    _prepare_output_parent,
    _publish_directory,
    _render_summary,
    _required_paths,
    _review_findings,
    _safe_sarif_path,
    _selected_stages,
    _severity_counts,
    _staged_sarif_path,
    _validate_output_path,
    _validate_stage_dependencies,
)
from trustweave.config import CONFIG_FILE_NAME, find_project_config, load_project_config
from trustweave.io import canonical_json, load_document, write_json
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
    with pytest.raises(ValidationError) as error:
        _selected_stages({"enabled_stages": ("a", "b")})
    assert str(error.value) == "trustweave ci does not implement configured stages: a, b"

    assert _required_paths(()) == set()
    assert _required_paths(("scan", "scenarios", "chain_review")) == {
        "manifest",
        "policy",
        "scenarios",
        "chain_manifest",
    }
    assert _required_paths(("diff",)) == {"baseline_bundle", "candidate_bundle"}
    assert _required_paths(("trace_review",)) == {"manifest", "policy", "trace"}
    assert _required_paths(("mcp_profile_review",)) == {"manifest", "mcp_profile"}
    for unsafe_path in ("../escaped.sarif", "/absolute/escaped.sarif", "nested/../escaped.sarif"):
        with pytest.raises(ValidationError) as error:
            _safe_sarif_path({"sarif_output": unsafe_path})
        assert str(error.value) == (
            "tool.trustweave.sarif_output must remain within the CI artifact directory"
        )
    assert _safe_sarif_path({"sarif_output": "nested/trustweave.sarif"}) == Path(
        "nested/trustweave.sarif"
    )
    _validate_stage_dependencies(("policy_review", "risk", "sarif"))
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
        "nested/../out.sarif",
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
    assert _fail_on_findings({"findings": [{"severity": "low"}]}, "low", False) is True
    assert _severity_counts(
        [
            {"severity": "low"},
            {"severity": "low"},
            {"severity": "high"},
            {"severity": "unsupported"},
        ]
    ) == {"critical": 0, "high": 1, "medium": 0, "low": 2, "info": 0, "review": 0}
    signal_finding = {"id": "TW-SIGNAL-001", "severity": "medium"}
    assert _review_findings({"signals": [signal_finding]}) == [signal_finding]
    assert _review_findings({"findings": [signal_finding], "signals": []}) == [signal_finding]
    assert _review_findings({"findings": "not-a-list", "signals": [signal_finding]}) == []

    summary = {
        "schema_version": CI_SUMMARY_SCHEMA_VERSION,
        "status": "clear",
        "generated_at": "2026-08-14T00:00:00+00:00",
        "artifacts": ["ci-summary.json", "report.md"],
    }
    assert _render_summary(summary, "text") == (
        "Wrote staged local CI evidence: ci-summary.json, report.md"
    )
    assert _render_summary(summary, "json") == canonical_json(summary).rstrip()
    assert _render_summary(summary, "markdown") == (
        "# TrustWeave Local CI Summary\n\n"
        "**Status:** **clear**  \n"
        "**Generated at:** `2026-08-14T00:00:00+00:00`\n\n"
        "## Published artifacts\n\n"
        "- `ci-summary.json`\n- `report.md`"
    )


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
    mcp_review = load_document(output_dir / "mcp-profile-review.json")
    assert mcp_review["summary"] == {
        "tools_reviewed": 2,
        "review_findings": 0,
        "status": "clear",
    }
    assert mcp_review["mappings"] == [
        {
            "mcp_tool": "knowledge.search",
            "manifest_tool": "search_knowledge_base",
            "declared_action_class": "read",
            "manifest_action_class": "read",
            "status": "clear",
        },
        {
            "mcp_tool": "customer.lookup",
            "manifest_tool": "lookup_customer_record",
            "declared_action_class": "sensitive",
            "manifest_action_class": "sensitive",
            "status": "clear",
        },
    ]


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


def test_ci_scenario_failure_drives_review_exit_and_summary_status(tmp_path: Path) -> None:
    """A failed supplied scenario must remain visible in test evidence and produce review status."""

    root = Path(__file__).resolve().parents[1]
    scenarios = tmp_path / "failing-scenarios.json"
    scenarios.write_text(
        "{\n"
        '  "schema_version": "trustweave.dev/v1alpha1",\n'
        '  "name": "failing-scenario",\n'
        '  "scenarios": [{\n'
        '    "id": "TW-SC-FAIL",\n'
        '    "description": "A deliberately mismatched declared decision.",\n'
        '    "source_trust": "trusted",\n'
        '    "tool_action_class": "read",\n'
        '    "expected_decision": "deny"\n'
        "  }]\n"
        "}\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{(root / "examples/support-agent.manifest.json").as_posix()}"\n'
        f'policy = "{(root / "policies/default-policy.json").as_posix()}"\n'
        f'scenarios = "{scenarios.name}"\n'
        f'output_dir = "{output_dir.name}"\n'
        'enabled_stages = ["scan", "scenarios", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-18T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == EXIT_REVIEW
    )
    summary = load_document(output_dir / "ci-summary.json")
    results = load_document(output_dir / "security-test-results.json")
    assert results["summary"]["status"] == "failed"
    assert summary["status"] == "review_required"
    assert summary["artifacts"] == [
        "agent-security-bundle.json",
        "ci-summary.json",
        "security-test-results.json",
    ]


def test_ci_suppression_lifecycle_preserves_provenance_and_removes_active_gate(
    tmp_path: Path,
) -> None:
    """A matching suppression remains visible but removes its finding from active CI gating."""

    generated_at = "2026-08-18T00:00:00+00:00"
    chain_document = {
        "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
        "name": "suppressed-chain",
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
    chain_path = write_json(tmp_path / "chain.json", chain_document)
    initial_review = review_risks(
        [review_declared_chains(chain_document, generated_at=generated_at)],
        reviewed_at=generated_at,
        artifact_paths=["chain-review.json"],
    )
    baseline = create_baseline(
        initial_review,
        "Explicit temporary local suppression.",
        "2026-09-01T00:00:00+00:00",
        owner="security-review",
        created_at=generated_at,
    )
    suppressions = {
        "schema_version": "trustweave.dev/risk-suppressions/v1alpha2",
        "suppressions": baseline["baseline"],
    }
    suppressions_path = write_json(tmp_path / "suppressions.json", suppressions)
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'chain_manifest = "{chain_path.as_posix()}"\n'
        f'suppressions = "{suppressions_path.as_posix()}"\n'
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
    risk_review = load_document(output_dir / "risk-review.json")
    assert summary["status"] == "clear"
    assert summary["finding_counts"]["high"] > 0
    assert summary["active_severity_counts"]["high"] == 0
    assert summary["applied_decisions"] == {
        "baselined": 0,
        "suppressed": len(initial_review["findings"]),
        "expired_baseline": 0,
        "expired_suppression": 0,
    }
    assert all(finding["risk_state"] == "suppressed" for finding in risk_review["findings"])
    assert all(
        finding["source_artifact_paths"] == ["chain-review.json"]
        for finding in risk_review["findings"]
    )


def test_project_config_required_sections_and_declared_values_are_strict(tmp_path: Path) -> None:
    """Local configuration preserves explicit sections, values, and bounded-stage contracts."""

    path = tmp_path / CONFIG_FILE_NAME
    cases = [
        ("", "project configuration requires [tool.trustweave]"),
        ("[tool]\n", "project configuration requires [tool.trustweave]"),
        ('[tool.trustweave]\nunknown = "value"\n', "tool.trustweave: unknown field 'unknown'"),
        (
            "[tool.trustweave]\n"
            'enabled_stages = ["scan", "scan", "scan", "scan", "scan", "scan", "scan", '
            '"scan", "scan", "scan", "scan", "scan", "scan", "scan", "scan", "scan", "scan"]\n',
            "tool.trustweave.enabled_stages must contain between 1 and 16 stage names",
        ),
    ]
    for contents, message in cases:
        path.write_text(contents, encoding="utf-8")
        with pytest.raises(ValidationError) as error:
            load_project_config(path)
        assert str(error.value) == message

    path.write_text(
        "[tool.trustweave]\n"
        'output_dir = "  artifacts  "\n'
        'failure_threshold = "review"\n'
        'enabled_stages = ["scan", "summary"]\n'
        "reproducible = false\n",
        encoding="utf-8",
    )
    assert load_project_config(path) == {
        "output_dir": "artifacts",
        "failure_threshold": "review",
        "enabled_stages": ("scan", "summary"),
        "reproducible": False,
    }


@pytest.mark.parametrize(
    ("stages", "message"),
    [
        (["policy_coverage"], "policy_coverage stage requires selected stages: policy_review"),
        (["attestation"], "attestation stage requires selected stages: scan, scenarios"),
        (
            ["report"],
            "report stage requires selected stages: attestation, scan, scenarios",
        ),
        (["risk"], "risk stage requires at least one selected local review stage"),
        (["sarif"], "sarif stage requires risk or at least one selected local review stage"),
    ],
)
def test_ci_stage_dependencies_fail_closed_with_exact_public_diagnostics(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    stages: list[str],
    message: str,
) -> None:
    """Impossible selected-stage combinations fail before a local artifact directory is created."""

    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    rendered_stages = ", ".join(f'"{stage}"' for stage in stages)
    config.write_text(
        "[tool.trustweave]\n"
        f'output_dir = "{output_dir.name}"\n'
        f"enabled_stages = [{rendered_stages}]\n"
        "reproducible = false\n",
        encoding="utf-8",
    )

    assert main(["ci", "--config", str(config), "--quiet"]) == 2
    assert capsys.readouterr().err == f"Validation error: {message}\n"
    assert not output_dir.exists()


def test_ci_uses_documented_none_threshold_when_configuration_omits_it(tmp_path: Path) -> None:
    """An omitted local failure threshold defaults to `none` and does not gate review findings."""

    root = Path(__file__).resolve().parents[1]
    policy_document = dict(load_document(root / "policies" / "default-policy.json"))
    policy_document.pop("approval_control")
    policy_path = write_json(tmp_path / "review-required-policy.json", policy_document)
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'policy = "{policy_path.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["policy_review", "summary"]\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-18T00:00:00+00:00",
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
    assert summary["finding_counts"]["review"] == 1
    assert summary["active_severity_counts"]["review"] == 1


@pytest.mark.parametrize("bundle_field", ("baseline_bundle", "candidate_bundle"))
def test_ci_validate_stage_preserves_exact_configured_bundle_field_diagnostic(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    bundle_field: str,
) -> None:
    """Validate-only CI names the malformed configured bundle field before publishing output."""

    malformed = tmp_path / f"{bundle_field}.json"
    malformed.write_text('{"not": "a supported bundle"}', encoding="utf-8")
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'{bundle_field} = "{malformed.name}"\n'
        f'output_dir = "{output_dir.name}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-18T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 2
    )
    assert capsys.readouterr().err.startswith(f"Validation error: {bundle_field}.")
    assert not output_dir.exists()


@pytest.mark.parametrize(
    ("field", "schema_version", "collection", "summary_key"),
    [
        (
            "risk_baseline",
            "trustweave.dev/risk-baseline/v1alpha2",
            "baseline",
            "expired_baseline",
        ),
        (
            "suppressions",
            "trustweave.dev/risk-suppressions/v1alpha2",
            "suppressions",
            "expired_suppression",
        ),
    ],
)
def test_ci_expired_reviewer_decisions_remain_active_and_counted(
    tmp_path: Path,
    field: str,
    schema_version: str,
    collection: str,
    summary_key: str,
) -> None:
    """Expired local decisions remain reviewer-visible and cannot suppress the active risk gate."""

    generated_at = "2026-08-18T00:00:00+00:00"
    chain_document = {
        "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
        "name": "expired-decision-chain",
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
    chain_path = write_json(tmp_path / "chain.json", chain_document)
    initial_review = review_risks(
        [review_declared_chains(chain_document, generated_at="2026-08-16T00:00:00+00:00")],
        reviewed_at="2026-08-16T00:00:00+00:00",
        artifact_paths=["chain-review.json"],
    )
    decision = create_baseline(
        initial_review,
        "A previously approved local decision that has now expired.",
        "2026-08-17T00:00:00+00:00",
        owner="security-review",
        created_at="2026-08-16T00:00:00+00:00",
    )
    document = {"schema_version": schema_version, collection: decision["baseline"]}
    decision_path = write_json(tmp_path / f"{field}.json", document)
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'chain_manifest = "{chain_path.as_posix()}"\n'
        f'{field} = "{decision_path.as_posix()}"\n'
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
        == EXIT_REVIEW
    )
    summary = load_document(output_dir / "ci-summary.json")
    risk_review = load_document(output_dir / "risk-review.json")
    assert summary["status"] == "review_required"
    assert summary["applied_decisions"] == {
        "baselined": 0,
        "suppressed": 0,
        "expired_baseline": (
            len(initial_review["findings"]) if summary_key == "expired_baseline" else 0
        ),
        "expired_suppression": (
            len(initial_review["findings"]) if summary_key == "expired_suppression" else 0
        ),
    }
    assert summary["active_severity_counts"]["high"] > 0
    assert all(finding["risk_state"] == summary_key for finding in risk_review["findings"])


def test_ci_validate_stage_dispatches_every_configured_document_and_stages_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate-only CI semantically dispatches each declared local document before publication."""

    names = (
        "manifest",
        "policy",
        "scenarios",
        "mcp_profile",
        "chain_manifest",
        "trace",
        "risk_baseline",
        "suppressions",
        "baseline_bundle",
        "candidate_bundle",
    )
    config_path = tmp_path / "trustweave.toml"
    config_path.write_text("[tool.trustweave]\n", encoding="utf-8")
    output_dir = tmp_path / "nested" / "artifacts"
    paths = {name: tmp_path / f"{name}.json" for name in names}
    paths["output_dir"] = output_dir
    documents = {path: {"document": name} for name, path in paths.items() if name != "output_dir"}
    config: dict[str, object] = {
        "enabled_stages": ("validate", "summary"),
        "reproducible": False,
        "failure_threshold": "none",
        **{name: path.as_posix() for name, path in paths.items() if name != "output_dir"},
        "output_dir": output_dir.as_posix(),
    }
    calls: list[tuple[str, object]] = []
    original_temporary_directory = ci_command.tempfile.TemporaryDirectory

    monkeypatch.setattr(ci_command, "load_project_config", lambda _path: config)
    monkeypatch.setattr(ci_command, "configured_paths", lambda _path, _values: paths)
    monkeypatch.setattr(ci_command, "load_document", lambda path: documents[path])
    monkeypatch.setattr(
        ci_command, "parse_manifest", lambda document: calls.append(("manifest", document))
    )
    monkeypatch.setattr(
        ci_command, "parse_policy", lambda document: calls.append(("policy", document))
    )
    monkeypatch.setattr(
        ci_command, "parse_scenarios", lambda document: calls.append(("scenarios", document))
    )
    monkeypatch.setattr(
        ci_command, "parse_mcp_profile", lambda document: calls.append(("mcp_profile", document))
    )
    monkeypatch.setattr(
        ci_command,
        "review_declared_chains",
        lambda document, generated_at: calls.append(("chain_manifest", (document, generated_at))),
    )
    monkeypatch.setattr(
        ci_command, "parse_trace", lambda document: calls.append(("trace", document))
    )
    monkeypatch.setattr(
        ci_command,
        "validate_decision_document",
        lambda document, kind: calls.append((kind, document)),
    )
    monkeypatch.setattr(
        ci_command,
        "validate_bundle",
        lambda document, name: calls.append((name, document)),
    )

    temporary_calls: list[tuple[object, object]] = []

    def temporary_directory(*, prefix: object = None, dir: object = None) -> object:
        temporary_calls.append((prefix, dir))
        return original_temporary_directory(prefix=prefix, dir=dir)

    monkeypatch.setattr(ci_command.tempfile, "TemporaryDirectory", temporary_directory)
    staged_directories: list[Path] = []
    original_publish_directory = ci_command._publish_directory

    def capture_publish_directory(staging: Path, output: Path) -> None:
        staged_directories.append(staging)
        original_publish_directory(staging, output)

    monkeypatch.setattr(ci_command, "_publish_directory", capture_publish_directory)
    args = argparse.Namespace(
        config=config_path,
        no_config_discovery=False,
        output_dir=None,
        source_revision="dispatch-contract",
        coverage=False,
        exit_on_review=False,
        fail_on=None,
        quiet=True,
        format="text",
        generated_at_source="explicit",
    )

    rendered, code = ci_command.handle(args, "2026-08-15T00:00:00+00:00")
    assert rendered == ""
    assert code == 0
    assert [name for name, _ in calls] == [
        "manifest",
        "policy",
        "scenarios",
        "mcp_profile",
        "chain_manifest",
        "trace",
        "baseline",
        "suppressions",
        "baseline_bundle",
        "candidate_bundle",
    ]
    assert calls[4][1] == (
        documents[paths["chain_manifest"]],
        "2026-08-15T00:00:00+00:00",
    )
    assert temporary_calls == [(".trustweave-ci-", output_dir.parent)]
    assert [directory.name for directory in staged_directories] == ["artifacts"]
    assert (output_dir / "ci-summary.json").is_file()


def test_ci_summary_only_uses_clock_default_and_requested_rendering_for_embedded_callers(
    tmp_path: Path,
) -> None:
    """Summary-only CI callers without CLI provenance metadata receive stable safe defaults."""

    output_dir = tmp_path / "artifacts"
    config_path = tmp_path / "trustweave.toml"
    config_path.write_text(
        "[tool.trustweave]\n"
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["summary"]\n'
        'failure_threshold = "none"\n',
        encoding="utf-8",
    )
    args = argparse.Namespace(
        config=config_path,
        no_config_discovery=False,
        output_dir=None,
        source_revision="summary-default-contract",
        coverage=False,
        exit_on_review=False,
        fail_on=None,
        quiet=False,
        format="markdown",
    )

    rendered, code = ci_command.handle(args, "2026-08-18T00:00:00+00:00")
    summary = load_document(output_dir / "ci-summary.json")

    assert code == 0
    assert rendered.startswith("# TrustWeave Local CI Summary")
    assert summary["provenance"] == {
        "generated_at_source": "clock",
        "source_revision": "summary-default-contract",
    }
    assert summary["artifacts"] == ["ci-summary.json"]
    assert summary["applied_decisions"] == {
        "baselined": 0,
        "suppressed": 0,
        "expired_baseline": 0,
        "expired_suppression": 0,
    }


def test_ci_reproducible_embedded_callers_reject_implicit_clock_provenance(tmp_path: Path) -> None:
    """Reproducible CI never accepts an embedded invocation that omits generated-at provenance."""

    config_path = tmp_path / "trustweave.toml"
    config_path.write_text(
        "[tool.trustweave]\n"
        f'output_dir = "{(tmp_path / "artifacts").as_posix()}"\n'
        'enabled_stages = ["summary"]\n'
        "reproducible = true\n",
        encoding="utf-8",
    )
    args = argparse.Namespace(
        config=config_path,
        no_config_discovery=False,
        output_dir=None,
        source_revision="reproducible-embedded",
        coverage=False,
        exit_on_review=False,
        fail_on=None,
        quiet=True,
        format="json",
    )

    with pytest.raises(ValidationError) as error:
        ci_command.handle(args, "2026-08-18T00:00:00+00:00")
    assert str(error.value) == (
        "reproducible CI requires --generated-at or SOURCE_DATE_EPOCH; wall-clock provenance "
        "is not deterministic"
    )


def test_ci_mcp_profile_stage_loads_manifest_without_prior_scan(tmp_path: Path) -> None:
    """An MCP-only configured review parses its declared manifest.

    It must not depend on state that only the scan stage creates.
    """

    root = Path(__file__).resolve().parents[1]
    manifest_path = root / "examples" / "support-agent.manifest.json"
    profile_path = root / "examples" / "mcp-profiles" / "clear-support-profile.json"
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{manifest_path.as_posix()}"\n'
        f'mcp_profile = "{profile_path.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["mcp_profile_review", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-18T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )
    review = load_document(output_dir / "mcp-profile-review.json")
    assert review["mappings"] == [
        {
            "mcp_tool": "knowledge.search",
            "manifest_tool": "search_knowledge_base",
            "declared_action_class": "read",
            "manifest_action_class": "read",
            "status": "clear",
        },
        {
            "mcp_tool": "customer.lookup",
            "manifest_tool": "lookup_customer_record",
            "declared_action_class": "sensitive",
            "manifest_action_class": "sensitive",
            "status": "clear",
        },
    ]


def test_ci_exit_on_review_gates_selected_review_without_risk_stage(tmp_path: Path) -> None:
    """The direct selected-review gate remains active when risk lifecycle processing is omitted."""

    root = Path(__file__).resolve().parents[1]
    policy = dict(load_document(root / "policies/default-policy.json"))
    policy.pop("approval_control")
    policy_path = write_json(tmp_path / "review-required-policy.json", policy)
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'policy = "{policy_path.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["policy_review", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-18T00:00:00+00:00",
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
        "selected_kinds": ["policy"],
        "uses_risk_lifecycle": False,
    }
    assert summary["finding_counts"]["review"] == 1


def test_ci_directory_publication_restores_only_replaced_output_after_staging_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed staged replacement restores an existing output but never revives stale backups."""

    original_replace = Path.replace

    def fail_staging_replace(path: Path, target: Path) -> Path:
        if path.name.endswith("staging"):
            raise OSError("simulated staged publish failure")
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", fail_staging_replace)

    output = tmp_path / "artifacts"
    output.mkdir()
    (output / "old.txt").write_text("old", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "new.txt").write_text("new", encoding="utf-8")

    with pytest.raises(InputOutputError) as error:
        _publish_directory(staging, output)
    assert str(error.value) == (
        f"Could not publish CI artifacts to {output}: simulated staged publish failure"
    )
    assert (output / "old.txt").read_text(encoding="utf-8") == "old"
    assert not (output / "new.txt").exists()
    assert not (tmp_path / ".artifacts.previous").exists()

    empty_output = tmp_path / "empty-artifacts"
    stale_backup = tmp_path / ".empty-artifacts.previous"
    stale_backup.mkdir()
    (stale_backup / "stale.txt").write_text("stale", encoding="utf-8")
    empty_staging = tmp_path / "empty-staging"
    empty_staging.mkdir()
    (empty_staging / "new.txt").write_text("new", encoding="utf-8")

    with pytest.raises(InputOutputError):
        _publish_directory(empty_staging, empty_output)
    assert not empty_output.exists()
    assert not stale_backup.exists()


def test_ci_handle_rejects_partial_artifact_prerequisites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attestation and report never accept partially-created prerequisite artifacts."""

    config_path = tmp_path / "trustweave.toml"
    config_path.write_text("[tool.trustweave]\n", encoding="utf-8")
    paths = {
        "manifest": tmp_path / "manifest.json",
        "policy": tmp_path / "policy.json",
        "scenarios": tmp_path / "scenarios.json",
        "output_dir": tmp_path / "artifacts",
    }
    config: dict[str, object] = {
        "enabled_stages": ("scan", "scenarios", "attestation"),
        "reproducible": False,
        "failure_threshold": "none",
    }
    args = argparse.Namespace(
        config=config_path,
        no_config_discovery=False,
        output_dir=None,
        source_revision="partial-artifact-contract",
        coverage=False,
        exit_on_review=False,
        fail_on=None,
        quiet=True,
        format="text",
        generated_at_source="explicit",
    )

    monkeypatch.setattr(ci_command, "load_project_config", lambda _path: config)
    monkeypatch.setattr(ci_command, "configured_paths", lambda _path, _values: paths)
    monkeypatch.setattr(ci_command, "read_json", lambda _path: {})
    monkeypatch.setattr(ci_command, "parse_manifest", lambda _document: object())
    monkeypatch.setattr(ci_command, "parse_policy", lambda _document: object())
    monkeypatch.setattr(ci_command, "parse_scenarios", lambda _document: object())
    monkeypatch.setattr(ci_command, "build_bundle", lambda *_args: {})
    monkeypatch.setattr(ci_command, "run_scenarios", lambda *_args: {})

    attestation_outputs: list[Path | None] = [None, tmp_path / "test-results.json"]
    monkeypatch.setattr(
        ci_command,
        "write_json",
        lambda _path, _document: attestation_outputs.pop(0),
    )
    with pytest.raises(ValidationError) as error:
        ci_command.handle(args, "2026-08-18T00:00:00+00:00")
    assert str(error.value) == "attestation stage requires selected scan and scenarios stages"

    config["enabled_stages"] = ("scan", "scenarios", "attestation", "report")
    report_outputs: list[Path | None] = [
        tmp_path / "bundle.json",
        tmp_path / "test-results.json",
        None,
    ]
    monkeypatch.setattr(
        ci_command,
        "write_json",
        lambda _path, _document: report_outputs.pop(0),
    )
    monkeypatch.setattr(ci_command, "build_attestation", lambda *_args, **_kwargs: {})
    with pytest.raises(ValidationError) as error:
        ci_command.handle(args, "2026-08-18T00:00:00+00:00")
    assert str(error.value) == (
        "report stage requires selected scan, scenarios, and attestation stages"
    )


@pytest.mark.parametrize("risk_review", [{}, {"findings": ["not-a-mapping"]}])
def test_ci_handle_tolerates_missing_or_malformed_optional_risk_collections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    risk_review: dict[str, object],
) -> None:
    """Optional risk review collections default safely without changing a clear CI result."""

    root = Path(__file__).resolve().parents[1]
    config_path = tmp_path / "trustweave.toml"
    config_path.write_text("[tool.trustweave]\n", encoding="utf-8")
    output_dir = tmp_path / "artifacts"
    config: dict[str, object] = {
        "enabled_stages": ("policy_review", "risk", "summary"),
        "reproducible": False,
        "failure_threshold": "none",
    }
    paths = {"policy": root / "policies" / "default-policy.json", "output_dir": output_dir}
    args = argparse.Namespace(
        config=config_path,
        no_config_discovery=False,
        output_dir=None,
        source_revision="risk-optional-contract",
        coverage=False,
        exit_on_review=False,
        fail_on=None,
        quiet=True,
        format="text",
        generated_at_source="explicit",
    )

    monkeypatch.setattr(ci_command, "load_project_config", lambda _path: config)
    monkeypatch.setattr(ci_command, "configured_paths", lambda _path, _values: paths)
    monkeypatch.setattr(ci_command, "review_policy", lambda *_args, **_kwargs: {"findings": []})
    monkeypatch.setattr(ci_command, "render_policy_review_report", lambda _review: "")
    monkeypatch.setattr(ci_command, "review_risks", lambda *_args, **_kwargs: risk_review)
    monkeypatch.setattr(ci_command, "render_risk_review_report", lambda _review: "")
    monkeypatch.setattr(ci_command, "should_fail", lambda *_args: False)

    rendered, code = ci_command.handle(args, "2026-08-18T00:00:00+00:00")
    summary = load_document(output_dir / "ci-summary.json")

    assert rendered == ""
    assert code == 0
    assert summary["status"] == "clear"
    assert summary["finding_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "review": 0,
    }
    assert summary["applied_decisions"] == {
        "baselined": 0,
        "suppressed": 0,
        "expired_baseline": 0,
        "expired_suppression": 0,
    }


def test_ci_handle_records_chain_budget_limit_in_the_public_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Chain traversal limits are retained in the published CI decision context."""

    chain_manifest = tmp_path / "chain.json"
    chain_manifest.write_text("{}", encoding="utf-8")
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'chain_manifest = "{chain_manifest.as_posix()}"\n'
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["chain_review", "summary"]\n'
        'failure_threshold = "none"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ci_command,
        "review_declared_chains",
        lambda *_args: {
            "findings": [
                {
                    "id": "TW-CHAIN-004",
                    "severity": "review",
                    "message": "Traversal budget was reached.",
                }
            ]
        },
    )
    monkeypatch.setattr(ci_command, "render_chain_review", lambda _review: "")

    assert (
        main(
            [
                "--generated-at",
                "2026-08-18T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )
    summary = load_document(output_dir / "ci-summary.json")
    assert summary["incomplete_analyses"] == [
        "Declared chain analysis reached a configured traversal budget."
    ]


def test_ci_summary_stage_serializes_a_non_null_pre_artifact_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first summary write is a complete mapping before its artifact name is appended."""

    config = tmp_path / "trustweave.toml"
    output_dir = tmp_path / "artifacts"
    config.write_text(
        "[tool.trustweave]\n"
        f'output_dir = "{output_dir.as_posix()}"\n'
        'enabled_stages = ["summary"]\n'
        'failure_threshold = "none"\n',
        encoding="utf-8",
    )
    original_write_json = ci_command.write_json
    captured_documents: list[dict[str, object]] = []

    def capture_write_json(path: Path, document: object) -> Path:
        if path.name == "ci-summary.json":
            assert isinstance(document, dict)
            captured_documents.append(
                {
                    **document,
                    "artifacts": list(document["artifacts"]),
                }
            )
        return original_write_json(path, document)

    monkeypatch.setattr(ci_command, "write_json", capture_write_json)

    assert (
        main(
            [
                "--generated-at",
                "2026-08-18T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 0
    )
    assert [document["artifacts"] for document in captured_documents] == [[], ["ci-summary.json"]]


@pytest.mark.parametrize("sarif_output", ["/tmp/trustweave.sarif", r"\rooted.sarif"])
def test_safe_sarif_path_rejects_native_or_windows_rooted_absolute_paths(
    sarif_output: str,
) -> None:
    """Portable SARIF artifacts cannot use either host-absolute or Windows-rooted paths."""

    with pytest.raises(ValidationError) as error:
        _safe_sarif_path({"sarif_output": sarif_output})
    assert str(error.value) == (
        "tool.trustweave.sarif_output must remain within the CI artifact directory"
    )


def test_ci_output_path_rejects_symbolic_links_with_exact_diagnostic(tmp_path: Path) -> None:
    """CI outputs must not traverse symbolic links at any path component."""

    target = tmp_path / "target"
    target.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(target, target_is_directory=True)
    output = linked_parent / "artifacts"

    with pytest.raises(InputOutputError) as error:
        _validate_output_path(output)
    assert str(error.value) == f"CI output path must not traverse a symbolic link: {linked_parent}"


def test_ci_output_parent_creation_preserves_exact_oserror_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Output-parent creation retains the local OSError detail in its public diagnostic."""

    def fail_mkdir(_path: Path, *_args: object, **_kwargs: object) -> None:
        raise OSError(13, "permission denied")

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)
    output = tmp_path / "nested" / "artifacts"
    with pytest.raises(InputOutputError) as error:
        _prepare_output_parent(output)
    assert (
        str(error.value) == f"Could not create CI output parent {output.parent}: permission denied"
    )


def test_ci_directory_publication_rejects_a_symbolic_link_output_with_exact_diagnostic(
    tmp_path: Path,
) -> None:
    """The publication boundary must not replace an output directory through a symbolic link."""

    outside = tmp_path / "outside"
    outside.mkdir()
    output = tmp_path / "artifacts"
    try:
        output.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symbolic links are unavailable: {error}")
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(InputOutputError) as error:
        _publish_directory(staging, output)
    assert str(error.value) == f"CI output path must not be a symbolic link: {output}"
