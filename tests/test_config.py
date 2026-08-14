from __future__ import annotations

from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.config import (
    CONFIG_FILE_NAME,
    find_project_config,
    init_project,
    load_project_config,
)
from trustweave.models import InputOutputError, ValidationError


def test_init_creates_a_local_template_and_never_overwrites(tmp_path: Path) -> None:
    assert main(["init", "--directory", str(tmp_path)]) == 0
    config_path = tmp_path / CONFIG_FILE_NAME
    assert config_path.is_file()
    assert load_project_config(config_path)["output_dir"] == "artifacts"
    with pytest.raises(InputOutputError, match="Refusing"):
        init_project(tmp_path)


def test_project_config_auto_discovery_and_read_only_cli_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "project"
    nested = project / "nested" / "work"
    nested.mkdir(parents=True)
    config_path = init_project(project)

    assert find_project_config(nested) == config_path
    assert main(["config", "validate", "--config", str(config_path)]) == 0
    assert main(["config", "show", "--config", str(config_path)]) == 0
    shown = capsys.readouterr().out
    assert '"manifest":"examples/support-agent.manifest.json"' in shown


def test_scan_uses_explicit_local_project_configuration(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    config_path = tmp_path / CONFIG_FILE_NAME
    config_path.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{(root / "examples" / "support-agent.manifest.json").as_posix()}"\n'
        f'policy = "{(root / "policies" / "default-policy.json").as_posix()}"\n'
        'output_dir = "configured-artifacts"\n',
        encoding="utf-8",
    )

    assert main(["scan", "--config", str(config_path)]) == 0
    assert (tmp_path / "configured-artifacts" / "agent-security-bundle.json").is_file()


def test_ci_coordinator_runs_local_configured_evidence_workflow(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    config_path = tmp_path / CONFIG_FILE_NAME
    config_path.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{(root / "examples" / "support-agent.manifest.json").as_posix()}"\n'
        f'policy = "{(root / "policies" / "default-policy.json").as_posix()}"\n'
        f'scenarios = "{(root / "scenarios" / "default-scenarios.json").as_posix()}"\n'
        'output_dir = "ci-artifacts"\n',
        encoding="utf-8",
    )

    assert main(["ci", "--config", str(config_path)]) == 0
    output_dir = tmp_path / "ci-artifacts"
    for name in (
        "agent-security-bundle.json",
        "security-test-results.json",
        "policy-review.json",
        "attestation.json",
        "report.md",
    ):
        assert (output_dir / name).is_file()


def test_project_config_reports_file_and_document_boundary_failures(tmp_path: Path) -> None:
    project = tmp_path / "project"
    nested = project / "nested"
    nested.mkdir(parents=True)
    config_path = init_project(project)
    marker = nested / "marker.txt"
    marker.write_text("local", encoding="utf-8")

    assert find_project_config(marker) == config_path
    with pytest.raises(InputOutputError, match="No trustweave.toml"):
        find_project_config(tmp_path / "unconfigured")
    with pytest.raises(InputOutputError, match="does not exist"):
        load_project_config(tmp_path / "missing.toml")

    invalid = tmp_path / "invalid.toml"
    invalid.write_text("[tool.trustweave", encoding="utf-8")
    with pytest.raises(ValidationError, match="invalid TOML"):
        load_project_config(invalid)
    invalid.write_text("name = 'not-a-tool-table'", encoding="utf-8")
    with pytest.raises(ValidationError, match="requires \\[tool.trustweave\\]"):
        load_project_config(invalid)
    invalid.write_text("[tool]\nname = 'missing-trustweave'", encoding="utf-8")
    with pytest.raises(ValidationError, match="requires \\[tool.trustweave\\]"):
        load_project_config(invalid)
    invalid.write_bytes(b"\xff")
    with pytest.raises(InputOutputError, match="not valid UTF-8"):
        load_project_config(invalid)


def test_project_config_rejects_unknown_and_non_string_values(tmp_path: Path) -> None:
    path = tmp_path / CONFIG_FILE_NAME
    path.write_text("[tool.trustweave]\nunknown = 'value'\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="unknown field"):
        load_project_config(path)
    path.write_text("[tool.trustweave]\nmanifest = 1\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="non-empty string"):
        load_project_config(path)


def test_project_config_accepts_safe_typed_ci_workflow_fields(tmp_path: Path) -> None:
    """The config contract admits only explicit local coordinator settings."""

    path = tmp_path / CONFIG_FILE_NAME
    path.write_text(
        "[tool.trustweave]\n"
        'manifest = "manifest.json"\n'
        'policy = "policy.json"\n'
        'scenarios = "scenarios.json"\n'
        'chain_manifest = "chain.json"\n'
        'baseline_bundle = "base.json"\n'
        'candidate_bundle = "candidate.json"\n'
        'trace = "trace.json"\n'
        'mcp_profile = "profile.json"\n'
        'risk_baseline = "baseline.json"\n'
        'suppressions = "suppressions.json"\n'
        'output_dir = "artifacts"\n'
        'sarif_output = "artifacts/trustweave.sarif"\n'
        'failure_threshold = "high"\n'
        'enabled_stages = ["scan", "policy_review", "sarif"]\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    config = load_project_config(path)

    assert config["chain_manifest"] == "chain.json"
    assert config["enabled_stages"] == ("scan", "policy_review", "sarif")
    assert config["reproducible"] is True


def test_project_config_discovery_has_an_explicit_upward_bound(tmp_path: Path) -> None:
    """Discovery cannot silently escape an explicitly chosen local project boundary."""

    project = tmp_path / "project"
    nested = project / "nested" / "work"
    nested.mkdir(parents=True)
    config_path = init_project(project)

    assert find_project_config(nested, max_parents=2) == config_path
    with pytest.raises(InputOutputError, match="within 1 parent directories"):
        find_project_config(nested, max_parents=1)


def test_ci_uses_configured_stages_formats_and_quiet_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Configured CI publishes only selected deterministic stages with a stable JSON summary."""

    root = Path(__file__).resolve().parents[1]
    config_path = tmp_path / CONFIG_FILE_NAME
    config_path.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{(root / "examples" / "support-agent.manifest.json").as_posix()}"\n'
        f'policy = "{(root / "policies" / "default-policy.json").as_posix()}"\n'
        'output_dir = "ci-artifacts"\n'
        'enabled_stages = ["scan", "policy_review", "summary"]\n'
        'failure_threshold = "none"\n',
        encoding="utf-8",
    )

    assert main(["ci", "--config", str(config_path), "--format", "json", "--quiet"]) == 0
    assert capsys.readouterr().out == ""
    output_dir = tmp_path / "ci-artifacts"
    assert (output_dir / "agent-security-bundle.json").is_file()
    assert (output_dir / "policy-review.json").is_file()
    summary = (output_dir / "ci-summary.json").read_text(encoding="utf-8")
    assert '"schema_version": "trustweave.dev/ci-summary/v1alpha1"' in summary
    assert '"stages": [' in summary
    assert not (output_dir / "security-test-results.json").exists()


def test_ci_preserves_existing_artifacts_when_a_later_stage_fails(tmp_path: Path) -> None:
    """A failed run cannot publish a mixed artifact directory over prior local evidence."""

    root = Path(__file__).resolve().parents[1]
    output_dir = tmp_path / "ci-artifacts"
    output_dir.mkdir()
    marker = output_dir / "previous-evidence.txt"
    marker.write_text("keep", encoding="utf-8")
    config_path = tmp_path / CONFIG_FILE_NAME
    config_path.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{(root / "examples" / "support-agent.manifest.json").as_posix()}"\n'
        'policy = "missing-policy.json"\n'
        'output_dir = "ci-artifacts"\n'
        'enabled_stages = ["scan", "policy_review"]\n',
        encoding="utf-8",
    )

    assert main(["ci", "--config", str(config_path)]) == 3
    assert marker.read_text(encoding="utf-8") == "keep"
    assert sorted(path.name for path in output_dir.iterdir()) == ["previous-evidence.txt"]


def test_ci_runs_selected_chain_and_sarif_stages(tmp_path: Path) -> None:
    """Optional local review stages must publish deterministic artifacts when explicitly enabled."""

    root = Path(__file__).resolve().parents[1]
    chain_manifest = root / "examples" / "chains" / "safe-sanitized-external.chain.json"
    config_path = tmp_path / CONFIG_FILE_NAME
    config_path.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{(root / "examples" / "support-agent.manifest.json").as_posix()}"\n'
        f'policy = "{(root / "policies" / "default-policy.json").as_posix()}"\n'
        f'chain_manifest = "{chain_manifest.as_posix()}"\n'
        'output_dir = "ci-artifacts"\n'
        'enabled_stages = ["scan", "policy_review", "chain_review", "sarif", "summary"]\n'
        'sarif_output = "trustweave.sarif"\n'
        'failure_threshold = "none"\n',
        encoding="utf-8",
    )

    assert main(["ci", "--config", str(config_path), "--quiet"]) == 0
    output_dir = tmp_path / "ci-artifacts"
    assert (output_dir / "chain-review.json").is_file()
    assert (output_dir / "chain-review.md").is_file()
    assert (output_dir / "trustweave.sarif").is_file()
