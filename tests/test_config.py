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
