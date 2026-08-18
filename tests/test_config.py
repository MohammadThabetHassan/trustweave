from __future__ import annotations

from pathlib import Path

import pytest

import trustweave.config as config_module
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


@pytest.mark.parametrize(
    ("fragment", "message"),
    [
        ("manifest = 1\n", "tool.trustweave.manifest must be a non-empty string"),
        (
            'failure_threshold = "urgent"\n',
            "tool.trustweave.failure_threshold must be one of "
            "['critical', 'high', 'info', 'low', 'medium', 'none', 'review']",
        ),
        ('reproducible = "true"\n', "tool.trustweave.reproducible must be a boolean"),
        ('unknown = "value"\n', "tool.trustweave: unknown field 'unknown'"),
    ],
)
def test_project_config_preserves_exact_malformed_field_paths(
    tmp_path: Path, fragment: str, message: str
) -> None:
    """Strict local configuration failures retain their full field paths for remediation."""

    path = tmp_path / CONFIG_FILE_NAME
    path.write_text("[tool.trustweave]\n" + fragment, encoding="utf-8")

    with pytest.raises(ValidationError) as error:
        load_project_config(path)
    assert str(error.value) == message


def test_project_config_stage_and_discovery_boundaries_preserve_exact_diagnostics(
    tmp_path: Path,
) -> None:
    """Configuration stage and discovery validation remains explicit at each public boundary."""

    from trustweave.config import _enabled_stages

    with pytest.raises(ValidationError) as error:
        _enabled_stages("scan")
    assert str(error.value) == "tool.trustweave.enabled_stages must be a list of stage names"

    with pytest.raises(ValidationError) as error:
        _enabled_stages(["a", "b"])
    assert str(error.value) == "tool.trustweave.enabled_stages contains unsupported stages: a, b"

    with pytest.raises(ValidationError) as error:
        _enabled_stages(["scan", "scan"])
    assert str(error.value) == "tool.trustweave.enabled_stages must not contain duplicates"

    config_path = tmp_path / CONFIG_FILE_NAME
    config_path.write_text("[tool.trustweave]\n", encoding="utf-8")
    assert find_project_config(tmp_path, max_parents=0) == config_path
    with pytest.raises(ValidationError) as error:
        find_project_config(tmp_path, max_parents=-1)
    assert str(error.value) == "config discovery max_parents must be non-negative"


def test_project_config_preserves_exact_utf8_threshold_and_unknown_key_diagnostics(
    tmp_path: Path,
) -> None:
    """Strict local configuration failures retain stable reviewer-facing diagnostics."""

    path = tmp_path / CONFIG_FILE_NAME
    path.write_bytes(b"\xff")
    with pytest.raises(InputOutputError) as error:
        load_project_config(path)
    assert str(error.value) == f"Project configuration is not valid UTF-8: {path}"

    path.write_text("[tool.trustweave]\nfailure_threshold = 'invalid'\n", encoding="utf-8")
    with pytest.raises(ValidationError) as error:
        load_project_config(path)
    assert str(error.value) == (
        "tool.trustweave.failure_threshold must be one of "
        "['critical', 'high', 'info', 'low', 'medium', 'none', 'review']"
    )

    path.write_text("[tool.trustweave]\nsome_unknown = true\n", encoding="utf-8")
    with pytest.raises(ValidationError) as error:
        load_project_config(path)
    assert str(error.value) == "tool.trustweave: unknown field 'some_unknown'"


def test_project_config_requires_utf8_decoding_a_top_level_table_and_typed_threshold_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Configuration decoding and malformed-value diagnostics remain explicit."""

    path = tmp_path / CONFIG_FILE_NAME
    observed_encodings: list[str | None] = []

    def capture_read_text(
        _path: Path, *, encoding: str | None = None, errors: str | None = None
    ) -> str:
        observed_encodings.append(encoding)
        return "[tool.trustweave]\n"

    monkeypatch.setattr(Path, "read_text", capture_read_text)
    assert load_project_config(path) == {}
    assert observed_encodings == ["utf-8"]

    monkeypatch.setattr(config_module.tomllib, "loads", lambda _document: 42)
    with pytest.raises(ValidationError) as error:
        load_project_config(path)
    assert str(error.value) == "project configuration must be a TOML table"

    monkeypatch.setattr(
        config_module.tomllib,
        "loads",
        lambda _document: {"tool": {"trustweave": {"failure_threshold": 1}}},
    )
    with pytest.raises(ValidationError) as error:
        load_project_config(path)
    assert str(error.value) == "tool.trustweave.failure_threshold must be a non-empty string"
