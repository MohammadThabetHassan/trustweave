"""Behavioral regressions for the configured local CI coordinator boundaries."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from trustweave.cli import main
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
from trustweave.models import InputOutputError, ValidationError


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


def test_ci_helper_contracts_are_deterministic_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stage selection, gating, rendering, and local path containment have stable semantics."""

    assert _selected_stages({})[:3] == ("scan", "scenarios", "policy_review")
    assert _selected_stages({"enabled_stages": ("scan", "summary")}) == ("scan", "summary")
    with pytest.raises(ValidationError, match="validated stage list"):
        _selected_stages({"enabled_stages": ["scan"]})
    with pytest.raises(ValidationError, match="does not implement configured stages: trace_review"):
        _selected_stages({"enabled_stages": ("trace_review",)})

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
    for value in ("../out.sarif", str((tmp_path / "out.sarif").resolve())):
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reproducible configured CI must not silently derive provenance from the wall clock."""

    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    config = tmp_path / "trustweave.toml"
    output_dir = tmp_path / "artifacts"
    _write_ci_config(config, output_dir)

    assert main(["ci", "--config", str(config), "--quiet"]) == 2
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
        'enabled_stages = ["chain_review", "summary"]\n'
        'failure_threshold = "high"\n'
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
        == EXIT_REVIEW
    )
    assert '"status": "review_required"' in (output_dir / "ci-summary.json").read_text(
        encoding="utf-8"
    )
