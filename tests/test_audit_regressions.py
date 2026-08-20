"""Executable regressions for audit-remediation documentation and contracts."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from trustweave.cli import EXIT_SUCCESS, main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
RISK_EXAMPLES = ROOT / "examples" / "risk-management"


def test_risk_management_quickstart_accepts_current_examples_from_clean_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented risk command must accept its checked-in v1alpha2 decision examples."""

    examples_dir = tmp_path / "examples" / "risk-management"
    examples_dir.mkdir(parents=True)
    for filename in (
        "risk-baseline.example.json",
        "risk-suppressions.example.json",
    ):
        shutil.copyfile(RISK_EXAMPLES / filename, examples_dir / filename)

    monkeypatch.chdir(tmp_path)
    assert (
        main(
            [
                "policy-check",
                "--policy",
                str(POLICY),
                "--output-dir",
                "artifacts",
            ]
        )
        == EXIT_SUCCESS
    )
    for output_dir in ("baseline", "candidate"):
        assert (
            main(
                [
                    "scan",
                    "--manifest",
                    str(MANIFEST),
                    "--policy",
                    str(POLICY),
                    "--output-dir",
                    output_dir,
                ]
            )
            == EXIT_SUCCESS
        )
    assert (
        main(
            [
                "diff",
                "--base",
                "baseline/agent-security-bundle.json",
                "--head",
                "candidate/agent-security-bundle.json",
                "--output-dir",
                "artifacts/review",
            ]
        )
        == EXIT_SUCCESS
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-13T00:00:00+00:00",
                "risk-check",
                "--input",
                "artifacts/policy-review.json",
                "--input",
                "artifacts/review/bundle-diff.json",
                "--baseline",
                "examples/risk-management/risk-baseline.example.json",
                "--suppressions",
                "examples/risk-management/risk-suppressions.example.json",
                "--fail-on",
                "high",
                "--output",
                "artifacts/risk-review.json",
            ]
        )
        == EXIT_SUCCESS
    )
    review = json.loads((tmp_path / "artifacts" / "risk-review.json").read_text(encoding="utf-8"))
    assert review["schema_version"] == "trustweave.dev/risk-review/v1alpha2"
