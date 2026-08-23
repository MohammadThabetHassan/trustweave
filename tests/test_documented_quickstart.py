"""End-to-end contract for the published local-review quickstart."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLATION_GUIDE = ROOT / "docs" / "site" / "INSTALLATION.md"


def _run(*arguments: str) -> None:
    """Execute one documented module command and retain its output if it fails."""

    completed = subprocess.run(
        [sys.executable, "-m", "trustweave", *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_installation_quickstart_runs_end_to_end_in_documented_order(tmp_path: Path) -> None:
    """The published quickstart creates attestation input before requesting a report."""

    guide = INSTALLATION_GUIDE.read_text(encoding="utf-8")
    assert guide.index(
        "trustweave attest --source-revision local --output-dir artifacts"
    ) < guide.index("trustweave report --output-dir artifacts")

    artifacts = tmp_path / "artifacts"
    _run(
        "scan",
        "--manifest",
        "examples/support-agent.manifest.json",
        "--policy",
        "policies/default-policy.json",
        "--output-dir",
        str(artifacts),
    )
    _run(
        "test",
        "--policy",
        "policies/default-policy.json",
        "--scenarios",
        "scenarios/default-scenarios.json",
        "--output-dir",
        str(artifacts),
    )
    _run("attest", "--source-revision", "local", "--output-dir", str(artifacts))
    _run("report", "--output-dir", str(artifacts))
    _run(
        "verify",
        "--attestation",
        str(artifacts / "attestation.json"),
        "--bundle",
        str(artifacts / "agent-security-bundle.json"),
        "--test-results",
        str(artifacts / "security-test-results.json"),
    )

    assert (artifacts / "report.md").is_file()
