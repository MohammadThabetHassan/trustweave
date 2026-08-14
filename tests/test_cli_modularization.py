"""Regression coverage for the thin CLI facade and public command discoverability."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "src" / "trustweave" / "cli.py"
GOLDEN_HELP_PATH = ROOT / "tests" / "fixtures" / "cli-top-level-help.txt"
RISK_HELP_PATH = ROOT / "tests" / "fixtures" / "cli-risk-check-help.txt"


def _normalized_help(text: str) -> str:
    """Compare golden help content while ignoring platform-specific argparse line wrapping."""

    paragraphs = text.split("\n\n")
    return "\n\n".join(" ".join(paragraph.split()) for paragraph in paragraphs).strip()


def test_cli_facade_remains_under_two_hundred_lines() -> None:
    assert len(CLI_PATH.read_text(encoding="utf-8").splitlines()) < 200


def test_top_level_help_matches_the_golden_command_contract() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "trustweave.cli", "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        env={**os.environ, "COLUMNS": "100"},
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert _normalized_help(completed.stdout) == _normalized_help(
        GOLDEN_HELP_PATH.read_text(encoding="utf-8")
    )


def test_risk_check_help_matches_the_golden_contract() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "trustweave.cli", "risk-check", "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        env={**os.environ, "COLUMNS": "100"},
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert _normalized_help(completed.stdout) == _normalized_help(
        RISK_HELP_PATH.read_text(encoding="utf-8")
    )
