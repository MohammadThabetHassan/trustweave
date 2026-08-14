"""Regression coverage for the thin CLI facade and public command discoverability."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from trustweave.models import InputOutputError, ValidationError

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


@pytest.mark.parametrize(
    ("error", "expected_code", "expected_prefix"),
    [
        (ValidationError("invalid local declaration"), 2, "Validation error:"),
        (InputOutputError("missing local artifact"), 3, "Input/output error:"),
        (OSError("local write failed"), 3, "Input/output error:"),
        (RuntimeError("unexpected local failure"), 4, "Internal error: RuntimeError:"),
    ],
)
def test_cli_maps_handler_failures_to_stable_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    expected_code: int,
    expected_prefix: str,
) -> None:
    from trustweave import cli

    def raise_error(*_args: object) -> tuple[str, int]:
        raise error

    monkeypatch.setattr(cli, "dispatch", raise_error)

    assert cli.main(["scan"]) == expected_code
    assert capsys.readouterr().err.startswith(expected_prefix)


def test_cli_debug_mode_reraises_validation_errors() -> None:
    from trustweave import cli

    with pytest.raises(ValidationError, match="required"):
        cli.main(["--debug", "scan"])
