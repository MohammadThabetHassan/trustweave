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
CI_HELP_PATH = ROOT / "tests" / "fixtures" / "cli-ci-help.txt"


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


def test_ci_parser_help_matches_the_golden_contract_in_process(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The registered CI command exposes its complete stable contract in the active process."""

    from trustweave.cli import _parser

    parser = _parser()
    with pytest.raises(SystemExit) as exit_status:
        parser.parse_args(["ci", "--help"])
    assert exit_status.value.code == 0
    assert _normalized_help(capsys.readouterr().out) == _normalized_help(
        CI_HELP_PATH.read_text(encoding="utf-8")
    )


def test_ci_help_matches_the_golden_contract() -> None:
    """The CI coordinator exposes stable local-only parser options and threshold semantics."""

    completed = subprocess.run(
        [sys.executable, "-m", "trustweave.cli", "ci", "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        env={**os.environ, "COLUMNS": "100"},
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert _normalized_help(completed.stdout) == _normalized_help(
        CI_HELP_PATH.read_text(encoding="utf-8")
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


def test_ci_parser_preserves_declared_argument_types_defaults_and_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The in-process CI parser retains stable typed options and declared command defaults."""

    from trustweave.cli import _parser

    monkeypatch.setenv("GITHUB_SHA", "parser-contract-revision")
    parser = _parser()
    defaults = parser.parse_args(["ci"])
    assert defaults.config is None
    assert defaults.no_config_discovery is False
    assert defaults.output_dir is None
    assert defaults.source_revision == "parser-contract-revision"
    assert defaults.coverage is False
    assert defaults.exit_on_review is False
    assert defaults.fail_on is None
    assert defaults.format == "text"
    assert defaults.quiet is False

    parsed = parser.parse_args(
        [
            "ci",
            "--config",
            "nested/trustweave.toml",
            "--no-config-discovery",
            "--output-dir",
            "nested/artifacts",
            "--source-revision",
            "fixed-revision",
            "--coverage",
            "--exit-on-review",
            "--fail-on",
            "medium",
            "--format",
            "markdown",
            "--quiet",
        ]
    )
    assert parsed.config == Path("nested/trustweave.toml")
    assert parsed.no_config_discovery is True
    assert parsed.output_dir == Path("nested/artifacts")
    assert parsed.source_revision == "fixed-revision"
    assert parsed.coverage is True
    assert parsed.exit_on_review is True
    assert parsed.fail_on == "medium"
    assert parsed.format == "markdown"
    assert parsed.quiet is True


def test_ci_registration_preserves_top_level_description_and_local_revision_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CI registration exposes local-only intent and a deterministic no-environment revision."""

    from trustweave.cli import _parser

    monkeypatch.delenv("GITHUB_SHA", raising=False)
    parser = _parser()
    assert (
        "Run configured local evidence stages without executing an agent or contacting services."
        in _normalized_help(parser.format_help())
    )
    assert parser.parse_args(["ci"]).source_revision == "local-uncommitted"
