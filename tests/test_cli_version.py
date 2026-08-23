"""Public top-level CLI version-contract regression coverage."""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from trustweave import __version__

ROOT = Path(__file__).resolve().parents[1]


def _declared_project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as project_file:
        document = tomllib.load(project_file)
    version = document["project"]["version"]
    assert isinstance(version, str)
    return version


def _git_status() -> str:
    if not (ROOT / ".git").exists():
        pytest.skip("version side-effect checks require a git checkout")
    completed = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


@pytest.mark.parametrize("flag", ("--version", "-V"))
def test_top_level_version_flags_work_from_a_source_checkout_without_file_output(flag: str) -> None:
    """The source console invocation must emit only the package version without side effects."""

    before_status = _git_status()
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("MUTMUT") and key != "MUTANT_UNDER_TEST"
    }
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-m", "trustweave.cli", flag],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == f"{__version__}\n"
    assert completed.stderr == ""
    assert _git_status() == before_status


@pytest.mark.parametrize("flag", ("--version", "-V"))
def test_top_level_version_flags_bypass_dispatch_and_configuration_discovery(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    """Version display must not require a subcommand or enter command-dispatch infrastructure."""

    from trustweave import cli

    def fail_dispatch(*_args: object) -> tuple[str, int]:
        raise AssertionError("version display must not dispatch a command")

    monkeypatch.setattr(cli, "dispatch", fail_dispatch)
    with pytest.raises(SystemExit) as exit_status:
        cli.main([flag])

    assert exit_status.value.code == 0
    captured = capsys.readouterr()
    assert captured.out == f"{__version__}\n"
    assert captured.err == ""


def test_package_and_build_metadata_expose_one_authoritative_version() -> None:
    """The top-level version output must be sourced from package metadata, not a second literal."""

    assert __version__ == _declared_project_version() == "0.3.1"
