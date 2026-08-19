"""Regression coverage for the package module CLI entry point."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from trustweave import __version__

ROOT = Path(__file__).resolve().parents[1]


def _clean_environment() -> dict[str, str]:
    """Return a source-checkout environment without mutation-test overrides."""

    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("MUTMUT") and key != "MUTANT_UNDER_TEST"
    }
    environment["PYTHONPATH"] = str(ROOT / "src")
    return environment


def test_module_entrypoint_prints_the_authoritative_version() -> None:
    """`python -m trustweave` must expose the same package version as the console script."""

    completed = subprocess.run(
        [sys.executable, "-m", "trustweave", "--version"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=_clean_environment(),
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == f"{__version__}\n"
    assert completed.stderr == ""


def test_module_entrypoint_exposes_the_documented_command_surface() -> None:
    """Module invocation must remain a complete, local-only alternative to the console script."""

    completed = subprocess.run(
        [sys.executable, "-m", "trustweave", "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=_clean_environment(),
    )

    assert completed.returncode == 0, completed.stderr
    assert "usage: trustweave" in completed.stdout
    assert "framework-import" in completed.stdout
    assert "mcp-import" in completed.stdout
    assert completed.stderr == ""
