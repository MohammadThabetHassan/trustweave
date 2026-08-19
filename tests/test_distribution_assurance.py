"""Regression tests for clean-environment wheel and source-distribution assurance."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
DISTRIBUTION_VERIFIER = ROOT / "scripts" / "verify_distribution_artifacts.py"


def _distribution_verifier_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "verify_distribution_artifacts", DISTRIBUTION_VERIFIER
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_distribution_verifier_refuses_dirty_checkout_without_test_escape_hatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    distribution = _distribution_verifier_module()
    monkeypatch.setattr(distribution, "_git_status", lambda: " M src/trustweave/cli.py\n")

    assert distribution.main([]) == 2


def test_distribution_verifier_rejects_path_traversal_archive_members() -> None:
    distribution = _distribution_verifier_module()

    with pytest.raises(ValueError, match="unsafe archive members"):
        distribution._assert_safe_archive_names(["trustweave-0.2.3/../../outside.txt"], "source")


def test_distribution_verifier_uses_posix_venv_executables() -> None:
    distribution = _distribution_verifier_module()

    python, console = distribution._venv_executables(Path("temporary-venv"), platform_name="posix")

    assert python == Path("temporary-venv/bin/python")
    assert console == Path("temporary-venv/bin/trustweave")


def test_distribution_verifier_uses_windows_venv_executables() -> None:
    distribution = _distribution_verifier_module()
    venv = Path("temporary-venv")

    python, console = distribution._venv_executables(venv, platform_name="nt")

    assert python.as_posix() == "temporary-venv/Scripts/python.exe"
    assert console.as_posix() == "temporary-venv/Scripts/trustweave.exe"
