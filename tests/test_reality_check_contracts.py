"""Contract tests for deterministic repository reality validation."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from trustweave.cli import _parser

ROOT = Path(__file__).resolve().parents[1]
REALITY_CHECK = ROOT / "scripts" / "reality_check.py"


def _reality_check_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location("reality_check", REALITY_CHECK)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _top_level_parser_commands() -> tuple[str, ...]:
    for action in _parser()._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            return tuple(sorted(choices))
    raise AssertionError("TrustWeave parser has no top-level subcommands")


def test_reality_check_derives_cli_commands_from_the_parser() -> None:
    reality_check = _reality_check_module()

    assert reality_check._parser_command_names() == _top_level_parser_commands()


def test_reality_check_validates_real_generated_artifacts_against_published_schemas() -> None:
    reality_check = _reality_check_module()

    assert reality_check._check_generated_artifact_schemas() == []


def test_reality_check_validates_schema_resources_from_an_installed_wheel() -> None:
    reality_check = _reality_check_module()

    assert reality_check._check_installed_wheel_schema_resources() == []


def test_reality_check_validates_installed_wheel_runtime_contract() -> None:
    reality_check = _reality_check_module()

    assert reality_check._check_installed_wheel_runtime_contract() == []


def test_reality_check_validates_changelog_version_synchronization() -> None:
    reality_check = _reality_check_module()

    assert reality_check._check_changelog_version_synchronization() == []
