"""Contract tests for deterministic repository reality validation."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from trustweave.cli import _parser

ROOT = Path(__file__).resolve().parents[1]
REALITY_CHECK = ROOT / "scripts" / "reality_check.py"


def _require_git_checkout() -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("repository reality checks require a git checkout")


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


def test_reality_check_executes_representative_documentation_commands() -> None:
    _require_git_checkout()
    reality_check = _reality_check_module()

    assert reality_check._check_documentation_commands() == []


def test_reality_check_verifies_generated_schema_coverage_and_packaged_resource_sync() -> None:
    """Every runtime-emitted versioned artifact must have a byte-identical public schema."""

    reality_check = _reality_check_module()

    assert reality_check._check_schema_resource_synchronization() == []
    assert reality_check._check_generated_artifact_schema_coverage() == []


def test_reality_check_verifies_current_contract_documentation_markers() -> None:
    """Current maintained guides must not silently drift from emitted versions and quality gates."""

    reality_check = _reality_check_module()

    assert reality_check._check_current_contract_documentation() == []


def test_reality_check_verifies_assurance_contracts() -> None:
    """Public assurance claims must agree with the machine-readable compatibility source."""

    reality_check = _reality_check_module()

    assert reality_check._check_assurance_contracts() == []


def test_reality_check_verifies_golden_evidence() -> None:
    """The repository integrity gate must execute the check-only golden corpus verifier."""

    reality_check = _reality_check_module()

    assert reality_check._check_golden_evidence() == []


def test_reality_check_verifies_control_traceability() -> None:
    """Threat/control/test linkage must remain a required repository integrity contract."""

    reality_check = _reality_check_module()

    assert reality_check._check_control_traceability() == []


def test_reality_check_verifies_distribution_assurance() -> None:
    """Temporary wheel and source-distribution validation must remain a release integrity gate."""

    _require_git_checkout()
    reality_check = _reality_check_module()

    assert reality_check._check_distribution_assurance() == []


def test_reality_check_verifies_package_provenance_controls() -> None:
    """Configured PyPI attestation generation must remain a release integrity contract."""

    reality_check = _reality_check_module()

    assert reality_check._check_package_provenance_controls() == []
