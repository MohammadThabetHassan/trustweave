"""Contract tests for deterministic repository reality validation."""

from __future__ import annotations

import importlib.util
import json
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


def test_reality_check_executes_representative_documentation_commands() -> None:
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


def test_reality_check_verifies_declaration_completeness_provenance() -> None:
    """Synthetic benchmark inputs must remain bound to reviewed exact-file digest records."""

    reality_check = _reality_check_module()

    assert reality_check._check_declaration_completeness_provenance() == []


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

    reality_check = _reality_check_module()

    assert reality_check._check_distribution_assurance() == []


def test_reality_check_verifies_package_provenance_controls() -> None:
    """Configured PyPI attestation generation must remain a release integrity contract."""

    reality_check = _reality_check_module()

    assert reality_check._check_package_provenance_controls() == []


def test_reality_check_ties_the_mutation_record_to_the_survivor_inventory() -> None:
    """The published mutation prose must agree with the inventory it describes."""

    reality_check = _reality_check_module()
    record = reality_check.MUTATION_RECORD_PATH.read_text(encoding="utf-8")

    assert reality_check._check_mutation_record_matches_inventory(record) == []


def test_reality_check_rejects_a_mutation_record_that_contradicts_the_inventory() -> None:
    """A stale survivor count in the prose must be reported, not tolerated.

    The record and the inventory previously disagreed -- 126 survivors of 6,691 mutants in
    the prose against 133 of 6,566 in the inventory -- because nothing compared them.
    """

    reality_check = _reality_check_module()

    failures = reality_check._check_mutation_record_matches_inventory(
        "A record that states no counts at all."
    )

    assert failures, "a record stating no counts must not satisfy the inventory check"
    assert any("classified survivors" in failure for failure in failures)


def test_reality_check_ties_the_equivalence_audit_to_the_survivor_inventory() -> None:
    """The audit's reviewed families must account for every survivor in the inventory."""

    reality_check = _reality_check_module()
    inventory = json.loads(reality_check.MUTATION_TRIAGE_PATH.read_text(encoding="utf-8"))

    assert (
        reality_check._check_equivalence_audit_matches_inventory(inventory["survivor_count"]) == []
    )


def test_reality_check_rejects_an_audit_that_does_not_account_for_every_survivor() -> None:
    """A run that adds survivors in an unreviewed module must fail, not pass silently.

    The audit summed to 126 across ten families while the inventory held 147 across
    fourteen modules, with no row at all for the engine, source-intake or discovery
    survivors, because nothing added the rows up.
    """

    reality_check = _reality_check_module()

    failures = reality_check._check_equivalence_audit_matches_inventory(10_000)

    assert failures, "an audit that accounts for far fewer survivors must be reported"
    assert any("do not account for the inventory" in failure for failure in failures)
