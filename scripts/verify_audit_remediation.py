#!/usr/bin/env python3
"""Run the bounded local evidence checks for the 2026-08-19 audit remediation."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATHS = (
    ROOT / "schemas" / "bundle-diff-v1alpha3.schema.json",
    ROOT / "src" / "trustweave" / "schemas" / "bundle-diff-v1alpha3.schema.json",
)
EXPECTED_AUDIT_IDS = tuple(f"TW-AUDIT-{number:03d}" for number in range(1, 11))
AUDIT_TEST_NODES: dict[str, tuple[str, ...]] = {
    "TW-AUDIT-001": (
        "tests/test_bundle_validation.py::"
        "test_validate_current_bundle_rejects_a_missing_declared_finding",
        "tests/test_bundle_validation.py::"
        "test_validate_current_bundle_rejects_duplicate_substitution_for_a_declared_flow",
    ),
    "TW-AUDIT-002": (
        "tests/test_bundle_validation.py::test_validate_current_bundle_rejects_a_fabricated_policy_result",
    ),
    "TW-AUDIT-003": (
        "tests/test_policy_review.py::"
        "test_policy_coverage_does_not_shadow_with_an_impossible_earlier_rule",
    ),
    "TW-AUDIT-004": (
        "tests/test_policy_review.py::"
        "test_policy_parser_and_schema_reject_the_same_declared_boundary_violations",
    ),
    "TW-AUDIT-005": (
        "tests/test_diff.py::test_bundle_diff_reports_policy_only_fail_closed_weakening",
        "tests/test_diff.py::"
        "test_policy_weakening_classifier_retains_each_category_in_a_combined_delta",
    ),
    "TW-AUDIT-006": (
        "tests/test_audit_regressions.py::"
        "test_risk_management_quickstart_accepts_current_examples_from_clean_workspace",
    ),
    "TW-AUDIT-007": (
        "tests/test_package_provenance_controls.py::"
        "test_package_provenance_controls_reject_semantically_weakened_job_graph",
        "tests/test_package_provenance_controls.py::"
        "test_package_provenance_controls_reject_missing_release_binding_control",
    ),
    "TW-AUDIT-008": (
        "tests/test_foundation_hardening.py::"
        "test_repository_reality_check_accepts_tracked_public_contracts",
    ),
    "TW-AUDIT-009": (
        "tests/test_integrations.py::"
        "test_quality_workflow_executes_real_container_build_and_smoke_contract",
    ),
    "TW-AUDIT-010": (
        "tests/test_phase0_integrity.py::test_cli_verify_v1alpha3_accepts_supplied_evidence_files",
        "tests/test_phase0_integrity.py::"
        "test_v1alpha3_individual_supplied_file_verification_reports_exact_success_contract",
    ),
}
HARDENING_TEST_NODES: dict[str, tuple[str, ...]] = {
    "no_approval_control": (
        "tests/test_bundle_validation.py::"
        "test_current_bundle_without_approval_control_round_trips_and_self_diffs",
        "tests/test_bundle_validation.py::"
        "test_current_bundle_rejects_malformed_non_null_approval_control",
        "tests/test_bundle_validation.py::"
        "test_cli_scan_and_self_diff_accept_policy_without_approval_control",
    ),
    "policy_weakening_signals": (
        "tests/test_diff.py::test_bundle_diff_reports_removed_approval_control_once",
        "tests/test_diff.py::test_bundle_diff_reports_removed_approval_binding_once",
        "tests/test_diff.py::test_bundle_diff_reports_unexercised_rule_decision_weakening",
        "tests/test_diff.py::test_bundle_diff_reports_removed_required_controls",
        "tests/test_diff.py::test_bundle_diff_reports_classification_taxonomy_change",
        "tests/test_diff.py::test_bundle_diff_does_not_signal_neutral_rule_reordering",
    ),
    "structural_policy_review": (
        "tests/test_diff.py::test_bundle_diff_reports_added_unexercised_rule_for_structural_review",
        "tests/test_diff.py::test_bundle_diff_reports_removed_unexercised_deny_for_structural_review",
        "tests/test_diff.py::"
        "test_bundle_diff_reports_changed_unexercised_matching_predicate_for_structural_review",
        "tests/test_diff.py::"
        "test_bundle_diff_reports_potentially_overlapping_rule_reordering_for_structural_review",
        "tests/test_diff.py::"
        "test_bundle_diff_does_not_report_description_or_rationale_only_rule_edit",
        "tests/test_diff.py::"
        "test_policy_weakening_classifier_combines_specific_and_structural_review_once",
        "tests/test_diff.py::"
        "test_policy_weakening_classifier_sorts_and_deduplicates_structural_rule_identifiers",
        "tests/test_diff.py::"
        "test_policy_weakening_classifier_ignores_exact_canonical_rule_equivalence",
    ),
    "strict_v1alpha3_schema": (
        "tests/test_generated_schema_conformance.py::"
        "test_real_generated_v1alpha3_policy_delta_conforms_to_its_schema",
        "tests/test_generated_schema_conformance.py::"
        "test_v1alpha3_policy_delta_schema_rejects_invalid_default_decision_changes",
        "tests/test_generated_schema_conformance.py::"
        "test_v1alpha3_policy_delta_schema_rejects_oversized_approval_bindings_and_text",
        "tests/test_generated_schema_conformance.py::"
        "test_v1alpha3_policy_delta_schema_rejects_malformed_rule_payload",
    ),
    "release_controls": (
        "tests/test_package_provenance_controls.py::"
        "test_package_provenance_controls_match_checked_in_workflows",
    ),
    "version_boundary": (
        "tests/test_assurance_contracts.py::"
        "test_assurance_contract_rejects_published_v1alpha3_boundary_drift",
    ),
    "documentation_consistency": (
        "tests/test_current_diff_documentation_contract.py::"
        "test_current_bundle_diff_guidance_consistently_names_v1alpha3",
    ),
}


def _run(command: Sequence[str]) -> int:
    """Run one displayed local verification command and preserve its return status."""

    print(f"+ {' '.join(command)}", flush=True)
    return subprocess.run(command, cwd=ROOT, check=False).returncode


def _flatten_nodes(groups: Mapping[str, Sequence[str]]) -> tuple[str, ...]:
    """Return de-duplicated node IDs in reviewed mapping order."""

    return tuple(dict.fromkeys(node for nodes in groups.values() for node in nodes))


def _all_test_nodes() -> tuple[str, ...]:
    """Return every audit and separate hardening node required by this bounded verifier."""

    return tuple(
        dict.fromkeys((*_flatten_nodes(AUDIT_TEST_NODES), *_flatten_nodes(HARDENING_TEST_NODES)))
    )


def _mapping_failures() -> list[str]:
    """Validate that audit coverage is complete, exact, reviewable, and non-empty."""

    failures: list[str] = []
    if tuple(AUDIT_TEST_NODES) != EXPECTED_AUDIT_IDS:
        failures.append(
            "Audit node mapping keys must be exactly TW-AUDIT-001 through TW-AUDIT-010 in order."
        )
    for audit_id, nodes in AUDIT_TEST_NODES.items():
        if not nodes:
            failures.append(f"Audit node mapping must not be empty: {audit_id}")
        for node in nodes:
            if not isinstance(node, str) or "::" not in node:
                failures.append(f"Audit node mapping has invalid pytest node: {audit_id}: {node!r}")
    for category, nodes in HARDENING_TEST_NODES.items():
        if not nodes:
            failures.append(f"Hardening node mapping must not be empty: {category}")
    return failures


def _node_collection_failures(nodes: Sequence[str]) -> list[str]:
    """Fail closed unless every mapped node is collected by pytest from the repository root."""

    command = [sys.executable, "-m", "pytest", "--collect-only", "--no-cov", "-q", *nodes]
    collected = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if collected.returncode == 0:
        return []
    return [
        "Mapped pytest nodes failed collection:\n" + (collected.stdout + collected.stderr).strip()
    ]


def main() -> int:
    """Execute bounded audit evidence checks without external or repository side effects."""

    failures = _mapping_failures()
    all_nodes = _all_test_nodes()
    failures.extend(_node_collection_failures(all_nodes))
    if SCHEMA_PATHS[0].read_bytes() != SCHEMA_PATHS[1].read_bytes():
        failures.append("Root and packaged v1alpha3 schemas differ.")
    if failures:
        print("Audit remediation verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    commands = (
        [sys.executable, "scripts/verify_package_provenance_controls.py"],
        [sys.executable, "scripts/verify_assurance_contracts.py"],
        [sys.executable, "-m", "pytest", "--no-cov", *all_nodes],
    )
    for command in commands:
        if _run(command) != 0:
            print("Audit remediation verification failed.")
            return 1
    print(
        "Audit remediation verification passed: all ten audit IDs and separate hardening "
        "evidence are green."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
