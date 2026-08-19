#!/usr/bin/env python3
"""Validate configured PyPI package-attestation controls without claiming observed provenance."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs" / "contracts" / "package-provenance-v1.json"
GUIDE_PATH = ROOT / "docs" / "PACKAGE_PROVENANCE.md"
SUPPLY_CHAIN_PATH = ROOT / "docs" / "SUPPLY_CHAIN.md"
ACTION_REFERENCE = "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
REPOSITORY = "MohammadThabetHassan/trustweave"


def _load_contract() -> dict[str, Any]:
    """Load the machine-readable release-provenance control source."""

    document = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("package provenance contract must be a JSON object")
    return document


def _publish_job(workflow: str) -> str:
    """Return the isolated publishing-job text from a small checked-in workflow file."""

    match = re.search(r"^  publish:\n(?P<body>.*)", workflow, flags=re.MULTILINE | re.DOTALL)
    if match is None:
        return ""
    return match.group("body")


def _validate_control(control: dict[str, Any], failures: list[str]) -> None:
    """Validate one workflow policy record against its exact checked-in YAML text."""

    path = control.get("path")
    if not isinstance(path, str):
        failures.append("Package provenance workflow control lacks a path")
        return
    workflow_path = ROOT / path
    if not workflow_path.is_file():
        failures.append(f"Package provenance workflow is missing: {path}")
        return
    workflow = workflow_path.read_text(encoding="utf-8")
    expected_name = control.get("expected_artifact_name")
    if not isinstance(expected_name, str) or f"name: {expected_name}" not in workflow:
        failures.append(f"Package provenance workflow {path} lacks its expected artifact name")
    if (
        control.get("trusted_publishing_action") != ACTION_REFERENCE
        or ACTION_REFERENCE not in workflow
    ):
        failures.append(
            f"Package provenance workflow {path} lacks the expected pinned publishing action"
        )
    if control.get("attestations") is not True or "attestations: true" not in workflow:
        failures.append(f"Package provenance workflow {path} does not enable project attestations")
    publish_job = _publish_job(workflow)
    required_permissions = control.get("required_job_permissions")
    if required_permissions != ["id-token: write"] or "id-token: write" not in publish_job:
        failures.append(
            f"Package provenance workflow {path} lacks the required publish-job OIDC permission"
        )
    environment_required = control.get("environment_required")
    has_environment = "environment:" in publish_job
    if environment_required is True and not has_environment:
        failures.append(f"Package provenance workflow {path} requires a protected environment")
    if environment_required is False and has_environment:
        failures.append(
            f"Package provenance workflow {path} unexpectedly adds a protected environment"
        )


def _validate_contract(contract: dict[str, Any]) -> list[str]:
    """Validate workflow configuration and present-tense claims against the release policy."""

    failures: list[str] = []
    if contract.get("schema_version") != "trustweave.dev/package-provenance/v1alpha1":
        failures.append("Package provenance contract has an unexpected schema_version")
    if contract.get("repository") != REPOSITORY:
        failures.append("Package provenance contract has an unexpected repository identity")
    if contract.get("claim_state") != "generation-enabled-observation-required":
        failures.append(
            "Package provenance contract must retain the observation-required claim state"
        )
    controls = contract.get("workflow_controls")
    if not isinstance(controls, list) or len(controls) != 2:
        return failures + ["Package provenance contract must contain exactly two workflow controls"]
    expected_paths = {
        ".github/workflows/publish-testpypi.yml",
        ".github/workflows/publish-pypi.yml",
    }
    actual_paths = {control.get("path") for control in controls if isinstance(control, dict)}
    if actual_paths != expected_paths:
        failures.append("Package provenance contract workflow paths differ from the release pair")
    for control in controls:
        if not isinstance(control, dict):
            failures.append("Package provenance workflow control entries must be objects")
            continue
        _validate_control(control, failures)
    requirements = contract.get("observation_requirements")
    if not isinstance(requirements, list) or len(requirements) < 4:
        failures.append("Package provenance contract lacks complete observed-release requirements")
    non_claims = contract.get("non_claims_until_observed")
    if not isinstance(non_claims, list) or len(non_claims) < 3:
        failures.append("Package provenance contract lacks complete pre-observation non-claims")
    for guide in (GUIDE_PATH, SUPPLY_CHAIN_PATH):
        if not guide.is_file():
            failures.append(f"Missing public provenance guide: {guide.relative_to(ROOT)}")
            continue
        text = guide.read_text(encoding="utf-8")
        for marker in ("authenticated package provenance", "unsigned local"):
            if marker not in text.lower():
                failures.append(
                    f"{guide.relative_to(ROOT)} lacks required provenance non-claim "
                    f"marker: {marker}"
                )
    if GUIDE_PATH.is_file():
        guide_text = GUIDE_PATH.read_text(encoding="utf-8")
        for marker in ("attestations: true", REPOSITORY, "pypi-attestations verify pypi"):
            if marker not in guide_text:
                failures.append(
                    f"Package provenance guide lacks required verification marker: {marker}"
                )
    return failures


def main() -> int:
    """Check package-attestation generation controls without making a release-time network call."""

    try:
        contract = _load_contract()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Package provenance control validation failed: {error}", file=sys.stderr)
        return 1
    failures = _validate_contract(contract)
    if failures:
        print("Package provenance control validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(
        "Package provenance controls passed: generation is enabled and observation remains "
        "required."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
