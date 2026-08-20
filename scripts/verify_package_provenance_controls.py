#!/usr/bin/env python3
"""Validate configured PyPI release controls without claiming unexecuted external evidence."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs" / "contracts" / "package-provenance-v1.json"
GUIDE_PATH = ROOT / "docs" / "PACKAGE_PROVENANCE.md"
RELEASE_EVIDENCE_PATH = ROOT / "docs" / "RELEASE_EVIDENCE_0.3.0.md"
SUPPLY_CHAIN_PATH = ROOT / "docs" / "SUPPLY_CHAIN.md"
ACTION_REFERENCE = "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
REPOSITORY = "MohammadThabetHassan/trustweave"
REQUIRED_LOCAL_RELEASE_COMMANDS = (
    "ruff format --check .",
    "ruff check .",
    "mypy src",
    "bandit -r src/trustweave -q",
    "pytest",
    "python scripts/reality_check.py",
    "mkdocs build --strict",
    "pip-audit -r requirements.txt",
)
REQUIRED_TAG_TARGET_COMMANDS = (
    'expected_tag_ref="refs/tags/v${EXPECTED_VERSION}"',
    'test "$GITHUB_REF_TYPE" = "tag"',
    'test "$GITHUB_REF_NAME" = "v${EXPECTED_VERSION}"',
    'test "$GITHUB_REF" = "$expected_tag_ref"',
    'test "$(git cat-file -t "refs/tags/${GITHUB_REF_NAME}")" = "tag"',
    'tag_target_sha="$(git rev-parse "refs/tags/${GITHUB_REF_NAME}^{}")"',
    'test "$tag_target_sha" = "$GITHUB_SHA"',
    'test "$(git rev-parse HEAD)" = "$tag_target_sha"',
)


def _load_contract() -> dict[str, Any]:
    """Load the machine-readable release-provenance control source."""

    document = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("package provenance contract must be a JSON object")
    return document


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else ()


def _workflow_document(workflow: str) -> Mapping[str, Any]:
    """Parse a checked-in workflow as data so control checks follow YAML job semantics."""

    try:
        document = yaml.load(workflow, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise ValueError(f"workflow YAML is invalid: {error}") from error
    if not isinstance(document, Mapping):
        raise ValueError("workflow YAML root must be an object")
    return document


def _steps_run(job: Mapping[str, Any]) -> str:
    """Collect only shell commands belonging to one parsed workflow job."""

    return "\n".join(
        run
        for step in _sequence(job.get("steps"))
        if isinstance(step, Mapping) and isinstance((run := step.get("run")), str)
    )


def _needs(job: Mapping[str, Any]) -> set[str]:
    """Normalize GitHub Actions job dependencies from scalar or sequence form."""

    value = job.get("needs")
    if isinstance(value, str):
        return {value}
    return {item for item in _sequence(value) if isinstance(item, str)}


def _release_binding_failures(workflow: str) -> list[str]:
    """Return semantic fail-closed control failures for one parsed publication workflow."""

    try:
        document = _workflow_document(workflow)
    except ValueError as error:
        return [f"invalid release workflow: {error}"]

    failures: list[str] = []
    triggers = _mapping(document.get("on"))
    if set(triggers) != {"workflow_dispatch"}:
        failures.append("missing release-binding control: manual workflow_dispatch-only trigger")
    inputs = _mapping(_mapping(triggers.get("workflow_dispatch")).get("inputs"))
    expected_version = _mapping(inputs.get("expected_version"))
    if expected_version.get("required") != "true" or expected_version.get("type") != "string":
        failures.append("missing release-binding control: required expected_version dispatch input")

    jobs = _mapping(document.get("jobs"))
    release_gate = _mapping(jobs.get("release-gate"))
    build = _mapping(jobs.get("build"))
    publish = _mapping(jobs.get("publish"))
    if not release_gate:
        failures.append("missing release-binding control: release-gate job")
        return failures
    if not build:
        failures.append("missing release-binding control: build job")
    if not publish:
        failures.append("missing release-binding control: publish job")

    outputs = _mapping(release_gate.get("outputs"))
    if outputs.get("target_sha") != "${{ steps.release_target.outputs.sha }}":
        failures.append("missing release-binding control: release-gate target_sha output")
    gate_run = _steps_run(release_gate)
    for command in REQUIRED_TAG_TARGET_COMMANDS:
        if command not in gate_run:
            failures.append(
                f"missing release-binding control: annotated tag target command: {command}"
            )
    for command in REQUIRED_LOCAL_RELEASE_COMMANDS:
        if command not in gate_run:
            failures.append(
                f"missing release-binding control: local release gate command: {command}"
            )

    if build:
        if _needs(build) != {"release-gate"}:
            failures.append("missing release-binding control: build needs only release-gate")
        if build.get("if") != "needs.release-gate.outputs.target_sha == github.sha":
            failures.append("missing release-binding control: build exact target SHA condition")
        build_run = _steps_run(build)
        if 'test "$(git rev-parse HEAD)" = "$TARGET_SHA"' not in build_run:
            failures.append("missing release-binding control: build checked-out SHA assertion")
        if "python -m build" not in build_run or "twine check dist/*" not in build_run:
            failures.append("missing release-binding control: build distribution validation")

    if publish:
        if _needs(publish) != {"release-gate", "build"}:
            failures.append("missing release-binding control: publish needs release-gate and build")
        expected_publish_if = (
            "needs.release-gate.outputs.target_sha == github.sha && needs.build.result == 'success'"
        )
        if publish.get("if") != expected_publish_if:
            failures.append(
                "missing release-binding control: publish exact target and build condition"
            )
    return failures


def _publish_job(workflow: str) -> Mapping[str, Any]:
    """Return the parsed isolated publishing job when present."""

    return _mapping(_mapping(_workflow_document(workflow).get("jobs")).get("publish"))


def _validate_control(control: dict[str, Any], failures: list[str]) -> None:
    """Validate one workflow policy record against parsed job and dependency semantics."""

    path = control.get("path")
    if not isinstance(path, str):
        failures.append("Package provenance workflow control lacks a path")
        return
    workflow_path = ROOT / path
    if not workflow_path.is_file():
        failures.append(f"Package provenance workflow is missing: {path}")
        return
    workflow = workflow_path.read_text(encoding="utf-8")
    try:
        publish_job = _publish_job(workflow)
    except ValueError as error:
        failures.append(f"Package provenance workflow {path} {error}")
        return
    expected_name = control.get("expected_artifact_name")
    artifact_steps = _sequence(publish_job.get("steps"))
    has_expected_artifact = any(
        isinstance(step, Mapping) and _mapping(step.get("with")).get("name") == expected_name
        for step in artifact_steps
    )
    if not isinstance(expected_name, str) or not has_expected_artifact:
        failures.append(f"Package provenance workflow {path} lacks its expected artifact name")
    has_pinned_publisher = any(
        isinstance(step, Mapping) and step.get("uses") == ACTION_REFERENCE
        for step in artifact_steps
    )
    if control.get("trusted_publishing_action") != ACTION_REFERENCE or not has_pinned_publisher:
        failures.append(
            f"Package provenance workflow {path} lacks the expected pinned publishing action"
        )
    publisher_step = next(
        (
            _mapping(step)
            for step in artifact_steps
            if isinstance(step, Mapping) and step.get("uses") == ACTION_REFERENCE
        ),
        {},
    )
    if (
        control.get("attestations") is not True
        or _mapping(publisher_step.get("with")).get("attestations") != "true"
    ):
        failures.append(f"Package provenance workflow {path} does not enable project attestations")
    required_permissions = control.get("required_job_permissions")
    permissions = _mapping(publish_job.get("permissions"))
    if required_permissions != ["id-token: write"] or permissions.get("id-token") != "write":
        failures.append(
            f"Package provenance workflow {path} lacks the required publish-job OIDC permission"
        )
    environment_required = control.get("environment_required")
    has_environment = isinstance(publish_job.get("environment"), Mapping)
    if environment_required is True and not has_environment:
        failures.append(f"Package provenance workflow {path} requires a protected environment")
    if environment_required is False and has_environment:
        failures.append(
            f"Package provenance workflow {path} unexpectedly adds a protected environment"
        )
    for failure in _release_binding_failures(workflow):
        failures.append(f"Package provenance workflow {path} {failure}")


def _validate_contract(contract: dict[str, Any]) -> list[str]:
    """Validate workflow configuration and present-tense claims against the release policy."""

    failures: list[str] = []
    if contract.get("schema_version") != "trustweave.dev/package-provenance/v1alpha1":
        failures.append("Package provenance contract has an unexpected schema_version")
    if contract.get("repository") != REPOSITORY:
        failures.append("Package provenance contract has an unexpected repository identity")
    if contract.get("claim_state") != "generation-enabled-observed-exact-files":
        failures.append(
            "Package provenance contract must record the exact-file observed claim state"
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
    observed_release = contract.get("observed_release")
    if not isinstance(observed_release, dict):
        failures.append("Package provenance contract lacks an observed_release record")
    else:
        expected_observation = {
            "version": "0.3.0",
            "tag": "v0.3.0",
            "commit": "30308f47e84025315de2083047039e7efe0fd0ae",
            "evidence_record": "docs/RELEASE_EVIDENCE_0.3.0.md",
            "expected_repository": f"https://github.com/{REPOSITORY}",
        }
        if observed_release != expected_observation:
            failures.append(
                "Package provenance observed_release record differs from 0.3.0 evidence"
            )
    limits = contract.get("non_claims_until_observed")
    if not isinstance(limits, list) or len(limits) < 3:
        failures.append("Package provenance contract lacks complete exact-file claim limits")
    for guide in (GUIDE_PATH, SUPPLY_CHAIN_PATH):
        if not guide.is_file():
            failures.append(f"Missing public provenance guide: {guide.relative_to(ROOT)}")
            continue
        text = guide.read_text(encoding="utf-8").lower()
        for marker in ("authenticated package-provenance", "unsigned local"):
            if marker not in text:
                failures.append(
                    f"{guide.relative_to(ROOT)} lacks required provenance-limit marker: {marker}"
                )
    if not RELEASE_EVIDENCE_PATH.is_file():
        failures.append(
            f"Missing observed release evidence: {RELEASE_EVIDENCE_PATH.relative_to(ROOT)}"
        )
    else:
        evidence_text = RELEASE_EVIDENCE_PATH.read_text(encoding="utf-8")
        for marker in (
            "v0.3.0",
            "30308f47e84025315de2083047039e7efe0fd0ae",
            "https://github.com/MohammadThabetHassan/trustweave",
            "pypi-attestations verify pypi",
            "TestPyPI",
            "PyPI",
        ):
            if marker not in evidence_text:
                failures.append(f"Release evidence lacks required provenance marker: {marker}")
    if GUIDE_PATH.is_file():
        guide_text = GUIDE_PATH.read_text(encoding="utf-8")
        for marker in (
            "attestations: true",
            REPOSITORY,
            "https://github.com/MohammadThabetHassan/trustweave",
            "pypi-attestations verify pypi",
            "TestPyPI Integrity API",
        ):
            if marker not in guide_text:
                failures.append(
                    f"Package provenance guide lacks required verification marker: {marker}"
                )
    return failures


def main() -> int:
    """Check package-attestation generation controls without a release-time network call."""

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
        "Package provenance controls passed: parsed release workflow bindings and the exact-file "
        "0.3.0 observed release record match."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
