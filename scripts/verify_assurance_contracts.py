#!/usr/bin/env python3
"""Validate TrustWeave's versioned compatibility and assurance documentation contracts."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

from trustweave.cli import _parser
from trustweave.commands._shared import (
    EXIT_INPUT_OUTPUT,
    EXIT_INTERNAL,
    EXIT_INVALID_INPUT,
    EXIT_REVIEW,
    EXIT_SUCCESS,
)

ROOT = Path(__file__).resolve().parents[1]
COMPATIBILITY_PATH = ROOT / "docs" / "contracts" / "compatibility-v1.json"
COMPATIBILITY_GUIDE_PATH = ROOT / "docs" / "COMPATIBILITY.md"
SUPPORT_POLICY_PATH = ROOT / "docs" / "SUPPORT_POLICY.md"
ASSURANCE_MAP_PATH = ROOT / "docs" / "ASSURANCE.md"
SUPPLY_CHAIN_PATH = ROOT / "docs" / "SUPPLY_CHAIN.md"
PROVENANCE_ADR_PATH = ROOT / "docs" / "ADR-0005-PACKAGE-RELEASE-PROVENANCE.md"
SCHEMA_POLICY_PATH = ROOT / "docs" / "SCHEMA_AND_COMPATIBILITY.md"

EXPECTED_EXIT_CODES = {
    "0": "successful local command completion",
    "1": "review-required result when a command explicitly requests review-gate behavior",
    "2": "invalid input, configuration, or command syntax",
    "3": "local input or output failure",
    "4": "unexpected internal error",
}
ACTUAL_EXIT_CODES = {
    "0": EXIT_SUCCESS,
    "1": EXIT_REVIEW,
    "2": EXIT_INVALID_INPUT,
    "3": EXIT_INPUT_OUTPUT,
    "4": EXIT_INTERNAL,
}


def _load_json(path: Path) -> dict[str, Any]:
    """Load one strict JSON object from a checked-in contract path."""

    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return document


def _parser_command_names() -> list[str]:
    """Return the parser-owned top-level command names in stable order."""

    for action in _parser()._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            return sorted(choices)
    raise RuntimeError("TrustWeave parser has no top-level command mapping")


def _schema_versions() -> set[str]:
    """Return schema-version constants published in the source schema catalog."""

    versions: set[str] = set()
    for path in (ROOT / "schemas").glob("*.schema.json"):
        document = _load_json(path)
        properties = document.get("properties")
        if not isinstance(properties, dict):
            continue
        schema_version = properties.get("schema_version")
        if not isinstance(schema_version, dict):
            continue
        value = schema_version.get("const")
        if isinstance(value, str):
            versions.add(value)
    return versions


def _string_list(value: Any, label: str, failures: list[str]) -> list[str]:
    """Return a strict string list while collecting concise contract failures."""

    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        failures.append(f"Compatibility contract {label} must be a non-empty string list")
        return []
    return value


def _check_compatibility_contract() -> list[str]:
    """Verify that the public compatibility source matches actual implementation evidence."""

    failures: list[str] = []
    required_paths = (
        COMPATIBILITY_PATH,
        COMPATIBILITY_GUIDE_PATH,
        SUPPORT_POLICY_PATH,
        ASSURANCE_MAP_PATH,
        SUPPLY_CHAIN_PATH,
        PROVENANCE_ADR_PATH,
        SCHEMA_POLICY_PATH,
    )
    for path in required_paths:
        if not path.is_file():
            failures.append(f"Missing assurance contract resource: {path.relative_to(ROOT)}")
    if failures:
        return failures

    try:
        contract = _load_json(COMPATIBILITY_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [f"Invalid compatibility contract: {error}"]

    if contract.get("contract_version") != "trustweave.dev/compatibility/v1alpha1":
        failures.append("Compatibility contract must declare trustweave.dev/compatibility/v1alpha1")

    package = contract.get("package")
    if not isinstance(package, dict):
        return failures + ["Compatibility contract package must be an object"]
    with (ROOT / "pyproject.toml").open("rb") as project_file:
        project = tomllib.load(project_file)
    metadata = project.get("project")
    if not isinstance(metadata, dict):
        return failures + ["pyproject.toml must contain a project mapping"]

    if package.get("name") != metadata.get("name"):
        failures.append("Compatibility package name does not match pyproject.toml")
    if package.get("current_public_release") != metadata.get("version"):
        failures.append(
            "Compatibility current_public_release does not match pyproject.toml version"
        )
    if package.get("requires_python") != metadata.get("requires-python"):
        failures.append("Compatibility requires_python does not match pyproject.toml")

    supported_python = _string_list(
        package.get("supported_python"), "package.supported_python", failures
    )
    classifiers = metadata.get("classifiers")
    if not isinstance(classifiers, list):
        failures.append("pyproject.toml project.classifiers must be a list")
    else:
        for version in supported_python:
            marker = f"Programming Language :: Python :: {version}"
            if marker not in classifiers:
                failures.append(
                    f"Compatibility Python {version} is missing from package classifiers"
                )

    ci_contract = package.get("continuous_integration")
    if not isinstance(ci_contract, dict):
        failures.append("Compatibility package.continuous_integration must be an object")
    else:
        ci_python = _string_list(
            ci_contract.get("python"), "continuous_integration.python", failures
        )
        ci_platforms = _string_list(
            ci_contract.get("platforms"), "continuous_integration.platforms", failures
        )
        try:
            ci_workflow = yaml.safe_load(
                (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
            )
        except yaml.YAMLError as error:
            failures.append(f"Could not parse CI workflow for compatibility contract: {error}")
        else:
            jobs = ci_workflow.get("jobs") if isinstance(ci_workflow, dict) else None
            compatibility = jobs.get("compatibility") if isinstance(jobs, dict) else None
            strategy = compatibility.get("strategy") if isinstance(compatibility, dict) else None
            matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
            if not isinstance(matrix, dict):
                failures.append("CI workflow lacks compatibility matrix")
            else:
                if matrix.get("python-version") != ci_python:
                    failures.append("Compatibility Python matrix differs from CI workflow")
                if matrix.get("os") != ci_platforms:
                    failures.append("Compatibility platform matrix differs from CI workflow")

    interfaces = contract.get("interfaces")
    if not isinstance(interfaces, dict):
        return failures + ["Compatibility interfaces must be an object"]
    if interfaces.get("console_command") != "trustweave":
        failures.append("Compatibility console command must be trustweave")
    if interfaces.get("module_command") != "python -m trustweave":
        failures.append("Compatibility module command must be python -m trustweave")
    if interfaces.get("top_level_commands") != _parser_command_names():
        failures.append("Compatibility top-level commands differ from the authoritative CLI parser")
    if interfaces.get("exit_codes") != EXPECTED_EXIT_CODES:
        failures.append("Compatibility exit-code descriptions differ from the stable contract")
    for key, value in ACTUAL_EXIT_CODES.items():
        if int(key) != value:
            failures.append(f"Runtime exit-code constant differs from compatibility code {key}")

    artifacts = contract.get("artifact_contracts")
    if not isinstance(artifacts, dict):
        return failures + ["Compatibility artifact_contracts must be an object"]
    writers = artifacts.get("current_writers")
    if not isinstance(writers, dict) or not writers:
        failures.append("Compatibility current_writers must be a non-empty object")
    else:
        published_versions = _schema_versions()
        for name, version in writers.items():
            if not isinstance(name, str) or not isinstance(version, str):
                failures.append("Compatibility current_writers entries must map strings to strings")
            elif version not in published_versions:
                failures.append(
                    f"Compatibility writer {name} has no published schema-version "
                    f"resource: {version}"
                )

    schema_policy = SCHEMA_POLICY_PATH.read_text(encoding="utf-8")
    bounded_readers = artifacts.get("bounded_legacy_readers")
    if not isinstance(bounded_readers, dict) or not bounded_readers:
        failures.append("Compatibility bounded_legacy_readers must be a non-empty object")
    else:
        for reader_name, versions in bounded_readers.items():
            for version in _string_list(
                versions, f"bounded_legacy_readers.{reader_name}", failures
            ):
                if version not in schema_policy:
                    failures.append(
                        f"Compatibility legacy reader {reader_name} is absent from "
                        f"schema policy: {version}"
                    )
    for version in _string_list(
        artifacts.get("explicit_migration_required"), "explicit_migration_required", failures
    ):
        if version not in schema_policy:
            failures.append(
                f"Compatibility migration-required version is absent from schema policy: {version}"
            )

    required_document_markers = {
        COMPATIBILITY_GUIDE_PATH: (
            "trustweave.dev/compatibility/v1alpha1",
            "python -m trustweave",
            "Historical local evidence remains readable only",
        ),
        SUPPORT_POLICY_PATH: (
            "requires **Python 3.11 or later**",
            "TrustWeave’s core boundary",
            "Deprecation requires clear documentation",
        ),
        ASSURANCE_MAP_PATH: (
            "Evidence is not enforcement.",
            "Authenticated package provenance status",
            "Owner-controlled external settings",
        ),
        SUPPLY_CHAIN_PATH: (
            "ADR-0005",
            "TestPyPI-first procedure",
            "0.2.2",
        ),
        PROVENANCE_ADR_PATH: (
            "TestPyPI",
            "MohammadThabetHassan/trustweave",
            (
                "Accepted as the design and verification policy for the next "
                "TrustWeave package release."
            ),
        ),
    }
    for path, markers in required_document_markers.items():
        content = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                failures.append(
                    f"Assurance document lacks required marker: {path.relative_to(ROOT)}: {marker}"
                )
    return failures


def main(argv: list[str] | None = None) -> int:
    """Run the checked-in assurance-contract verification without external side effects."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    failures = _check_compatibility_contract()
    if failures:
        print("Assurance contract verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Assurance contract verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
