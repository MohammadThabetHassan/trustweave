#!/usr/bin/env python3
"""Validate and render TrustWeave's threat-control-test traceability contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs" / "contracts" / "control-traceability-v1.json"
THREAT_MODEL_PATH = ROOT / "docs" / "THREAT_MODEL.md"
OUTPUT_PATH = ROOT / "docs" / "CONTROL_TRACEABILITY.md"
THREAT_ID_PATTERN = re.compile(r"^TWT-[A-Z]+-[0-9]{3}$")
RESIDUAL_ID_PATTERN = re.compile(r"^TWR-[A-Z]+-[0-9]{3}$")
CONTROL_ID_PATTERN = re.compile(r"^TWC-[A-Z]+(?:-[A-Z]+)*$")
EXPECTED_THREAT_COUNT = 13
EXPECTED_RESIDUAL_RISK_COUNT = 7


def _load_contract() -> dict[str, Any]:
    """Return the checked-in traceability source as a strict JSON object."""

    document = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("control traceability contract must be a JSON object")
    return document


def _string_list(value: Any, label: str, failures: list[str]) -> list[str]:
    """Return a non-empty string list while collecting a precise structural failure."""

    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        failures.append(f"Traceability {label} must be a non-empty string list")
        return []
    return value


def _source_row_count(text: str) -> int:
    """Count addressed-threat table rows in the authoritative threat-model section."""

    parts = text.split("## Threats addressed at the declaration layer", maxsplit=1)
    if len(parts) != 2:
        return 0
    section = parts[1].split("## Out of scope threats", maxsplit=1)[0]
    return sum(
        line.startswith("|") and not line.startswith("|---") and "Threat pattern" not in line
        for line in section.splitlines()
    )


def _residual_risk_count(text: str) -> int:
    """Count explicit out-of-scope threat bullets from the authoritative source section."""

    after_heading = text.split("## Out of scope threats", maxsplit=1)
    if len(after_heading) != 2:
        return 0
    section = after_heading[1].split("## Attacker model", maxsplit=1)[0]
    return sum(line.startswith("- ") for line in section.splitlines())


def _validate_path(path: str, label: str, failures: list[str]) -> None:
    """Require every traceability path to resolve inside the checked-in repository."""

    candidate = ROOT / path
    if not candidate.is_file():
        failures.append(f"Traceability {label} is missing: {path}")


def _validate_contract(contract: dict[str, Any]) -> list[str]:
    """Validate complete source-to-threat-to-control-to-test traceability."""

    failures: list[str] = []
    if contract.get("schema_version") != "trustweave.dev/control-traceability/v1alpha1":
        failures.append("Traceability contract has an unexpected schema_version")
    if contract.get("source_document") != "docs/THREAT_MODEL.md":
        failures.append("Traceability contract source_document must be docs/THREAT_MODEL.md")
    if not THREAT_MODEL_PATH.is_file():
        return failures + ["Missing docs/THREAT_MODEL.md"]
    threat_model = THREAT_MODEL_PATH.read_text(encoding="utf-8")

    addressed = contract.get("addressed_threats")
    residuals = contract.get("residual_risks")
    controls = contract.get("controls")
    if not isinstance(addressed, list):
        return failures + ["Traceability addressed_threats must be a list"]
    if not isinstance(residuals, list):
        return failures + ["Traceability residual_risks must be a list"]
    if not isinstance(controls, list):
        return failures + ["Traceability controls must be a list"]
    if len(addressed) != EXPECTED_THREAT_COUNT or len(addressed) != _source_row_count(threat_model):
        failures.append("Traceability addressed threat count differs from the threat-model table")
    if len(residuals) != EXPECTED_RESIDUAL_RISK_COUNT or len(residuals) != _residual_risk_count(
        threat_model
    ):
        failures.append("Traceability residual risk count differs from the threat-model exclusions")

    all_identifiers: set[str] = set()
    control_identifiers: set[str] = set()
    control_references: set[str] = set()
    for control in controls:
        if not isinstance(control, dict):
            failures.append("Traceability control entries must be objects")
            continue
        identifier = control.get("id")
        if not isinstance(identifier, str) or not CONTROL_ID_PATTERN.fullmatch(identifier):
            failures.append(f"Traceability control has invalid ID: {identifier!r}")
            continue
        if identifier in all_identifiers:
            failures.append(f"Traceability ID is duplicated: {identifier}")
        all_identifiers.add(identifier)
        control_identifiers.add(identifier)
        for field in ("control_statement", "ci_gate", "maintenance_trigger", "known_limit"):
            if not isinstance(control.get(field), str) or not control[field].strip():
                failures.append(f"Traceability control {identifier} lacks non-empty {field}")
        if control.get("ci_gate") != "Quality and tests":
            failures.append(
                f"Traceability control {identifier} must use the Quality and tests gate"
            )
        for field in ("implementation_paths", "test_paths", "evidence_paths"):
            for path in _string_list(control.get(field), f"control {identifier}.{field}", failures):
                _validate_path(path, f"control {identifier}.{field}", failures)

    for threat in addressed:
        if not isinstance(threat, dict):
            failures.append("Traceability addressed threat entries must be objects")
            continue
        identifier = threat.get("id")
        if not isinstance(identifier, str) or not THREAT_ID_PATTERN.fullmatch(identifier):
            failures.append(f"Traceability addressed threat has invalid ID: {identifier!r}")
            continue
        if identifier in all_identifiers:
            failures.append(f"Traceability ID is duplicated: {identifier}")
        all_identifiers.add(identifier)
        for field in ("statement_marker", "residual_limit_marker"):
            marker = threat.get(field)
            if not isinstance(marker, str) or marker not in threat_model:
                failures.append(
                    f"Traceability threat {identifier} marker is absent from threat model: {field}"
                )
        controls_for_threat = _string_list(
            threat.get("control_ids"), f"threat {identifier}.control_ids", failures
        )
        for control_id in controls_for_threat:
            if control_id not in control_identifiers:
                failures.append(
                    f"Traceability threat {identifier} references unknown control: {control_id}"
                )
            else:
                control_references.add(control_id)

    for residual in residuals:
        if not isinstance(residual, dict):
            failures.append("Traceability residual risk entries must be objects")
            continue
        identifier = residual.get("id")
        if not isinstance(identifier, str) or not RESIDUAL_ID_PATTERN.fullmatch(identifier):
            failures.append(f"Traceability residual risk has invalid ID: {identifier!r}")
            continue
        if identifier in all_identifiers:
            failures.append(f"Traceability ID is duplicated: {identifier}")
        all_identifiers.add(identifier)
        marker = residual.get("statement_marker")
        if not isinstance(marker, str) or marker not in threat_model:
            failures.append(
                f"Traceability residual risk {identifier} marker is absent from threat model"
            )
        reason = residual.get("exclusion_reason")
        if not isinstance(reason, str) or not reason.strip():
            failures.append(f"Traceability residual risk {identifier} lacks an exclusion_reason")

    for control_id in sorted(control_identifiers - control_references):
        failures.append(f"Traceability control is orphaned from addressed threats: {control_id}")
    return failures


def _render_controls(controls: list[dict[str, Any]]) -> list[str]:
    """Render compact deterministic documentation rows for implementation controls."""

    lines = [
        "## Implemented controls",
        "",
        "| ID | Control | Code, tests, and evidence | Residual limit |",
        "| --- | --- | --- | --- |",
    ]
    for control in controls:
        paths = ", ".join(
            [*control["implementation_paths"], *control["test_paths"], *control["evidence_paths"]]
        )
        lines.append(
            f"| `{control['id']}` | {control['control_statement']} | `{paths}` | "
            f"{control['known_limit']} |"
        )
    return lines


def _render_document(contract: dict[str, Any]) -> str:
    """Render the public traceability guide only from the versioned JSON source."""

    controls = contract["controls"]
    lines = [
        "# Control Traceability",
        "",
        "## Purpose",
        "",
        "This document is generated from "
        "[`docs/contracts/control-traceability-v1.json`](contracts/control-traceability-v1.json). "
        "It links each threat-model statement to a checked-in control, source/test/evidence paths, "
        "and an explicit residual limit. The validator rejects missing paths, duplicate "
        "identifiers, orphaned controls, unlinked stated threats, and unlinked out-of-scope risks.",
        "",
        "> A control identifies reviewable declaration-layer evidence. It does not prove complete "
        "runtime security, external certification, or deployed enforcement.",
        "",
        "## Addressed declaration-layer threats",
        "",
        "| ID | Threat-model statement | Controls | Explicit residual limit |",
        "| --- | --- | --- | --- |",
    ]
    for threat in contract["addressed_threats"]:
        controls_text = ", ".join(f"`{identifier}`" for identifier in threat["control_ids"])
        lines.append(
            f"| `{threat['id']}` | {threat['statement_marker']} | {controls_text} | "
            f"{threat['residual_limit_marker']} |"
        )
    lines.extend(
        ["", *_render_controls(controls), "", "## Deliberately excluded residual risks", ""]
    )
    lines.extend(["| ID | Out-of-scope threat | Why it remains excluded |", "| --- | --- | --- |"])
    for residual in contract["residual_risks"]:
        lines.append(
            f"| `{residual['id']}` | {residual['statement_marker']} | "
            f"{residual['exclusion_reason']} |"
        )
    lines.extend(
        [
            "",
            "## Maintenance rule",
            "",
            "Any change to a command, schema, evidence format, review finding, threat statement, "
            "or release control must update the JSON source and this generated guide in the same "
            "review. Run `python scripts/verify_control_traceability.py --write` only after "
            "reviewing the updated source; the default command is check-only.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Validate traceability and optionally refresh its deterministic generated guide."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write the generated Markdown guide.")
    args = parser.parse_args(argv)
    try:
        contract = _load_contract()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Traceability validation failed: {error}", file=sys.stderr)
        return 1
    failures = _validate_contract(contract)
    if failures:
        print("Traceability validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    rendered = _render_document(contract)
    if args.write:
        OUTPUT_PATH.write_text(rendered, encoding="utf-8")
        print(f"Traceability guide updated: {OUTPUT_PATH.relative_to(ROOT)}")
        return 0
    if not OUTPUT_PATH.is_file():
        print(
            "Traceability validation failed: missing docs/CONTROL_TRACEABILITY.md", file=sys.stderr
        )
        return 1
    if OUTPUT_PATH.read_text(encoding="utf-8") != rendered:
        print("Traceability validation failed: generated guide is stale", file=sys.stderr)
        return 1
    print(
        "Traceability validation passed: threats, controls, tests, evidence, and limits are linked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
