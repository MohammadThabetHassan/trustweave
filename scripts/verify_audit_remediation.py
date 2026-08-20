#!/usr/bin/env python3
"""Run the bounded local evidence checks for the 2026-08-19 audit remediation."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATHS = (
    ROOT / "schemas" / "bundle-diff-v1alpha3.schema.json",
    ROOT / "src" / "trustweave" / "schemas" / "bundle-diff-v1alpha3.schema.json",
)
REGRESSION_FILES = (
    "tests/test_bundle_validation.py",
    "tests/test_diff.py",
    "tests/test_generated_schema_conformance.py",
    "tests/test_package_provenance_controls.py",
    "tests/test_assurance_contracts.py",
    "tests/test_audit_regressions.py",
    "tests/test_models_contracts.py",
    "tests/test_current_diff_documentation_contract.py",
)


def _run(command: list[str]) -> int:
    """Run one displayed local verification command and preserve its return status."""

    print(f"+ {' '.join(command)}", flush=True)
    return subprocess.run(command, cwd=ROOT, check=False).returncode


def main() -> int:
    """Execute bounded audit evidence checks without external or repository side effects."""

    if SCHEMA_PATHS[0].read_bytes() != SCHEMA_PATHS[1].read_bytes():
        print("Audit remediation verification failed: root and packaged v1alpha3 schemas differ.")
        return 1
    commands = (
        [sys.executable, "scripts/verify_package_provenance_controls.py"],
        [sys.executable, "scripts/verify_assurance_contracts.py"],
        [sys.executable, "-m", "pytest", "--no-cov", *REGRESSION_FILES],
    )
    for command in commands:
        if _run(command) != 0:
            print("Audit remediation verification failed.")
            return 1
    print(
        "Audit remediation verification passed: bounded semantic, schema, and regression "
        "evidence is green."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
