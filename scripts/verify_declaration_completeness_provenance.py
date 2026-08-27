#!/usr/bin/env python3
"""Verify synthetic declaration-completeness fixture provenance and integrity locally."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Final

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
FIXTURE_DIRECTORY: Final[Path] = (
    ROOT / "examples" / "evaluation-corpus" / "declaration-completeness"
)
BENCHMARK_PATH: Final[Path] = FIXTURE_DIRECTORY / "benchmark.json"
PROVENANCE_PATH: Final[Path] = FIXTURE_DIRECTORY / "provenance.json"
SCHEMA_VERSION: Final[str] = "trustweave.dev/declaration-completeness-provenance/v1alpha1"
FIXTURE_SET: Final[str] = "trustweave-synthetic-declaration-completeness"
FIXTURE_VERSION: Final[str] = "v1alpha1"
SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "fixture_set",
        "fixture_version",
        "maintainer",
        "origin",
        "update_policy",
        "non_claim",
        "files",
    }
)
FILE_FIELDS: Final[frozenset[str]] = frozenset({"path", "sha256"})
FIXTURE_PREFIX: Final[str] = "examples/evaluation-corpus/declaration-completeness/"


def _load_object(path: Path, label: str) -> tuple[dict[str, Any] | None, list[str]]:
    """Load one JSON object with deterministic, reviewer-readable failures."""

    if not path.is_file():
        return None, [f"Missing {label}: {path.relative_to(ROOT)}"]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return None, [f"Invalid {label} JSON: {error}"]
    if not isinstance(document, dict):
        return None, [f"{label.capitalize()} must be a JSON object"]
    return document, []


def _require_string(value: object, path: str, failures: list[str]) -> str | None:
    """Validate one non-empty string without stopping review of the remaining contract."""

    if not isinstance(value, str) or not value.strip():
        failures.append(f"{path} must be a non-empty string")
        return None
    return value.strip()


def _fixture_paths() -> tuple[list[str] | None, list[str]]:
    """Derive the exact tracked input set from the benchmark definition itself."""

    definition, failures = _load_object(BENCHMARK_PATH, "benchmark definition")
    if definition is None:
        return None, failures
    cases = definition.get("cases")
    if not isinstance(cases, list) or not cases:
        return None, failures + ["Benchmark definition cases must be a non-empty list"]
    paths = {BENCHMARK_PATH.relative_to(ROOT).as_posix()}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            failures.append(f"Benchmark case {index} must be an object")
            continue
        for field in ("framework_input", "manifest"):
            value = _require_string(case.get(field), f"benchmark.cases[{index}].{field}", failures)
            if value is None:
                continue
            candidate = Path(value)
            if (
                candidate.is_absolute()
                or ".." in candidate.parts
                or not value.startswith(FIXTURE_PREFIX)
            ):
                failures.append(
                    f"benchmark.cases[{index}].{field} must be a checked-in fixture path"
                )
                continue
            resolved = (ROOT / candidate).resolve()
            if not resolved.is_file() or FIXTURE_DIRECTORY not in resolved.parents:
                failures.append(
                    f"benchmark.cases[{index}].{field} must name a fixture file in the corpus"
                )
                continue
            paths.add(candidate.as_posix())
    return sorted(paths), failures


def _sha256(path: Path) -> str:
    """Return one exact-file SHA-256 digest without normalizing bytes."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_provenance(provenance_path: Path = PROVENANCE_PATH) -> list[str]:
    """Validate provenance metadata and exact fixture bytes without external access."""

    expected_paths, failures = _fixture_paths()
    provenance, provenance_failures = _load_object(provenance_path, "fixture provenance manifest")
    failures.extend(provenance_failures)
    if provenance is None or expected_paths is None:
        return failures
    if set(provenance) != REQUIRED_FIELDS:
        failures.append(
            f"Fixture provenance manifest must contain exactly {', '.join(sorted(REQUIRED_FIELDS))}"
        )
    if provenance.get("schema_version") != SCHEMA_VERSION:
        failures.append("Fixture provenance manifest has an unsupported schema_version")
    if provenance.get("fixture_set") != FIXTURE_SET:
        failures.append("Fixture provenance manifest has an unsupported fixture_set")
    if provenance.get("fixture_version") != FIXTURE_VERSION:
        failures.append("Fixture provenance manifest has an unsupported fixture_version")
    for field in ("maintainer", "origin", "non_claim"):
        _require_string(provenance.get(field), f"provenance.{field}", failures)
    update_policy = provenance.get("update_policy")
    if (
        not isinstance(update_policy, list)
        or not update_policy
        or not all(isinstance(item, str) and item.strip() for item in update_policy)
    ):
        failures.append("provenance.update_policy must be a non-empty list of non-empty strings")
    public_strings = [
        value
        for field in ("maintainer", "origin", "non_claim")
        if isinstance((value := provenance.get(field)), str)
    ]
    if isinstance(update_policy, list):
        public_strings.extend(item for item in update_policy if isinstance(item, str))
    if any("http://" in value or "https://" in value for value in public_strings):
        failures.append("Fixture provenance manifest must not contain external URLs")

    files = provenance.get("files")
    if not isinstance(files, list) or not files:
        return failures + ["provenance.files must be a non-empty list"]
    declared: dict[str, str] = {}
    for index, entry in enumerate(files):
        entry_path = f"provenance.files[{index}]"
        if not isinstance(entry, dict) or set(entry) != FILE_FIELDS:
            failures.append(f"{entry_path} must contain exactly path and sha256")
            continue
        relative_path = _require_string(entry.get("path"), f"{entry_path}.path", failures)
        digest = _require_string(entry.get("sha256"), f"{entry_path}.sha256", failures)
        if relative_path is None or digest is None:
            continue
        if not SHA256_PATTERN.fullmatch(digest):
            failures.append(f"{entry_path}.sha256 must be a lowercase SHA-256 digest")
            continue
        if relative_path in declared:
            failures.append(f"provenance.files contains duplicate path: {relative_path}")
            continue
        declared[relative_path] = digest

    if sorted(declared) != expected_paths:
        failures.append(
            "Fixture provenance paths must exactly match benchmark definition inputs: "
            f"expected {expected_paths}, found {sorted(declared)}"
        )
    for relative_path, digest in sorted(declared.items()):
        path = ROOT / relative_path
        if not path.is_file():
            failures.append(f"Provenance path does not name a checked-in file: {relative_path}")
            continue
        actual = _sha256(path)
        if actual != digest:
            failures.append(
                f"Fixture digest mismatch for {relative_path}: expected {digest}, found {actual}"
            )
    return failures


def main() -> int:
    """Run the checked-in provenance verification without writing files or using the network."""

    failures = verify_provenance()
    if failures:
        print("Declaration-completeness fixture provenance verification failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(
        "Declaration-completeness fixture provenance verification passed: "
        "synthetic inputs match the reviewed exact-file digest record."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
