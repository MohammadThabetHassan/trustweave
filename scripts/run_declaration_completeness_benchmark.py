#!/usr/bin/env python3
"""Evaluate synthetic framework-declaration coverage without network or runtime execution."""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path
from typing import Any, Final

from trustweave.framework_import import SUPPORTED_FRAMEWORKS, normalize_framework_declaration
from trustweave.io import load_document, write_json
from trustweave.models import ValidationError, parse_manifest

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_DEFINITION: Final[Path] = (
    ROOT / "examples" / "evaluation-corpus" / "declaration-completeness" / "benchmark.json"
)
SCHEMA_VERSION: Final[str] = "trustweave.dev/declaration-completeness-benchmark/v1alpha1"
BENCHMARK_ID: Final[str] = "trustweave-synthetic-declaration-completeness"
BENCHMARK_VERSION: Final[str] = "v1alpha1"
FIXED_GENERATED_AT: Final[str] = "2026-08-25T00:00:00+00:00"
CASE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"TW-COMP-(?P<number>\d{3})")
EXPECTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "inventory_tools",
        "manifest_tools",
        "missing_from_manifest",
        "manifest_only_tools",
        "status",
    }
)


class BenchmarkError(ValueError):
    """Raised when the checked-in local benchmark definition is invalid."""


def _inside_root(value: str) -> Path:
    """Resolve one benchmark path and reject absolute or repository-escaping inputs."""

    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise BenchmarkError(f"Benchmark path must be relative and in-repository: {value}")
    resolved = (ROOT / candidate).resolve()
    if resolved != ROOT and ROOT not in resolved.parents:
        raise BenchmarkError(f"Benchmark path escapes the repository: {value}")
    if not resolved.is_file():
        raise BenchmarkError(f"Benchmark path does not name a checked-in file: {value}")
    return resolved


def _require_string(value: object, path: str) -> str:
    """Return a non-empty string with a precise benchmark-contract failure."""

    if not isinstance(value, str) or not value.strip():
        raise BenchmarkError(f"{path} must be a non-empty string")
    return value.strip()


def _string_values(value: object) -> list[str]:
    """Collect strings so benchmark definitions cannot embed external URLs."""

    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for nested in value for item in _string_values(nested)]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _string_values(nested)]
    return []


def _tool_list(value: object, path: str) -> list[str]:
    """Validate a sorted, duplicate-free list of static tool labels."""

    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise BenchmarkError(f"{path} must be a list of non-empty strings")
    if value != sorted(value) or len(value) != len(set(value)):
        raise BenchmarkError(f"{path} must be sorted and duplicate-free")
    return list(value)


def _validate_definition(document: object) -> list[dict[str, object]]:
    """Validate the narrow synthetic benchmark contract before reading a case input."""

    if not isinstance(document, dict):
        raise BenchmarkError("Benchmark definition root must be an object")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise BenchmarkError("Unsupported benchmark schema_version")
    if document.get("benchmark_id") != BENCHMARK_ID:
        raise BenchmarkError("Unsupported benchmark_id")
    if document.get("benchmark_version") != BENCHMARK_VERSION:
        raise BenchmarkError("Unsupported benchmark_version")
    _require_string(document.get("description"), "benchmark.description")
    _require_string(document.get("non_claim"), "benchmark.non_claim")
    if any("http://" in item or "https://" in item for item in _string_values(document)):
        raise BenchmarkError("Benchmark definition must not contain an external URL")
    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list) or len(raw_cases) < 2:
        raise BenchmarkError("Benchmark definition requires at least two cases")

    cases: list[dict[str, object]] = []
    for expected_number, raw_case in enumerate(raw_cases, start=1):
        if not isinstance(raw_case, dict):
            raise BenchmarkError("Every benchmark case must be an object")
        case = dict(raw_case)
        identifier = _require_string(case.get("id"), "benchmark case id")
        identifier_match = CASE_ID_PATTERN.fullmatch(identifier)
        if identifier_match is None or int(identifier_match["number"]) != expected_number:
            raise BenchmarkError(
                f"Benchmark IDs must be contiguous; expected TW-COMP-{expected_number:03d}"
            )
        _require_string(case.get("title"), f"{identifier}.title")
        framework = _require_string(case.get("framework"), f"{identifier}.framework")
        if framework not in SUPPORTED_FRAMEWORKS:
            raise BenchmarkError(f"{identifier}.framework is not supported: {framework}")
        _inside_root(_require_string(case.get("framework_input"), f"{identifier}.framework_input"))
        _inside_root(_require_string(case.get("manifest"), f"{identifier}.manifest"))
        _require_string(case.get("rationale"), f"{identifier}.rationale")
        _require_string(case.get("non_claim"), f"{identifier}.non_claim")
        expected = case.get("expected")
        if not isinstance(expected, dict) or set(expected) != EXPECTED_FIELDS:
            raise BenchmarkError(f"{identifier}.expected must contain exactly the benchmark fields")
        for field in EXPECTED_FIELDS - {"status"}:
            _tool_list(expected[field], f"{identifier}.expected.{field}")
        if expected.get("status") not in {"complete", "mismatch"}:
            raise BenchmarkError(f"{identifier}.expected.status must be complete or mismatch")
        cases.append(case)
    return cases


def _inventory_tools(inventory: dict[str, Any]) -> list[str]:
    """Return the exact supplied framework tool labels, without interpreting their behavior."""

    entries = inventory.get("entries")
    if not isinstance(entries, list):
        raise BenchmarkError("Framework inventory has no entries list")
    labels: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise BenchmarkError("Framework inventory entry must be an object")
        tools = entry.get("tools", [])
        if not isinstance(tools, list) or not all(isinstance(tool, str) for tool in tools):
            raise BenchmarkError("Framework inventory tools must be a string list")
        labels.update(tools)
    return sorted(labels)


def _evaluate_case(case: dict[str, object]) -> dict[str, object]:
    """Compare one local framework snapshot and manifest by exact static tool label."""

    identifier = str(case["id"])
    try:
        framework_document = load_document(_inside_root(str(case["framework_input"])))
        if not isinstance(framework_document, dict):
            raise BenchmarkError(f"{identifier} framework input must be an object")
        inventory = normalize_framework_declaration(str(case["framework"]), framework_document)
        manifest_document = load_document(_inside_root(str(case["manifest"])))
        if not isinstance(manifest_document, dict):
            raise BenchmarkError(f"{identifier} manifest must be an object")
        manifest = parse_manifest(manifest_document)
        inventory_tools = _inventory_tools(inventory)
        manifest_tools = sorted(tool.name for tool in manifest.tools)
        missing_from_manifest = sorted(set(inventory_tools) - set(manifest_tools))
        manifest_only_tools = sorted(set(manifest_tools) - set(inventory_tools))
        observed = {
            "inventory_tools": inventory_tools,
            "manifest_tools": manifest_tools,
            "missing_from_manifest": missing_from_manifest,
            "manifest_only_tools": manifest_only_tools,
            "status": "complete"
            if not missing_from_manifest and not manifest_only_tools
            else "mismatch",
        }
        expected = case["expected"]
        assert isinstance(expected, dict)
        status = "passed" if observed == expected else "failed"
        result: dict[str, object] = {
            "id": identifier,
            "title": case["title"],
            "framework": case["framework"],
            "status": status,
            "expected": expected,
            "observed": observed,
            "rationale": case["rationale"],
            "non_claim": case["non_claim"],
        }
        if status == "failed":
            result["reason"] = "Observed static label comparison did not match fixture expectation"
        return result
    except (BenchmarkError, ValidationError, ValueError, OSError) as error:
        return {
            "id": identifier,
            "title": case["title"],
            "framework": case["framework"],
            "status": "failed",
            "reason": str(error),
            "rationale": case["rationale"],
            "non_claim": case["non_claim"],
        }


def _markdown_summary(summary: dict[str, object]) -> str:
    """Render a reviewer-friendly local report with the benchmark claim boundary."""

    cases = summary["cases"]
    assert isinstance(cases, list)
    lines = [
        "# Synthetic declaration-completeness benchmark summary",
        "",
        (
            "This local synthetic output compares exact tool labels in supplied framework metadata "
            "with exact tool names in a supplied TrustWeave manifest. It does not import or run a "
            "framework, inspect application source, establish runtime reachability, authenticate "
            "metadata, or prove that either declaration is complete."
        ),
        "",
        "| Case | Framework | Status | Missing from manifest | Manifest-only tools |",
        "| --- | --- | --- | --- | --- |",
    ]
    for case in cases:
        assert isinstance(case, dict)
        observed = case.get("observed", {})
        if not isinstance(observed, dict):
            observed = {}
        missing = ", ".join(observed.get("missing_from_manifest", [])) or "—"
        manifest_only = ", ".join(observed.get("manifest_only_tools", [])) or "—"
        lines.append(
            f"| `{case['id']}` | `{case['framework']}` | {case['status']} | "
            f"{missing} | {manifest_only} |"
        )
    lines.extend(["", "## Case limits", ""])
    for case in cases:
        assert isinstance(case, dict)
        lines.append(f"- **{case['id']}:** {case['non_claim']}")
    lines.append("")
    return "\n".join(lines)


def run_benchmark(definition_path: Path, output_dir: Path) -> dict[str, object]:
    """Run all checked-in synthetic comparisons into a caller-selected local directory."""

    definition = load_document(definition_path)
    cases = _validate_definition(definition)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = [_evaluate_case(case) for case in cases]
    passed = sum(result["status"] == "passed" for result in results)
    summary: dict[str, object] = {
        "schema_version": "trustweave.dev/declaration-completeness-summary/v1alpha1",
        "benchmark_id": BENCHMARK_ID,
        "benchmark_version": BENCHMARK_VERSION,
        "generated_at": FIXED_GENERATED_AT,
        "summary": {
            "cases": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "status": "passed" if passed == len(results) else "failed",
        },
        "non_claim": definition["non_claim"],
        "cases": results,
    }
    write_json(output_dir / "declaration-completeness-summary.json", summary)
    (output_dir / "declaration-completeness-summary.md").write_text(
        _markdown_summary(summary), encoding="utf-8"
    )
    return summary


def _parser() -> argparse.ArgumentParser:
    """Build the small local-only benchmark runner interface."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--definition",
        type=Path,
        default=DEFAULT_DEFINITION,
        help="Checked-in benchmark definition.",
    )
    parser.add_argument(
        "--output-dir", type=Path, help="Local output directory; defaults to a temporary directory."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Validate the benchmark contract only.")
    mode.add_argument(
        "--verify", action="store_true", help="Return non-zero when any fixture fails."
    )
    return parser


def main_runner(argv: list[str] | None = None) -> int:
    """Validate or run the static synthetic benchmark without network or runtime execution."""

    args = _parser().parse_args(argv)
    definition_path = args.definition.resolve()
    try:
        _inside_root(definition_path.relative_to(ROOT).as_posix())
        if args.check:
            definition = load_document(definition_path)
            cases = _validate_definition(definition)
            print(
                "Declaration-completeness benchmark contract passed: "
                f"{len(cases)} cases, {definition['benchmark_version']}."
            )
            return 0
        if args.output_dir is None:
            with tempfile.TemporaryDirectory(
                prefix="trustweave-declaration-completeness-"
            ) as temporary:
                summary = run_benchmark(definition_path, Path(temporary))
        else:
            summary = run_benchmark(definition_path, args.output_dir.resolve())
    except (BenchmarkError, ValidationError, ValueError, OSError) as error:
        print(f"Declaration-completeness benchmark error: {error}")
        return 2
    details = summary["summary"]
    assert isinstance(details, dict)
    print(
        "Declaration-completeness benchmark "
        f"{details['status']}: {details['passed']}/{details['cases']} cases passed; "
        f"{details['failed']} failed."
    )
    return 0 if details["status"] == "passed" or not args.verify else 1


if __name__ == "__main__":
    raise SystemExit(main_runner())
