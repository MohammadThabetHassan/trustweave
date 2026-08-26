#!/usr/bin/env python3
"""Evaluate supplied declaration consistency without network or runtime execution."""

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
        "declared_reconciliations",
        "unresolved_missing_from_manifest",
        "unresolved_manifest_only_tools",
        "status",
    }
)
RECONCILIATION_FIELDS: Final[frozenset[str]] = frozenset(
    {"framework_tool", "manifest_tool", "declared_by", "rationale"}
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


def _reconciliations(value: object, path: str) -> list[dict[str, str]]:
    """Validate explicit reviewer-declared local label mappings without inferring equivalence."""

    if value is None:
        return []
    if not isinstance(value, list):
        raise BenchmarkError(f"{path} must be a list when present")
    mappings: list[dict[str, str]] = []
    for index, raw_mapping in enumerate(value):
        mapping_path = f"{path}[{index}]"
        if not isinstance(raw_mapping, dict) or set(raw_mapping) != RECONCILIATION_FIELDS:
            raise BenchmarkError(
                f"{mapping_path} must contain exactly {', '.join(sorted(RECONCILIATION_FIELDS))}"
            )
        mappings.append(
            {
                field: _require_string(raw_mapping[field], f"{mapping_path}.{field}")
                for field in sorted(RECONCILIATION_FIELDS)
            }
        )

    def sort_key(item: dict[str, str]) -> tuple[str, str]:
        return item["framework_tool"], item["manifest_tool"]

    if mappings != sorted(mappings, key=sort_key):
        raise BenchmarkError(f"{path} must be sorted by framework_tool then manifest_tool")
    pairs = [(item["framework_tool"], item["manifest_tool"]) for item in mappings]
    if len(pairs) != len(set(pairs)):
        raise BenchmarkError(f"{path} contains duplicate declared reconciliation pairs")
    return mappings


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
    if not isinstance(raw_cases, list) or len(raw_cases) < 4:
        raise BenchmarkError("Benchmark definition requires at least four cases")

    cases: list[dict[str, object]] = []
    for expected_number, raw_case in enumerate(raw_cases, start=1):
        if not isinstance(raw_case, dict):
            raise BenchmarkError("Every benchmark case must be an object")
        allowed_fields = {
            "id",
            "title",
            "framework",
            "framework_input",
            "manifest",
            "expected",
            "rationale",
            "non_claim",
            "declared_reconciliations",
        }
        if set(raw_case) - allowed_fields:
            raise BenchmarkError(
                f"Benchmark case has unknown fields: {sorted(set(raw_case) - allowed_fields)}"
            )
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
        case["declared_reconciliations"] = _reconciliations(
            case.get("declared_reconciliations"), f"{identifier}.declared_reconciliations"
        )
        expected = case.get("expected")
        if not isinstance(expected, dict) or set(expected) != EXPECTED_FIELDS:
            raise BenchmarkError(f"{identifier}.expected must contain exactly the benchmark fields")
        for field in EXPECTED_FIELDS - {"status", "declared_reconciliations"}:
            _tool_list(expected[field], f"{identifier}.expected.{field}")
        _reconciliations(
            expected["declared_reconciliations"], f"{identifier}.expected.declared_reconciliations"
        )
        if expected.get("status") not in {"complete", "declared_reconciliation", "mismatch"}:
            raise BenchmarkError(
                f"{identifier}.expected.status must be complete, "
                "declared_reconciliation, or mismatch"
            )
        cases.append(case)
    return cases


def _inventory_tools(inventory: dict[str, Any]) -> list[str]:
    """Return exact supplied framework tool labels without interpreting their behavior."""

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


def _reconcile(
    missing_from_manifest: list[str],
    manifest_only_tools: list[str],
    mappings: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """Apply only explicit mappings that match raw supplied-label differences exactly."""

    unresolved_missing = set(missing_from_manifest)
    unresolved_manifest_only = set(manifest_only_tools)
    reconciled: list[dict[str, str]] = []
    for mapping in mappings:
        framework_tool = mapping["framework_tool"]
        manifest_tool = mapping["manifest_tool"]
        if (
            framework_tool not in unresolved_missing
            or manifest_tool not in unresolved_manifest_only
        ):
            raise BenchmarkError(
                "Declared reconciliation must pair one raw framework-only label with one raw "
                "manifest-only label"
            )
        unresolved_missing.remove(framework_tool)
        unresolved_manifest_only.remove(manifest_tool)
        reconciled.append(mapping)
    return reconciled, sorted(unresolved_missing), sorted(unresolved_manifest_only)


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
        mappings = case["declared_reconciliations"]
        assert isinstance(mappings, list)
        reconciled, unresolved_missing, unresolved_manifest_only = _reconcile(
            missing_from_manifest, manifest_only_tools, mappings
        )
        observed = {
            "inventory_tools": inventory_tools,
            "manifest_tools": manifest_tools,
            "missing_from_manifest": missing_from_manifest,
            "manifest_only_tools": manifest_only_tools,
            "declared_reconciliations": reconciled,
            "unresolved_missing_from_manifest": unresolved_missing,
            "unresolved_manifest_only_tools": unresolved_manifest_only,
            "status": (
                "complete"
                if not missing_from_manifest and not manifest_only_tools
                else "declared_reconciliation"
                if not unresolved_missing and not unresolved_manifest_only
                else "mismatch"
            ),
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


def _join(values: object) -> str:
    """Render a sorted list of labels compactly for the local Markdown report."""

    return ", ".join(values) if isinstance(values, list) and values else "—"


def _mapping_text(mappings: object) -> str:
    """Render declared mappings without implying verified semantic equivalence."""

    if not isinstance(mappings, list) or not mappings:
        return "—"
    return (
        ", ".join(
            f"{item['framework_tool']} → {item['manifest_tool']}"
            for item in mappings
            if isinstance(item, dict)
        )
        or "—"
    )


def _markdown_summary(summary: dict[str, object]) -> str:
    """Render a reviewer-friendly local report with raw and reconciled claim boundaries."""

    cases = summary["cases"]
    assert isinstance(cases, list)
    details = summary["summary"]
    assert isinstance(details, dict)
    lines = [
        "# Synthetic declaration-consistency benchmark summary",
        "",
        (
            "This local synthetic output compares exact tool labels in supplied framework metadata "
            "with exact tool names in a supplied TrustWeave manifest. Explicit declared "
            "reconciliations are reviewer-provided labels, not inferred or verified semantic "
            "equivalence. The runner does not import or run a framework, inspect application "
            "source, establish runtime reachability, authenticate metadata, or prove that either "
            "declaration is complete."
        ),
        "",
        "## Fixture totals",
        "",
        (
            "| Cases | Passed | Exact agreements | Declared reconciliations | Mismatches | "
            "Raw missing labels | Raw manifest-only labels | Unresolved labels |"
        ),
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {details['cases']} | {details['passed']} | {details['exact_agreement_cases']} | "
            f"{details['declared_reconciliation_cases']} | {details['mismatch_cases']} | "
            f"{details['raw_missing_from_manifest']} | {details['raw_manifest_only_tools']} | "
            f"{details['unresolved_labels']} |"
        ),
        "",
        "## Case results",
        "",
        (
            "| Case | Framework | Fixture status | Raw missing from manifest | Raw manifest-only | "
            "Declared reconciliation | Unresolved labels |"
        ),
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for case in cases:
        assert isinstance(case, dict)
        observed = case.get("observed", {})
        if not isinstance(observed, dict):
            observed = {}
        unresolved = sorted(
            [
                *_tool_list(
                    observed.get("unresolved_missing_from_manifest", []),
                    "report.unresolved_missing_from_manifest",
                ),
                *_tool_list(
                    observed.get("unresolved_manifest_only_tools", []),
                    "report.unresolved_manifest_only_tools",
                ),
            ]
        )
        lines.append(
            f"| `{case['id']}` | `{case['framework']}` | {observed.get('status', '—')} | "
            f"{_join(observed.get('missing_from_manifest'))} | "
            f"{_join(observed.get('manifest_only_tools'))} | "
            f"{_mapping_text(observed.get('declared_reconciliations'))} | {_join(unresolved)} |"
        )
    lines.extend(["", "## Interpretation and limits", ""])
    lines.extend(
        [
            (
                "- Raw labels are always retained. A declared reconciliation never removes or "
                "conceals a raw difference."
            ),
            (
                "- `declared_reconciliation` means all raw differences in that fixture were paired "
                "by an explicit local mapping. It does not mean the labels, endpoint behavior, "
                "source code, or runtime paths were verified as equivalent."
            ),
            (
                "- `mismatch` means one or more raw labels remain unresolved within the supplied "
                "artifacts. It does not prove that a live tool exists, is reachable, or is unsafe."
            ),
            (
                "- This fixture suite is planned local evidence only; it is not an independent "
                "review, pilot, comparative benchmark result, adoption signal, or "
                "security-efficacy study."
            ),
            "",
            "## Case limits",
            "",
        ]
    )
    for case in cases:
        assert isinstance(case, dict)
        lines.append(f"- **{case['id']}:** {case['non_claim']}")
    lines.append("")
    return "\n".join(lines)


def _select_cases(cases: list[dict[str, object]], case_id: str | None) -> list[dict[str, object]]:
    """Return the full corpus or one exact checked-in case for a local walkthrough."""

    if case_id is None:
        return cases
    selected = [case for case in cases if case["id"] == case_id]
    if not selected:
        raise BenchmarkError(f"Unknown benchmark case: {case_id}")
    return selected


def _summary_counts(results: list[dict[str, object]]) -> dict[str, int]:
    """Count fixture-only raw and unresolved labels using deterministic aggregate fields."""

    exact_agreement_cases = 0
    declared_reconciliation_cases = 0
    mismatch_cases = 0
    raw_missing_from_manifest = 0
    raw_manifest_only_tools = 0
    unresolved_labels = 0
    for result in results:
        observed = result.get("observed", {})
        if not isinstance(observed, dict):
            continue
        status = observed.get("status")
        if status == "complete":
            exact_agreement_cases += 1
        elif status == "declared_reconciliation":
            declared_reconciliation_cases += 1
        elif status == "mismatch":
            mismatch_cases += 1
        raw_missing_from_manifest += len(observed.get("missing_from_manifest", []))
        raw_manifest_only_tools += len(observed.get("manifest_only_tools", []))
        unresolved_labels += len(observed.get("unresolved_missing_from_manifest", []))
        unresolved_labels += len(observed.get("unresolved_manifest_only_tools", []))
    return {
        "exact_agreement_cases": exact_agreement_cases,
        "declared_reconciliation_cases": declared_reconciliation_cases,
        "mismatch_cases": mismatch_cases,
        "raw_missing_from_manifest": raw_missing_from_manifest,
        "raw_manifest_only_tools": raw_manifest_only_tools,
        "unresolved_labels": unresolved_labels,
    }


def run_benchmark(
    definition_path: Path, output_dir: Path, case_id: str | None = None
) -> dict[str, object]:
    """Run all checked-in synthetic comparisons or one exact selected case locally."""

    definition = load_document(definition_path)
    cases = _select_cases(_validate_definition(definition), case_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = [_evaluate_case(case) for case in cases]
    passed = sum(result["status"] == "passed" for result in results)
    summary: dict[str, object] = {
        "schema_version": "trustweave.dev/declaration-consistency-summary/v1alpha1",
        "benchmark_id": BENCHMARK_ID,
        "benchmark_version": BENCHMARK_VERSION,
        "generated_at": FIXED_GENERATED_AT,
        "summary": {
            "cases": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "status": "passed" if passed == len(results) else "failed",
            **_summary_counts(results),
        },
        "non_claim": definition["non_claim"],
        "cases": results,
    }
    write_json(output_dir / "declaration-consistency-summary.json", summary)
    (output_dir / "declaration-consistency-summary.md").write_text(
        _markdown_summary(summary), encoding="utf-8"
    )
    return summary


def _parser() -> argparse.ArgumentParser:
    """Build the small local-only benchmark runner interface."""

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "--definition",
        type=Path,
        default=DEFAULT_DEFINITION,
        help="Checked-in benchmark definition.",
    )
    parser.add_argument(
        "--output-dir", type=Path, help="Local output directory; defaults to a temporary directory."
    )
    parser.add_argument(
        "--case",
        metavar="TW-COMP-NNN",
        help="Run or validate one exact checked-in synthetic case for a local walkthrough.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Validate the benchmark contract only.")
    mode.add_argument(
        "--verify", action="store_true", help="Return non-zero when any fixture fails."
    )
    return parser


def main_runner(argv: list[str] | None = None) -> int:
    """Validate or run static local fixtures without network or runtime execution."""

    args = _parser().parse_args(argv)
    definition_path = args.definition.resolve()
    try:
        _inside_root(definition_path.relative_to(ROOT).as_posix())
        if args.check:
            definition = load_document(definition_path)
            cases = _select_cases(_validate_definition(definition), args.case)
            scope = args.case if args.case is not None else "benchmark"
            print(
                "Declaration-consistency "
                f"{scope} contract passed: {len(cases)} cases, {definition['benchmark_version']}."
            )
            return 0
        if args.output_dir is None:
            with tempfile.TemporaryDirectory(
                prefix="trustweave-declaration-consistency-"
            ) as temporary:
                summary = run_benchmark(definition_path, Path(temporary), args.case)
        else:
            summary = run_benchmark(definition_path, args.output_dir.resolve(), args.case)
    except (BenchmarkError, ValidationError, ValueError, OSError) as error:
        print(f"Declaration-consistency benchmark error: {error}")
        return 2
    details = summary["summary"]
    assert isinstance(details, dict)
    scope = args.case if args.case is not None else "benchmark"
    print(
        "Declaration-consistency "
        f"{scope} {details['status']}: {details['passed']}/{details['cases']} cases passed; "
        f"{details['failed']} failed."
    )
    return 0 if details["status"] == "passed" or not args.verify else 1


if __name__ == "__main__":
    raise SystemExit(main_runner())
