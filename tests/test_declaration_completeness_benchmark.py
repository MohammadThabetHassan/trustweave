import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts" / "run_declaration_completeness_benchmark.py"
DEFINITION_PATH = (
    ROOT / "examples" / "evaluation-corpus" / "declaration-completeness" / "benchmark.json"
)


def _runner_module() -> ModuleType:
    """Load the standalone benchmark runner without changing package boundaries."""

    specification = importlib.util.spec_from_file_location(
        "declaration_completeness_benchmark", RUNNER_PATH
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _definition() -> dict[str, object]:
    document = json.loads(DEFINITION_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_benchmark_passes_and_records_the_static_mismatch_control(tmp_path: Path) -> None:
    runner = _runner_module()

    summary = runner.run_benchmark(DEFINITION_PATH, tmp_path)

    assert summary["schema_version"] == "trustweave.dev/declaration-completeness-summary/v1alpha1"
    assert summary["summary"] == {"cases": 2, "passed": 2, "failed": 0, "status": "passed"}
    cases = summary["cases"]
    assert isinstance(cases, list)
    assert cases[0]["observed"] == {
        "inventory_tools": ["customer_lookup", "knowledge_search", "ticket_draft"],
        "manifest_tools": ["customer_lookup", "knowledge_search", "ticket_draft"],
        "missing_from_manifest": [],
        "manifest_only_tools": [],
        "status": "complete",
    }
    assert cases[1]["observed"] == {
        "inventory_tools": [
            "customer_lookup",
            "knowledge_search",
            "ticket_draft",
            "webhook_notify",
        ],
        "manifest_tools": ["customer_lookup", "knowledge_search", "ticket_draft"],
        "missing_from_manifest": ["webhook_notify"],
        "manifest_only_tools": [],
        "status": "mismatch",
    }
    report = (tmp_path / "declaration-completeness-summary.md").read_text(encoding="utf-8")
    assert "does not import or run a framework" in report
    assert (tmp_path / "declaration-completeness-summary.json").is_file()


def test_benchmark_rejects_external_urls_before_reading_case_inputs() -> None:
    runner = _runner_module()
    definition = _definition()
    definition["description"] = "https://example.invalid is prohibited"

    with pytest.raises(runner.BenchmarkError, match="external URL"):
        runner._validate_definition(definition)


def test_benchmark_rejects_non_contiguous_case_identifiers() -> None:
    runner = _runner_module()
    definition = _definition()
    cases = definition["cases"]
    assert isinstance(cases, list)
    second_case = cases[1]
    assert isinstance(second_case, dict)
    second_case["id"] = "TW-COMP-003"

    with pytest.raises(runner.BenchmarkError, match="contiguous"):
        runner._validate_definition(definition)


def test_benchmark_runner_is_local_and_uses_the_framework_normalizer() -> None:
    source = RUNNER_PATH.read_text(encoding="utf-8")

    assert "normalize_framework_declaration" in source
    assert "subprocess" not in source
    assert "requests" not in source
    assert "httpx" not in source
    assert "urllib" not in source
    assert "socket" not in source


def test_benchmark_documentation_and_status_preserve_non_claims() -> None:
    benchmark = (ROOT / "docs" / "evaluation" / "DECLARATION_COMPLETENESS_BENCHMARK.md").read_text(
        encoding="utf-8"
    )
    status = (ROOT / "docs" / "evaluation" / "STATUS.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "site" / "EVALUATION.md").read_text(encoding="utf-8")

    assert "not yet an independent evaluation result" in benchmark
    assert "does not import or execute a framework" in benchmark
    assert "does not prove that either declaration is complete" in benchmark
    assert "Declaration-completeness benchmark" in status
    assert "no source-completeness, runtime-discovery, or security-efficacy claim" in status
    assert "fixture-level consistency demonstration" in guide
