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
        "declaration_consistency_benchmark", RUNNER_PATH
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


def _cases(definition: dict[str, object]) -> list[dict[str, object]]:
    cases = definition["cases"]
    assert isinstance(cases, list)
    assert all(isinstance(case, dict) for case in cases)
    return cases


def test_benchmark_passes_and_records_all_four_static_controls(tmp_path: Path) -> None:
    runner = _runner_module()

    summary = runner.run_benchmark(DEFINITION_PATH, tmp_path)

    assert summary["schema_version"] == "trustweave.dev/declaration-consistency-summary/v1alpha1"
    assert summary["summary"] == {
        "cases": 4,
        "passed": 4,
        "failed": 0,
        "status": "passed",
        "exact_agreement_cases": 1,
        "declared_reconciliation_cases": 1,
        "mismatch_cases": 2,
        "raw_missing_from_manifest": 3,
        "raw_manifest_only_tools": 3,
        "unresolved_labels": 2,
    }
    cases = summary["cases"]
    assert isinstance(cases, list)
    assert [case["id"] for case in cases] == [
        "TW-COMP-001",
        "TW-COMP-002",
        "TW-COMP-003",
        "TW-COMP-004",
    ]
    assert cases[0]["observed"]["status"] == "complete"
    assert cases[1]["observed"]["unresolved_missing_from_manifest"] == ["webhook_notify"]
    assert cases[2]["observed"]["unresolved_manifest_only_tools"] == ["audit_log"]
    assert cases[3]["observed"]["status"] == "declared_reconciliation"
    assert cases[3]["observed"]["missing_from_manifest"] == ["ticket_draft", "webhook_notify"]
    assert cases[3]["observed"]["manifest_only_tools"] == ["audit_log", "draft_ticket"]
    assert cases[3]["observed"]["unresolved_missing_from_manifest"] == []
    assert cases[3]["observed"]["unresolved_manifest_only_tools"] == []
    reconciliations = cases[3]["observed"]["declared_reconciliations"]
    assert isinstance(reconciliations, list)
    assert [(item["framework_tool"], item["manifest_tool"]) for item in reconciliations] == [
        ("ticket_draft", "draft_ticket"),
        ("webhook_notify", "audit_log"),
    ]
    report = (tmp_path / "declaration-consistency-summary.md").read_text(encoding="utf-8")
    assert "Raw labels are always retained" in report
    assert "not inferred or verified semantic equivalence" in report
    assert (tmp_path / "declaration-consistency-summary.json").is_file()


def test_benchmark_outputs_are_byte_deterministic(tmp_path: Path) -> None:
    runner = _runner_module()
    first = tmp_path / "first"
    second = tmp_path / "second"

    runner.run_benchmark(DEFINITION_PATH, first)
    runner.run_benchmark(DEFINITION_PATH, second)

    for filename in ("declaration-consistency-summary.json", "declaration-consistency-summary.md"):
        assert (first / filename).read_bytes() == (second / filename).read_bytes()


def test_benchmark_rejects_external_urls_before_reading_case_inputs() -> None:
    runner = _runner_module()
    definition = _definition()
    definition["description"] = "https://example.invalid is prohibited"

    with pytest.raises(runner.BenchmarkError, match="external URL"):
        runner._validate_definition(definition)


def test_benchmark_rejects_non_contiguous_case_identifiers() -> None:
    runner = _runner_module()
    definition = _definition()
    _cases(definition)[1]["id"] = "TW-COMP-005"

    with pytest.raises(runner.BenchmarkError, match="contiguous"):
        runner._validate_definition(definition)


def test_benchmark_rejects_unknown_case_and_mapping_fields() -> None:
    runner = _runner_module()
    definition = _definition()
    _cases(definition)[0]["unexpected"] = "prohibited"

    with pytest.raises(runner.BenchmarkError, match="unknown fields"):
        runner._validate_definition(definition)

    definition = _definition()
    mappings = _cases(definition)[3]["declared_reconciliations"]
    assert isinstance(mappings, list)
    mapping = mappings[0]
    assert isinstance(mapping, dict)
    mapping["unexpected"] = "prohibited"

    with pytest.raises(runner.BenchmarkError, match="must contain exactly"):
        runner._validate_definition(definition)


@pytest.mark.parametrize("mutation", ["duplicate", "unsorted"])
def test_benchmark_rejects_duplicate_or_unsorted_declared_reconciliations(mutation: str) -> None:
    runner = _runner_module()
    definition = _definition()
    mappings = _cases(definition)[3]["declared_reconciliations"]
    assert isinstance(mappings, list)
    if mutation == "duplicate":
        mappings.append(dict(mappings[0]))
    else:
        mappings.reverse()

    with pytest.raises(runner.BenchmarkError, match="duplicate|sorted"):
        runner._validate_definition(definition)


def test_benchmark_records_unmappable_declared_pair_as_a_failed_fixture() -> None:
    runner = _runner_module()
    definition = _definition()
    cases = runner._validate_definition(definition)
    mixed_case = cases[3]
    mappings = mixed_case["declared_reconciliations"]
    assert isinstance(mappings, list)
    mappings[0]["manifest_tool"] = "knowledge_search"

    result = runner._evaluate_case(mixed_case)

    assert result["status"] == "failed"
    assert "must pair one raw framework-only label" in result["reason"]


def test_benchmark_runner_is_local_and_uses_the_framework_normalizer() -> None:
    source = RUNNER_PATH.read_text(encoding="utf-8")

    assert "normalize_framework_declaration" in source
    for prohibited in (
        "subprocess",
        "requests",
        "httpx",
        "urllib",
        "socket",
        "os.environ",
        "getenv",
        "importlib",
    ):
        assert prohibited not in source


def test_benchmark_documentation_and_reviewer_assets_preserve_non_claims() -> None:
    benchmark = (ROOT / "docs" / "evaluation" / "DECLARATION_COMPLETENESS_BENCHMARK.md").read_text(
        encoding="utf-8"
    )
    status = (ROOT / "docs" / "evaluation" / "STATUS.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "site" / "EVALUATION.md").read_text(encoding="utf-8")
    packet = (ROOT / "examples" / "evaluation-corpus" / "reviewer-packet" / "README.md").read_text(
        encoding="utf-8"
    )
    feedback = (
        ROOT / "examples" / "evaluation-corpus" / "reviewer-packet" / "FEEDBACK_TEMPLATE.md"
    ).read_text(encoding="utf-8")

    for identifier in ("TW-COMP-001", "TW-COMP-002", "TW-COMP-003", "TW-COMP-004"):
        assert identifier in benchmark
    assert "not yet an independent evaluation result" in benchmark
    assert "does not import or execute a framework" in benchmark
    assert "does not prove that either declaration is complete" in benchmark
    assert "Declared reconciliation" in benchmark
    assert "semantic-equivalence" in status
    assert "fixture-level consistency demonstration" in guide
    assert "4/4 cases passed" in packet
    assert "T7 optional declaration-consistency outcome" in feedback
