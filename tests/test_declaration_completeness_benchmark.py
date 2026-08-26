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


def test_benchmark_passes_and_records_all_fourteen_static_controls(tmp_path: Path) -> None:
    runner = _runner_module()

    summary = runner.run_benchmark(DEFINITION_PATH, tmp_path)

    assert summary["schema_version"] == "trustweave.dev/declaration-consistency-summary/v1alpha1"
    assert summary["summary"] == {
        "cases": 14,
        "passed": 14,
        "failed": 0,
        "status": "passed",
        "exact_agreement_cases": 4,
        "declared_reconciliation_cases": 1,
        "mismatch_cases": 9,
        "raw_missing_from_manifest": 12,
        "raw_manifest_only_tools": 12,
        "unresolved_labels": 16,
    }
    cases = summary["cases"]
    assert isinstance(cases, list)
    assert [case["id"] for case in cases] == [f"TW-COMP-{i:03d}" for i in range(1, 15)]
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


def test_benchmark_check_mode_validates_without_running_cases(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = _runner_module()

    def should_not_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("--check must not run benchmark cases")

    monkeypatch.setattr(runner, "run_benchmark", should_not_run)

    assert runner.main_runner(["--check"]) == 0
    assert "benchmark contract passed: 14 cases, v1alpha1" in capsys.readouterr().out


def test_benchmark_verify_mode_returns_nonzero_for_failed_fixture(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = _runner_module()

    monkeypatch.setattr(
        runner,
        "run_benchmark",
        lambda *_args, **_kwargs: {
            "summary": {"status": "failed", "passed": 13, "cases": 14, "failed": 1}
        },
    )

    assert runner.main_runner(["--verify"]) == 1
    assert "failed: 13/14 cases passed; 1 failed" in capsys.readouterr().out


def test_benchmark_cli_rejects_undocumented_abbreviated_option() -> None:
    runner = _runner_module()

    with pytest.raises(SystemExit) as raised:
        runner.main_runner(["--output", "unused"])

    assert raised.value.code == 2


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
    quickstart = (ROOT / "docs" / "evaluation" / "REVIEWER_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    packet = (ROOT / "examples" / "evaluation-corpus" / "reviewer-packet" / "README.md").read_text(
        encoding="utf-8"
    )
    feedback = (
        ROOT / "examples" / "evaluation-corpus" / "reviewer-packet" / "FEEDBACK_TEMPLATE.md"
    ).read_text(encoding="utf-8")

    for identifier in (f"TW-COMP-{i:03d}" for i in range(1, 15)):
        assert identifier in benchmark
    assert "not yet an independent evaluation result" in benchmark
    assert "does not import or execute a framework" in benchmark
    assert "does not prove that either declaration is complete" in benchmark
    assert "Declared reconciliation" in benchmark
    assert "OpenAI Agents-style, LangGraph-style, or CrewAI-style" in benchmark
    assert "## Realism and bounded usefulness" in benchmark
    assert "synthetic, not real application exports or deployments" in benchmark
    assert "it cannot be created by relabeling these fixtures as real" in benchmark
    assert "semantic-equivalence" in status
    assert "fourteen reproducible, local-only controls" in guide
    assert "OpenAI Agents-style, LangGraph-style, and CrewAI-style descriptors" in guide
    assert "fixture-level consistency demonstration" in guide
    assert "14/14 cases passed" in quickstart
    assert "verify_declaration_completeness_provenance.py" in quickstart
    assert "not an authenticity record for a real framework export" in quickstart
    assert "14/14 cases passed" in packet
    assert "T7 optional declaration-consistency outcome" in feedback
