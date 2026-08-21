from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts" / "run_evaluation_corpus.py"
CORPUS_PATH = ROOT / "examples" / "evaluation-corpus" / "corpus.json"


def _runner_module() -> ModuleType:
    """Load the standalone local corpus runner without changing packaging boundaries."""

    specification = importlib.util.spec_from_file_location("evaluation_corpus_runner", RUNNER_PATH)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _corpus_document() -> dict[str, object]:
    document = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_synthetic_evaluation_corpus_passes_and_emits_local_summary(tmp_path: Path) -> None:
    runner = _runner_module()

    summary = runner.run_corpus(CORPUS_PATH, tmp_path)

    assert summary["schema_version"] == "trustweave.dev/evaluation-corpus-summary/v1alpha1"
    assert summary["summary"] == {"cases": 12, "passed": 12, "failed": 0, "status": "passed"}
    assert (tmp_path / "evaluation-corpus-summary.json").is_file()
    assert (tmp_path / "evaluation-corpus-summary.md").is_file()
    report = (tmp_path / "evaluation-corpus-summary.md").read_text(encoding="utf-8")
    assert "does not establish runtime enforcement" in report


def test_corpus_cases_cover_validation_review_and_clear_controls() -> None:
    corpus = _corpus_document()
    cases = corpus["cases"]
    assert isinstance(cases, list)
    identifiers = {case["id"] for case in cases if isinstance(case, dict)}
    assert identifiers == {f"TW-EVAL-{number:03d}" for number in range(1, 13)}
    clear_cases = [
        case
        for case in cases
        if isinstance(case, dict)
        and any(
            assertion.get("path") == "summary.status" and assertion.get("equals") == "clear"
            for assertion in case.get("assertions", [])
            if isinstance(assertion, dict)
        )
    ]
    assert len(clear_cases) >= 3
    expected_exits = {case["id"]: case["expected_exit"] for case in cases if isinstance(case, dict)}
    assert expected_exits["TW-EVAL-002"] == 2
    assert expected_exits["TW-EVAL-003"] == 2
    assert expected_exits["TW-EVAL-005"] == 1
    assert expected_exits["TW-EVAL-010"] == 1
    assert expected_exits["TW-EVAL-012"] == 1


def test_corpus_rejects_external_references_before_execution(tmp_path: Path) -> None:
    runner = _runner_module()
    corpus = _corpus_document()
    cases = corpus["cases"]
    assert isinstance(cases, list)
    first_case = cases[0]
    assert isinstance(first_case, dict)
    first_case["rationale"] = "https://example.invalid must never be executed"

    with pytest.raises(runner.CorpusError, match="external URL"):
        runner._validate_corpus(corpus)


def test_evaluation_documents_distinguish_prepared_from_collected_evidence() -> None:
    status = (ROOT / "docs" / "evaluation" / "STATUS.md").read_text(encoding="utf-8")
    charter = (ROOT / "docs" / "evaluation" / "EVALUATION_CHARTER.md").read_text(encoding="utf-8")
    protocol = (ROOT / "docs" / "evaluation" / "REVIEWER_PROTOCOL.md").read_text(encoding="utf-8")
    minimization = (ROOT / "docs" / "evaluation" / "DATA_MINIMIZATION_POLICY.md").read_text(
        encoding="utf-8"
    )

    assert "Not yet collected" in status
    assert "not yet collected" in charter
    assert "not yet executed" in protocol
    assert "credentials" in minimization.lower()
    assert "live hostnames" in minimization.lower()
    assert "live discovery behavior" in minimization.lower()
    assert "## Explicit non-claims" in charter
    assert "attack prevention" in charter


def test_corpus_runner_remains_local_and_uses_the_established_cli() -> None:
    source = RUNNER_PATH.read_text(encoding="utf-8")

    assert "from trustweave.cli import main" in source
    assert "subprocess" not in source
    assert "requests" not in source
    assert "httpx" not in source
    assert "urllib" not in source
    assert "socket" not in source
