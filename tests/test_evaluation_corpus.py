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


def test_corpus_preflight_rejects_non_contiguous_case_identifiers() -> None:
    runner = _runner_module()
    corpus = _corpus_document()
    cases = corpus["cases"]
    assert isinstance(cases, list)
    second_case = cases[1]
    assert isinstance(second_case, dict)
    second_case["id"] = "TW-EVAL-004"

    with pytest.raises(runner.CorpusError, match="ordered and contiguous"):
        runner._validate_corpus(corpus)


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("corpus_id", "other-corpus", "corpus_id"),
        ("corpus_version", "v9alpha9", "corpus_version"),
        ("description", "", "description"),
    ],
)
def test_corpus_preflight_rejects_incompatible_metadata(
    field: str, replacement: str, error: str
) -> None:
    runner = _runner_module()
    corpus = _corpus_document()
    corpus[field] = replacement

    with pytest.raises(runner.CorpusError, match=error):
        runner._validate_corpus(corpus)


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("exit_on_review", "true", "exit_on_review"),
        ("expected_signal_ids", ["TW-DIFF-003", "TW-DIFF-003"], "unique non-empty"),
    ],
)
def test_corpus_preflight_rejects_invalid_case_control_metadata(
    field: str, replacement: object, error: str
) -> None:
    runner = _runner_module()
    corpus = _corpus_document()
    cases = corpus["cases"]
    assert isinstance(cases, list)
    case_index = 6 if field == "expected_signal_ids" else 3
    case = cases[case_index]
    assert isinstance(case, dict)
    case[field] = replacement

    with pytest.raises(runner.CorpusError, match=error):
        runner._validate_corpus(corpus)


def test_check_only_mode_validates_the_contract_without_running_cases(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = _runner_module()

    exit_code = runner.main_runner(["--check"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Evaluation corpus contract passed: 12 cases, v1alpha1." in captured.out


def test_evaluation_lifecycle_and_public_guide_keep_the_local_evidence_boundary() -> None:
    lifecycle = (ROOT / "docs" / "evaluation" / "CORPUS_LIFECYCLE.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "site" / "EVALUATION.md").read_text(encoding="utf-8")

    assert "python scripts/run_evaluation_corpus.py --check" in lifecycle
    assert "Existing case IDs are immutable" in lifecycle
    assert (
        "No network, model, credential, agent, tool, server, target, or external-data behavior"
        in lifecycle
    )
    assert "twelve checked-in synthetic cases" in guide
    assert "not yet collected" in guide
    assert "does not demonstrate runtime enforcement" in guide


def test_reviewer_quickstart_and_archive_readiness_remain_reproducible_and_honest() -> None:
    quickstart = (ROOT / "docs" / "evaluation" / "REVIEWER_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    archive_readiness = (ROOT / "docs" / "evaluation" / "ARTIFACT_ARCHIVE_READINESS.md").read_text(
        encoding="utf-8"
    )

    assert "python scripts/run_evaluation_corpus.py --check" in quickstart
    assert "python scripts/run_evaluation_corpus.py --verify" in quickstart
    assert "cannot establish source authenticity" in quickstart
    assert "create an archive, reserve a DOI" in archive_readiness
    assert "SHA-256" in archive_readiness
    assert "A durable archive URL or DOI has not yet been recorded." in archive_readiness


def test_public_feedback_triage_preserves_safe_evidence_and_owner_control() -> None:
    triage = (ROOT / "docs" / "ISSUE_TRIAGE.md").read_text(encoding="utf-8")
    feedback = (ROOT / "docs" / "COMMUNITY_FEEDBACK.md").read_text(encoding="utf-8")
    handoff = (ROOT / "docs" / "MAINTAINER_HANDOFF.md").read_text(encoding="utf-8")

    assert "does not create a response-time guarantee" in triage
    assert "must not be processed through a public issue" in triage
    assert "not an independently collected reviewer-study result" in triage
    assert "automatic merge" in triage
    assert "Public Issue Triage Procedure" in feedback
    assert "not automatically a participant response" in feedback
    assert "Evaluation corpus and feedback status:" in handoff


def test_manual_scorecard_assessment_remains_owner_gated_and_non_publishing() -> None:
    workflow = (ROOT / ".github" / "workflows" / "scorecard.yml").read_text(encoding="utf-8")
    governance = (ROOT / "docs" / "GITHUB_GOVERNANCE_DECISION.md").read_text(encoding="utf-8")
    assessment = (ROOT / "docs" / "EXTERNAL_ASSESSMENT.md").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "reason:" in workflow
    assert "publish_results: false" in workflow
    assert "security-events: write" not in workflow
    assert "id-token: write" not in workflow
    assert "ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc" in workflow
    assert "Choose one maintenance profile" in governance
    assert "Do not claim a branch-protection rule" in governance
    assert "Until an owner-approved run exists" in assessment
    assert "Published externally by this workflow: no" in assessment
