from __future__ import annotations

import json
from pathlib import Path

from trustweave.cli import main
from trustweave.io import load_document
from trustweave.models import parse_manifest, parse_policy
from trustweave.report import render_trace_review_report
from trustweave.trace_review import review_trace

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
CLEAR_TRACE = ROOT / "examples" / "traces" / "clear-support-trace.json"
REVIEW_TRACE = ROOT / "examples" / "traces" / "review-required-support-trace.json"


def _document(path: Path) -> dict[str, object]:
    return json.loads(json.dumps(load_document(path)))


def _review(path: Path) -> dict[str, object]:
    return review_trace(
        parse_manifest(_document(MANIFEST)),
        parse_policy(_document(POLICY)),
        _document(path),
    )


def test_clear_trace_has_no_review_findings() -> None:
    review = _review(CLEAR_TRACE)

    assert review["summary"] == {
        "messages_observed": 1,
        "tool_calls_observed": 1,
        "untrusted_context_events": 0,
        "review_findings": 0,
        "status": "clear",
    }
    observation = review["observations"][0]
    assert observation["decision"] == "allow"
    assert observation["status"] == "clear"


def test_denied_trace_produces_review_finding_without_exposing_private_fields() -> None:
    review = _review(REVIEW_TRACE)

    assert review["summary"]["status"] == "review_required"
    assert review["summary"]["untrusted_context_events"] == 1
    assert review["findings"][0]["id"] == "TW-TRACE-004"
    report = render_trace_review_report(review)
    assert "synthetic@example.invalid" not in report
    assert "Synthetic message content" not in report
    assert "send_mock_email" in report


def test_trace_review_flags_unknown_tool() -> None:
    trace = _document(CLEAR_TRACE)
    trace["tool_calls"][0]["name"] = "unknown_synthetic_tool"

    review = review_trace(
        parse_manifest(_document(MANIFEST)),
        parse_policy(_document(POLICY)),
        trace,
    )

    assert review["summary"]["status"] == "review_required"
    assert review["findings"][0]["id"] == "TW-TRACE-002"


def test_cli_trace_review_writes_artifacts_and_can_fail_a_review_gate(tmp_path: Path) -> None:
    clear_dir = tmp_path / "clear"
    assert (
        main(
            [
                "trace-review",
                "--manifest",
                str(MANIFEST),
                "--policy",
                str(POLICY),
                "--trace",
                str(CLEAR_TRACE),
                "--output-dir",
                str(clear_dir),
                "--exit-on-review",
            ]
        )
        == 0
    )
    assert (clear_dir / "trace-review.json").is_file()
    assert (clear_dir / "trace-review.md").is_file()

    review_dir = tmp_path / "review"
    assert (
        main(
            [
                "trace-review",
                "--manifest",
                str(MANIFEST),
                "--policy",
                str(POLICY),
                "--trace",
                str(REVIEW_TRACE),
                "--output-dir",
                str(review_dir),
                "--exit-on-review",
            ]
        )
        == 1
    )
    assert (review_dir / "trace-review.json").is_file()
    assert (review_dir / "trace-review.md").is_file()
