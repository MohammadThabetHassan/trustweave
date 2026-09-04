from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.io import load_document
from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.report import render_trace_review_report
from trustweave.trace_review import parse_trace, review_trace

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
    assert "Trace matches a deny decision" in report
    assert "Investigate the mismatch through the human review process" in report


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


def test_trace_review_flags_unknown_source() -> None:
    trace = _document(CLEAR_TRACE)
    calls = trace["tool_calls"]
    assert isinstance(calls, list)
    calls[0]["source"] = "unknown_synthetic_source"

    review = review_trace(
        parse_manifest(_document(MANIFEST)),
        parse_policy(_document(POLICY)),
        trace,
    )

    assert review["findings"][0]["id"] == "TW-TRACE-001"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda trace: trace.update({"schema_version": "unsupported"}), "schema_version"),
        (lambda trace: trace.update({"messages": "not-a-list"}), "messages"),
        (lambda trace: trace["messages"][0].update({"content": 1}), "content"),
        (lambda trace: trace["tool_calls"][0].update({"arguments": []}), "arguments"),
        (lambda trace: trace["tool_calls"][0].pop("tool_name"), "requires one"),
        (
            lambda trace: trace["tool_calls"][0].update({"tool": "different_tool"}),
            "conflicting tool names",
        ),
        (lambda trace: trace["events"][0].update({"policy": 1}), "policy"),
    ],
)
def test_trace_parser_rejects_malformed_minimized_metadata(mutate: object, message: str) -> None:
    trace = _document(REVIEW_TRACE)
    assert callable(mutate)
    mutate(trace)

    with pytest.raises(ValidationError, match=message):
        parse_trace(trace)


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


def test_an_observed_call_requiring_approval_is_reported() -> None:
    """The human-approval decision had no test and no fixture.

    Both shipped traces exercised only allow and deny, so deleting the
    require_approval branch left the suite green while trace-review stopped
    reporting the one decision that exists to put a person in the loop.
    """

    manifest = parse_manifest(load_document(ROOT / "examples" / "support-agent.manifest.json"))
    policy = parse_policy(load_document(ROOT / "policies" / "default-policy.json"))
    trace = load_document(ROOT / "examples" / "traces" / "approval-required-support-trace.json")

    review = review_trace(manifest, policy, trace, "2026-01-01T00:00:00Z")

    observations = review["observations"]
    assert [observation["decision"] for observation in observations] == ["require_approval"]
    assert [observation["rule_id"] for observation in observations] == ["TW-002"]
    assert [finding["id"] for finding in review["findings"]] == ["TW-TRACE-005"]
    assert int(review["summary"]["review_findings"]) == 1


def test_the_approval_trace_exits_non_zero_under_exit_on_review(tmp_path: Path) -> None:
    """A decision that needs a person must not be reportable as a clean run."""

    arguments = [
        "trace-review",
        "--manifest",
        str(ROOT / "examples" / "support-agent.manifest.json"),
        "--policy",
        str(ROOT / "policies" / "default-policy.json"),
        "--trace",
        str(ROOT / "examples" / "traces" / "approval-required-support-trace.json"),
        "--output-dir",
        str(tmp_path),
        "--exit-on-review",
    ]

    assert main(arguments) == 1
