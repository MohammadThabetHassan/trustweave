"""Regression tests for Markdown interpolation in the reviewer-facing renderers."""

from __future__ import annotations

from typing import Any

from trustweave.report import (
    render_diff_report,
    render_mcp_profile_review_report,
    render_policy_review_report,
    render_report,
    render_risk_review_report,
    render_trace_review_report,
)

# The audit's payload shape, minus the newlines an upstream validator now refuses: a
# value that closes its own table cell and then opens an HTML block over everything after
# it. The renderers read generated JSON back from disk, so they must survive it even
# where no validator saw the document.
_PAYLOAD = "support-agent | forged | <!--"


def _bundle(name: str) -> dict[str, Any]:
    return {
        "schema_version": "trustweave.dev/bundle/v1alpha2",
        "manifest": {"name": name},
        "summary": {"allow": 1, "require_approval": 1, "deny": 2},
        "findings": [
            {
                "source": {"name": "customer_request", "trust": "trusted"},
                "tool": {"name": "send_mock_email", "action_class": "external"},
                "decision": "deny",
                "rule_id": "TW-DENY-MARKETING",
            }
        ],
    }


def test_a_manifest_name_carrying_a_comment_opener_cannot_hide_the_decision_summary() -> None:
    """render_report used to emit the payload raw, commenting out the real path table.

    The audit reproduced a `## Decision summary` block that reported `Allow 9` over a
    bundle whose real summary was `Allow 1 / Require approval 1 / Deny 2`, because the
    trailing `<!--` swallowed the genuine rows that followed.
    """

    report = render_report(
        _bundle(_PAYLOAD),
        {"summary": {"total": 5, "passed": 5, "failed": 0, "status": "passed"}},
        {"integrity": {"chain_sha256": "0" * 64}},
    )

    assert "<!--" not in report
    assert "&lt;!--" in report
    assert "| Allow | 1 |" in report
    assert "| Require approval | 1 |" in report
    assert "| Deny | 2 |" in report
    assert "| customer_request | trusted | send_mock_email | external | **deny** |" in report


def test_a_pipe_in_a_declared_name_stays_inside_its_own_table_cell() -> None:
    """An unescaped pipe added a column, shifting every later value one cell to the left."""

    report = render_report(
        _bundle("support | agent"),
        {"summary": {"total": 1, "passed": 1, "failed": 0, "status": "passed"}},
        {"integrity": {"chain_sha256": "0" * 64}},
    )

    assert "**Agent:** `support \\| agent`" in report


def test_an_ordinary_bundle_renders_without_escaping_artifacts() -> None:
    """Pins the refusal direction: a clean declaration must render exactly as before."""

    report = render_report(
        _bundle("support-agent"),
        {"summary": {"total": 1, "passed": 1, "failed": 0, "status": "passed"}},
        {"integrity": {"chain_sha256": "0" * 64}},
    )

    assert "**Agent:** `support-agent`" in report
    assert "\\|" not in report
    assert "&lt;" not in report


def test_every_review_renderer_neutralises_a_comment_opener_in_a_declared_field() -> None:
    """Only render_report and the trace renderer were probed; the hole was in all seven."""

    rendered = [
        render_diff_report(
            {
                "base": {"agent": _PAYLOAD},
                "head": {"agent": _PAYLOAD},
                "summary": {},
                "changes": {},
                "signals": [{"severity": "high", "id": "TW-DIFF-001", "message": _PAYLOAD}],
            }
        ),
        render_policy_review_report(
            {
                "policy": _PAYLOAD,
                "summary": {"status": "review_required", "rules": 1, "review_findings": 1},
                "approval_control": {},
                "findings": [{"severity": "review", "id": "TW-POL-001", "message": _PAYLOAD}],
            }
        ),
        render_trace_review_report(
            {
                "agent": _PAYLOAD,
                "policy": _PAYLOAD,
                "summary": {"status": "review_required", "review_findings": 1},
                "observations": [
                    {"index": 0, "source": _PAYLOAD, "tool": _PAYLOAD, "status": "review_required"}
                ],
                "findings": [{"severity": "review", "id": "TW-TRACE-001", "message": _PAYLOAD}],
            }
        ),
        render_mcp_profile_review_report(
            {
                "profile": {"name": _PAYLOAD, "transport": "http"},
                "summary": {"status": "review_required", "tools_reviewed": 1},
                "mappings": [{"mcp_tool": _PAYLOAD, "manifest_tool": _PAYLOAD, "status": "clear"}],
                "findings": [{"severity": "review", "id": "TW-MCP-001", "message": _PAYLOAD}],
            }
        ),
        render_risk_review_report(
            {
                "summary": {"status": "review_required", "findings": 1},
                "findings": [
                    {
                        "risk_state": "new",
                        "severity": "high",
                        "id": "TW-CHAIN-001",
                        "message": _PAYLOAD,
                    }
                ],
            }
        ),
    ]

    for report in rendered:
        assert "<!--" not in report
        assert "&lt;!--" in report
        assert " | forged | " not in report
