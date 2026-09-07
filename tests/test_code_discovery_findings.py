"""Assertion strength for the findings a discovery review emits.

The existing suite checks which rule ids appear. It does not check the severity, the
subject, the location, the properties, or the reason arithmetic that decides which rule
fires — so a change that lowercased a rule id, flipped a severity, dropped a line number or
inverted a reason test passed the suite. Mutation testing put the kill rate on this module
at 53%.

These are the fields a reviewer acts on: the id tells them which rule, the subject tells
them which tool, the location tells them where to look, and the properties carry the
specifics. Each is asserted exactly.
"""

from __future__ import annotations

from typing import Any

from trustweave.code_analysis import DiscoveredTool, EffectSignal
from trustweave.code_discovery import _findings


def _tool(
    name: str = "probe",
    *,
    reasons: set[str] | None = None,
    signals: list[EffectSignal] | None = None,
    line: int = 12,
) -> DiscoveredTool:
    return DiscoveredTool(
        name,
        "langchain_tool_decorator",
        "tools/probe.py",
        line,
        signals=list(signals or []),
        reasons=set(reasons or ()),
    )


def _by_id(findings: list[dict[str, Any]], rule: str) -> dict[str, Any]:
    matching = [finding for finding in findings if finding["id"] == rule]
    assert len(matching) == 1, f"expected exactly one {rule}, got {[f['id'] for f in findings]}"
    return matching[0]


def _empty_drift() -> dict[str, Any]:
    return {"missing_from_manifest": [], "declared_not_found_in_code": []}


# ---------------------------------------------------------------------------------------
# Every rule reports where to look and what it is about
# ---------------------------------------------------------------------------------------


def test_a_missing_body_reports_the_tool_and_its_location() -> None:
    findings = _findings([_tool(reasons={"BODY_UNAVAILABLE"})], [], _empty_drift(), None)

    finding = _by_id(findings, "TW-CODE-001")

    assert finding["severity"] == "review"
    assert finding["subject"] == {"tool": "probe", "file": "tools/probe.py"}
    assert finding["location"] == {"file": "tools/probe.py", "line": "12"}
    assert "probe" in finding["message"]


def test_an_exhausted_budget_reports_the_tool_and_its_location() -> None:
    findings = _findings([_tool(reasons={"BUDGET_EXHAUSTED"})], [], _empty_drift(), None)

    finding = _by_id(findings, "TW-CODE-006")

    assert finding["severity"] == "review"
    assert finding["subject"] == {"tool": "probe", "file": "tools/probe.py"}
    assert finding["location"] == {"file": "tools/probe.py", "line": "12"}


def test_a_refusal_reports_which_reasons_caused_it() -> None:
    """The reason codes are the work list; a finding without them says only 'look again'."""

    findings = _findings(
        [_tool(reasons={"DYNAMIC_DISPATCH", "NONLITERAL_ARGUMENT"})], [], _empty_drift(), None
    )

    finding = _by_id(findings, "TW-CODE-005")

    assert finding["severity"] == "review"
    assert finding["properties"]["reasons"] == ["DYNAMIC_DISPATCH", "NONLITERAL_ARGUMENT"]
    assert finding["location"] == {"file": "tools/probe.py", "line": "12"}


def test_the_line_number_is_the_tool_s_own_line() -> None:
    """A location pinned to the wrong line sends a reviewer to the wrong code."""

    findings = _findings([_tool(reasons={"BODY_UNAVAILABLE"}, line=97)], [], _empty_drift(), None)

    assert _by_id(findings, "TW-CODE-001")["location"]["line"] == "97"


# ---------------------------------------------------------------------------------------
# Which rule fires is arithmetic on the reason set
# ---------------------------------------------------------------------------------------


def test_a_body_unavailable_reason_alone_does_not_also_raise_a_refusal() -> None:
    """It is excluded from the refusal set on purpose; reporting both double-counts it."""

    findings = _findings([_tool(reasons={"BODY_UNAVAILABLE"})], [], _empty_drift(), None)

    assert [finding["id"] for finding in findings] == ["TW-CODE-001"]


def test_an_exhausted_budget_alone_does_not_also_raise_a_refusal() -> None:
    findings = _findings([_tool(reasons={"BUDGET_EXHAUSTED"})], [], _empty_drift(), None)

    assert [finding["id"] for finding in findings] == ["TW-CODE-006"]


def test_a_tool_with_no_reasons_raises_nothing() -> None:
    assert _findings([_tool()], [], _empty_drift(), None) == []


def test_a_refusal_beside_a_missing_body_raises_both_rules() -> None:
    findings = _findings(
        [_tool(reasons={"BODY_UNAVAILABLE", "DYNAMIC_DISPATCH"})], [], _empty_drift(), None
    )

    assert sorted(finding["id"] for finding in findings) == ["TW-CODE-001", "TW-CODE-005"]
    assert _by_id(findings, "TW-CODE-005")["properties"]["reasons"] == ["DYNAMIC_DISPATCH"]


# ---------------------------------------------------------------------------------------
# Drift and parse failures name their subject
# ---------------------------------------------------------------------------------------


def test_a_tool_found_but_not_declared_names_that_tool() -> None:
    drift = {"missing_from_manifest": ["run_maintenance"], "declared_not_found_in_code": []}

    finding = _by_id(_findings([], [], drift, None), "TW-CODE-003")

    assert finding["severity"] == "review"
    assert finding["subject"] == {"tool": "run_maintenance"}
    assert "run_maintenance" in finding["message"]


def test_a_declared_tool_not_found_names_that_tool() -> None:
    drift = {"missing_from_manifest": [], "declared_not_found_in_code": ["send_receipt"]}

    finding = _by_id(_findings([], [], drift, None), "TW-CODE-004")

    assert finding["severity"] == "review"
    assert finding["subject"] == {"tool": "send_receipt"}


def test_a_file_that_could_not_be_analyzed_names_the_file_and_the_reason() -> None:
    problems = [{"file": "broken.py", "reason": "syntax_error_line_3"}]

    finding = _by_id(_findings([], problems, _empty_drift(), None), "TW-CODE-008")

    assert finding["severity"] == "review"
    assert finding["subject"] == {"file": "broken.py"}
    assert finding["properties"]["reason"] == "syntax_error_line_3"


def test_each_drifted_tool_gets_its_own_finding() -> None:
    """A loop turned into a single pass would under-report the drift."""

    drift = {"missing_from_manifest": ["one", "two"], "declared_not_found_in_code": ["three"]}

    findings = _findings([], [], drift, None)

    assert [finding["id"] for finding in findings] == [
        "TW-CODE-003",
        "TW-CODE-003",
        "TW-CODE-004",
    ]
    assert {finding["subject"]["tool"] for finding in findings} == {"one", "two", "three"}


# ---------------------------------------------------------------------------------------
# Ordering is part of the artifact contract
# ---------------------------------------------------------------------------------------


def test_findings_are_ordered_by_rule_then_message() -> None:
    """Two runs over the same tree must produce byte-identical artifacts."""

    drift = {"missing_from_manifest": ["zulu", "alpha"], "declared_not_found_in_code": []}

    findings = _findings(
        [_tool("probe", reasons={"BODY_UNAVAILABLE"})],
        [{"file": "broken.py", "reason": "syntax_error_line_1"}],
        drift,
        None,
    )
    keys = [(finding["id"], finding["message"]) for finding in findings]

    assert keys == sorted(keys)
    assert [finding["id"] for finding in findings] == [
        "TW-CODE-001",
        "TW-CODE-003",
        "TW-CODE-003",
        "TW-CODE-008",
    ]


# ---------------------------------------------------------------------------------------
# The refusal message says, in words, why no class was proposed
# ---------------------------------------------------------------------------------------


def test_a_refusal_message_spells_out_each_reason_in_words() -> None:
    """The reason codes are for tooling; this sentence is what a reviewer reads."""

    findings = _findings(
        [_tool(reasons={"DYNAMIC_DISPATCH", "LEXICAL_ONLY"})], [], _empty_drift(), None
    )

    message = _by_id(findings, "TW-CODE-005")["message"]

    assert "the implementation selects behaviour dynamically" in message
    assert "only naming evidence was present, with no observed behaviour" in message
    assert "; " in message, "several reasons are joined into one sentence"


def test_an_unmapped_reason_falls_back_to_its_code_rather_than_vanishing() -> None:
    """A reason with no prose must still appear, or the finding explains nothing."""

    findings = _findings([_tool(reasons={"SOME_NEW_REASON"})], [], _empty_drift(), None)

    finding = _by_id(findings, "TW-CODE-005")

    assert "SOME_NEW_REASON" in finding["message"]
    assert finding["properties"]["reasons"] == ["SOME_NEW_REASON"]
