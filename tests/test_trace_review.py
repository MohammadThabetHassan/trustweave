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


def _near_miss_manifest(classification: str) -> dict[str, object]:
    """The audit's own probe: one untrusted source whose classification differs only in case."""

    return {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "repro-agent",
        "description": "Reproduction probe for the trace-review classification guard gap.",
        "sources": [
            {
                "name": "scraped_page",
                "trust": "untrusted",
                "data_classification": classification,
                "description": "Untrusted scraped web page carrying restricted data.",
            }
        ],
        "tools": [
            {
                "name": "post_webhook",
                "action_class": "external",
                "capabilities": ["webhook.post"],
                "description": "Posts to an outbound webhook.",
            }
        ],
        "flows": [
            {
                "source": "scraped_page",
                "tool": "post_webhook",
                "purpose": "Exfiltration path that the policy is supposed to deny.",
            }
        ],
    }


def _near_miss_policy() -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/policy/v1alpha2",
        "name": "repro-boundary-policy",
        "default_decision": "allow",
        "classification_taxonomy": ["public", "internal", "confidential", "restricted"],
        "rules": [
            {
                "id": "TW-DENY-RESTRICTED",
                "description": "Deny untrusted restricted data reaching an external action.",
                "source_trust": ["untrusted"],
                "tool_action_classes": ["external"],
                "source_data_classifications": ["restricted"],
                "decision": "deny",
                "rationale": "Restricted data from an untrusted source must not leave.",
            }
        ],
    }


def _near_miss_trace() -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/trace/v1alpha1",
        "messages": [{"role": "user", "content": "omitted"}],
        "tool_calls": [{"name": "post_webhook", "source": "scraped_page", "arguments": {}}],
        "events": [],
    }


def test_a_classification_that_only_looks_like_the_policys_is_refused_not_reported_clear() -> None:
    """scan exits 2 on this pair; trace-review used to call the denied call an allow.

    review_trace never reached evaluate_manifest, so the manifest-level near-miss guard
    never ran. The audit's probe declares `Restricted` against a rule bound to
    `restricted`: the predicate stopped matching, evaluation fell through to
    `default_decision: allow`, and the review reported decision "allow", rule_id null,
    status "clear", zero findings, exit 0.
    """

    with pytest.raises(ValidationError, match="'Restricted' looks like 'restricted'"):
        review_trace(
            parse_manifest(_near_miss_manifest("Restricted")),
            parse_policy(_near_miss_policy()),
            _near_miss_trace(),
        )


def test_the_same_pair_spelled_exactly_is_reviewed_and_denied() -> None:
    """Pins the refusal direction: only the near miss is refused, not the working manifest."""

    review = review_trace(
        parse_manifest(_near_miss_manifest("restricted")),
        parse_policy(_near_miss_policy()),
        _near_miss_trace(),
    )

    observation = review["observations"][0]
    assert observation["decision"] == "deny"
    assert observation["rule_id"] == "TW-DENY-RESTRICTED"
    assert observation["status"] == "review_required"
    assert [finding["id"] for finding in review["findings"]] == ["TW-TRACE-004"]
    assert review["summary"]["status"] == "review_required"


def _duplicate_pair_manifest(flows: list[dict[str, object]]) -> dict[str, object]:
    """The audit's probe: one (source, tool) pair declared twice, once per purpose."""

    return {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "synthetic-customer-support-agent",
        "description": "A declarative demo whose external email action has two declared purposes.",
        "sources": [
            {
                "name": "customer_request",
                "trust": "trusted",
                "data_classification": "customer-provided",
                "description": "A direct support request from an authenticated customer.",
            }
        ],
        "tools": [
            {
                "name": "send_mock_email",
                "action_class": "external",
                "capabilities": ["email.send"],
                "description": "Writes a local mock email event only.",
            }
        ],
        "flows": flows,
    }


_SUPPORT_FLOW: dict[str, object] = {
    "source": "customer_request",
    "tool": "send_mock_email",
    "purpose": "Send a support reply.",
    "purpose_tags": ["support"],
}
_MARKETING_FLOW: dict[str, object] = {
    "source": "customer_request",
    "tool": "send_mock_email",
    "purpose": "Send a marketing blast.",
    "purpose_tags": ["marketing"],
}


def _duplicate_pair_policy() -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/policy/v1alpha2",
        "name": "dup-flow-probe-policy",
        "default_decision": "require_approval",
        "rules": [
            {
                "id": "TW-DENY-MARKETING",
                "description": "Deny marketing-purpose external actions.",
                "purpose_tags": ["marketing"],
                "tool_action_classes": ["external"],
                "source_trust": ["trusted", "conditional", "untrusted"],
                "decision": "deny",
                "rationale": "Marketing purpose must never reach an external action.",
            },
            {
                "id": "TW-ALLOW-SUPPORT",
                "description": "Allow trusted support-purpose external actions.",
                "source_trust": ["trusted"],
                "tool_action_classes": ["external"],
                "decision": "allow",
                "rationale": "Trusted support requests may use the external mock email action.",
            },
        ],
    }


def _duplicate_pair_trace() -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/trace/v1alpha1",
        "messages": [],
        "tool_calls": [{"source": "customer_request", "name": "send_mock_email"}],
        "events": [],
    }


def test_swapping_two_declared_flows_for_one_pair_does_not_change_the_verdict() -> None:
    """The review used to keep only the first flow per (source, tool) pair.

    With the allowing flow written first the audit's probe reviewed clear at exit 0; the
    identical manifest with the two flow entries swapped reported TW-TRACE-004 and
    rule_id TW-DENY-MARKETING. An observed call carries no purpose of its own, so both
    declared flows apply to it and the strictest verdict is the only order-independent
    answer. scan reports the discarded flow as a high-severity deny on the same manifest.
    """

    policy = parse_policy(_duplicate_pair_policy())
    trace = _duplicate_pair_trace()

    support_first = review_trace(
        parse_manifest(_duplicate_pair_manifest([_SUPPORT_FLOW, _MARKETING_FLOW])), policy, trace
    )
    marketing_first = review_trace(
        parse_manifest(_duplicate_pair_manifest([_MARKETING_FLOW, _SUPPORT_FLOW])), policy, trace
    )

    assert support_first["observations"] == marketing_first["observations"]
    assert support_first["summary"] == marketing_first["summary"]
    observation = support_first["observations"][0]
    assert observation["decision"] == "deny"
    assert observation["rule_id"] == "TW-DENY-MARKETING"
    assert observation["status"] == "review_required"
    assert [finding["id"] for finding in support_first["findings"]] == ["TW-TRACE-004"]


def test_a_pair_declared_once_still_reports_that_flows_own_decision() -> None:
    """Pins the refusal direction: the strictest-of-many rule must not invent a stricter one."""

    review = review_trace(
        parse_manifest(_duplicate_pair_manifest([_SUPPORT_FLOW])),
        parse_policy(_duplicate_pair_policy()),
        _duplicate_pair_trace(),
    )

    observation = review["observations"][0]
    assert observation["decision"] == "allow"
    assert observation["rule_id"] == "TW-ALLOW-SUPPORT"
    assert observation["status"] == "clear"
    assert review["findings"] == []
