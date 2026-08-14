"""Offline review of local trace metadata against a TrustWeave manifest and policy."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from trustweave.engine import evaluate_flow
from trustweave.models import AgentManifest, Flow, Policy, ValidationError, reject_unknown_fields
from trustweave.provenance import add_generated_at
from trustweave.rules import finding_for_rule

TRACE_SCHEMA_VERSION = "trustweave.dev/trace/v1alpha1"
TRACE_REVIEW_SCHEMA_VERSION = "trustweave.dev/trace-review/v1alpha1"


@dataclass(frozen=True)
class ObservedToolCall:
    """A minimized local observation used for deterministic review only."""

    index: int
    source: str
    tool: str


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{path} must be a list")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _tool_name(call: Mapping[str, Any], path: str) -> str:
    values = [
        _text(call[key], f"{path}.{key}") for key in ("name", "tool", "tool_name") if key in call
    ]
    if not values:
        raise ValidationError(f"{path} requires one of name, tool, or tool_name")
    if len(set(values)) > 1:
        raise ValidationError(f"{path} contains conflicting tool names")
    return values[0]


def _finding(identifier: str, message: str, call: ObservedToolCall) -> dict[str, Any]:
    """Build a canonical finding from minimized local trace metadata only."""

    return finding_for_rule(
        identifier,
        "review",
        message,
        subject={"source": call.source, "tool": call.tool},
        properties={"call_index": str(call.index)},
    )


def parse_trace(
    document: Mapping[str, Any],
) -> tuple[tuple[ObservedToolCall, ...], int, tuple[str, ...]]:
    """Validate a local trace shape without inspecting message content or tool arguments."""

    root = _mapping(document, "trace")
    reject_unknown_fields(root, {"schema_version", "messages", "tool_calls", "events"}, "trace")
    if root.get("schema_version") != TRACE_SCHEMA_VERSION:
        raise ValidationError(f"trace.schema_version must be {TRACE_SCHEMA_VERSION}")
    messages = _sequence(root.get("messages"), "trace.messages")
    tool_calls = _sequence(root.get("tool_calls"), "trace.tool_calls")
    events = _sequence(root.get("events"), "trace.events")

    for index, raw_message in enumerate(messages):
        message = _mapping(raw_message, f"trace.messages[{index}]")
        reject_unknown_fields(message, {"role", "content"}, f"trace.messages[{index}]")
        _text(message.get("role"), f"trace.messages[{index}].role")
        if not isinstance(message.get("content"), str):
            raise ValidationError(f"trace.messages[{index}].content must be a string")

    calls: list[ObservedToolCall] = []
    for index, raw_call in enumerate(tool_calls):
        call = _mapping(raw_call, f"trace.tool_calls[{index}]")
        reject_unknown_fields(
            call,
            {"source", "name", "tool", "tool_name", "arguments"},
            f"trace.tool_calls[{index}]",
        )
        arguments = call.get("arguments")
        if arguments is not None and not isinstance(arguments, Mapping):
            raise ValidationError(f"trace.tool_calls[{index}].arguments must be an object")
        calls.append(
            ObservedToolCall(
                index=index,
                source=_text(call.get("source"), f"trace.tool_calls[{index}].source"),
                tool=_tool_name(call, f"trace.tool_calls[{index}]"),
            )
        )

    event_types: list[str] = []
    for index, raw_event in enumerate(events):
        event = _mapping(raw_event, f"trace.events[{index}]")
        reject_unknown_fields(event, {"type", "policy"}, f"trace.events[{index}]")
        event_types.append(_text(event.get("type"), f"trace.events[{index}].type"))
        if "policy" in event:
            _text(event["policy"], f"trace.events[{index}].policy")

    return tuple(calls), len(messages), tuple(event_types)


def review_trace(
    manifest: AgentManifest,
    policy: Policy,
    trace: Mapping[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Review local metadata with optional application-layer provenance."""

    calls, message_count, event_types = parse_trace(trace)
    sources = {source.name: source for source in manifest.sources}
    tools = {tool.name: tool for tool in manifest.tools}
    flows_by_pair: dict[tuple[str, str], Flow] = {}
    for flow in manifest.flows:
        flows_by_pair.setdefault((flow.source, flow.tool), flow)

    observations: list[dict[str, Any]] = []
    findings: list[dict[str, str | int]] = []
    for call in calls:
        observation: dict[str, Any] = {
            "index": call.index,
            "source": call.source,
            "tool": call.tool,
        }
        source = sources.get(call.source)
        tool = tools.get(call.tool)
        if source is None:
            observation["status"] = "review_required"
            findings.append(
                _finding(
                    "TW-TRACE-001",
                    f"Observed call references undeclared source {call.source}.",
                    call,
                )
            )
        elif tool is None:
            observation["status"] = "review_required"
            findings.append(
                _finding(
                    "TW-TRACE-002",
                    f"Observed call references undeclared tool {call.tool}.",
                    call,
                )
            )
        else:
            declared_flow = flows_by_pair.get((call.source, call.tool))
            if declared_flow is None:
                observation["status"] = "review_required"
                observation["action_class"] = tool.action_class
                findings.append(
                    _finding(
                        "TW-TRACE-003",
                        (
                            f"Observed call from {call.source} to {call.tool} is not a declared "
                            "manifest flow."
                        ),
                        call,
                    )
                )
            else:
                decision = evaluate_flow(declared_flow, source, tool, policy)
                observation.update(
                    {
                        "status": "review_required" if decision.decision != "allow" else "clear",
                        "action_class": tool.action_class,
                        "decision": decision.decision,
                        "rule_id": decision.rule_id,
                    }
                )
                if decision.decision == "deny":
                    findings.append(
                        _finding(
                            "TW-TRACE-004",
                            (
                                f"Observed call from {call.source} to {call.tool} matches a policy "
                                "decision of deny."
                            ),
                            call,
                        )
                    )
                elif decision.decision == "require_approval":
                    findings.append(
                        _finding(
                            "TW-TRACE-005",
                            (
                                f"Observed call from {call.source} to {call.tool} requires "
                                "approval under the declared policy."
                            ),
                            call,
                        )
                    )
        observations.append(observation)

    untrusted_context_count = sum(
        event_type == "untrusted_context_received" for event_type in event_types
    )
    review: dict[str, object] = {
        "schema_version": TRACE_REVIEW_SCHEMA_VERSION,
        "agent": manifest.name,
        "policy": policy.name,
        "summary": {
            "messages_observed": message_count,
            "tool_calls_observed": len(calls),
            "untrusted_context_events": untrusted_context_count,
            "review_findings": len(findings),
            "status": "review_required" if findings else "clear",
        },
        "observations": observations,
        "findings": findings,
        "limits": [
            (
                "The trace review reads local structured metadata only. It does not execute a "
                "target, tool, adapter, model, or network request."
            ),
            (
                "Message content and tool arguments are intentionally not inspected, copied, or "
                "emitted in review artifacts to reduce privacy and secret-exposure risk."
            ),
            (
                "A review finding identifies a mismatch between local evidence and declared "
                "architecture or policy; it is not a vulnerability verdict or incident conclusion."
            ),
        ],
    }
    return add_generated_at(review, generated_at)
