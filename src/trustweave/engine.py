"""Deterministic bundle construction and flow-policy evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from trustweave.models import AgentManifest, Flow, Policy, PolicyRule, Source, Tool


@dataclass(frozen=True)
class Finding:
    """A reviewable policy decision for one declared source-to-tool path."""

    flow: Flow
    source: Source
    tool: Tool
    decision: str
    rule_id: str | None
    rationale: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "flow": self.flow.as_dict(),
            "source": self.source.as_dict(),
            "tool": self.tool.as_dict(),
            "decision": self.decision,
            "rule_id": self.rule_id,
            "rationale": self.rationale,
        }


def evaluate_flow(flow: Flow, source: Source, tool: Tool, policy: Policy) -> Finding:
    """Apply the first matching deterministic rule to a declared flow."""

    for rule in policy.rules:
        if source.trust in rule.source_trust and tool.action_class in rule.tool_action_classes:
            return Finding(
                flow=flow,
                source=source,
                tool=tool,
                decision=rule.decision,
                rule_id=rule.id,
                rationale=rule.rationale,
            )
    return Finding(
        flow=flow,
        source=source,
        tool=tool,
        decision=policy.default_decision,
        rule_id=None,
        rationale="No policy rule matched this declared path; the default decision was applied.",
    )


def evaluate_manifest(manifest: AgentManifest, policy: Policy) -> tuple[Finding, ...]:
    """Evaluate every declared path in a manifest without executing the agent or tools."""

    source_by_name = {source.name: source for source in manifest.sources}
    tool_by_name = {tool.name: tool for tool in manifest.tools}
    return tuple(
        evaluate_flow(flow, source_by_name[flow.source], tool_by_name[flow.tool], policy)
        for flow in manifest.flows
    )


def build_bundle(manifest: AgentManifest, policy: Policy) -> dict[str, Any]:
    """Construct a portable, deterministic Agent Security Bundle document."""

    findings = evaluate_manifest(manifest, policy)
    summary = {decision: 0 for decision in ("allow", "deny", "require_approval")}
    for finding in findings:
        summary[finding.decision] += 1

    return {
        "schema_version": "trustweave.dev/bundle/v1alpha1",
        "generated_at": datetime.now(UTC).isoformat(),
        "manifest": manifest.as_dict(),
        "policy": {
            "schema_version": policy.schema_version,
            "name": policy.name,
            "default_decision": policy.default_decision,
            "rules": [asdict(rule) for rule in policy.rules],
        },
        "findings": [finding.as_dict() for finding in findings],
        "summary": summary,
        "limits": [
            (
                "The bundle reflects declared architecture only; it does not discover or "
                "execute tools."
            ),
            (
                "The bundle applies deterministic local rules; it does not establish "
                "security of a deployed system."
            ),
            (
                "No model output, credential, network traffic, or external system was "
                "analyzed to create this bundle."
            ),
        ],
    }


def matching_rule(policy: Policy, source_trust: str, action_class: str) -> PolicyRule | None:
    """Return the first policy rule that matches a synthetic scenario input."""

    for rule in policy.rules:
        if source_trust in rule.source_trust and action_class in rule.tool_action_classes:
            return rule
    return None


def decision_for_labels(
    policy: Policy, source_trust: str, action_class: str
) -> tuple[str, str | None]:
    """Return decision and optional rule identifier for a synthetic scenario."""

    rule = matching_rule(policy, source_trust, action_class)
    if rule is None:
        return policy.default_decision, None
    return rule.decision, rule.id
