"""Deterministic bundle construction and flow-policy evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from trustweave.models import AgentManifest, Flow, Policy, PolicyRule, Source, Tool
from trustweave.provenance import add_generated_at


@dataclass(frozen=True)
class Finding:
    """A reviewable policy decision for one declared source-to-tool path."""

    flow: Flow
    source: Source
    tool: Tool
    decision: str
    severity: str
    rule_id: str | None
    rationale: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "flow": self.flow.as_dict(),
            "source": self.source.as_dict(),
            "tool": self.tool.as_dict(),
            "decision": self.decision,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "rationale": self.rationale,
        }


def _default_severity(decision: str) -> str:
    return {"deny": "high", "require_approval": "medium", "allow": "info"}[decision]


def capability_matches(pattern: str, capability: str) -> bool:
    """Match an exact capability or one validated final namespace wildcard."""

    if pattern.endswith(".*"):
        return capability.startswith(pattern[:-1])
    return capability == pattern


def capability_pattern_covers(first: str, later: str) -> bool:
    """Return only proven capability-pattern subsumption relationships."""

    if first == later:
        return True
    if not first.endswith(".*"):
        return False
    prefix = first[:-1]
    return later.startswith(prefix)


def _classification_matches(rule: PolicyRule, source: Source, policy: Policy) -> bool:
    """Evaluate bounded taxonomy comparisons; unknown classifications never satisfy a bound."""

    if (
        rule.source_data_classification_at_least is None
        and rule.source_data_classification_at_most is None
    ):
        return True
    if source.data_classification not in policy.classification_taxonomy:
        return False
    rank = policy.classification_taxonomy.index(source.data_classification)
    if (
        rule.source_data_classification_at_least is not None
        and rank < policy.classification_taxonomy.index(rule.source_data_classification_at_least)
    ):
        return False
    return (
        rule.source_data_classification_at_most is None
        or rank <= policy.classification_taxonomy.index(rule.source_data_classification_at_most)
    )


def _declared_controls(policy: Policy) -> frozenset[str]:
    """Expose only design-time control declarations, never runtime enforcement state."""

    controls: set[str] = set()
    if policy.approval_control is not None:
        controls.add("approval")
        if policy.approval_control.fail_closed:
            controls.add("approval.fail_closed")
    return frozenset(controls)


def _rule_matches(
    rule: PolicyRule,
    source: Source,
    tool: Tool,
    policy: Policy,
    flow: Flow | None = None,
) -> bool:
    if source.trust not in rule.source_trust or tool.action_class not in rule.tool_action_classes:
        return False
    if (
        rule.source_data_classifications
        and source.data_classification not in rule.source_data_classifications
    ):
        return False
    if rule.source_identifiers and source.name not in rule.source_identifiers:
        return False
    if rule.tool_identifiers and tool.name not in rule.tool_identifiers:
        return False
    if rule.purpose_tags and (
        flow is None or not set(rule.purpose_tags).intersection(flow.purpose_tags)
    ):
        return False
    if not _classification_matches(rule, source, policy):
        return False
    if rule.required_controls and not set(rule.required_controls).issubset(
        _declared_controls(policy)
    ):
        return False
    return not rule.tool_capabilities or any(
        capability_matches(pattern, capability)
        for pattern in rule.tool_capabilities
        for capability in tool.capabilities
    )


def evaluate_flow(flow: Flow, source: Source, tool: Tool, policy: Policy) -> Finding:
    """Apply the first matching declarative rule to one declared flow."""

    for rule in policy.rules:
        if _rule_matches(rule, source, tool, policy, flow):
            return Finding(
                flow=flow,
                source=source,
                tool=tool,
                decision=rule.decision,
                severity=rule.severity or _default_severity(rule.decision),
                rule_id=rule.id,
                rationale=rule.rationale,
            )
    return Finding(
        flow=flow,
        source=source,
        tool=tool,
        decision=policy.default_decision,
        severity=_default_severity(policy.default_decision),
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


def build_bundle(
    manifest: AgentManifest, policy: Policy, generated_at: str | None = None
) -> dict[str, Any]:
    """Construct a portable bundle from stable declarations and optional provenance."""

    findings = evaluate_manifest(manifest, policy)
    summary = {decision: 0 for decision in ("allow", "deny", "require_approval")}
    for finding in findings:
        summary[finding.decision] += 1

    bundle: dict[str, object] = {
        "schema_version": "trustweave.dev/bundle/v1alpha1",
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
    return add_generated_at(bundle, generated_at)


def matching_rule(
    policy: Policy,
    source_trust: str,
    action_class: str,
    source_data_classification: str | None = None,
    tool_capabilities: tuple[str, ...] = (),
    source_identifier: str = "synthetic-source",
    tool_identifier: str = "synthetic-tool",
    purpose: str = "synthetic",
) -> PolicyRule | None:
    """Return the first rule that matches a synthetic input using manifest-equivalent semantics."""

    source = Source(
        name=source_identifier,
        trust=source_trust,
        data_classification=source_data_classification or "unspecified",
        description="Synthetic policy scenario input.",
    )
    tool = Tool(
        name=tool_identifier,
        action_class=action_class,
        capabilities=tool_capabilities,
        description="Synthetic policy scenario input.",
    )
    flow = Flow(source=source.name, tool=tool.name, purpose=purpose, purpose_tags=(purpose,))
    return next(
        (rule for rule in policy.rules if _rule_matches(rule, source, tool, policy, flow)), None
    )


def decision_for_scenario(
    policy: Policy,
    source_trust: str,
    action_class: str,
    source_data_classification: str | None = None,
    tool_capabilities: tuple[str, ...] = (),
    source_identifier: str = "synthetic-source",
    tool_identifier: str = "synthetic-tool",
    purpose: str = "synthetic",
) -> tuple[str, str | None]:
    """Return a synthetic decision using the same matcher as declared manifest flows."""

    rule = matching_rule(
        policy,
        source_trust,
        action_class,
        source_data_classification,
        tool_capabilities,
        source_identifier,
        tool_identifier,
        purpose,
    )
    if rule is None:
        return policy.default_decision, None
    return rule.decision, rule.id


def explain_policy_decision(
    policy: Policy,
    source_trust: str,
    action_class: str,
    source_data_classification: str | None = None,
    tool_capabilities: tuple[str, ...] = (),
    source_identifier: str = "synthetic-source",
    tool_identifier: str = "synthetic-tool",
    purpose: str = "synthetic",
) -> dict[str, Any]:
    """Explain first-match evaluation over supplied synthetic labels and declared metadata."""

    source = Source(
        name=source_identifier,
        trust=source_trust,
        data_classification=source_data_classification or "unspecified",
        description="Synthetic explanation input.",
    )
    tool = Tool(
        name=tool_identifier,
        action_class=action_class,
        capabilities=tool_capabilities,
        description="Synthetic explanation input.",
    )
    flow = Flow(source=source.name, tool=tool.name, purpose=purpose, purpose_tags=(purpose,))
    checked_rules = [
        {"id": rule.id, "matched": _rule_matches(rule, source, tool, policy, flow)}
        for rule in policy.rules
    ]
    matched_rule = next(
        (
            rule
            for rule, checked in zip(policy.rules, checked_rules, strict=True)
            if checked["matched"]
        ),
        None,
    )
    decision = matched_rule.decision if matched_rule is not None else policy.default_decision
    rationale = (
        matched_rule.rationale
        if matched_rule is not None
        else "No policy rule matched this supplied local input; the default decision was applied."
    )
    return {
        "schema_version": "trustweave.dev/policy-explanation/v1alpha1",
        "policy": policy.name,
        "input": {
            "source_trust": source.trust,
            "source_data_classification": source.data_classification,
            "source_identifier": source.name,
            "tool_action_class": tool.action_class,
            "tool_capabilities": list(tool.capabilities),
            "tool_identifier": tool.name,
            "purpose_tag": flow.purpose,
        },
        "checked_rules": checked_rules,
        "decision": decision,
        "rule_id": matched_rule.id if matched_rule is not None else None,
        "rationale": rationale,
        "limits": [
            (
                "The explanation applies only to supplied synthetic labels and declared local "
                "policy metadata; it does not inspect or enforce a deployed runtime."
            )
        ],
    }


def decision_for_labels(
    policy: Policy, source_trust: str, action_class: str
) -> tuple[str, str | None]:
    """Preserve the legacy label-only synthetic decision API."""

    return decision_for_scenario(policy, source_trust, action_class)
