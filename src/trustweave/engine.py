"""Deterministic bundle construction and flow-policy evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from difflib import get_close_matches
from typing import Any

from trustweave.bundles import BUNDLE_SCHEMA_V1ALPHA2
from trustweave.models import AgentManifest, Flow, Policy, PolicyRule, Source, Tool, ValidationError
from trustweave.policy_predicates import (
    PolicySubject,
    checks_for_rule,
    declared_controls,
    rule_matches,
)
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


def _policy_subject(
    source: Source, tool: Tool, policy: Policy, flow: Flow | None = None
) -> PolicySubject:
    """Create the exact declared predicate subject used by every evaluation entry point."""

    return PolicySubject(
        source_trust=source.trust,
        tool_action_class=tool.action_class,
        source_data_classification=source.data_classification,
        source_identifier=source.name,
        tool_identifier=tool.name,
        purpose_tags=flow.purpose_tags if flow is not None else (),
        tool_capabilities=tool.capabilities,
        declared_controls=declared_controls(policy),
    )


def _rule_match_checks(
    rule: PolicyRule,
    source: Source,
    tool: Tool,
    policy: Policy,
    flow: Flow | None = None,
) -> dict[str, dict[str, Any]]:
    """Return deterministic local evidence from the shared predicate model."""

    return checks_for_rule(rule, _policy_subject(source, tool, policy, flow), policy)


def _rule_matches(
    rule: PolicyRule,
    source: Source,
    tool: Tool,
    policy: Policy,
    flow: Flow | None = None,
) -> bool:
    """Return whether every declared predicate matches local inputs."""

    return rule_matches(rule, _policy_subject(source, tool, policy, flow), policy)


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


def _reject_near_miss_classifications(manifest: AgentManifest, policy: Policy) -> None:
    """Refuse a classification that looks like a misspelling of one the policy knows.

    Classification predicates compare exact strings, so `Restricted` silently fails to
    match a rule bound to `restricted`: the rule stops applying, evaluation falls through
    to the default decision, and a deny becomes an allow with no error and no warning.

    Only near misses are refused. A value that is plainly different vocabulary, such as
    `customer-provided`, is descriptive metadata a policy may simply not bind to, and
    rejecting it would refuse working configurations.
    """

    constrains_classification = any(
        rule.source_data_classifications
        or rule.source_data_classification_at_least is not None
        or rule.source_data_classification_at_most is not None
        for rule in policy.rules
    )
    if not constrains_classification:
        return

    taxonomy = policy.classification_taxonomy
    folded = {value.casefold(): value for value in taxonomy}
    suspect: list[tuple[str, str]] = []
    for source in manifest.sources:
        declared = source.data_classification
        if declared in taxonomy:
            continue
        match = folded.get(declared.casefold().strip())
        if match is None:
            close = get_close_matches(declared.casefold(), list(folded), n=1, cutoff=0.85)
            match = folded[close[0]] if close else None
        if match is not None:
            suspect.append((declared, match))

    if suspect:
        listed = "; ".join(f"{declared!r} looks like {match!r}" for declared, match in suspect)
        raise ValidationError(
            f"manifest declares data classifications the policy will not match: {listed}. "
            "Classification predicates compare exact strings, so this would silently fall "
            "through to the default decision. Correct the manifest, or declare the value "
            "in the policy's classification_taxonomy."
        )


def evaluate_manifest(manifest: AgentManifest, policy: Policy) -> tuple[Finding, ...]:
    """Evaluate every declared path in a manifest without executing the agent or tools."""

    _reject_near_miss_classifications(manifest, policy)
    source_by_name = {source.name: source for source in manifest.sources}
    tool_by_name = {tool.name: tool for tool in manifest.tools}
    return tuple(
        evaluate_flow(flow, source_by_name[flow.source], tool_by_name[flow.tool], policy)
        for flow in manifest.flows
    )


def expected_finding_dicts(manifest: AgentManifest, policy: Policy) -> tuple[dict[str, Any], ...]:
    """Render the authoritative normalized current finding collection for supplied declarations.

    Both bundle construction and current-bundle validation use this pure oracle.  Keeping
    first-match evaluation in one place prevents a validly shaped but fabricated finding
    collection from being accepted as local evidence.
    """

    return tuple(finding.as_dict() for finding in evaluate_manifest(manifest, policy))


def _bundle_rule(rule: PolicyRule) -> dict[str, Any]:
    """Render a policy rule as JSON-compatible local bundle evidence."""

    rendered = asdict(rule)
    return {
        key: list(value) if isinstance(value, tuple) else value for key, value in rendered.items()
    }


def build_bundle(
    manifest: AgentManifest, policy: Policy, generated_at: str | None = None
) -> dict[str, Any]:
    """Construct a portable bundle from stable declarations and optional provenance."""

    findings = expected_finding_dicts(manifest, policy)
    summary = {decision: 0 for decision in ("allow", "deny", "require_approval")}
    for finding in findings:
        summary[str(finding["decision"])] += 1

    bundle: dict[str, object] = {
        "schema_version": BUNDLE_SCHEMA_V1ALPHA2,
        "manifest": manifest.as_dict(),
        "policy": {
            "schema_version": policy.schema_version,
            "name": policy.name,
            "default_decision": policy.default_decision,
            "classification_taxonomy": list(policy.classification_taxonomy),
            "approval_control": (
                {
                    "mechanism": policy.approval_control.mechanism,
                    "binds_to": list(policy.approval_control.binds_to),
                    "fail_closed": policy.approval_control.fail_closed,
                }
                if policy.approval_control is not None
                else None
            ),
            "rules": [_bundle_rule(rule) for rule in policy.rules],
        },
        "findings": list(findings),
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
        {
            "id": rule.id,
            "matched": _rule_matches(rule, source, tool, policy, flow),
            "checks": _rule_match_checks(rule, source, tool, policy, flow),
        }
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
