"""Strict dependency-free validation for local TrustWeave bundle evidence."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from trustweave.models import (
    VALID_DECISIONS,
    VALID_SEVERITIES,
    AgentManifest,
    Policy,
    ValidationError,
    parse_manifest,
    parse_policy,
    reject_unknown_fields,
    validate_rule_identifier,
)

BUNDLE_SCHEMA_V1ALPHA1 = "trustweave.dev/bundle/v1alpha1"
BUNDLE_SCHEMA_V1ALPHA2 = "trustweave.dev/bundle/v1alpha2"
SUPPORTED_BUNDLE_SCHEMA_VERSIONS = frozenset({BUNDLE_SCHEMA_V1ALPHA1, BUNDLE_SCHEMA_V1ALPHA2})
MAX_BUNDLE_FINDINGS = 10_000
MAX_BUNDLE_LIMITS = 32


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


def _timestamp(value: Any, path: str) -> None:
    text = _text(value, path)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{path} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValidationError(f"{path} must include a UTC offset")


def _parse_bundle_policy(value: Any, path: str) -> Policy:
    """Parse the normalized policy payload rendered into a current local bundle."""

    rendered = dict(_mapping(value, path))
    schema_version = _text(rendered.get("schema_version"), f"{path}.schema_version")
    if schema_version == "trustweave.dev/v1alpha1":
        rendered["schema_version"] = "trustweave.dev/policy/v1alpha2"
    rules = rendered.get("rules")
    if isinstance(rules, Sequence) and not isinstance(rules, (str, bytes, bytearray)):
        rendered["rules"] = [
            {key: item for key, item in rule.items() if key != "severity" or item is not None}
            if isinstance(rule, Mapping)
            else rule
            for rule in rules
        ]
    return parse_policy(rendered)


def _validate_finding(
    raw: Any,
    path: str,
    manifest: AgentManifest,
    policy: Policy,
) -> str:
    finding = _mapping(raw, path)
    required = {"flow", "source", "tool", "decision", "severity", "rule_id", "rationale"}
    reject_unknown_fields(finding, required, path)
    missing = sorted(required - set(finding))
    if missing:
        raise ValidationError(f"{path} is missing required fields: {', '.join(missing)}")

    flow = _mapping(finding["flow"], f"{path}.flow")
    source = _mapping(finding["source"], f"{path}.source")
    tool = _mapping(finding["tool"], f"{path}.tool")
    reject_unknown_fields(flow, {"source", "tool", "purpose", "purpose_tags"}, f"{path}.flow")
    reject_unknown_fields(
        source,
        {"name", "trust", "data_classification", "description"},
        f"{path}.source",
    )
    reject_unknown_fields(
        tool,
        {"name", "action_class", "capabilities", "description"},
        f"{path}.tool",
    )

    source_name = _text(flow.get("source"), f"{path}.flow.source")
    tool_name = _text(flow.get("tool"), f"{path}.flow.tool")
    purpose = _text(flow.get("purpose"), f"{path}.flow.purpose")
    purpose_tags = _sequence(flow.get("purpose_tags"), f"{path}.flow.purpose_tags")
    if not all(isinstance(tag, str) and tag.strip() for tag in purpose_tags):
        raise ValidationError(f"{path}.flow.purpose_tags must contain non-empty strings")

    source_by_name = {item.name: item for item in manifest.sources}
    tool_by_name = {item.name: item for item in manifest.tools}
    declared_source = source_by_name.get(source_name)
    declared_tool = tool_by_name.get(tool_name)
    if declared_source is None or declared_tool is None:
        raise ValidationError(f"{path}.flow must reference declared manifest source and tool")
    if source != declared_source.as_dict() or tool != declared_tool.as_dict():
        raise ValidationError(f"{path} source and tool must match referenced manifest declarations")
    if not any(
        item.source == source_name
        and item.tool == tool_name
        and item.purpose == purpose
        and tuple(purpose_tags) == item.purpose_tags
        for item in manifest.flows
    ):
        raise ValidationError(f"{path}.flow must match one declared manifest flow")

    decision = _text(finding.get("decision"), f"{path}.decision")
    if decision not in VALID_DECISIONS:
        raise ValidationError(f"{path}.decision must be one of {sorted(VALID_DECISIONS)}")
    severity = _text(finding.get("severity"), f"{path}.severity")
    if severity not in VALID_SEVERITIES:
        raise ValidationError(f"{path}.severity must be one of {sorted(VALID_SEVERITIES)}")
    rule_id = finding.get("rule_id")
    if rule_id is not None:
        validated_rule = validate_rule_identifier(rule_id, f"{path}.rule_id")
        if validated_rule not in {rule.id for rule in policy.rules}:
            raise ValidationError(f"{path}.rule_id must identify a declared policy rule")
    _text(finding.get("rationale"), f"{path}.rationale")
    return decision


def _parse_legacy_manifest(value: Any, path: str) -> AgentManifest:
    """Parse only the manifest shape emitted by the released v0.1.1 bundle builder."""

    manifest = _mapping(value, path)
    reject_unknown_fields(
        manifest,
        {"schema_version", "name", "description", "sources", "tools", "flows"},
        path,
    )
    for field in ("sources", "tools", "flows"):
        items = _sequence(manifest.get(field), f"{path}.{field}")
        if len(items) > MAX_BUNDLE_FINDINGS:
            raise ValidationError(
                f"{path}.{field} must contain at most {MAX_BUNDLE_FINDINGS} entries"
            )
    for index, raw_flow in enumerate(_sequence(manifest.get("flows"), f"{path}.flows")):
        reject_unknown_fields(
            _mapping(raw_flow, f"{path}.flows[{index}]"),
            {"source", "tool", "purpose"},
            f"{path}.flows[{index}]",
        )
    return parse_manifest(manifest)


def _parse_legacy_policy(value: Any, path: str) -> Policy:
    """Parse only the policy shape serialized into released v0.1.1 bundles."""

    policy = _mapping(value, path)
    reject_unknown_fields(policy, {"schema_version", "name", "default_decision", "rules"}, path)
    rules = _sequence(policy.get("rules"), f"{path}.rules")
    if len(rules) > MAX_BUNDLE_FINDINGS:
        raise ValidationError(f"{path}.rules must contain at most {MAX_BUNDLE_FINDINGS} entries")
    for index, raw_rule in enumerate(rules):
        reject_unknown_fields(
            _mapping(raw_rule, f"{path}.rules[{index}]"),
            {
                "id",
                "description",
                "source_trust",
                "tool_action_classes",
                "decision",
                "rationale",
            },
            f"{path}.rules[{index}]",
        )
    return parse_policy(policy)


def _legacy_expected_decision(
    policy: Policy, source_trust: str, action_class: str
) -> tuple[str, str | None, str]:
    """Return the exact first-match decision semantics used by the released v0.1.1 builder."""

    for rule in policy.rules:
        if source_trust in rule.source_trust and action_class in rule.tool_action_classes:
            return rule.decision, rule.id, rule.rationale
    return (
        policy.default_decision,
        None,
        "No policy rule matched this declared path; the default decision was applied.",
    )


def _validate_legacy_finding(
    raw: Any,
    path: str,
    manifest: AgentManifest,
    policy: Policy,
) -> tuple[str, tuple[str, str, str]]:
    """Validate one authentic v0.1.1 finding snapshot without adding modern severity evidence."""

    finding = _mapping(raw, path)
    required = {"flow", "source", "tool", "decision", "rule_id", "rationale"}
    reject_unknown_fields(finding, required, path)
    missing = sorted(required - set(finding))
    if missing:
        raise ValidationError(f"{path} is missing required fields: {', '.join(missing)}")
    flow = _mapping(finding["flow"], f"{path}.flow")
    source = _mapping(finding["source"], f"{path}.source")
    tool = _mapping(finding["tool"], f"{path}.tool")
    reject_unknown_fields(flow, {"source", "tool", "purpose"}, f"{path}.flow")
    reject_unknown_fields(
        source,
        {"name", "trust", "data_classification", "description"},
        f"{path}.source",
    )
    reject_unknown_fields(
        tool,
        {"name", "action_class", "capabilities", "description"},
        f"{path}.tool",
    )
    source_name = _text(flow.get("source"), f"{path}.flow.source")
    tool_name = _text(flow.get("tool"), f"{path}.flow.tool")
    purpose = _text(flow.get("purpose"), f"{path}.flow.purpose")
    source_by_name = {item.name: item for item in manifest.sources}
    tool_by_name = {item.name: item for item in manifest.tools}
    declared_source = source_by_name.get(source_name)
    declared_tool = tool_by_name.get(tool_name)
    if declared_source is None or declared_tool is None:
        raise ValidationError(f"{path}.flow must reference declared manifest source and tool")
    if source != declared_source.as_dict() or tool != declared_tool.as_dict():
        raise ValidationError(f"{path} source and tool must match referenced manifest declarations")
    if not any(
        item.source == source_name and item.tool == tool_name and item.purpose == purpose
        for item in manifest.flows
    ):
        raise ValidationError(f"{path}.flow must match one declared manifest flow")
    decision = _text(finding.get("decision"), f"{path}.decision")
    if decision not in VALID_DECISIONS:
        raise ValidationError(f"{path}.decision must be one of {sorted(VALID_DECISIONS)}")
    expected_decision, expected_rule_id, expected_rationale = _legacy_expected_decision(
        policy, declared_source.trust, declared_tool.action_class
    )
    if decision != expected_decision:
        raise ValidationError(f"{path}.decision must match the declared historical policy")
    rule_id = finding.get("rule_id")
    if expected_rule_id is None:
        if rule_id is not None:
            raise ValidationError(f"{path}.rule_id must be null when no policy rule matches")
    else:
        validated_rule = validate_rule_identifier(rule_id, f"{path}.rule_id")
        if validated_rule != expected_rule_id:
            raise ValidationError(f"{path}.rule_id must match the declared historical policy rule")
    if _text(finding.get("rationale"), f"{path}.rationale") != expected_rationale:
        raise ValidationError(f"{path}.rationale must match the declared historical policy")
    return decision, (source_name, tool_name, purpose)


def _validate_legacy_bundle(bundle: Mapping[str, Any], label: str) -> None:
    """Validate the exact historical v1alpha1 generated shape from the released 0.1.1 builder."""

    required = {"schema_version", "manifest", "policy", "findings", "summary", "limits"}
    allowed = required | {"generated_at"}
    reject_unknown_fields(bundle, allowed, label)
    missing = sorted(required - set(bundle))
    if missing:
        raise ValidationError(f"{label} is missing required fields: {', '.join(missing)}")
    if "generated_at" in bundle:
        _timestamp(bundle["generated_at"], f"{label}.generated_at")
    manifest = _parse_legacy_manifest(bundle["manifest"], f"{label}.manifest")
    policy = _parse_legacy_policy(bundle["policy"], f"{label}.policy")
    findings = _sequence(bundle["findings"], f"{label}.findings")
    if len(findings) > MAX_BUNDLE_FINDINGS:
        raise ValidationError(
            f"{label}.findings must contain at most {MAX_BUNDLE_FINDINGS} entries"
        )
    decisions: Counter[str] = Counter()
    finding_flows: Counter[tuple[str, str, str]] = Counter()
    for index, finding in enumerate(findings):
        decision, flow_key = _validate_legacy_finding(
            finding, f"{label}.findings[{index}]", manifest, policy
        )
        decisions[decision] += 1
        finding_flows[flow_key] += 1
    declared_flows = Counter((flow.source, flow.tool, flow.purpose) for flow in manifest.flows)
    if finding_flows != declared_flows:
        raise ValidationError(
            f"{label}.findings must contain one finding for every declared manifest flow"
        )
    summary = _mapping(bundle["summary"], f"{label}.summary")
    summary_fields = {"allow", "deny", "require_approval"}
    reject_unknown_fields(summary, summary_fields, f"{label}.summary")
    if set(summary) != summary_fields:
        missing_summary = sorted(summary_fields - set(summary))
        raise ValidationError(
            f"{label}.summary is missing required fields: {', '.join(missing_summary)}"
        )
    for decision in sorted(summary_fields):
        value = summary[decision]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValidationError(f"{label}.summary.{decision} must be a non-negative integer")
        if value != decisions[decision]:
            raise ValidationError(f"{label}.summary.{decision} must match bundle findings")
    limits = _sequence(bundle["limits"], f"{label}.limits")
    if not limits or len(limits) > MAX_BUNDLE_LIMITS:
        raise ValidationError(
            f"{label}.limits must contain between 1 and {MAX_BUNDLE_LIMITS} entries"
        )
    for index, limit in enumerate(limits):
        _text(limit, f"{label}.limits[{index}]")


def _validate_current_bundle(bundle: Mapping[str, Any], label: str) -> None:
    """Validate the fully normalized v1alpha2 evidence contract."""

    required = {"schema_version", "manifest", "policy", "findings", "summary", "limits"}
    allowed = required | {"generated_at"}
    reject_unknown_fields(bundle, allowed, label)
    missing = sorted(required - set(bundle))
    if missing:
        raise ValidationError(f"{label} is missing required fields: {', '.join(missing)}")
    if "generated_at" in bundle:
        _timestamp(bundle["generated_at"], f"{label}.generated_at")

    manifest = parse_manifest(_mapping(bundle.get("manifest"), f"{label}.manifest"))
    policy = _parse_bundle_policy(bundle.get("policy"), f"{label}.policy")
    findings = _sequence(bundle.get("findings"), f"{label}.findings")
    if len(findings) > MAX_BUNDLE_FINDINGS:
        raise ValidationError(
            f"{label}.findings must contain at most {MAX_BUNDLE_FINDINGS} entries"
        )
    decisions = Counter(
        _validate_finding(item, f"{label}.findings[{index}]", manifest, policy)
        for index, item in enumerate(findings)
    )

    # Import lazily because engine imports this module's schema-version constant while
    # initializing. The shared oracle keeps build and validation semantics aligned.
    from trustweave.engine import expected_finding_dicts
    from trustweave.io import canonical_json

    actual_findings = Counter(canonical_json(dict(item)) for item in findings)
    expected_findings = Counter(
        canonical_json(item) for item in expected_finding_dicts(manifest, policy)
    )
    if actual_findings != expected_findings:
        raise ValidationError(
            f"{label}.findings must exactly match fresh evaluation of the declared "
            "manifest and policy"
        )

    summary = _mapping(bundle.get("summary"), f"{label}.summary")
    summary_fields = {"allow", "deny", "require_approval"}
    reject_unknown_fields(summary, summary_fields, f"{label}.summary")
    if set(summary) != summary_fields:
        missing = sorted(summary_fields - set(summary))
        raise ValidationError(f"{label}.summary is missing required fields: {', '.join(missing)}")
    for decision in sorted(summary_fields):
        value = summary[decision]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValidationError(f"{label}.summary.{decision} must be a non-negative integer")
        if value != decisions[decision]:
            raise ValidationError(f"{label}.summary.{decision} must match bundle findings")

    limits = _sequence(bundle.get("limits"), f"{label}.limits")
    if not limits or len(limits) > MAX_BUNDLE_LIMITS:
        raise ValidationError(
            f"{label}.limits must contain between 1 and {MAX_BUNDLE_LIMITS} entries"
        )
    for index, limit in enumerate(limits):
        _text(limit, f"{label}.limits[{index}]")


def validate_bundle(document: Mapping[str, Any], label: str = "bundle") -> None:
    """Validate a supported local bundle version without reading files or performing writes."""

    bundle = _mapping(document, label)
    schema_version = _text(bundle.get("schema_version"), f"{label}.schema_version")
    if schema_version == BUNDLE_SCHEMA_V1ALPHA1:
        _validate_legacy_bundle(bundle, label)
        return
    if schema_version == BUNDLE_SCHEMA_V1ALPHA2:
        _validate_current_bundle(bundle, label)
        return
    supported = ", ".join(sorted(SUPPORTED_BUNDLE_SCHEMA_VERSIONS))
    raise ValidationError(f"{label}.schema_version must be one of: {supported}")
