"""Human-readable reporting for TrustWeave local security evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []


def render_report(
    bundle: Mapping[str, Any], test_results: Mapping[str, Any], attestation: Mapping[str, Any]
) -> str:
    """Render a deterministic Markdown report from generated JSON artifacts."""

    manifest = _as_mapping(bundle.get("manifest"))
    summary = _as_mapping(bundle.get("summary"))
    test_summary = _as_mapping(test_results.get("summary"))
    evidence_chain = _as_mapping(attestation.get("integrity")).get("chain_sha256", "unknown")
    lines = [
        "# TrustWeave Security Evidence Report",
        "",
        f"**Agent:** `{manifest.get('name', 'unknown')}`  ",
        f"**Bundle schema:** `{bundle.get('schema_version', 'unknown')}`  ",
        f"**Evidence chain:** `{evidence_chain}`",
        "",
        "## Decision summary",
        "",
        "| Decision | Declared paths |",
        "|---|---:|",
        f"| Allow | {summary.get('allow', 0)} |",
        f"| Require approval | {summary.get('require_approval', 0)} |",
        f"| Deny | {summary.get('deny', 0)} |",
        "",
        "## Declared trust-boundary paths",
        "",
        "| Source | Trust | Tool | Action class | Decision | Policy rule |",
        "|---|---|---|---|---|---|",
    ]
    findings = _as_sequence(bundle.get("findings"))
    for raw_finding in findings:
        finding = _as_mapping(raw_finding)
        source = _as_mapping(finding.get("source"))
        tool = _as_mapping(finding.get("tool"))
        lines.append(
            "| {source} | {trust} | {tool} | {action} | **{decision}** | {rule} |".format(
                source=source.get("name", "unknown"),
                trust=source.get("trust", "unknown"),
                tool=tool.get("name", "unknown"),
                action=tool.get("action_class", "unknown"),
                decision=finding.get("decision", "unknown"),
                rule=finding.get("rule_id") or "default",
            )
        )

    lines.extend(
        [
            "",
            "## Synthetic regression scenarios",
            "",
            "| Status | Result |",
            "|---|---:|",
            f"| Total | {test_summary.get('total', 0)} |",
            f"| Passed | {test_summary.get('passed', 0)} |",
            f"| Failed | {test_summary.get('failed', 0)} |",
            f"| Overall | **{test_summary.get('status', 'unknown')}** |",
            "",
            "## Evidence limits",
            "",
            (
                "This report is generated entirely from local declarative inputs and synthetic "
                "scenarios. It does not execute tools, contact external systems, inspect "
                "credentials, or establish the security of a deployed agent. The attestation "
                "is hash-linked but is not externally signed."
            ),
            "",
            "## Next review action",
            "",
            (
                "Review every `deny` and `require_approval` path before merging a change. "
                "If a newly declared path is expected, update the policy and add a safe "
                "regression scenario that documents the intended decision."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def render_diff_report(diff: Mapping[str, Any]) -> str:
    """Render a deterministic Markdown review report for a bundle diff."""

    summary = _as_mapping(diff.get("summary"))
    changes = _as_mapping(diff.get("changes"))
    signals = _as_sequence(diff.get("signals"))
    lines = [
        "# TrustWeave Bundle Diff Report",
        "",
        f"**Base agent:** `{_as_mapping(diff.get('base')).get('agent', 'unknown')}`  ",
        f"**Head agent:** `{_as_mapping(diff.get('head')).get('agent', 'unknown')}`",
        "",
        "## Change summary",
        "",
        "| Category | Added | Removed | Changed |",
        "|---|---:|---:|---:|",
        (
            f"| Sources | {summary.get('added_sources', 0)} | "
            f"{summary.get('removed_sources', 0)} | {summary.get('changed_sources', 0)} |"
        ),
        (
            f"| Tools | {summary.get('added_tools', 0)} | "
            f"{summary.get('removed_tools', 0)} | {summary.get('changed_tools', 0)} |"
        ),
        "",
        "| Capability outcome | Count |",
        "|---|---:|",
        f"| Tools with capability changes | {summary.get('tools_with_capability_changes', 0)} |",
        f"| Added capabilities | {summary.get('added_capabilities', 0)} |",
        f"| Removed capabilities | {summary.get('removed_capabilities', 0)} |",
        "",
        "| Path outcome | Count |",
        "|---|---:|",
        f"| Added paths | {summary.get('added_paths', 0)} |",
        f"| Removed paths | {summary.get('removed_paths', 0)} |",
        f"| Policy decision changes | {summary.get('decision_changes', 0)} |",
        f"| Review signals | {summary.get('review_signals', 0)} |",
        "",
        "## Review signals",
        "",
    ]
    if not signals:
        lines.append("No automatic review signals were generated from the declared head bundle.")
    else:
        lines.extend(["| Severity | Identifier | Message |", "|---|---|---|"])
        for raw_signal in signals:
            signal = _as_mapping(raw_signal)
            lines.append(
                "| {severity} | `{identifier}` | {message} |".format(
                    severity=signal.get("severity", "unknown"),
                    identifier=signal.get("id", "unknown"),
                    message=signal.get("message", "unknown"),
                )
            )

    capability_changes = _as_sequence(changes.get("capabilities"))
    lines.extend(["", "## Capability changes", ""])
    if not capability_changes:
        lines.append("No existing declared tool changed its capability set.")
    else:
        lines.extend(["| Tool | Action class | Added | Removed |", "|---|---|---|---|"])
        for raw_change in capability_changes:
            change = _as_mapping(raw_change)
            added = (
                ", ".join(str(capability) for capability in _as_sequence(change.get("added")))
                or "—"
            )
            removed = (
                ", ".join(str(capability) for capability in _as_sequence(change.get("removed")))
                or "—"
            )
            lines.append(
                "| {tool} | {action_class} | {added} | {removed} |".format(
                    tool=change.get("name", "unknown"),
                    action_class=change.get("action_class", "unknown"),
                    added=added,
                    removed=removed,
                )
            )

    path_changes = _as_mapping(changes.get("paths"))
    lines.extend(["", "## Changed path decisions", ""])
    decision_changes = _as_sequence(path_changes.get("decision_changed"))
    if not decision_changes:
        lines.append("No existing declared path changed its policy decision or matching rule.")
    else:
        lines.extend(["| Source | Tool | Before | After |", "|---|---|---|---|"])
        for raw_change in decision_changes:
            change = _as_mapping(raw_change)
            key = _as_sequence(change.get("key"))
            before = _as_mapping(change.get("before"))
            after = _as_mapping(change.get("after"))
            source = key[0] if len(key) > 0 else "unknown"
            tool = key[1] if len(key) > 1 else "unknown"
            lines.append(
                f"| {source} | {tool} | {before.get('decision', 'unknown')} | "
                f"{after.get('decision', 'unknown')} |"
            )

    lines.extend(
        [
            "",
            "## Evidence limits",
            "",
            (
                "This report is a deterministic comparison of two generated bundles. It does "
                "not discover undeclared runtime behavior, execute a tool, or make a security "
                "verdict. Capability changes are declared metadata, not proof of runtime scope. "
                "Review every signal and changed path in the context of the underlying manifest, "
                "policy, and operational authorization boundary."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def render_policy_review_report(review: Mapping[str, Any]) -> str:
    """Render deterministic static policy-review findings as Markdown."""

    summary = _as_mapping(review.get("summary"))
    approval_control = _as_mapping(review.get("approval_control"))
    findings = _as_sequence(review.get("findings"))
    approval_rules = _as_sequence(approval_control.get("high_impact_approval_rules"))
    approval_bindings = _as_sequence(approval_control.get("binds_to"))
    approval_rule_value = ", ".join(str(rule) for rule in approval_rules) or "none"
    approval_binding_value = ", ".join(str(binding) for binding in approval_bindings)
    if not approval_binding_value:
        approval_binding_value = "not declared"
    lines = [
        "# TrustWeave Policy Review Report",
        "",
        f"**Policy:** `{review.get('policy', 'unknown')}`  ",
        f"**Status:** **{summary.get('status', 'unknown')}**",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Rules reviewed | {summary.get('rules', 0)} |",
        f"| Findings requiring review | {summary.get('review_findings', 0)} |",
        "",
        "## Declared approval boundary",
        "",
        "| Control | Declared value |",
        "|---|---|",
        f"| High-impact approval rules | {approval_rule_value} |",
        f"| Approval control declared | {approval_control.get('declared', False)} |",
        f"| Mechanism | {approval_control.get('mechanism', 'not declared')} |",
        f"| Approval bindings | {approval_binding_value} |",
        f"| Fail closed | {approval_control.get('fail_closed', 'not declared')} |",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No deterministic structural review findings were generated.")
    else:
        lines.extend(["| Severity | Identifier | Message |", "|---|---|---|"])
        for raw_finding in findings:
            finding = _as_mapping(raw_finding)
            lines.append(
                "| {severity} | `{identifier}` | {message} |".format(
                    severity=finding.get("severity", "unknown"),
                    identifier=finding.get("id", "unknown"),
                    message=finding.get("message", "unknown"),
                )
            )

    coverage_value = review.get("coverage")
    if isinstance(coverage_value, Mapping):
        coverage = _as_mapping(coverage_value)
        coverage_rules = _as_mapping(coverage.get("rules"))
        lines.extend(
            [
                "",
                "## Rule coverage",
                "",
                "| Rule | Reachable | Possible | Shadowed by |",
                "|---|---|---|---|",
            ]
        )
        for rule_id, raw_result in sorted(coverage_rules.items()):
            result = _as_mapping(raw_result)
            lines.append(
                "| `{rule_id}` | {reachable} | {possible} | {shadowed_by} |".format(
                    rule_id=rule_id,
                    reachable=result.get("reachable", "unknown"),
                    possible=result.get("possible", "unknown"),
                    shadowed_by=result.get("shadowed_by") or "—",
                )
            )

    lines.extend(
        [
            "",
            "## Evidence limits",
            "",
            (
                "This report evaluates deterministic policy structure only. It does not replace "
                "authorization design, runtime validation, human review, or a security assessment."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def render_trace_review_report(review: Mapping[str, Any]) -> str:
    """Render a local trace-policy review without exposing messages or tool arguments."""

    summary = _as_mapping(review.get("summary"))
    observations = _as_sequence(review.get("observations"))
    findings = _as_sequence(review.get("findings"))
    lines = [
        "# TrustWeave Offline Trace Review",
        "",
        f"**Agent:** `{review.get('agent', 'unknown')}`  ",
        f"**Policy:** `{review.get('policy', 'unknown')}`  ",
        f"**Status:** **{summary.get('status', 'unknown')}**",
        "",
        "## Review summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Messages observed | {summary.get('messages_observed', 0)} |",
        f"| Tool calls observed | {summary.get('tool_calls_observed', 0)} |",
        f"| Untrusted-context events | {summary.get('untrusted_context_events', 0)} |",
        f"| Findings requiring review | {summary.get('review_findings', 0)} |",
        "",
        "## Tool-call observations",
        "",
        "| Index | Declared source | Tool | Action class | Policy decision | Status |",
        "|---:|---|---|---|---|---|",
    ]
    for raw_observation in observations:
        observation = _as_mapping(raw_observation)
        lines.append(
            "| {index} | {source} | {tool} | {action_class} | {decision} | **{status}** |".format(
                index=observation.get("index", "unknown"),
                source=observation.get("source", "unknown"),
                tool=observation.get("tool", "unknown"),
                action_class=observation.get("action_class", "not available"),
                decision=observation.get("decision", "not available"),
                status=observation.get("status", "unknown"),
            )
        )

    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No local trace-policy mismatches requiring review were generated.")
    else:
        lines.extend(["| Severity | Identifier | Call index | Message |", "|---|---|---:|---|"])
        for raw_finding in findings:
            finding = _as_mapping(raw_finding)
            lines.append(
                "| {severity} | `{identifier}` | {index} | {message} |".format(
                    severity=finding.get("severity", "unknown"),
                    identifier=finding.get("id", "unknown"),
                    index=finding.get("index", "not available"),
                    message=finding.get("message", "unknown"),
                )
            )

    lines.extend(
        [
            "",
            "## Privacy and evidence limits",
            "",
            (
                "This report intentionally excludes message content and tool arguments. It reads "
                "local structured metadata only and does not execute a target, tool, adapter, "
                "model, or network request. A finding is a review obligation, not a vulnerability "
                "verdict or incident conclusion."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def render_mcp_profile_review_report(review: Mapping[str, Any]) -> str:
    """Render a static MCP metadata review without implying live-server validation."""

    profile = _as_mapping(review.get("profile"))
    summary = _as_mapping(review.get("summary"))
    mappings = _as_sequence(review.get("mappings"))
    findings = _as_sequence(review.get("findings"))
    lines = [
        "# TrustWeave MCP Metadata Profile Review",
        "",
        f"**Profile:** `{profile.get('name', 'unknown')}`  ",
        f"**Transport:** `{profile.get('transport', 'unknown')}`  ",
        f"**Resource URI:** `{profile.get('resource_uri', 'not declared')}`  ",
        f"**Authorization expected:** `{profile.get('authorization_expected', 'unknown')}`  ",
        f"**Status:** **{summary.get('status', 'unknown')}**",
        "",
        "## Review summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Tools reviewed | {summary.get('tools_reviewed', 0)} |",
        f"| Findings requiring review | {summary.get('review_findings', 0)} |",
        "",
        "## Declared tool mappings",
        "",
        "| MCP tool | Manifest tool | Profile action class | Manifest action class | Status |",
        "|---|---|---|---|---|",
    ]
    for raw_mapping in mappings:
        mapping = _as_mapping(raw_mapping)
        lines.append(
            "| {mcp_tool} | {manifest_tool} | {declared_action} | {manifest_action} | "
            "**{status}** |".format(
                mcp_tool=mapping.get("mcp_tool", "unknown"),
                manifest_tool=mapping.get("manifest_tool", "unknown"),
                declared_action=mapping.get("declared_action_class", "unknown"),
                manifest_action=mapping.get("manifest_action_class", "not available"),
                status=mapping.get("status", "unknown"),
            )
        )

    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No local profile-to-manifest mismatches requiring review were generated.")
    else:
        lines.extend(["| Severity | Identifier | Message |", "|---|---|---|"])
        for raw_finding in findings:
            finding = _as_mapping(raw_finding)
            lines.append(
                "| {severity} | `{identifier}` | {message} |".format(
                    severity=finding.get("severity", "unknown"),
                    identifier=finding.get("id", "unknown"),
                    message=finding.get("message", "unknown"),
                )
            )

    lines.extend(
        [
            "",
            "## Evidence limits",
            "",
            (
                "This is a local metadata-profile review. TrustWeave did not discover, connect "
                "to, authenticate with, or execute an MCP server. The profile resource URI is an "
                "identifier only; no token or remote server metadata was read."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def render_risk_review_report(review: Mapping[str, Any]) -> str:
    """Render a deterministic Markdown summary for a local risk-review artifact."""

    summary = _as_mapping(review.get("summary"))
    findings = _as_sequence(review.get("findings"))
    active_by_severity = _as_mapping(summary.get("active_by_severity"))
    lines = [
        "# TrustWeave Local Risk Review",
        "",
        f"**Status:** **{summary.get('status', 'unknown')}**  ",
        f"**Findings:** {summary.get('findings', 0)}",
        "",
        "## Risk-state summary",
        "",
        "| State | Count |",
        "|---|---:|",
        f"| New | {summary.get('new', 0)} |",
        f"| Baselined | {summary.get('baselined', 0)} |",
        f"| Suppressed | {summary.get('suppressed', 0)} |",
        f"| Expired baseline | {summary.get('expired_baseline', 0)} |",
        f"| Expired suppression | {summary.get('expired_suppression', 0)} |",
        "",
        "## Active findings by severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity} | {active_by_severity.get(severity, 0)} |")

    lines.extend(["", "## Finding decisions", ""])
    if not findings:
        lines.append("No supplied local review findings were present.")
    else:
        lines.extend(
            [
                "| State | Severity | Identifier | Expiry | Message |",
                "|---|---|---|---|---|",
            ]
        )
        for raw_finding in findings:
            finding = _as_mapping(raw_finding)
            lines.append(
                "| {state} | {severity} | `{identifier}` | {expiry} | {message} |".format(
                    state=finding.get("risk_state", "unknown"),
                    severity=finding.get("severity", "unknown"),
                    identifier=finding.get("id", "unknown"),
                    expiry=finding.get("expires_at", "—"),
                    message=finding.get("message", "unknown"),
                )
            )

    lines.extend(
        [
            "",
            "## Evidence limits",
            "",
            (
                "This report derives solely from supplied local review artifacts and explicit "
                "local baseline or suppression decisions. It does not remediate a finding, contact "
                "a ticketing system, authenticate an approver, inspect a deployed agent, or "
                "establish runtime security."
            ),
            "",
        ]
    )
    return "\n".join(lines)
