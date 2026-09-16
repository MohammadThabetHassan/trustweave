"""Human-readable reporting for TrustWeave local security evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from trustweave.models import contains_control_characters
from trustweave.rules import RULES


def _cell(value: Any) -> str:
    """Render one value into a Markdown table cell or header line without letting it escape.

    Every renderer here reads generated JSON back from disk, so a value can carry text no
    validator saw. Two characters decide whether the document still describes the artifact
    it came from: a pipe ends the cell it sits in, and an unterminated ``<!--`` opens a
    CommonMark HTML block that runs to the end of the document and hides every genuine
    finding after it. Control characters are folded to a space for the same reason a
    validator refuses them upstream.
    """

    text = str(value)
    if contains_control_characters(text):
        text = "".join(
            " " if contains_control_characters(character) else character for character in text
        )
    return text.replace("|", "\\|").replace("<!--", "&lt;!--")


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []


def _append_builtin_rule_guidance(lines: list[str], findings: Sequence[Any]) -> None:
    """Append stable remediation guidance for known built-in findings only."""

    identifiers = sorted(
        {
            identifier
            for raw_finding in findings
            if isinstance((finding := _as_mapping(raw_finding)).get("id"), str)
            and (identifier := str(finding["id"])) in RULES
        }
    )
    if not identifiers:
        return
    lines.extend(["", "## Built-in rule guidance", ""])
    for identifier in identifiers:
        rule = RULES[identifier]
        lines.append(f"- **{rule.title}** (`{identifier}`): {rule.remediation}")


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
        f"**Agent:** `{_cell(manifest.get('name', 'unknown'))}`  ",
        f"**Bundle schema:** `{_cell(bundle.get('schema_version', 'unknown'))}`  ",
        f"**Evidence chain:** `{_cell(evidence_chain)}`",
        "",
        "## Decision summary",
        "",
        "| Decision | Declared paths |",
        "|---|---:|",
        f"| Allow | {_cell(summary.get('allow', 0))} |",
        f"| Require approval | {_cell(summary.get('require_approval', 0))} |",
        f"| Deny | {_cell(summary.get('deny', 0))} |",
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
                source=_cell(source.get("name", "unknown")),
                trust=_cell(source.get("trust", "unknown")),
                tool=_cell(tool.get("name", "unknown")),
                action=_cell(tool.get("action_class", "unknown")),
                decision=_cell(finding.get("decision", "unknown")),
                rule=_cell(finding.get("rule_id") or "default"),
            )
        )

    lines.extend(
        [
            "",
            "## Synthetic regression scenarios",
            "",
            "| Status | Result |",
            "|---|---:|",
            f"| Total | {_cell(test_summary.get('total', 0))} |",
            f"| Passed | {_cell(test_summary.get('passed', 0))} |",
            f"| Failed | {_cell(test_summary.get('failed', 0))} |",
            f"| Overall | **{_cell(test_summary.get('status', 'unknown'))}** |",
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
        f"**Base agent:** `{_cell(_as_mapping(diff.get('base')).get('agent', 'unknown'))}`  ",
        f"**Head agent:** `{_cell(_as_mapping(diff.get('head')).get('agent', 'unknown'))}`",
        "",
        "## Change summary",
        "",
        "| Category | Added | Removed | Changed |",
        "|---|---:|---:|---:|",
        (
            f"| Sources | {_cell(summary.get('added_sources', 0))} | "
            f"{_cell(summary.get('removed_sources', 0))} | "
            f"{_cell(summary.get('changed_sources', 0))} |"
        ),
        (
            f"| Tools | {_cell(summary.get('added_tools', 0))} | "
            f"{_cell(summary.get('removed_tools', 0))} | "
            f"{_cell(summary.get('changed_tools', 0))} |"
        ),
        "",
        "| Capability outcome | Count |",
        "|---|---:|",
        (
            "| Tools with capability changes | "
            f"{_cell(summary.get('tools_with_capability_changes', 0))} |"
        ),
        f"| Added capabilities | {_cell(summary.get('added_capabilities', 0))} |",
        f"| Removed capabilities | {_cell(summary.get('removed_capabilities', 0))} |",
        "",
        "| Path outcome | Count |",
        "|---|---:|",
        f"| Added paths | {_cell(summary.get('added_paths', 0))} |",
        f"| Removed paths | {_cell(summary.get('removed_paths', 0))} |",
        f"| Policy decision changes | {_cell(summary.get('decision_changes', 0))} |",
        f"| Policy-only changes | {_cell(summary.get('policy_changes', 0))} |",
        f"| Review signals | {_cell(summary.get('review_signals', 0))} |",
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
                    severity=_cell(signal.get("severity", "unknown")),
                    identifier=_cell(signal.get("id", "unknown")),
                    message=_cell(signal.get("message", "unknown")),
                )
            )

    _append_builtin_rule_guidance(lines, signals)
    capability_changes = _as_sequence(changes.get("capabilities"))
    lines.extend(["", "## Capability changes", ""])
    if not capability_changes:
        lines.append("No existing declared tool changed its capability set.")
    else:
        lines.extend(["| Tool | Action class | Added | Removed |", "|---|---|---|---|"])
        for raw_change in capability_changes:
            change = _as_mapping(raw_change)
            added = (
                ", ".join(_cell(capability) for capability in _as_sequence(change.get("added")))
                or "—"
            )
            removed = (
                ", ".join(_cell(capability) for capability in _as_sequence(change.get("removed")))
                or "—"
            )
            lines.append(
                "| {tool} | {action_class} | {added} | {removed} |".format(
                    tool=_cell(change.get("name", "unknown")),
                    action_class=_cell(change.get("action_class", "unknown")),
                    added=added,
                    removed=removed,
                )
            )

    policy_changes = _as_sequence(_as_mapping(changes.get("policy")).get("changed"))
    lines.extend(["", "## Policy-only changes", ""])
    if not policy_changes:
        lines.append("No policy-only semantic changes were recorded.")
    else:
        lines.extend(["| Field | Before | After | Security-relevant |", "|---|---|---|---|"])
        for raw_change in policy_changes:
            change = _as_mapping(raw_change)
            lines.append(
                "| {path} | `{before}` | `{after}` | {security_relevant} |".format(
                    path=_cell(change.get("path", "unknown")),
                    before=_cell(change.get("before")),
                    after=_cell(change.get("after")),
                    security_relevant=_cell(change.get("security_relevant", False)),
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
            source = _cell(key[0] if len(key) > 0 else "unknown")
            tool = _cell(key[1] if len(key) > 1 else "unknown")
            lines.append(
                f"| {source} | {tool} | {_cell(before.get('decision', 'unknown'))} | "
                f"{_cell(after.get('decision', 'unknown'))} |"
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
    approval_rule_value = ", ".join(_cell(rule) for rule in approval_rules) or "none"
    approval_binding_value = ", ".join(_cell(binding) for binding in approval_bindings)
    if not approval_binding_value:
        approval_binding_value = "not declared"
    lines = [
        "# TrustWeave Policy Review Report",
        "",
        f"**Policy:** `{_cell(review.get('policy', 'unknown'))}`  ",
        f"**Status:** **{_cell(summary.get('status', 'unknown'))}**",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Rules reviewed | {_cell(summary.get('rules', 0))} |",
        f"| Findings requiring review | {_cell(summary.get('review_findings', 0))} |",
        "",
        "## Declared approval boundary",
        "",
        "| Control | Declared value |",
        "|---|---|",
        f"| High-impact approval rules | {approval_rule_value} |",
        f"| Approval control declared | {_cell(approval_control.get('declared', False))} |",
        f"| Mechanism | {_cell(approval_control.get('mechanism', 'not declared'))} |",
        f"| Approval bindings | {approval_binding_value} |",
        f"| Fail closed | {_cell(approval_control.get('fail_closed', 'not declared'))} |",
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
                    severity=_cell(finding.get("severity", "unknown")),
                    identifier=_cell(finding.get("id", "unknown")),
                    message=_cell(finding.get("message", "unknown")),
                )
            )

    _append_builtin_rule_guidance(lines, findings)
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
            # One rule shadows on its own, or several do together; name whichever it is.
            covering = result.get("shadowed_by_rules")
            shadowed_by = (
                ", ".join(_cell(rule) for rule in covering)
                if isinstance(covering, list) and covering
                else _cell(result.get("shadowed_by") or "—")
            )
            reachable = _cell(result.get("reachable", "unknown"))
            if result.get("cover_search") == "declined":
                # The search that decides reachability did not run, so printing True here
                # would read as a verdict the review never reached.
                shadowed_by = "not searched (rule names more cells than the enumeration limit)"
                reachable = "not established"
            lines.append(
                "| `{rule_id}` | {reachable} | {possible} | {shadowed_by} |".format(
                    rule_id=_cell(rule_id),
                    reachable=reachable,
                    possible=_cell(result.get("possible", "unknown")),
                    shadowed_by=shadowed_by,
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
        f"**Agent:** `{_cell(review.get('agent', 'unknown'))}`  ",
        f"**Policy:** `{_cell(review.get('policy', 'unknown'))}`  ",
        f"**Status:** **{_cell(summary.get('status', 'unknown'))}**",
        "",
        "## Review summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Messages observed | {_cell(summary.get('messages_observed', 0))} |",
        f"| Tool calls observed | {_cell(summary.get('tool_calls_observed', 0))} |",
        f"| Untrusted-context events | {_cell(summary.get('untrusted_context_events', 0))} |",
        f"| Findings requiring review | {_cell(summary.get('review_findings', 0))} |",
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
                index=_cell(observation.get("index", "unknown")),
                source=_cell(observation.get("source", "unknown")),
                tool=_cell(observation.get("tool", "unknown")),
                action_class=_cell(observation.get("action_class", "not available")),
                decision=_cell(observation.get("decision", "not available")),
                status=_cell(observation.get("status", "unknown")),
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
                    severity=_cell(finding.get("severity", "unknown")),
                    identifier=_cell(finding.get("id", "unknown")),
                    index=_cell(finding.get("index", "not available")),
                    message=_cell(finding.get("message", "unknown")),
                )
            )

    _append_builtin_rule_guidance(lines, findings)
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
        f"**Profile:** `{_cell(profile.get('name', 'unknown'))}`  ",
        f"**Transport:** `{_cell(profile.get('transport', 'unknown'))}`  ",
        f"**Resource URI:** `{_cell(profile.get('resource_uri', 'not declared'))}`  ",
        (
            "**Authorization expected:** "
            f"`{_cell(profile.get('authorization_expected', 'unknown'))}`  "
        ),
        f"**Status:** **{_cell(summary.get('status', 'unknown'))}**",
        "",
        "## Review summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Tools reviewed | {_cell(summary.get('tools_reviewed', 0))} |",
        f"| Findings requiring review | {_cell(summary.get('review_findings', 0))} |",
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
                mcp_tool=_cell(mapping.get("mcp_tool", "unknown")),
                manifest_tool=_cell(mapping.get("manifest_tool", "unknown")),
                declared_action=_cell(mapping.get("declared_action_class", "unknown")),
                manifest_action=_cell(mapping.get("manifest_action_class", "not available")),
                status=_cell(mapping.get("status", "unknown")),
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
                    severity=_cell(finding.get("severity", "unknown")),
                    identifier=_cell(finding.get("id", "unknown")),
                    message=_cell(finding.get("message", "unknown")),
                )
            )

    _append_builtin_rule_guidance(lines, findings)
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
        f"**Status:** **{_cell(summary.get('status', 'unknown'))}**  ",
        f"**Findings:** {_cell(summary.get('findings', 0))}",
        "",
        "## Risk-state summary",
        "",
        "| State | Count |",
        "|---|---:|",
        f"| New | {_cell(summary.get('new', 0))} |",
        f"| Baselined | {_cell(summary.get('baselined', 0))} |",
        f"| Suppressed | {_cell(summary.get('suppressed', 0))} |",
        f"| Expired baseline | {_cell(summary.get('expired_baseline', 0))} |",
        f"| Expired suppression | {_cell(summary.get('expired_suppression', 0))} |",
        "",
        "## Active findings by severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity} | {_cell(active_by_severity.get(severity, 0))} |")

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
                    state=_cell(finding.get("risk_state", "unknown")),
                    severity=_cell(finding.get("severity", "unknown")),
                    identifier=_cell(finding.get("id", "unknown")),
                    expiry=_cell(finding.get("expires_at", "—")),
                    message=_cell(finding.get("message", "unknown")),
                )
            )

    _append_builtin_rule_guidance(lines, findings)
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


def render_code_discovery_report(review: Mapping[str, Any]) -> str:
    """Render a static local-source discovery review as a reviewer-facing document."""

    source = _as_mapping(review.get("source"))
    summary = _as_mapping(review.get("summary"))
    drift = _as_mapping(review.get("drift"))
    tools = _as_sequence(review.get("tools"))
    findings = _as_sequence(review.get("findings"))

    lines = [
        "# TrustWeave Local Code Discovery",
        "",
        f"**Analyzed root:** `{_cell(source.get('root_name', 'unknown'))}`  ",
        f"**Files analyzed:** {_cell(source.get('files_analyzed', 0))}  ",
        f"**Symbol catalog:** `{_cell(source.get('catalog_version', 'unknown'))}`  ",
        f"**Status:** **{_cell(summary.get('status', 'unknown'))}**",
        "",
        "## Review summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Tools discovered | {_cell(summary.get('tools_discovered', 0))} |",
        f"| Action class proposed | {_cell(summary.get('tools_classified', 0))} |",
        f"| Left unknown for review | {_cell(summary.get('tools_unknown', 0))} |",
        f"| Findings requiring review | {_cell(summary.get('review_findings', 0))} |",
        "",
        "## Declaration coverage",
        "",
    ]

    if drift.get("coverage_status") == "measured":
        lines.extend(
            [
                "| Metric | Value |",
                "|---|---:|",
                f"| Declared tools | {_cell(drift.get('tools_declared', 0))} |",
                f"| Discovered tools | {_cell(drift.get('tools_discovered', 0))} |",
                f"| Matched by name | {_cell(drift.get('tools_matched', 0))} |",
                (
                    "| Declaration coverage | "
                    f"{_cell(drift.get('declaration_coverage_percent', '0.00'))}% |"
                ),
                "",
            ]
        )
        missing = [_cell(name) for name in _as_sequence(drift.get("missing_from_manifest"))]
        absent = [_cell(name) for name in _as_sequence(drift.get("declared_not_found_in_code"))]
        lines.append(
            "Found in code but not declared: "
            + (", ".join(f"`{name}`" for name in missing) if missing else "none")
        )
        lines.append("")
        lines.append(
            "Declared but not found in code: "
            + (", ".join(f"`{name}`" for name in absent) if absent else "none")
        )
    else:
        lines.append(
            "No manifest was supplied, so declaration coverage was not measured. Pass "
            "`--manifest` to compare the discovered surface against a declaration."
        )

    lines.extend(
        [
            "",
            "## Discovered tools",
            "",
            "| Tool | Registered by | Proposed action class | Confidence | Evidence | Location |",
            "|---|---|---|---|---|---|",
        ]
    )
    for raw_tool in tools:
        tool = _as_mapping(raw_tool)
        location = _as_mapping(tool.get("location"))
        signals = [
            _cell(_as_mapping(signal).get("symbol", "unknown"))
            for signal in _as_sequence(tool.get("signals"))
        ]
        reasons = [_cell(reason) for reason in _as_sequence(tool.get("reasons"))]
        evidence = ", ".join(f"`{symbol}`" for symbol in signals) if signals else ""
        if reasons:
            evidence = (evidence + " " if evidence else "") + "refused: " + ", ".join(reasons)
        lines.append(
            "| `{name}`{implemented} | {framework} | **{action}** | {confidence} "
            "| {evidence} | `{file}:{line}` |".format(
                name=_cell(tool.get("name", "unknown")),
                # A factory may register a tool under a name the implementing function does
                # not share. A reviewer reading this table needs the second one to find the
                # code the evidence came from.
                implemented=(
                    f"<br>via `{_cell(tool['implementation'])}`"
                    if tool.get("implementation")
                    else ""
                ),
                framework=_cell(str(tool.get("framework", "unknown")).replace("_", " ")),
                action=_cell(tool.get("proposed_action_class", "unknown")),
                confidence=_cell(tool.get("confidence", "unknown")),
                evidence=evidence or "no recognised effect",
                file=_cell(location.get("file", "unknown")),
                line=_cell(location.get("line", "0")),
            )
        )

    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No local discovery findings requiring review were generated.")
    else:
        lines.extend(["| Severity | Identifier | Message |", "|---|---|---|"])
        for raw_finding in findings:
            finding = _as_mapping(raw_finding)
            lines.append(
                "| {severity} | `{identifier}` | {message} |".format(
                    severity=_cell(finding.get("severity", "unknown")),
                    identifier=_cell(finding.get("id", "unknown")),
                    message=_cell(finding.get("message", "unknown")),
                )
            )

    _append_builtin_rule_guidance(lines, findings)
    lines.extend(["", "## Evidence limits", ""])
    for limit in _as_sequence(review.get("limits")):
        lines.append(f"- {_cell(limit)}")
    lines.append("")
    return "\n".join(lines)
