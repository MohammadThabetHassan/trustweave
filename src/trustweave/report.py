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
                "verdict. Review every signal and changed path in the context of the underlying "
                "manifest, policy, and operational authorization boundary."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def render_policy_review_report(review: Mapping[str, Any]) -> str:
    """Render deterministic static policy-review findings as Markdown."""

    summary = _as_mapping(review.get("summary"))
    findings = _as_sequence(review.get("findings"))
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
