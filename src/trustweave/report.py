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
