"""Authoritative local-review rule metadata for canonical TrustWeave findings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final


@dataclass(frozen=True)
class RuleDefinition:
    """Stable reviewer guidance for one local deterministic finding identifier."""

    identifier: str
    evidence_kind: str
    title: str
    rationale: str
    remediation: str


_RULES: Final[dict[str, RuleDefinition]] = {
    "TW-CHAIN-001": RuleDefinition(
        "TW-CHAIN-001",
        "declared_chain_configuration",
        "Declared untrusted path reaches an external action",
        (
            "The supplied graph propagates a sensitive classification from an explicitly "
            "untrusted source to a declared external action."
        ),
        "Confirm the declared graph, classification, boundary ownership, and policy intent.",
    ),
    "TW-CHAIN-002": RuleDefinition(
        "TW-CHAIN-002",
        "declared_chain_configuration",
        "Declared sensitive path lacks scoped fail-closed approval",
        (
            "The supplied path reaches an external action without a fail-closed approval "
            "covering every propagated sensitive classification."
        ),
        "Confirm that approval is required and binds to the relevant declared scope.",
    ),
    "TW-CHAIN-003": RuleDefinition(
        "TW-CHAIN-003",
        "declared_chain_configuration",
        "Declared sanitizer coverage is incomplete",
        (
            "A supplied sanitizer does not list coverage for every propagated sensitive "
            "classification."
        ),
        "Review the sanitizer’s stated coverage and any residual classification.",
    ),
    "TW-CHAIN-004": RuleDefinition(
        "TW-CHAIN-004",
        "declared_chain_configuration",
        "Declared chain analysis is incomplete",
        (
            "A configured local traversal budget was reached before the supplied graph could "
            "be fully reviewed."
        ),
        (
            "Increase an explicit budget only after reviewing input scale; do not treat an "
            "incomplete review as clear."
        ),
    ),
    "TW-DIFF-001": RuleDefinition(
        "TW-DIFF-001",
        "declared_bundle_difference",
        "Sensitive or external tool declaration changed",
        "A supplied bundle comparison adds or changes a sensitive or external declared tool.",
        "Review the tool’s declared capabilities and policy coverage.",
    ),
    "TW-DIFF-002": RuleDefinition(
        "TW-DIFF-002",
        "declared_bundle_difference",
        "Untrusted high-impact path is not denied",
        (
            "The supplied head bundle includes an untrusted path to a sensitive or external "
            "tool without a deny decision."
        ),
        "Review the decision and human-control boundary.",
    ),
    "TW-DIFF-003": RuleDefinition(
        "TW-DIFF-003",
        "declared_bundle_difference",
        "Sensitive or external tool gained capability",
        (
            "A supplied bundle comparison shows new declared capabilities on a sensitive or "
            "external tool."
        ),
        "Review least-privilege scope and policy coverage.",
    ),
    "TW-MCP-001": RuleDefinition(
        "TW-MCP-001",
        "pre_recorded_mcp_metadata",
        "MCP HTTP profile declares no authorization expectation",
        (
            "The supplied static MCP profile declares authorization_expected as false for "
            "HTTP transport."
        ),
        "Review whether unauthenticated transport is intentional and appropriately protected.",
    ),
    "TW-MCP-002": RuleDefinition(
        "TW-MCP-002",
        "pre_recorded_mcp_metadata",
        "MCP mapping names an unknown manifest tool",
        "A supplied MCP profile mapping does not identify a declared manifest tool.",
        "Correct or review the static mapping.",
    ),
    "TW-MCP-003": RuleDefinition(
        "TW-MCP-003",
        "pre_recorded_mcp_metadata",
        "MCP action class disagrees with manifest mapping",
        "A supplied MCP profile action class differs from its mapped manifest tool classification.",
        "Reconcile the declared classifications.",
    ),
    "TW-POL-001": RuleDefinition(
        "TW-POL-001",
        "declared_policy_structure",
        "Policy default decision allows unmatched paths",
        "The supplied policy uses allow as the default decision for unmatched declared paths.",
        "Confirm that the default is intentional and appropriately bounded.",
    ),
    "TW-POL-002": RuleDefinition(
        "TW-POL-002",
        "declared_policy_structure",
        "Policy rule is structurally shadowed",
        "An earlier deterministic rule structurally covers a later supplied rule.",
        "Reorder, narrow, or remove the later declaration.",
    ),
    "TW-POL-003": RuleDefinition(
        "TW-POL-003",
        "declared_policy_structure",
        "Policy permits untrusted high-impact action",
        "A supplied rule permits untrusted input to a sensitive or external action.",
        "Confirm the policy rationale and human-control boundary.",
    ),
    "TW-POL-004": RuleDefinition(
        "TW-POL-004",
        "declared_policy_structure",
        "High-impact approval path lacks a control",
        "A supplied high-impact approval path has no declared approval control.",
        "Declare the control or revise the path policy.",
    ),
    "TW-POL-005": RuleDefinition(
        "TW-POL-005",
        "declared_policy_structure",
        "Approval control lacks required bindings",
        "A supplied approval control omits one or more required binding fields.",
        "Bind the approval to actor, tool, target, parameters, issuance, and expiry as applicable.",
    ),
    "TW-POL-006": RuleDefinition(
        "TW-POL-006",
        "declared_policy_structure",
        "Approval control is fail-open",
        "A supplied approval control is not fail-closed when its state cannot be validated.",
        "Review whether a fail-closed control is required for the stated path.",
    ),
    "TW-POL-007": RuleDefinition(
        "TW-POL-007",
        "declared_policy_structure",
        "Policy rules conflict structurally",
        "Two supplied rules can match the same declared path while specifying different decisions.",
        "Resolve the conflict by narrowing, reordering, or removing a declaration.",
    ),
    "TW-POL-008": RuleDefinition(
        "TW-POL-008",
        "declared_policy_structure",
        "Policy rule requires undeclared controls",
        "A supplied rule names required controls outside the declared control catalog.",
        "Declare the required controls or correct the rule references.",
    ),
    "TW-TRACE-001": RuleDefinition(
        "TW-TRACE-001",
        "pre_recorded_trace_metadata",
        "Trace metadata names an undeclared source",
        "A supplied minimized trace call references a source absent from the declared inventory.",
        "Reconcile minimized trace metadata with the declared source inventory.",
    ),
    "TW-TRACE-002": RuleDefinition(
        "TW-TRACE-002",
        "pre_recorded_trace_metadata",
        "Trace metadata names an undeclared tool",
        "A supplied minimized trace call references a tool absent from the declared inventory.",
        "Reconcile minimized trace metadata with the declared tool inventory.",
    ),
    "TW-TRACE-003": RuleDefinition(
        "TW-TRACE-003",
        "pre_recorded_trace_metadata",
        "Trace source-tool pair is undeclared",
        "A supplied trace source-tool pair is not present in the declared flow inventory.",
        "Review the declaration and the provenance of the local trace.",
    ),
    "TW-TRACE-004": RuleDefinition(
        "TW-TRACE-004",
        "pre_recorded_trace_metadata",
        "Trace matches a deny decision",
        "A supplied trace call matches a deterministic deny policy decision.",
        "Investigate the mismatch through the human review process; TrustWeave takes no action.",
    ),
    "TW-TRACE-005": RuleDefinition(
        "TW-TRACE-005",
        "pre_recorded_trace_metadata",
        "Trace requires approval evidence",
        "A supplied trace call matches a deterministic require_approval policy decision.",
        "Verify the relevant approval evidence outside TrustWeave’s local metadata boundary.",
    ),
}

RULES: Final[Mapping[str, RuleDefinition]] = MappingProxyType(_RULES)


def get_rule(identifier: str) -> RuleDefinition:
    """Return authoritative metadata for one built-in finding identifier."""

    try:
        return RULES[identifier]
    except KeyError as error:
        raise ValueError(f"unknown built-in TrustWeave rule: {identifier}") from error


def finding_for_rule(
    identifier: str,
    severity: str,
    message: str,
    *,
    subject: Mapping[str, str | Sequence[str]] | None = None,
    location: Mapping[str, str] | None = None,
    references: Sequence[Mapping[str, str]] = (),
    properties: Mapping[str, str | bool | int | Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Build one canonical finding enriched from the authoritative built-in rule registry."""

    from trustweave.findings import finding

    rule = get_rule(identifier)
    return finding(
        identifier,
        severity,
        message,
        rule.evidence_kind,
        subject=subject,
        location=location,
        references=references,
        properties=properties,
    )
