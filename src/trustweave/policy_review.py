"""Deterministic static review for TrustWeave ordered flow policies."""

from __future__ import annotations

from typing import Any

from trustweave.models import Policy
from trustweave.policy_predicates import rule_covers, rule_is_possible
from trustweave.provenance import add_generated_at
from trustweave.rules import finding_for_rule

REVIEW_ACTION_CLASSES = frozenset({"sensitive", "external"})
REQUIRED_APPROVAL_BINDINGS = frozenset(
    {"actor", "tool", "target", "parameters", "issued_at", "expires_at"}
)


def review_policy(
    policy: Policy, generated_at: str | None = None, *, include_coverage: bool = False
) -> dict[str, Any]:
    """Review policy structure with optional application-layer provenance."""

    findings: list[dict[str, Any]] = []
    if policy.default_decision == "allow":
        findings.append(
            {
                "severity": "review",
                "id": "TW-POL-001",
                "message": (
                    "The policy default decision is allow. Unmatched declared paths will be "
                    "allowed and require explicit human review."
                ),
            }
        )

    coverage_rules: dict[str, dict[str, object]] = {}
    for later_index, later_rule in enumerate(policy.rules):
        shadowing_rule = next(
            (
                earlier_rule
                for earlier_rule in policy.rules[:later_index]
                if rule_covers(earlier_rule, later_rule, policy)
            ),
            None,
        )
        impossible = not rule_is_possible(later_rule, policy)
        if include_coverage:
            coverage_rules[later_rule.id] = {
                "reachable": shadowing_rule is None and not impossible,
                "possible": not impossible,
                "shadowed_by": shadowing_rule.id if shadowing_rule is not None else None,
                "decision": later_rule.decision,
            }
        if shadowing_rule is not None:
            findings.append(
                {
                    "severity": "review",
                    "id": "TW-POL-002",
                    "message": (
                        f"Rule {later_rule.id} is shadowed by earlier rule {shadowing_rule.id} "
                        "under first-match semantics and cannot determine a decision."
                    ),
                }
            )
            if include_coverage and shadowing_rule.decision != later_rule.decision:
                findings.append(
                    {
                        "severity": "review",
                        "id": "TW-POL-007",
                        "message": (
                            f"Rule {later_rule.id} conflicts with shadowing rule "
                            f"{shadowing_rule.id}: their declared decisions differ."
                        ),
                    }
                )
        if include_coverage and impossible:
            findings.append(
                {
                    "severity": "review",
                    "id": "TW-POL-008",
                    "message": (
                        f"Rule {later_rule.id} requires declared controls that this policy does "
                        "not provide and cannot determine a decision."
                    ),
                }
            )
        if (
            later_rule.decision == "allow"
            and "untrusted" in later_rule.source_trust
            and REVIEW_ACTION_CLASSES.intersection(later_rule.tool_action_classes)
        ):
            findings.append(
                {
                    "severity": "review",
                    "id": "TW-POL-003",
                    "message": (
                        f"Rule {later_rule.id} allows untrusted input to a sensitive or external "
                        "action class; review its authorization and human-control boundary."
                    ),
                }
            )

    high_impact_approval_rules = tuple(
        rule
        for rule in policy.rules
        if rule.decision == "require_approval"
        and REVIEW_ACTION_CLASSES.intersection(rule.tool_action_classes)
    )
    approval_control = policy.approval_control
    missing_bindings: tuple[str, ...] = ()
    if high_impact_approval_rules and approval_control is None:
        findings.append(
            {
                "severity": "review",
                "id": "TW-POL-004",
                "message": (
                    "Sensitive or external paths require approval, but the policy does not declare "
                    "an approval control that reviewers can inspect."
                ),
            }
        )
    if high_impact_approval_rules and approval_control is not None:
        missing_bindings = tuple(
            sorted(REQUIRED_APPROVAL_BINDINGS - set(approval_control.binds_to))
        )
        if missing_bindings:
            findings.append(
                {
                    "severity": "review",
                    "id": "TW-POL-005",
                    "message": (
                        "The declared approval control does not bind approvals to: "
                        f"{', '.join(missing_bindings)}."
                    ),
                }
            )
        if not approval_control.fail_closed:
            findings.append(
                {
                    "severity": "review",
                    "id": "TW-POL-006",
                    "message": (
                        "The declared approval control is not fail-closed when approval state "
                        "cannot be validated."
                    ),
                }
            )

    canonical_findings = [
        finding_for_rule(
            str(item["id"]),
            str(item["severity"]),
            str(item["message"]),
            subject=item.get("subject", {"policy": policy.name}),
        )
        for item in findings
    ]

    approval_summary: dict[str, Any] = {
        "high_impact_approval_rules": [rule.id for rule in high_impact_approval_rules],
        "declared": approval_control is not None,
    }
    if approval_control is not None:
        approval_summary.update(
            {
                "mechanism": approval_control.mechanism,
                "binds_to": list(approval_control.binds_to),
                "fail_closed": approval_control.fail_closed,
                "missing_required_bindings": list(missing_bindings),
            }
        )

    review: dict[str, object] = {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "policy": policy.name,
        "approval_control": approval_summary,
        "findings": canonical_findings,
        "summary": {
            "rules": len(policy.rules),
            "review_findings": len(canonical_findings),
            "status": "review_required" if canonical_findings else "clear",
        },
        "limits": [
            (
                "The review checks only deterministic structure and declared labels; it does not "
                "prove an approval mechanism exists, authenticate approvers, or authorize a "
                "deployed runtime."
            ),
            (
                "Findings indicate review obligations rather than vulnerabilities, compliance "
                "conclusions, or automatic approval decisions."
            ),
        ],
    }
    if include_coverage:
        review["coverage"] = {
            "rules": coverage_rules,
            "shadowed_rules": sorted(
                rule_id
                for rule_id, result in coverage_rules.items()
                if result["shadowed_by"] is not None
            ),
            "impossible_rules": sorted(
                rule_id for rule_id, result in coverage_rules.items() if result["possible"] is False
            ),
        }
    return add_generated_at(review, generated_at)
