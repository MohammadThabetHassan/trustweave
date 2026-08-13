"""Deterministic static review for TrustWeave ordered flow policies."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from trustweave.models import Policy, PolicyRule

REVIEW_ACTION_CLASSES = frozenset({"sensitive", "external"})


def _covers(first: PolicyRule, later: PolicyRule) -> bool:
    """Return whether an earlier ordered rule matches every combination of a later rule."""

    return set(later.source_trust).issubset(first.source_trust) and set(
        later.tool_action_classes
    ).issubset(first.tool_action_classes)


def review_policy(policy: Policy) -> dict[str, Any]:
    """Review deterministic policy structure without calling an agent or policy engine."""

    findings: list[dict[str, str]] = []
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

    for later_index, later_rule in enumerate(policy.rules):
        for earlier_rule in policy.rules[:later_index]:
            if _covers(earlier_rule, later_rule):
                findings.append(
                    {
                        "severity": "review",
                        "id": "TW-POL-002",
                        "message": (
                            f"Rule {later_rule.id} is shadowed by earlier rule {earlier_rule.id} "
                            "under first-match semantics and cannot determine a decision."
                        ),
                    }
                )
                break
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

    return {
        "schema_version": "trustweave.dev/policy-review/v1alpha1",
        "generated_at": datetime.now(UTC).isoformat(),
        "policy": policy.name,
        "findings": findings,
        "summary": {
            "rules": len(policy.rules),
            "review_findings": len(findings),
            "status": "review_required" if findings else "clear",
        },
        "limits": [
            (
                "The review checks only deterministic structure and declared labels; it does not "
                "prove a policy is complete, authorized, or effective in a deployed runtime."
            ),
            (
                "Findings indicate review obligations rather than vulnerabilities, compliance "
                "conclusions, or automatic approval decisions."
            ),
        ],
    }
