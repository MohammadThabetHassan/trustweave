"""Deterministic static review for TrustWeave ordered flow policies."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from itertools import product
from math import prod
from typing import Any, cast

from trustweave.models import Policy, PolicyRule
from trustweave.policy_predicates import rule_covers, rule_is_possible
from trustweave.provenance import add_generated_at
from trustweave.rules import finding_for_rule

REVIEW_ACTION_CLASSES = frozenset({"sensitive", "external"})
REQUIRED_APPROVAL_BINDINGS = frozenset(
    {"actor", "tool", "target", "parameters", "issued_at", "expires_at"}
)
# Rule fields whose subject carries exactly one value, so a rule naming several is the
# union of one cell per value. These are the fields a collective cover is enumerated over.
_CELL_FIELDS = (
    "source_trust",
    "tool_action_classes",
    "source_identifiers",
    "tool_identifiers",
    "source_data_classifications",
)
# The enumeration is declined above this many cells and the pairwise answer stands. The
# artifact says which happened: `cover_search` is "declined" rather than "complete", since
# a declined enumeration is the one case where "no cover found" was not actually looked
# for, and `reachable: true` on its own would read as a verdict.
MAX_COVERAGE_CELLS = 10_000


def _covering_rules(
    earlier: Sequence[PolicyRule], later: PolicyRule, policy: Policy
) -> tuple[str | None, list[str], bool]:
    """Return (single covering rule id, every rule in the cover, whether the search ran).

    A single covering rule was the only kind looked for, and absence of one was reported
    as ``reachable: true``. Three allow rules, one per trust label, followed by a deny rule
    naming all three, left the deny rule unreachable with no finding and a clear review.
    The later rule is therefore split into one cell per combination of the single-valued
    fields it names, and it is shadowed when every cell has some earlier rule covering it.
    That is exact for those fields; the pairwise coverage test decides the rest, so a
    cover it cannot see still reports the rule as reachable. Both ids are returned so the
    artifact keeps naming the single shadowing rule where there is one.
    """

    possible = [rule for rule in earlier if rule_is_possible(rule, policy)]
    single = next((rule for rule in possible if rule_covers(rule, later, policy)), None)
    if single is not None:
        return single.id, [single.id], True
    if not possible:
        return None, [], True
    fields = [name for name in _CELL_FIELDS if getattr(later, name)]
    domains = [getattr(later, name) for name in fields]
    if prod(len(domain) for domain in domains) > MAX_COVERAGE_CELLS:
        return None, [], False
    used: set[str] = set()
    for values in product(*domains):
        narrowed = {name: (value,) for name, value in zip(fields, values, strict=True)}
        cell = replace(later, **cast(dict[str, Any], narrowed))
        cover = next((rule for rule in possible if rule_covers(rule, cell, policy)), None)
        if cover is None:
            return None, [], True
        used.add(cover.id)
    return None, sorted(used), True


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
    rules_by_id = {rule.id: rule for rule in policy.rules}
    for later_index, later_rule in enumerate(policy.rules):
        single_id, covering_ids, searched = _covering_rules(
            policy.rules[:later_index], later_rule, policy
        )
        shadowing_rule = rules_by_id[single_id] if single_id is not None else None
        impossible = not rule_is_possible(later_rule, policy)
        if include_coverage:
            coverage_rules[later_rule.id] = {
                "reachable": not covering_ids and not impossible,
                "possible": not impossible,
                "shadowed_by": single_id,
                "shadowed_by_rules": covering_ids,
                "cover_search": "complete" if searched else "declined",
                "decision": later_rule.decision,
            }
        if shadowing_rule is None and covering_ids:
            named = ", ".join(covering_ids)
            findings.append(
                {
                    "severity": "review",
                    "id": "TW-POL-002",
                    "message": (
                        f"Rule {later_rule.id} is shadowed by earlier rules {named} together "
                        "under first-match semantics and cannot determine a decision."
                    ),
                }
            )
            if {rules_by_id[rule_id].decision for rule_id in covering_ids} != {later_rule.decision}:
                findings.append(
                    {
                        "severity": "review",
                        "id": "TW-POL-007",
                        "message": (
                            f"Rule {later_rule.id} conflicts with shadowing rules {named}: "
                            "their declared decisions differ."
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "review",
                        "id": "TW-POL-009",
                        "message": (
                            f"Rule {later_rule.id} is redundant because shadowing rules {named} "
                            "all specify the same decision."
                        ),
                    }
                )
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
            if shadowing_rule.decision != later_rule.decision:
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
            else:
                findings.append(
                    {
                        "severity": "review",
                        "id": "TW-POL-009",
                        "message": (
                            f"Rule {later_rule.id} is redundant because shadowing rule "
                            f"{shadowing_rule.id} specifies the same decision."
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
                rule_id for rule_id, result in coverage_rules.items() if result["shadowed_by_rules"]
            ),
            "impossible_rules": sorted(
                rule_id for rule_id, result in coverage_rules.items() if result["possible"] is False
            ),
        }
    return add_generated_at(review, generated_at)
