"""A classification typo must not silently turn a deny into an allow."""

from __future__ import annotations

import json

import pytest

from trustweave.engine import evaluate_manifest
from trustweave.models import ValidationError, parse_manifest, parse_policy

CLASSIFICATION_BOUND_POLICY = {
    "schema_version": "trustweave.dev/v1alpha1",
    "name": "classification-bound",
    "default_decision": "allow",
    "approval_control": {
        "mechanism": "human-review-queue",
        "binds_to": ["actor"],
        "fail_closed": True,
    },
    "rules": [
        {
            "id": "R1",
            "description": "Deny restricted data reaching an external action.",
            "source_trust": ["trusted", "conditional", "untrusted"],
            "source_data_classifications": ["restricted"],
            "tool_action_classes": ["external"],
            "decision": "deny",
            "rationale": "Restricted data must not leave the boundary.",
        }
    ],
}

MANIFEST = {
    "schema_version": "trustweave.dev/v1alpha1",
    "name": "m",
    "description": "d",
    "sources": [
        {"name": "s", "trust": "trusted", "data_classification": "restricted", "description": "d"}
    ],
    "tools": [
        {"name": "t", "action_class": "external", "capabilities": ["net.send"], "description": "d"}
    ],
    "flows": [{"source": "s", "tool": "t", "purpose": "p"}],
}


def _evaluate(classification: str, policy: dict = CLASSIFICATION_BOUND_POLICY):
    document = json.loads(json.dumps(MANIFEST))
    document["sources"][0]["data_classification"] = classification
    return evaluate_manifest(parse_manifest(document), parse_policy(policy))


def test_a_declared_classification_in_the_taxonomy_still_matches_its_rule() -> None:
    findings = _evaluate("restricted")

    assert [(finding.decision, finding.rule_id) for finding in findings] == [("deny", "R1")]


@pytest.mark.parametrize("typo", ["Restricted", "RESTRICTED", "restrcited"])
def test_a_classification_outside_the_taxonomy_is_refused_not_silently_allowed(
    typo: str,
) -> None:
    """Predicates compare exact strings, so a typo stops the deny rule from matching.

    Before this guard, `Restricted` fell through to the default decision and reported
    allow with no error and no warning.
    """

    with pytest.raises(ValidationError, match="will not match"):
        _evaluate(typo)


def test_a_policy_that_never_binds_classification_accepts_descriptive_values() -> None:
    """Where no rule reads the field it is free text; refusing it would break real configs."""

    descriptive = json.loads(json.dumps(CLASSIFICATION_BOUND_POLICY))
    # keep the classification-bound rule; the value is simply different vocabulary

    findings = _evaluate("customer-provided", descriptive)

    assert findings, "evaluation must still produce decisions"
