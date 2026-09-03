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


def test_the_refusal_names_the_declared_value_and_the_intended_one() -> None:
    """A reviewer needs to see both halves to fix the manifest without guessing."""

    with pytest.raises(ValidationError) as raised:
        _evaluate("Restricted")

    message = str(raised.value)
    assert "'Restricted'" in message
    assert "'restricted'" in message
    assert "classification_taxonomy" in message


def test_every_suspect_classification_is_listed_not_just_the_first() -> None:
    document = json.loads(json.dumps(MANIFEST))
    document["sources"] = [
        {"name": "a", "trust": "trusted", "data_classification": "Restricted", "description": "d"},
        {
            "name": "b",
            "trust": "trusted",
            "data_classification": "Confidential",
            "description": "d",
        },
    ]
    document["flows"] = [{"source": "a", "tool": "t", "purpose": "p"}]

    with pytest.raises(ValidationError) as raised:
        evaluate_manifest(parse_manifest(document), parse_policy(CLASSIFICATION_BOUND_POLICY))

    message = str(raised.value)
    assert "'Restricted'" in message
    assert "'Confidential'" in message


def test_a_value_that_is_merely_different_vocabulary_is_not_treated_as_a_typo() -> None:
    """`customer-provided` is not a misspelling of anything in the taxonomy."""

    findings = _evaluate("customer-provided")

    assert findings, "a descriptive classification must not block evaluation"


def _ordered_policy(bound: str) -> dict:
    """A v1alpha2 policy whose rule uses one ordered classification bound.

    The ordered bounds only exist under the v1alpha2 policy schema. Building this on
    v1alpha1 makes parse_policy reject the field, and a test asserting ValidationError
    would then pass on the schema rejection rather than on the behaviour under test.
    """

    policy = json.loads(json.dumps(CLASSIFICATION_BOUND_POLICY))
    policy["schema_version"] = "trustweave.dev/policy/v1alpha2"
    policy["rules"][0].pop("source_data_classifications")
    policy["rules"][0][bound] = "confidential"
    return policy


def test_an_at_least_bound_also_arms_the_check() -> None:
    """Ordered classification predicates read the field just as exact lists do."""

    ordered = _ordered_policy("source_data_classification_at_least")

    # Guard against the test passing on a schema rejection instead of the guard.
    assert parse_policy(ordered).rules[0].source_data_classification_at_least == "confidential"
    with pytest.raises(ValidationError, match="will not match"):
        _evaluate("Restricted", ordered)


def test_a_policy_without_any_classification_predicate_never_refuses() -> None:
    unbound = json.loads(json.dumps(CLASSIFICATION_BOUND_POLICY))
    unbound["rules"][0].pop("source_data_classifications")

    assert _evaluate("Restricted", unbound), "no rule reads the field, so nothing can silently fail"


def test_an_at_most_bound_alone_also_arms_the_check() -> None:
    """Either ordered bound reads the field, so either alone must arm the guard."""

    ordered = _ordered_policy("source_data_classification_at_most")

    assert parse_policy(ordered).rules[0].source_data_classification_at_most == "confidential"
    with pytest.raises(ValidationError, match="will not match"):
        _evaluate("Restricted", ordered)


def test_a_valid_source_before_a_suspect_one_does_not_end_the_scan() -> None:
    """Every source is examined; an early valid declaration must not stop the search."""

    document = json.loads(json.dumps(MANIFEST))
    document["sources"] = [
        {"name": "ok", "trust": "trusted", "data_classification": "restricted", "description": "d"},
        {
            "name": "bad",
            "trust": "trusted",
            "data_classification": "Confidential",
            "description": "d",
        },
    ]
    document["flows"] = [{"source": "ok", "tool": "t", "purpose": "p"}]

    with pytest.raises(ValidationError, match="Confidential"):
        evaluate_manifest(parse_manifest(document), parse_policy(CLASSIFICATION_BOUND_POLICY))


def test_the_refusal_message_is_exact() -> None:
    """Pin the whole sentence: a reviewer acts on this text, so it is a contract."""

    with pytest.raises(ValidationError) as raised:
        _evaluate("Restricted")

    assert str(raised.value) == (
        "manifest declares data classifications the policy will not match: "
        "'Restricted' looks like 'restricted'. Classification predicates compare exact "
        "strings, so this would silently fall through to the default decision. Correct "
        "the manifest, or declare the value in the policy's classification_taxonomy."
    )


def test_multiple_suspects_are_joined_with_a_semicolon() -> None:
    document = json.loads(json.dumps(MANIFEST))
    document["sources"] = [
        {"name": "a", "trust": "trusted", "data_classification": "Restricted", "description": "d"},
        {
            "name": "b",
            "trust": "trusted",
            "data_classification": "Confidential",
            "description": "d",
        },
    ]
    document["flows"] = [{"source": "a", "tool": "t", "purpose": "p"}]

    with pytest.raises(ValidationError) as raised:
        evaluate_manifest(parse_manifest(document), parse_policy(CLASSIFICATION_BOUND_POLICY))

    assert "'Restricted' looks like 'restricted'; 'Confidential' looks like 'confidential'" in str(
        raised.value
    )
