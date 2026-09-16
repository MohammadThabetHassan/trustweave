"""Assertion strength for the refusal that keeps two risks from becoming one.

The risk fingerprint is (evidence kind, id, subject) and deliberately excludes wording.
So a producer that emits two findings sharing an identifier and a subject but differing
in reviewer-facing text is asserting they are one risk, and keeping either one silently
is how a policy review with seven findings became a risk review with four.

`_reject_indistinct_findings` compares the wording to catch exactly that. Each optional
field is folded through `or ""` so that an absent field and an empty one compare equal.
Mutation testing showed the fold unasserted per field: replacing `or` with `and`
collapses every present value to the empty string, which makes two findings that differ
only in that field compare equal again -- reinstating the silent drop this refusal
exists to prevent. Each field is therefore exercised on its own.
"""

from __future__ import annotations

from typing import Any

import pytest

from trustweave import risk as risk_module
from trustweave.models import ValidationError

IDENTIFIER = "TW-DISTINCT-001"
SUBJECT: dict[str, Any] = {"policy": "support"}


def _finding(**overrides: Any) -> risk_module.CanonicalFinding:
    fields: dict[str, Any] = {
        "artifact_schema_version": "trustweave.dev/policy-review/v1alpha2",
        "evidence_kind": "declared_configuration",
        "identifier": IDENTIFIER,
        "severity": "high",
        "message": "Stable reviewer text.",
        "subject": dict(SUBJECT),
        "fingerprint": "a" * 64,
    }
    fields.update(overrides)
    return risk_module.CanonicalFinding(**fields)


def test_two_identical_findings_are_one_risk() -> None:
    """Repeating an identical observation stays legal: identical text is one risk."""

    risk_module._reject_indistinct_findings([_finding(), _finding()], "findings")


def test_findings_differing_only_in_message_are_refused() -> None:
    findings = [_finding(), _finding(message="Different reviewer text.")]

    with pytest.raises(ValidationError):
        risk_module._reject_indistinct_findings(findings, "findings")


@pytest.mark.parametrize("field", ["title", "rationale", "remediation"])
def test_findings_differing_only_in_one_optional_field_are_refused(field: str) -> None:
    """Each optional field distinguishes on its own.

    Folding a present value to the empty string -- which is what `and` does here --
    makes these two findings compare equal, and the second is dropped without a word.
    """

    findings = [_finding(), _finding(**{field: "only this differs"})]

    with pytest.raises(ValidationError):
        risk_module._reject_indistinct_findings(findings, "findings")


@pytest.mark.parametrize("field", ["title", "rationale", "remediation"])
def test_an_absent_optional_field_compares_equal_to_an_empty_one(field: str) -> None:
    """`or ""`: absent and empty are the same presentation, so this is one risk."""

    findings = [_finding(), _finding(**{field: ""})]

    risk_module._reject_indistinct_findings(findings, "findings")


def test_the_refusal_names_the_collection_the_identifier_and_the_remedy() -> None:
    """The message is what a producer acts on, so every part of it is asserted."""

    findings = [_finding(), _finding(title="only this differs")]

    with pytest.raises(ValidationError) as raised:
        risk_module._reject_indistinct_findings(findings, "policy_findings")

    message = str(raised.value)
    assert "artifact.policy_findings" in message, "the message names the collection it read"
    assert IDENTIFIER in message, "the message names the identifier that collided"
    assert "the risk fingerprint excludes wording" in message
    assert "producer must give each finding a distinguishing subject" in message


def test_findings_with_different_subjects_are_distinct_risks() -> None:
    findings = [_finding(), _finding(subject={"policy": "billing"}, title="other")]

    risk_module._reject_indistinct_findings(findings, "findings")


def test_findings_with_different_identifiers_are_distinct_risks() -> None:
    findings = [_finding(), _finding(identifier="TW-DISTINCT-002", title="other")]

    risk_module._reject_indistinct_findings(findings, "findings")
