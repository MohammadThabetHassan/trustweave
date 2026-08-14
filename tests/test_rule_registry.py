"""Regression coverage for the authoritative built-in review rule registry."""

from __future__ import annotations

import pytest

from trustweave.rules import RULES, finding_for_rule, get_rule
from trustweave.sarif import build_sarif


def test_registry_is_immutable_and_contains_every_builtin_review_family() -> None:
    """Built-in review taxonomy must not be mutable at runtime."""

    assert {identifier.split("-")[1] for identifier in RULES} == {
        "CHAIN",
        "DIFF",
        "MCP",
        "POL",
        "TRACE",
    }
    with pytest.raises(TypeError):
        RULES["TW-TEST-001"] = get_rule("TW-CHAIN-001")  # type: ignore[index]


def test_registry_rejects_unknown_builtin_identifier() -> None:
    """Producers cannot silently emit an unregistered built-in finding identifier."""

    with pytest.raises(ValueError, match="unknown built-in TrustWeave rule"):
        get_rule("TW-UNKNOWN-001")


def test_registry_backed_finding_enriches_canonical_contract() -> None:
    """A producer gets its stable reviewer guidance from the single registry."""

    finding = finding_for_rule(
        "TW-CHAIN-001",
        "high",
        "A supplied declared path requires human review.",
        subject={"path": ("source", "external-tool")},
    )
    rule = get_rule("TW-CHAIN-001")

    assert finding["evidence_kind"] == rule.evidence_kind
    assert finding["id"] == rule.identifier
    assert "title" not in finding
    assert "rationale" not in finding
    assert "remediation" not in finding


def test_sarif_rule_metadata_comes_from_registry() -> None:
    """SARIF guidance must not be reconstructed from an instance-specific finding message."""

    finding = finding_for_rule(
        "TW-CHAIN-001",
        "high",
        "A supplied declared path requires human review.",
        subject={"path": ("source", "external-tool")},
    )
    sarif = build_sarif(
        {
            "chain": (
                "artifacts/chain-review.json",
                {
                    "schema_version": "trustweave.dev/chain-review/v1alpha1",
                    "findings": [finding],
                },
            )
        }
    )

    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    metadata = get_rule("TW-CHAIN-001")
    assert rule["shortDescription"]["text"] == metadata.title
    assert rule["fullDescription"]["text"] == metadata.rationale
    assert rule["help"]["text"] == metadata.remediation
    assert rule["properties"]["trustweaveEvidenceKind"] == metadata.evidence_kind
