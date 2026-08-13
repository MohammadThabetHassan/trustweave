"""Canonical local review-finding contract shared by TrustWeave evidence producers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

FINDING_SCHEMA_VERSION = "trustweave.dev/finding/v1alpha1"
VALID_FINDING_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "review"})


@dataclass(frozen=True)
class LocalFinding:
    """One immutable, non-executing review observation with optional structured evidence."""

    identifier: str
    severity: str
    message: str
    evidence_kind: str
    subject: Mapping[str, str | tuple[str, ...]] = field(default_factory=dict)
    location: Mapping[str, str] | None = None
    references: tuple[Mapping[str, str], ...] = ()
    properties: Mapping[str, str | bool | tuple[str, ...]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Render deterministic JSON while omitting unavailable optional fields."""

        result: dict[str, Any] = {
            "id": self.identifier,
            "severity": self.severity,
            "message": self.message,
            "evidence_kind": self.evidence_kind,
        }
        if self.subject:
            result["subject"] = _ordered_mapping(self.subject)
        if self.location:
            result["location"] = _ordered_mapping(self.location)
        if self.references:
            result["references"] = [
                _ordered_mapping(reference)
                for reference in sorted(
                    self.references, key=lambda item: tuple(sorted(item.items()))
                )
            ]
        if self.properties:
            result["properties"] = _ordered_mapping(self.properties)
        return result


def _ordered_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize safe scalar metadata into deterministic JSON-compatible values."""

    normalized: dict[str, Any] = {}
    for key in sorted(value):
        item = value[key]
        normalized[key] = list(item) if isinstance(item, tuple) else item
    return normalized


def finding(
    identifier: str,
    severity: str,
    message: str,
    evidence_kind: str,
    *,
    subject: Mapping[str, str | Sequence[str]] | None = None,
    properties: Mapping[str, str | bool | Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Build one canonical local finding from safe, already-declared metadata only."""

    if severity not in VALID_FINDING_SEVERITIES:
        raise ValueError(f"unsupported canonical finding severity: {severity}")
    normalized_subject = {
        key: tuple(sorted(value))
        if isinstance(value, Sequence) and not isinstance(value, str)
        else value
        for key, value in (subject or {}).items()
    }
    normalized_properties = {
        key: tuple(sorted(value))
        if isinstance(value, Sequence) and not isinstance(value, str)
        else value
        for key, value in (properties or {}).items()
    }
    return LocalFinding(
        identifier=identifier,
        severity=severity,
        message=message,
        evidence_kind=evidence_kind,
        subject=normalized_subject,
        properties=normalized_properties,
    ).as_dict()
