"""Deterministic, local risk management for existing TrustWeave review artifacts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from trustweave.io import canonical_json
from trustweave.models import ValidationError, reject_unknown_fields
from trustweave.provenance import add_generated_at

RISK_REVIEW_SCHEMA_VERSION = "trustweave.dev/risk-review/v1alpha1"
RISK_BASELINE_SCHEMA_VERSION = "trustweave.dev/risk-baseline/v1alpha1"
RISK_SUPPRESSIONS_SCHEMA_VERSION = "trustweave.dev/risk-suppressions/v1alpha1"
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {severity: index for index, severity in enumerate(VALID_SEVERITIES)}
_LEGACY_SEVERITY_MAP = {"review": "medium"}


@dataclass(frozen=True)
class CanonicalFinding:
    """One reviewer-facing finding normalized from a local TrustWeave artifact."""

    artifact_schema_version: str
    identifier: str
    severity: str
    message: str
    fingerprint: str

    def as_dict(self) -> dict[str, str]:
        return {
            "artifact_schema_version": self.artifact_schema_version,
            "id": self.identifier,
            "severity": self.severity,
            "message": self.message,
            "fingerprint": self.fingerprint,
        }


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{path} must be a list")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _fingerprint(schema_version: str, identifier: str, severity: str, message: str) -> str:
    material = {
        "artifact_schema_version": schema_version,
        "id": identifier,
        "severity": severity,
        "message": message,
    }
    return sha256(canonical_json(material).encode("utf-8")).hexdigest()


def normalize_findings(artifact: Mapping[str, Any]) -> tuple[CanonicalFinding, ...]:
    """Normalize a generated local review artifact without adding external context."""

    schema_version = _text(artifact.get("schema_version"), "artifact.schema_version")
    raw_findings = _sequence(artifact.get("findings"), "artifact.findings")
    findings: list[CanonicalFinding] = []
    for index, raw_finding in enumerate(raw_findings):
        finding = _mapping(raw_finding, f"artifact.findings[{index}]")
        identifier = _text(finding.get("id"), f"artifact.findings[{index}].id")
        severity = _text(finding.get("severity"), f"artifact.findings[{index}].severity")
        severity = _LEGACY_SEVERITY_MAP.get(severity, severity)
        if severity not in SEVERITY_RANK:
            raise ValidationError(
                f"artifact.findings[{index}].severity must be one of {list(VALID_SEVERITIES)}"
            )
        message = _text(finding.get("message"), f"artifact.findings[{index}].message")
        findings.append(
            CanonicalFinding(
                artifact_schema_version=schema_version,
                identifier=identifier,
                severity=severity,
                message=message,
                fingerprint=_fingerprint(schema_version, identifier, severity, message),
            )
        )
    return tuple(sorted(findings, key=lambda item: (item.fingerprint, item.identifier)))


def _timestamp(value: Any, path: str) -> datetime:
    text = _text(value, path)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{path} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValidationError(f"{path} must include a UTC offset")
    return parsed.astimezone(UTC)


def _expiry_entries(
    document: Mapping[str, Any] | None,
    schema_version: str,
    collection_name: str,
) -> dict[str, tuple[str, datetime]]:
    if document is None:
        return {}
    root = _mapping(document, collection_name)
    reject_unknown_fields(root, {"schema_version", collection_name}, collection_name)
    if root.get("schema_version") != schema_version:
        raise ValidationError(f"{collection_name}.schema_version must be {schema_version}")
    entries: dict[str, tuple[str, datetime]] = {}
    for index, raw_entry in enumerate(_sequence(root.get(collection_name), collection_name)):
        entry = _mapping(raw_entry, f"{collection_name}[{index}]")
        reject_unknown_fields(
            entry,
            {"fingerprint", "reason", "expires_at"},
            f"{collection_name}[{index}]",
        )
        fingerprint = _text(entry.get("fingerprint"), f"{collection_name}[{index}].fingerprint")
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValidationError(
                f"{collection_name}[{index}].fingerprint must be a SHA-256 hex digest"
            )
        if fingerprint in entries:
            raise ValidationError(
                f"{collection_name} contains duplicate fingerprint: {fingerprint}"
            )
        entries[fingerprint] = (
            _text(entry.get("reason"), f"{collection_name}[{index}].reason"),
            _timestamp(entry.get("expires_at"), f"{collection_name}[{index}].expires_at"),
        )
    return entries


def _status_for(
    finding: CanonicalFinding,
    baseline: Mapping[str, tuple[str, datetime]],
    suppressions: Mapping[str, tuple[str, datetime]],
    reviewed_at: datetime,
) -> tuple[str, str | None, str | None]:
    if finding.fingerprint in suppressions:
        reason, expires_at = suppressions[finding.fingerprint]
        return (
            "suppressed" if expires_at >= reviewed_at else "expired_suppression",
            reason,
            expires_at.isoformat(),
        )
    if finding.fingerprint in baseline:
        reason, expires_at = baseline[finding.fingerprint]
        return (
            "baselined" if expires_at >= reviewed_at else "expired_baseline",
            reason,
            expires_at.isoformat(),
        )
    return "new", None, None


def review_risks(
    artifacts: Sequence[Mapping[str, Any]],
    baseline_document: Mapping[str, Any] | None = None,
    suppressions_document: Mapping[str, Any] | None = None,
    reviewed_at: str | None = None,
) -> dict[str, Any]:
    """Evaluate local review findings against explicit expiry-enforced risk decisions."""

    reviewed_timestamp = _timestamp(reviewed_at, "reviewed_at") if reviewed_at else None
    if reviewed_timestamp is None:
        raise ValidationError("reviewed_at must be supplied by the application boundary")
    baseline = _expiry_entries(baseline_document, RISK_BASELINE_SCHEMA_VERSION, "baseline")
    suppressions = _expiry_entries(
        suppressions_document, RISK_SUPPRESSIONS_SCHEMA_VERSION, "suppressions"
    )
    canonical_findings = tuple(
        finding for artifact in artifacts for finding in normalize_findings(artifact)
    )
    entries: list[dict[str, Any]] = []
    for finding in sorted(canonical_findings, key=lambda item: (item.fingerprint, item.identifier)):
        status, reason, expires_at = _status_for(
            finding, baseline, suppressions, reviewed_timestamp
        )
        entry = {**finding.as_dict(), "risk_state": status}
        if reason is not None:
            entry["reason"] = reason
        if expires_at is not None:
            entry["expires_at"] = expires_at
        entries.append(entry)

    states = Counter(str(entry["risk_state"]) for entry in entries)
    active = [
        entry
        for entry in entries
        if entry["risk_state"] in {"new", "expired_baseline", "expired_suppression"}
    ]
    review: dict[str, Any] = {
        "schema_version": RISK_REVIEW_SCHEMA_VERSION,
        "findings": entries,
        "summary": {
            "findings": len(entries),
            "new": states["new"],
            "baselined": states["baselined"],
            "suppressed": states["suppressed"],
            "expired_baseline": states["expired_baseline"],
            "expired_suppression": states["expired_suppression"],
            "active_by_severity": {
                severity: sum(1 for entry in active if entry["severity"] == severity)
                for severity in VALID_SEVERITIES
            },
            "status": "review_required" if active else "clear",
        },
        "limits": [
            (
                "Risk decisions apply only to supplied local review findings. A baseline or "
                "suppression does not resolve, remediate, waive, or prove the absence of a "
                "security condition."
            ),
            (
                "Expiry is evaluated against supplied generation provenance. TrustWeave does not "
                "contact a ticketing system, authenticate an approver, or enforce a deployed "
                "control."
            ),
        ],
    }
    return add_generated_at(review, reviewed_at)


def should_fail(review: Mapping[str, Any], fail_on: str) -> bool:
    """Return whether active findings meet the configured deterministic severity gate."""

    if fail_on == "none":
        return False
    if fail_on not in SEVERITY_RANK:
        raise ValidationError(f"fail_on must be one of {list(VALID_SEVERITIES)} or none")
    findings = _sequence(review.get("findings"), "risk_review.findings")
    threshold = SEVERITY_RANK[fail_on]
    for index, raw_finding in enumerate(findings):
        finding = _mapping(raw_finding, f"risk_review.findings[{index}]")
        state = _text(finding.get("risk_state"), f"risk_review.findings[{index}].risk_state")
        severity = _text(finding.get("severity"), f"risk_review.findings[{index}].severity")
        if (
            state in {"new", "expired_baseline", "expired_suppression"}
            and SEVERITY_RANK[severity] <= threshold
        ):
            return True
    return False
