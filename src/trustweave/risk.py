"""Deterministic, local risk management for existing TrustWeave review artifacts."""

from __future__ import annotations

from collections import Counter, defaultdict
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
FINGERPRINT_SCHEMA_VERSION = "trustweave/fingerprint/v2"
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {severity: index for index, severity in enumerate(VALID_SEVERITIES)}
_LEGACY_SEVERITY_MAP = {"review": "medium"}

_ARTIFACT_CONTRACTS: dict[str, tuple[str, str]] = {
    "trustweave.dev/policy-review/v1alpha1": ("findings", "declared_configuration"),
    "trustweave.dev/trace-review/v1alpha1": ("findings", "pre_recorded_trace_metadata"),
    "trustweave.dev/mcp-profile-review/v1alpha1": ("findings", "pre_recorded_mcp_metadata"),
    "trustweave.dev/bundle-diff/v1alpha1": ("signals", "configuration_difference"),
}


@dataclass(frozen=True)
class CanonicalFinding:
    """One reviewer-facing finding normalized from a supported local review artifact."""

    artifact_schema_version: str
    evidence_kind: str
    identifier: str
    severity: str
    message: str
    subject: Mapping[str, Any]
    fingerprint: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact_schema_version": self.artifact_schema_version,
            "evidence_kind": self.evidence_kind,
            "id": self.identifier,
            "severity": self.severity,
            "message": self.message,
            "subject": dict(self.subject),
            "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
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


def _stable_subject(value: Any, path: str) -> Mapping[str, Any]:
    """Accept a deliberately small JSON-compatible subject identity without private content."""

    if value is None:
        return {}
    subject = _mapping(value, path)
    normalized: dict[str, Any] = {}
    for key in sorted(subject):
        if not isinstance(key, str):
            raise ValidationError(f"{path}: subject keys must be strings")
        item = subject[key]
        if isinstance(item, str):
            normalized[key] = item
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            if not all(isinstance(part, str) for part in item):
                raise ValidationError(f"{path}.{key} must contain only strings")
            normalized[key] = sorted(set(item))
        else:
            raise ValidationError(f"{path}.{key} must be a string or list of strings")
    return normalized


def _fallback_subject(
    artifact: Mapping[str, Any], schema_version: str, message: str
) -> Mapping[str, Any]:
    """Preserve legacy distinctness when an older artifact has no structured subject."""

    if schema_version == "trustweave.dev/policy-review/v1alpha1":
        policy = artifact.get("policy")
        if isinstance(policy, str):
            return {"policy": policy}
    if schema_version == "trustweave.dev/trace-review/v1alpha1":
        identity = {
            key: artifact[key] for key in ("agent", "policy") if isinstance(artifact.get(key), str)
        }
        if identity:
            return identity
    if schema_version == "trustweave.dev/mcp-profile-review/v1alpha1":
        profile = artifact.get("profile")
        if isinstance(profile, Mapping) and isinstance(profile.get("name"), str):
            return {"profile": profile["name"]}
    if schema_version == "trustweave.dev/bundle-diff/v1alpha1":
        head = artifact.get("head")
        if isinstance(head, Mapping) and isinstance(head.get("agent"), str):
            return {"agent": head["agent"], "legacy_message": message}
    return {"legacy_message": message}


def _fingerprint(
    evidence_kind: str, identifier: str, severity: str, subject: Mapping[str, Any]
) -> str:
    material = {
        "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
        "evidence_kind": evidence_kind,
        "id": identifier,
        "severity": severity,
        "subject": subject,
    }
    return sha256(canonical_json(material).encode("utf-8")).hexdigest()


def normalize_findings(artifact: Mapping[str, Any]) -> tuple[CanonicalFinding, ...]:
    """Normalize one exact supported local review artifact without external side effects."""

    schema_version = _text(artifact.get("schema_version"), "artifact.schema_version")
    contract = _ARTIFACT_CONTRACTS.get(schema_version)
    if contract is None:
        supported = ", ".join(sorted(_ARTIFACT_CONTRACTS))
        raise ValidationError(
            f"artifact.schema_version {schema_version!r} is unsupported for risk review; "
            f"supported schemas: {supported}"
        )
    collection_name, evidence_kind = contract
    raw_findings = _sequence(artifact.get(collection_name), f"artifact.{collection_name}")
    findings: list[CanonicalFinding] = []
    for index, raw_finding in enumerate(raw_findings):
        path = f"artifact.{collection_name}[{index}]"
        finding = _mapping(raw_finding, path)
        identifier = _text(finding.get("id"), f"{path}.id")
        severity = _LEGACY_SEVERITY_MAP.get(
            _text(finding.get("severity"), f"{path}.severity"),
            _text(finding.get("severity"), f"{path}.severity"),
        )
        if severity not in SEVERITY_RANK:
            raise ValidationError(
                f"{path}.severity must be one of {list(VALID_SEVERITIES)} or legacy review"
            )
        message = _text(finding.get("message"), f"{path}.message")
        subject = _stable_subject(finding.get("subject"), f"{path}.subject")
        if not subject:
            subject = _fallback_subject(artifact, schema_version, message)
        findings.append(
            CanonicalFinding(
                artifact_schema_version=schema_version,
                evidence_kind=evidence_kind,
                identifier=identifier,
                severity=severity,
                message=message,
                subject=subject,
                fingerprint=_fingerprint(evidence_kind, identifier, severity, subject),
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
    artifact_paths: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Evaluate local review findings against explicit expiry-enforced risk decisions."""

    reviewed_timestamp = _timestamp(reviewed_at, "reviewed_at") if reviewed_at else None
    if reviewed_timestamp is None:
        raise ValidationError("reviewed_at must be supplied by the application boundary")
    if artifact_paths is not None and len(artifact_paths) != len(artifacts):
        raise ValidationError("artifact_paths must align one-to-one with artifacts")
    baseline = _expiry_entries(baseline_document, RISK_BASELINE_SCHEMA_VERSION, "baseline")
    suppressions = _expiry_entries(
        suppressions_document, RISK_SUPPRESSIONS_SCHEMA_VERSION, "suppressions"
    )
    conflict = sorted(set(baseline) & set(suppressions))
    if conflict:
        raise ValidationError(
            "baseline and suppressions conflict for fingerprint: " + ", ".join(conflict)
        )

    unique_findings: dict[str, CanonicalFinding] = {}
    sources_by_fingerprint: dict[str, set[str]] = defaultdict(set)
    for index, artifact in enumerate(artifacts):
        source_path = artifact_paths[index] if artifact_paths is not None else None
        for finding in normalize_findings(artifact):
            existing = unique_findings.get(finding.fingerprint)
            if existing is None or finding.message < existing.message:
                unique_findings[finding.fingerprint] = finding
            if source_path is not None:
                sources_by_fingerprint[finding.fingerprint].add(source_path)

    entries: list[dict[str, Any]] = []
    for fingerprint, finding in sorted(unique_findings.items()):
        status, reason, expires_at = _status_for(
            finding, baseline, suppressions, reviewed_timestamp
        )
        entry = {**finding.as_dict(), "risk_state": status}
        sources = sorted(sources_by_fingerprint[fingerprint])
        if sources:
            entry["source_artifact_paths"] = sources
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
