"""Deterministic, local risk management for existing TrustWeave review artifacts."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from types import MappingProxyType
from typing import Any

from trustweave.io import canonical_json
from trustweave.models import ValidationError, reject_unknown_fields, validate_rule_identifier
from trustweave.provenance import add_generated_at

LEGACY_RISK_REVIEW_SCHEMA_VERSION = "trustweave.dev/risk-review/v1alpha1"
RISK_REVIEW_SCHEMA_VERSION = "trustweave.dev/risk-review/v1alpha2"
RISK_BASELINE_SCHEMA_VERSION = "trustweave.dev/risk-baseline/v1alpha2"
RISK_SUPPRESSIONS_SCHEMA_VERSION = "trustweave.dev/risk-suppressions/v1alpha2"
LEGACY_RISK_BASELINE_SCHEMA_VERSION = "trustweave.dev/risk-baseline/v1alpha1"
LEGACY_RISK_SUPPRESSIONS_SCHEMA_VERSION = "trustweave.dev/risk-suppressions/v1alpha1"
FINGERPRINT_SCHEMA_VERSION = "trustweave/fingerprint/v3"
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {severity: index for index, severity in enumerate(VALID_SEVERITIES)}
ACTIVE_RISK_STATES = frozenset(
    {
        "new",
        "expired_baseline",
        "expired_suppression",
        "not_yet_applicable_baseline",
        "not_yet_applicable_suppression",
        "severity_escalated_baseline",
        "severity_escalated_suppression",
    }
)
_LEGACY_SEVERITY_MAP = {"review": "medium"}
_ORDERED_SUBJECT_FIELDS = frozenset({"path"})

_ARTIFACT_CONTRACTS: dict[str, tuple[str, str]] = {
    "trustweave.dev/policy-review/v1alpha1": ("findings", "declared_configuration"),
    "trustweave.dev/trace-review/v1alpha1": ("findings", "pre_recorded_trace_metadata"),
    "trustweave.dev/mcp-profile-review/v1alpha1": ("findings", "pre_recorded_mcp_metadata"),
    "trustweave.dev/bundle-diff/v1alpha1": ("signals", "configuration_difference"),
    "trustweave.dev/bundle-diff/v1alpha2": ("signals", "configuration_difference"),
    "trustweave.dev/chain-review/v1alpha1": ("findings", "declared_chain_configuration"),
}


@dataclass(frozen=True)
class RiskDecision:
    """One explicit, expiry-bound local baseline or suppression decision."""

    fingerprint: str
    accepted_severity: str
    reason: str
    owner: str
    created_at: datetime
    expires_at: datetime
    rule_id: str
    subject_digest: str
    reference: str | None = None


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
    title: str | None = None
    rationale: str | None = None
    remediation: str | None = None

    def __post_init__(self) -> None:
        """Defensively freeze the normalized, bounded subject identity."""

        frozen_subject = {
            key: tuple(value)
            if isinstance(value, Sequence) and not isinstance(value, str)
            else value
            for key, value in sorted(self.subject.items())
        }
        object.__setattr__(self, "subject", MappingProxyType(frozen_subject))

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "artifact_schema_version": self.artifact_schema_version,
            "evidence_kind": self.evidence_kind,
            "id": self.identifier,
            "severity": self.severity,
            "message": self.message,
            "subject": {
                key: list(value) if isinstance(value, tuple) else value
                for key, value in self.subject.items()
            },
            "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
            "fingerprint": self.fingerprint,
        }
        for name, value in (
            ("title", self.title),
            ("rationale", self.rationale),
            ("remediation", self.remediation),
        ):
            if value is not None:
                result[name] = value
        return result


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


def _optional_text(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _text(value, path)


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
            normalized[key] = list(item) if key in _ORDERED_SUBJECT_FIELDS else sorted(set(item))
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


def _fingerprint(evidence_kind: str, identifier: str, subject: Mapping[str, Any]) -> str:
    """Build v3 identity material without volatile wording or review severity."""

    material = {
        "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
        "evidence_kind": evidence_kind,
        "id": identifier,
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
                fingerprint=_fingerprint(evidence_kind, identifier, subject),
                title=_optional_text(finding.get("title"), f"{path}.title"),
                rationale=_optional_text(finding.get("rationale"), f"{path}.rationale"),
                remediation=_optional_text(finding.get("remediation"), f"{path}.remediation"),
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


def _subject_digest(subject: Mapping[str, Any]) -> str:
    """Bind a decision to the normalized subject identity without retaining mutable content."""

    return sha256(canonical_json(dict(subject)).encode("utf-8")).hexdigest()


def _artifact_path(value: Any, path: str) -> str:
    """Accept literal local provenance paths while excluding empty and control-containing values."""

    normalized = _text(value, path)
    if len(normalized) > 4096 or any(
        ord(character) < 32 or ord(character) == 127 for character in normalized
    ):
        raise ValidationError(f"{path} must be at most 4096 characters without control characters")
    return normalized


def _decision_identity_mismatches(
    finding: CanonicalFinding, decision: RiskDecision
) -> tuple[str, ...]:
    """Return fingerprint-bound identity fields that prevent a reviewer decision from applying."""

    mismatches: list[str] = []
    if decision.rule_id != finding.identifier:
        mismatches.append("rule_id")
    if decision.subject_digest != _subject_digest(finding.subject):
        mismatches.append("subject_digest")
    return tuple(mismatches)


def _decision_entries(
    document: Mapping[str, Any] | None,
    schema_version: str,
    legacy_schema_version: str,
    collection_name: str,
) -> dict[str, RiskDecision]:
    """Parse explicit v1alpha2 reviewer decisions and reject unsafe legacy reinterpretation."""

    if document is None:
        return {}
    root = _mapping(document, collection_name)
    document_schema_version = root.get("schema_version")
    if document_schema_version == legacy_schema_version:
        raise ValidationError(
            f"{collection_name}.schema_version {legacy_schema_version} requires explicit migration "
            f"to {schema_version}"
        )
    reject_unknown_fields(root, {"schema_version", collection_name}, collection_name)
    if document_schema_version != schema_version:
        raise ValidationError(f"{collection_name}.schema_version must be {schema_version}")
    entries: dict[str, RiskDecision] = {}
    required = {
        "fingerprint",
        "fingerprint_schema_version",
        "rule_id",
        "subject_digest",
        "accepted_severity",
        "reason",
        "owner",
        "created_at",
        "expires_at",
        "reference",
    }
    for index, raw_entry in enumerate(_sequence(root.get(collection_name), collection_name)):
        path = f"{collection_name}[{index}]"
        entry = _mapping(raw_entry, path)
        reject_unknown_fields(entry, required, path)
        fingerprint = _text(entry.get("fingerprint"), f"{path}.fingerprint")
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValidationError(f"{path}.fingerprint must be a SHA-256 hex digest")
        if entry.get("fingerprint_schema_version") != FINGERPRINT_SCHEMA_VERSION:
            raise ValidationError(
                f"{path}.fingerprint_schema_version must be {FINGERPRINT_SCHEMA_VERSION}"
            )
        rule_id = validate_rule_identifier(entry.get("rule_id"), f"{path}.rule_id")
        if not rule_id.startswith("TW-"):
            raise ValidationError(f"{path}.rule_id must begin with TW-")
        subject_digest = _text(entry.get("subject_digest"), f"{path}.subject_digest")
        if len(subject_digest) != 64 or any(
            character not in "0123456789abcdef" for character in subject_digest
        ):
            raise ValidationError(f"{path}.subject_digest must be a SHA-256 hex digest")
        accepted_severity = _text(entry.get("accepted_severity"), f"{path}.accepted_severity")
        if accepted_severity not in SEVERITY_RANK:
            raise ValidationError(
                f"{path}.accepted_severity must be one of {list(VALID_SEVERITIES)}"
            )
        created_at = _timestamp(entry.get("created_at"), f"{path}.created_at")
        expires_at = _timestamp(entry.get("expires_at"), f"{path}.expires_at")
        if expires_at <= created_at:
            raise ValidationError(f"{path}.expires_at must be later than created_at")
        if fingerprint in entries:
            raise ValidationError(
                f"{collection_name} contains duplicate fingerprint: {fingerprint}"
            )
        reference = entry.get("reference")
        entries[fingerprint] = RiskDecision(
            fingerprint=fingerprint,
            accepted_severity=accepted_severity,
            reason=_text(entry.get("reason"), f"{path}.reason"),
            owner=_text(entry.get("owner"), f"{path}.owner"),
            created_at=created_at,
            expires_at=expires_at,
            rule_id=rule_id,
            subject_digest=subject_digest,
            reference=_optional_text(reference, f"{path}.reference"),
        )
    return entries


def _stable_metadata(finding: CanonicalFinding) -> tuple[str, str, str, str]:
    """Return the identity fields that must agree within one fingerprint group."""

    return (
        finding.artifact_schema_version,
        finding.evidence_kind,
        finding.identifier,
        canonical_json({"subject": finding.as_dict()["subject"]}),
    )


def _reviewer_selection_key(finding: CanonicalFinding) -> tuple[int, str, str, str, str]:
    """Prefer severity, then lexically select a complete reviewer-facing presentation.

    A lower rank is more severe. Equal-severity variants select the lexical tuple of title,
    message, rationale, and remediation, with absent optional values represented by an empty
    string. This makes reviewer-facing text independent of artifact order without allowing it
    to influence severity.
    """

    return (
        SEVERITY_RANK[finding.severity],
        finding.title or "",
        finding.message,
        finding.rationale or "",
        finding.remediation or "",
    )


def _status_for(
    finding: CanonicalFinding,
    baseline: Mapping[str, RiskDecision],
    suppressions: Mapping[str, RiskDecision],
    reviewed_at: datetime,
) -> tuple[str, str | None, str | None]:
    decision = suppressions.get(finding.fingerprint)
    if decision is not None:
        if _decision_identity_mismatches(finding, decision):
            return "new", None, None
        if decision.created_at > reviewed_at:
            return "not_yet_applicable_suppression", None, None
        if decision.expires_at <= reviewed_at:
            return "expired_suppression", decision.reason, decision.expires_at.isoformat()
        if SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[decision.accepted_severity]:
            return "suppressed", decision.reason, decision.expires_at.isoformat()
        return "severity_escalated_suppression", None, None
    decision = baseline.get(finding.fingerprint)
    if decision is not None:
        if _decision_identity_mismatches(finding, decision):
            return "new", None, None
        if decision.created_at > reviewed_at:
            return "not_yet_applicable_baseline", None, None
        if decision.expires_at <= reviewed_at:
            return "expired_baseline", decision.reason, decision.expires_at.isoformat()
        if SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[decision.accepted_severity]:
            return "baselined", decision.reason, decision.expires_at.isoformat()
        return "severity_escalated_baseline", None, None
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
    baseline = _decision_entries(
        baseline_document,
        RISK_BASELINE_SCHEMA_VERSION,
        LEGACY_RISK_BASELINE_SCHEMA_VERSION,
        "baseline",
    )
    suppressions = _decision_entries(
        suppressions_document,
        RISK_SUPPRESSIONS_SCHEMA_VERSION,
        LEGACY_RISK_SUPPRESSIONS_SCHEMA_VERSION,
        "suppressions",
    )
    conflict = sorted(set(baseline) & set(suppressions))
    if conflict:
        raise ValidationError(
            "baseline and suppressions conflict for fingerprint: " + ", ".join(conflict)
        )

    unique_findings: dict[str, CanonicalFinding] = {}
    sources_by_fingerprint: dict[str, set[str]] = defaultdict(set)
    for index, artifact in enumerate(artifacts):
        source_path = (
            _artifact_path(artifact_paths[index], f"artifact_paths[{index}]")
            if artifact_paths is not None
            else None
        )
        for finding in normalize_findings(artifact):
            existing = unique_findings.get(finding.fingerprint)
            if existing is None:
                unique_findings[finding.fingerprint] = finding
            elif _stable_metadata(existing) != _stable_metadata(finding):
                raise ValidationError(
                    "risk findings with one fingerprint have contradictory stable metadata"
                )
            elif _reviewer_selection_key(finding) < _reviewer_selection_key(existing):
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
    observed_fingerprints = set(unique_findings)
    orphaned_decisions = {
        "baseline": sorted(set(baseline) - observed_fingerprints),
        "suppressions": sorted(set(suppressions) - observed_fingerprints),
    }
    mismatched_decisions = {
        decision_kind: [
            {
                "fingerprint": fingerprint,
                "mismatches": list(
                    _decision_identity_mismatches(unique_findings[fingerprint], decision)
                ),
            }
            for fingerprint, decision in sorted(decisions.items())
            if fingerprint in unique_findings
            and _decision_identity_mismatches(unique_findings[fingerprint], decision)
        ]
        for decision_kind, decisions in (
            ("baseline", baseline),
            ("suppressions", suppressions),
        )
    }
    active = [entry for entry in entries if entry["risk_state"] in ACTIVE_RISK_STATES]
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
            "not_yet_applicable_baseline": states["not_yet_applicable_baseline"],
            "not_yet_applicable_suppression": states["not_yet_applicable_suppression"],
            "severity_escalated_baseline": states["severity_escalated_baseline"],
            "severity_escalated_suppression": states["severity_escalated_suppression"],
            "orphaned_baseline": len(orphaned_decisions["baseline"]),
            "orphaned_suppressions": len(orphaned_decisions["suppressions"]),
            "mismatched_baseline": len(mismatched_decisions["baseline"]),
            "mismatched_suppressions": len(mismatched_decisions["suppressions"]),
            "active_by_severity": {
                severity: sum(1 for entry in active if entry["severity"] == severity)
                for severity in VALID_SEVERITIES
            },
            "status": "review_required" if active else "clear",
        },
        "orphaned_decisions": orphaned_decisions,
        "mismatched_decisions": mismatched_decisions,
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


def validate_decision_document(document: Mapping[str, Any], decision_kind: str) -> None:
    """Validate one local baseline or suppression document without changing or accepting it."""

    if decision_kind == "baseline":
        _decision_entries(
            document,
            RISK_BASELINE_SCHEMA_VERSION,
            LEGACY_RISK_BASELINE_SCHEMA_VERSION,
            "baseline",
        )
        return
    if decision_kind == "suppressions":
        _decision_entries(
            document,
            RISK_SUPPRESSIONS_SCHEMA_VERSION,
            LEGACY_RISK_SUPPRESSIONS_SCHEMA_VERSION,
            "suppressions",
        )
        return
    raise ValidationError("decision_kind must be baseline or suppressions")


def create_baseline(
    review: Mapping[str, Any],
    reason: str,
    expires_at: str,
    *,
    owner: str,
    created_at: str,
    reference: str | None = None,
) -> dict[str, Any]:
    """Create v1alpha2 decisions bound to active local findings and command provenance."""

    if review.get("schema_version") != RISK_REVIEW_SCHEMA_VERSION:
        raise ValidationError(f"risk_review.schema_version must be {RISK_REVIEW_SCHEMA_VERSION}")
    normalized_reason = _text(reason, "baseline.reason")
    normalized_owner = _text(owner, "baseline.owner")
    created = _timestamp(created_at, "baseline.created_at")
    expiry = _timestamp(expires_at, "baseline.expires_at")
    review_timestamp = _timestamp(review.get("generated_at"), "risk_review.generated_at")
    if created < review_timestamp:
        raise ValidationError("baseline.created_at must not precede review timestamp")
    if expiry <= created:
        raise ValidationError("baseline.expires_at must be later than created_at")
    normalized_reference = _optional_text(reference, "baseline.reference")
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw_finding in enumerate(_sequence(review.get("findings"), "risk_review.findings")):
        path = f"risk_review.findings[{index}]"
        finding = _mapping(raw_finding, path)
        state = _text(finding.get("risk_state"), f"{path}.risk_state")
        if state not in ACTIVE_RISK_STATES:
            continue
        fingerprint = _text(finding.get("fingerprint"), f"{path}.fingerprint")
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValidationError(f"{path}.fingerprint must be a SHA-256 hex digest")
        if finding.get("fingerprint_schema_version") != FINGERPRINT_SCHEMA_VERSION:
            raise ValidationError(
                f"{path}.fingerprint_schema_version must be {FINGERPRINT_SCHEMA_VERSION}"
            )
        accepted_severity = _text(finding.get("severity"), f"{path}.severity")
        if accepted_severity not in SEVERITY_RANK:
            raise ValidationError(f"{path}.severity must be one of {list(VALID_SEVERITIES)}")
        subject = _stable_subject(finding.get("subject"), f"{path}.subject")
        if not subject:
            raise ValidationError(f"{path}.subject must bind a v1alpha2 decision")
        if fingerprint not in seen:
            entry = {
                "fingerprint": fingerprint,
                "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
                "rule_id": _text(finding.get("id"), f"{path}.id"),
                "subject_digest": _subject_digest(subject),
                "accepted_severity": accepted_severity,
                "reason": normalized_reason,
                "owner": normalized_owner,
                "created_at": created.isoformat(),
                "expires_at": expiry.isoformat(),
            }
            if normalized_reference is not None:
                entry["reference"] = normalized_reference
            entries.append(entry)
            seen.add(fingerprint)
    return {
        "schema_version": RISK_BASELINE_SCHEMA_VERSION,
        "baseline": sorted(entries, key=lambda entry: entry["fingerprint"]),
    }


def should_fail(review: Mapping[str, Any], fail_on: str) -> bool:
    """Return whether active findings meet the configured deterministic severity gate."""

    if fail_on == "none":
        return False
    if fail_on not in {*VALID_SEVERITIES, "review"}:
        raise ValidationError(f"fail_on must be one of {[*VALID_SEVERITIES, 'review']} or none")
    findings = _sequence(review.get("findings"), "risk_review.findings")
    threshold = SEVERITY_RANK.get(fail_on)
    for index, raw_finding in enumerate(findings):
        finding = _mapping(raw_finding, f"risk_review.findings[{index}]")
        state = _text(finding.get("risk_state"), f"risk_review.findings[{index}].risk_state")
        severity = _text(finding.get("severity"), f"risk_review.findings[{index}].severity")
        if state not in ACTIVE_RISK_STATES:
            continue
        if fail_on == "review" or (threshold is not None and SEVERITY_RANK[severity] <= threshold):
            return True
    return False
