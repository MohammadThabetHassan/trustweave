"""Deterministic SARIF export for existing local TrustWeave review artifacts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import Any

from trustweave import __version__
from trustweave.models import ValidationError

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_INFORMATION_URI = "https://github.com/MohammadThabetHassan/trustweave"

REVIEW_INPUTS: tuple[tuple[str, str, str], ...] = (
    ("policy", "trustweave.dev/policy-review/v1alpha1", "findings"),
    ("diff", "trustweave.dev/bundle-diff/v1alpha1", "signals"),
    ("trace", "trustweave.dev/trace-review/v1alpha1", "findings"),
    ("mcp", "trustweave.dev/mcp-profile-review/v1alpha1", "findings"),
)
REVIEW_INPUT_MAP = {
    kind: (schema_version, finding_key) for kind, schema_version, finding_key in REVIEW_INPUTS
}
SEVERITY_TO_LEVEL = {"review": "warning", "warning": "warning", "error": "error", "note": "note"}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else ()


def _required_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{path} must be a non-empty string")
    return value


def _review_findings(kind: str, review: Mapping[str, Any]) -> list[dict[str, str]]:
    schema_version, finding_key = REVIEW_INPUT_MAP[kind]
    if review.get("schema_version") != schema_version:
        raise ValidationError(f"{kind} review must use {schema_version}")

    findings: list[dict[str, str]] = []
    for index, raw_finding in enumerate(_sequence(review.get(finding_key))):
        finding = _mapping(raw_finding)
        identifier = _required_string(finding.get("id"), f"{kind}.{finding_key}[{index}].id")
        message = _required_string(finding.get("message"), f"{kind}.{finding_key}[{index}].message")
        severity = _required_string(
            finding.get("severity"), f"{kind}.{finding_key}[{index}].severity"
        )
        findings.append({"id": identifier, "message": message, "severity": severity})
    return findings


def _fingerprint(kind: str, identifier: str, message: str, artifact_uri: str) -> str:
    material = "\0".join((kind, identifier, message, artifact_uri))
    return sha256(material.encode("utf-8")).hexdigest()


def build_sarif(reviews: Mapping[str, tuple[str, Mapping[str, Any]]]) -> dict[str, Any]:
    """Convert selected local review artifacts into deterministic SARIF 2.1.0 evidence.

    The exporter reads only already-generated local JSON. It neither uploads SARIF nor executes an
    agent, tool, model, MCP server, or network request.
    """

    if not reviews:
        raise ValidationError(
            "At least one TrustWeave review artifact is required for SARIF export"
        )
    unexpected_kinds = sorted(set(reviews) - set(REVIEW_INPUT_MAP))
    if unexpected_kinds:
        raise ValidationError(f"Unsupported SARIF review kinds: {', '.join(unexpected_kinds)}")

    results: list[dict[str, Any]] = []
    rules_by_id: dict[str, dict[str, Any]] = {}
    for kind, _, _ in REVIEW_INPUTS:
        selected = reviews.get(kind)
        if selected is None:
            continue
        artifact_uri, review = selected
        normalized_uri = _required_string(artifact_uri, f"{kind} artifact URI")
        for finding in _review_findings(kind, review):
            identifier = finding["id"]
            message = finding["message"]
            level = SEVERITY_TO_LEVEL.get(finding["severity"], "note")
            rules_by_id.setdefault(
                identifier,
                {
                    "id": identifier,
                    "name": identifier.lower().replace("-", "_"),
                    "shortDescription": {"text": f"TrustWeave {identifier} review signal"},
                    "fullDescription": {"text": message},
                    "defaultConfiguration": {"level": level},
                },
            )
            results.append(
                {
                    "ruleId": identifier,
                    "level": level,
                    "message": {"text": f"[{kind}] {message}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": normalized_uri},
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "trustweave/v1": _fingerprint(kind, identifier, message, normalized_uri)
                    },
                }
            )

    results.sort(
        key=lambda result: (
            str(result["ruleId"]),
            str(result["message"]["text"]),
            str(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]),
        )
    )
    rules = [rules_by_id[identifier] for identifier in sorted(rules_by_id)]
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TrustWeave",
                        "version": __version__,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "trustweaveScope": (
                        "Local declarative review evidence only; no runtime execution, network "
                        "connection, credential access, or automatic upload occurred."
                    )
                },
            }
        ],
    }
