"""Stable data-only public API for local TrustWeave evidence workflows.

Import public names from this module rather than internal implementation modules. The exported
services accept already-loaded local data and do not read files, invoke agents or tools, contact
networks, load plugins, or obtain clocks from the environment.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from trustweave.chain import review_declared_chains
from trustweave.diff import diff_bundles
from trustweave.engine import (
    Finding,
    build_bundle,
    evaluate_flow,
    evaluate_manifest,
    explain_policy_decision,
)
from trustweave.models import (
    AgentManifest,
    InputOutputError,
    Policy,
    PolicyRule,
    ValidationError,
    parse_manifest,
    parse_policy,
)
from trustweave.policy_review import review_policy
from trustweave.risk import normalize_findings, review_risks


@dataclass(frozen=True)
class LocalReviewResult:
    """Typed, data-only view of an already-generated local review artifact."""

    schema_version: str
    findings: tuple[Mapping[str, Any], ...]
    summary: Mapping[str, Any]
    limits: tuple[str, ...]

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "LocalReviewResult":
        """Validate the stable common review-artifact envelope without performing I/O."""

        schema_version = document.get("schema_version")
        findings = document.get("findings")
        summary = document.get("summary")
        limits = document.get("limits")
        if not isinstance(schema_version, str) or not schema_version:
            raise ValidationError("review.schema_version must be a non-empty string")
        if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes, bytearray)):
            raise ValidationError("review.findings must be a list")
        if not all(isinstance(finding, Mapping) for finding in findings):
            raise ValidationError("review.findings must contain objects")
        if not isinstance(summary, Mapping):
            raise ValidationError("review.summary must be an object")
        if not isinstance(limits, Sequence) or isinstance(limits, (str, bytes, bytearray)):
            raise ValidationError("review.limits must be a list")
        if not all(isinstance(limit, str) for limit in limits):
            raise ValidationError("review.limits must contain strings")
        return cls(schema_version, tuple(findings), summary, tuple(limits))


__all__ = [
    "AgentManifest",
    "Finding",
    "InputOutputError",
    "LocalReviewResult",
    "Policy",
    "PolicyRule",
    "ValidationError",
    "build_bundle",
    "diff_bundles",
    "evaluate_flow",
    "evaluate_manifest",
    "explain_policy_decision",
    "normalize_findings",
    "parse_manifest",
    "parse_policy",
    "review_declared_chains",
    "review_policy",
    "review_risks",
]
