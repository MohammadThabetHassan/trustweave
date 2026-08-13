"""Unsigned statement-shaped local evidence export."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from trustweave.evidence import ATTESTATION_SCHEMA_VERSION, LEGACY_ATTESTATION_SCHEMA_VERSION
from trustweave.models import ValidationError

STATEMENT_SCHEMA_VERSION = "trustweave.dev/unsigned-statement/v1alpha1"


def build_unsigned_statement(attestation: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a local TrustWeave attestation into an explicitly unsigned statement."""

    if attestation.get("schema_version") not in {
        LEGACY_ATTESTATION_SCHEMA_VERSION,
        ATTESTATION_SCHEMA_VERSION,
    }:
        raise ValidationError("statement input must be a TrustWeave local attestation")
    subject = attestation.get("subject")
    predicate = attestation.get("predicate")
    integrity = attestation.get("integrity")
    if (
        not isinstance(subject, list)
        or not isinstance(predicate, Mapping)
        or not isinstance(integrity, Mapping)
    ):
        raise ValidationError("attestation is missing subject, predicate, or integrity data")
    return {
        "schema_version": STATEMENT_SCHEMA_VERSION,
        "statement_type": "https://trustweave.dev/unsigned-local-evidence/v1alpha1",
        "unsigned": True,
        "subject": subject,
        "predicate_type": attestation.get("predicate_type"),
        "predicate": dict(predicate),
        "integrity": dict(integrity),
        "limits": [
            "This statement is a local format conversion and has no signature, trusted identity, "
            "or transparency-log entry.",
            "It does not establish provenance, non-repudiation, runtime behavior, or deployment "
            "authorization.",
        ],
    }
