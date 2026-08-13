"""Explicit generation provenance for local TrustWeave artifacts.

Core builders receive a timestamp when volatile provenance is wanted. They never read the
clock or environment themselves, which keeps their stable evidence payloads reproducible.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from trustweave.models import ValidationError


def normalize_timestamp(value: str) -> str:
    """Validate and normalize an explicit ISO 8601 timestamp to UTC."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError("generated_at must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValidationError("generated_at must include a UTC offset")
    return parsed.astimezone(UTC).isoformat()


def generation_timestamp(explicit: str | None = None) -> str:
    """Resolve application-layer provenance from an argument, epoch, or current UTC time.

    ``SOURCE_DATE_EPOCH`` takes precedence over the wall clock when callers do not pass an
    explicit timestamp. This mirrors standard reproducible-build behavior while keeping the
    environment and clock at the application boundary.
    """

    if explicit is not None:
        return normalize_timestamp(explicit)
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch is not None:
        try:
            epoch = int(source_date_epoch)
        except ValueError as error:
            raise ValidationError("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from error
        if epoch < 0:
            raise ValidationError("SOURCE_DATE_EPOCH must not be negative")
        return datetime.fromtimestamp(epoch, UTC).isoformat()
    return datetime.now(UTC).isoformat()


def add_generated_at(document: dict[str, object], generated_at: str | None) -> dict[str, object]:
    """Return a document with explicitly supplied volatile provenance, when requested."""

    if generated_at is None:
        return document
    result = dict(document)
    result["generated_at"] = normalize_timestamp(generated_at)
    return result


def stable_payload(document: dict[str, object]) -> dict[str, object]:
    """Return the evidence payload whose digest excludes volatile generation metadata."""

    result = dict(document)
    result.pop("generated_at", None)
    return result


def stable_document_hash(document: dict[str, object]) -> str:
    """Hash an artifact's stable evidence payload, excluding volatile generation metadata."""

    from trustweave.io import document_hash

    return document_hash(stable_payload(document))


__all__ = [
    "add_generated_at",
    "generation_timestamp",
    "normalize_timestamp",
    "stable_document_hash",
    "stable_payload",
]
