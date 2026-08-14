"""Canonical local review-finding contract shared by TrustWeave evidence producers."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, cast

FINDING_SCHEMA_VERSION = "trustweave.dev/finding/v1alpha1"
VALID_FINDING_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "review"})
_MAX_IDENTIFIER_LENGTH = 123
_MAX_METADATA_STRING_LENGTH = 1024
_MAX_MESSAGE_LENGTH = 4096
_MAX_TITLE_LENGTH = 256
_MAX_METADATA_ITEMS = 128
_MAX_REFERENCES = 64
_MAX_SUBJECT_FIELDS = 32
_MAX_PROPERTY_FIELDS = 64
_MAX_INTEGER = 2_147_483_647
_IDENTIFIER_PATTERN = re.compile(r"^TW-[A-Z0-9-]{1,120}$")
_EVIDENCE_KIND_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_METADATA_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ORDERED_SEQUENCE_FIELDS = frozenset({"path"})

_MetadataScalar = str | bool | int
_SubjectValue = str | tuple[str, ...]
_PropertyValue = _MetadataScalar | tuple[str, ...]


@dataclass(frozen=True)
class LocalFinding:
    """One deeply immutable, non-executing local review observation.

    Nested mappings and sequences are copied into immutable containers on construction. Only
    bounded scalar metadata and one-dimensional string sequences are supported, so producers
    cannot encode arbitrary nested evidence or caller-owned mutable values in a finding.
    """

    identifier: str
    severity: str
    message: str
    evidence_kind: str
    subject: Mapping[str, str | Sequence[str]] = field(default_factory=dict)
    location: Mapping[str, str] | None = None
    references: Sequence[Mapping[str, str]] = ()
    properties: Mapping[str, str | bool | int | Sequence[str]] = field(default_factory=dict)
    title: str | None = None
    rationale: str | None = None
    remediation: str | None = None

    def __post_init__(self) -> None:
        """Validate and defensively freeze all public finding data."""

        _validate_identifier(self.identifier)
        _validate_severity(self.severity)
        _validate_text(self.message, "message", _MAX_MESSAGE_LENGTH)
        _validate_evidence_kind(self.evidence_kind)
        if self.title is not None:
            _validate_text(self.title, "title", _MAX_TITLE_LENGTH)
        if self.rationale is not None:
            _validate_text(self.rationale, "rationale", _MAX_MESSAGE_LENGTH)
        if self.remediation is not None:
            _validate_text(self.remediation, "remediation", _MAX_MESSAGE_LENGTH)
        object.__setattr__(
            self,
            "subject",
            _freeze_metadata_mapping(
                self.subject,
                "subject",
                _MAX_SUBJECT_FIELDS,
                allow_boolean=False,
                allow_integer=False,
                allow_sequences=True,
            ),
        )
        location = (
            None
            if self.location is None
            else _freeze_metadata_mapping(
                self.location,
                "location",
                _MAX_SUBJECT_FIELDS,
                allow_boolean=False,
                allow_integer=False,
                allow_sequences=False,
            )
        )
        object.__setattr__(self, "location", location)
        object.__setattr__(self, "references", _freeze_references(self.references))
        object.__setattr__(
            self,
            "properties",
            _freeze_metadata_mapping(
                self.properties,
                "properties",
                _MAX_PROPERTY_FIELDS,
                allow_boolean=True,
                allow_integer=True,
                allow_sequences=True,
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        """Render deterministic JSON while omitting unavailable optional fields."""

        result: dict[str, Any] = {
            "id": self.identifier,
            "severity": self.severity,
            "message": self.message,
            "evidence_kind": self.evidence_kind,
        }
        if self.title is not None:
            result["title"] = self.title
        if self.rationale is not None:
            result["rationale"] = self.rationale
        if self.remediation is not None:
            result["remediation"] = self.remediation
        if self.subject:
            result["subject"] = _render_mapping(self.subject)
        if self.location:
            result["location"] = _render_mapping(self.location)
        if self.references:
            result["references"] = [_render_mapping(reference) for reference in self.references]
        if self.properties:
            result["properties"] = _render_mapping(self.properties)
        return result


def _validate_identifier(value: Any) -> None:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_IDENTIFIER_LENGTH
        or not _IDENTIFIER_PATTERN.fullmatch(value)
    ):
        raise ValueError("canonical finding id must match ^TW-[A-Z0-9-]{1,120}$")


def _validate_severity(value: Any) -> None:
    if value not in VALID_FINDING_SEVERITIES:
        raise ValueError(f"unsupported canonical finding severity: {value}")


def _validate_text(value: Any, path: str, maximum: int = _MAX_METADATA_STRING_LENGTH) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(
            f"canonical finding {path} must be a non-empty string up to {maximum} characters"
        )


def _validate_evidence_kind(value: Any) -> None:
    if not isinstance(value, str) or not _EVIDENCE_KIND_PATTERN.fullmatch(value):
        raise ValueError("canonical finding evidence_kind must use lower_snake_case")


def _freeze_metadata_mapping(
    value: Mapping[str, Any],
    path: str,
    maximum_fields: int,
    *,
    allow_boolean: bool,
    allow_integer: bool,
    allow_sequences: bool,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"canonical finding {path} must be an object")
    if len(value) > maximum_fields:
        raise ValueError(f"canonical finding {path} may contain at most {maximum_fields} fields")
    frozen: dict[str, Any] = {}
    for key in sorted(value):
        if not isinstance(key, str) or not _METADATA_KEY_PATTERN.fullmatch(key):
            raise ValueError(f"canonical finding {path} keys must use lower_snake_case")
        item = value[key]
        if isinstance(item, str):
            _validate_text(item, f"{path}.{key}")
            frozen[key] = item
        elif allow_boolean and isinstance(item, bool):
            frozen[key] = item
        elif allow_integer and isinstance(item, int) and not isinstance(item, bool):
            if not 0 <= item <= _MAX_INTEGER:
                raise ValueError(
                    f"canonical finding {path}.{key} must be between 0 and {_MAX_INTEGER}"
                )
            frozen[key] = item
        elif (
            allow_sequences
            and isinstance(item, Sequence)
            and not isinstance(item, (str, bytes, bytearray))
        ):
            if len(item) > _MAX_METADATA_ITEMS or any(not isinstance(entry, str) for entry in item):
                raise ValueError(
                    f"canonical finding {path}.{key} must be a string array with at most "
                    f"{_MAX_METADATA_ITEMS} entries"
                )
            normalized = tuple(item) if key in _ORDERED_SEQUENCE_FIELDS else tuple(sorted(item))
            for entry in normalized:
                _validate_text(entry, f"{path}.{key}[]")
            frozen[key] = normalized
        else:
            raise ValueError(f"canonical finding {path}.{key} has an unsupported value type")
    return MappingProxyType(frozen)


def _freeze_references(value: Any) -> tuple[Mapping[str, str], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("canonical finding references must be a list")
    if len(value) > _MAX_REFERENCES:
        raise ValueError(
            f"canonical finding references may contain at most {_MAX_REFERENCES} entries"
        )
    references = tuple(
        _freeze_metadata_mapping(
            entry,
            "references[]",
            _MAX_SUBJECT_FIELDS,
            allow_boolean=False,
            allow_integer=False,
            allow_sequences=False,
        )
        for entry in value
    )
    return tuple(sorted(references, key=lambda entry: tuple(entry.items())))


def _render_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: list(item) if isinstance(item, tuple) else item for key, item in value.items()}


def finding(
    identifier: str,
    severity: str,
    message: str,
    evidence_kind: str,
    *,
    subject: Mapping[str, str | Sequence[str]] | None = None,
    location: Mapping[str, str] | None = None,
    references: Sequence[Mapping[str, str]] = (),
    properties: Mapping[str, str | bool | int | Sequence[str]] | None = None,
    title: str | None = None,
    rationale: str | None = None,
    remediation: str | None = None,
) -> dict[str, Any]:
    """Build one bounded canonical finding from already-declared local metadata only."""

    return LocalFinding(
        identifier=identifier,
        severity=severity,
        message=message,
        evidence_kind=evidence_kind,
        subject=subject or {},
        location=location,
        references=references,
        properties=properties or {},
        title=title,
        rationale=rationale,
        remediation=remediation,
    ).as_dict()


def parse_finding(document: Mapping[str, Any]) -> LocalFinding:
    """Validate a serialized canonical finding and return its deeply immutable form."""

    if not isinstance(document, Mapping):
        raise ValueError("canonical finding must be an object")
    allowed = {
        "id",
        "severity",
        "message",
        "evidence_kind",
        "subject",
        "location",
        "references",
        "properties",
        "title",
        "rationale",
        "remediation",
    }
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise ValueError(f"canonical finding has unknown fields: {', '.join(unknown)}")
    return LocalFinding(
        identifier=cast(str, document.get("id")),
        severity=cast(str, document.get("severity")),
        message=cast(str, document.get("message")),
        evidence_kind=cast(str, document.get("evidence_kind")),
        subject=document.get("subject", {}),
        location=document.get("location"),
        references=document.get("references", ()),
        properties=document.get("properties", {}),
        title=document.get("title"),
        rationale=document.get("rationale"),
        remediation=document.get("remediation"),
    )
