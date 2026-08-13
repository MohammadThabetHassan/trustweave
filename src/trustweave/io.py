"""Safe local document and artifact handling for TrustWeave."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

from trustweave.models import ValidationError


def load_document(path: Path) -> Mapping[str, Any]:
    """Load a JSON document, or a constrained YAML subset when PyYAML is available.

    The loader never executes configuration, imports modules, resolves tags, or follows references.
    """

    if not path.is_file():
        raise ValidationError(f"Input document does not exist or is not a file: {path}")
    text = path.read_text(encoding="utf-8")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as json_error:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as import_error:
            raise ValidationError(
                f"{path} is not valid JSON. Install optional PyYAML support for YAML inputs."
            ) from import_error
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as yaml_error:
            raise ValidationError(
                f"{path} is not valid JSON or safe YAML: {yaml_error}"
            ) from yaml_error
        if document is None:
            raise ValidationError(f"{path} is empty") from json_error
        if not isinstance(document, Mapping):
            raise ValidationError(f"{path} must contain a top-level object") from json_error
        return document
    if not isinstance(document, Mapping):
        raise ValidationError(f"{path} must contain a top-level object")
    return document


def canonical_json(data: Mapping[str, Any]) -> str:
    """Return a stable JSON representation for hashing and reproducible artifacts."""

    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def document_hash(data: Mapping[str, Any]) -> str:
    """Hash the canonical representation of a structured document."""

    return sha256(canonical_json(data).encode("utf-8")).hexdigest()


def write_json(path: Path, data: Mapping[str, Any]) -> Path:
    """Write a canonical JSON artifact, creating the target directory when needed."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(data), encoding="utf-8")
    return path


def read_json(path: Path) -> Mapping[str, Any]:
    """Read an existing generated JSON artifact using the same safe validation rules."""

    return load_document(path)


def write_text(path: Path, content: str) -> Path:
    """Write a UTF-8 text artifact, creating its parent directory when necessary."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
