"""Safe local document and artifact handling for TrustWeave."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import Any

from trustweave.models import InputOutputError, ValidationError

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_DOCUMENT_NESTING = 64
MAX_DOCUMENT_ITEMS = 1_000_000


def _bounded_mapping(document: Any, path: Path) -> Mapping[str, Any]:
    """Reject structurally unsafe local documents without recursive traversal."""

    if not isinstance(document, Mapping):
        raise ValidationError(f"{path} must contain a top-level object")

    pending: list[tuple[Any, int]] = [(document, 1)]
    seen_containers: set[int] = set()
    item_count = 0
    while pending:
        value, depth = pending.pop()
        if depth > MAX_DOCUMENT_NESTING:
            raise ValidationError(
                f"{path} exceeds the maximum supported nesting of {MAX_DOCUMENT_NESTING}"
            )
        if isinstance(value, Mapping):
            identifier = id(value)
            if identifier in seen_containers:
                raise ValidationError(f"{path} must not contain recursive or aliased structures")
            seen_containers.add(identifier)
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValidationError(f"{path} object keys must be strings")
                item_count += 1
                if item_count > MAX_DOCUMENT_ITEMS:
                    raise ValidationError(
                        f"{path} exceeds the maximum supported item count of {MAX_DOCUMENT_ITEMS}"
                    )
                pending.append((child, depth + 1))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            identifier = id(value)
            if identifier in seen_containers:
                raise ValidationError(f"{path} must not contain recursive or aliased structures")
            seen_containers.add(identifier)
            for child in value:
                item_count += 1
                if item_count > MAX_DOCUMENT_ITEMS:
                    raise ValidationError(
                        f"{path} exceeds the maximum supported item count of {MAX_DOCUMENT_ITEMS}"
                    )
                pending.append((child, depth + 1))
    return document


def load_document(path: Path) -> Mapping[str, Any]:
    """Load local JSON or safe YAML without executing configuration or following references."""

    if path.is_symlink():
        raise InputOutputError(f"Input document must not be a symbolic link: {path}")
    if not path.exists():
        raise InputOutputError(f"Input document does not exist: {path}")
    if not path.is_file():
        raise InputOutputError(f"Input document is not a file: {path}")
    try:
        if path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise ValidationError(
                f"{path} exceeds the maximum supported size of {MAX_DOCUMENT_BYTES} bytes"
            )
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError(f"{path} is not valid UTF-8") from error
    except OSError as error:
        raise InputOutputError(
            f"Could not read input document {path}: {error.strerror or error}"
        ) from error
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
        return _bounded_mapping(document, path)
    return _bounded_mapping(document, path)


def canonical_json(data: Mapping[str, Any]) -> str:
    """Return a stable JSON representation for hashing and reproducible artifacts."""

    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def document_hash(data: Mapping[str, Any]) -> str:
    """Hash the canonical representation of a structured document."""

    return sha256(canonical_json(data).encode("utf-8")).hexdigest()


def _atomic_write(path: Path, content: str) -> Path:
    """Atomically replace one local artifact without leaving a partially written target."""

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            temporary_path.replace(path)
        except OSError:
            temporary_path.unlink(missing_ok=True)
            raise
    except OSError as error:
        raise InputOutputError(
            f"Could not write artifact {path}: {error.strerror or error}"
        ) from error
    return path


def write_json(path: Path, data: Mapping[str, Any]) -> Path:
    """Atomically write a canonical JSON artifact, creating its parent directory when needed."""

    return _atomic_write(path, canonical_json(data))


def read_json(path: Path) -> Mapping[str, Any]:
    """Read an existing generated JSON artifact using the same safe validation rules."""

    return load_document(path)


def write_text(path: Path, content: str) -> Path:
    """Atomically write a UTF-8 text artifact, creating its parent directory when needed."""

    return _atomic_write(path, content)
