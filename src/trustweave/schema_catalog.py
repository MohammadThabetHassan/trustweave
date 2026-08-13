"""Local discovery for checked-in TrustWeave JSON Schema contracts."""

from __future__ import annotations

from pathlib import Path

from trustweave.models import ValidationError

_SCHEMA_DIRECTORY = Path(__file__).resolve().parents[2] / "schemas"


def list_schema_names() -> tuple[str, ...]:
    """Return checked-in JSON Schema filenames in deterministic order."""

    return tuple(sorted(path.name for path in _SCHEMA_DIRECTORY.glob("*.schema.json")))


def read_schema(name: str) -> str:
    """Read one checked-in schema by exact basename without path traversal."""

    if name not in list_schema_names():
        raise ValidationError(f"Unknown checked-in schema: {name}")
    return (_SCHEMA_DIRECTORY / name).read_text(encoding="utf-8")
