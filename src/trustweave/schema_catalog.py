"""Discover packaged TrustWeave JSON Schema contracts without source-tree assumptions."""

from __future__ import annotations

from importlib.resources import files
from importlib.resources.abc import Traversable

from trustweave.models import ValidationError

_SCHEMA_PACKAGE = "trustweave.schemas"


def _schema_resources() -> tuple[Traversable, ...]:
    """Return packaged schema resources in deterministic filename order."""

    resources = files(_SCHEMA_PACKAGE)
    return tuple(
        sorted(
            (
                resource
                for resource in resources.iterdir()
                if resource.is_file() and resource.name.endswith(".schema.json")
            ),
            key=lambda resource: resource.name,
        )
    )


def list_schema_names() -> tuple[str, ...]:
    """Return packaged JSON Schema filenames in deterministic order."""

    return tuple(resource.name for resource in _schema_resources())


def read_schema(name: str) -> str:
    """Read one packaged schema by exact basename without path traversal."""

    for resource in _schema_resources():
        if resource.name == name:
            return resource.read_text(encoding="utf-8")
    raise ValidationError(f"Unknown checked-in schema: {name}")
