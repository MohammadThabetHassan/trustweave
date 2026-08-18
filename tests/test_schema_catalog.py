from __future__ import annotations

from dataclasses import dataclass

import pytest

import trustweave.schema_catalog as schema_catalog
from trustweave.cli import EXIT_INVALID_INPUT, main


@dataclass
class _FakeSchemaResource:
    name: str
    payload: str = ""
    file: bool = True
    read_encoding: str | None = None

    def is_file(self) -> bool:
        return self.file

    def read_text(self, *, encoding: str | None = None) -> str:
        self.read_encoding = encoding
        return self.payload


class _FakeSchemaDirectory:
    def __init__(self, resources: list[_FakeSchemaResource]) -> None:
        self._resources = resources

    def iterdir(self) -> list[_FakeSchemaResource]:
        return self._resources


def test_schema_list_and_show_are_local_and_deterministic(capsys: object) -> None:
    assert main(["schema", "list"]) == 0
    listed = capsys.readouterr().out.splitlines()  # type: ignore[attr-defined]
    assert listed == sorted(listed)
    assert "policy-v1alpha2.schema.json" in listed
    assert "risk-baseline-v1alpha2.schema.json" in listed
    assert "risk-suppressions-v1alpha2.schema.json" in listed

    assert main(["schema", "show", "policy-v1alpha2.schema.json"]) == 0
    assert '"$id": "https://trustweave.dev/schemas/policy/v1alpha2"' in capsys.readouterr().out  # type: ignore[attr-defined]


def test_schema_show_rejects_unknown_names(capsys: object) -> None:
    assert main(["schema", "show", "../secret.json"]) == EXIT_INVALID_INPUT
    assert "Unknown checked-in schema" in capsys.readouterr().err  # type: ignore[attr-defined]


def test_schema_catalog_filters_orders_and_reads_packaged_schema_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catalog enumeration includes only real schema files in filename order and reads UTF-8."""

    schema_a = _FakeSchemaResource("a.schema.json", '{"name":"a"}')
    schema_b = _FakeSchemaResource("b.schema.json", '{"name":"b"}')
    directory = _FakeSchemaDirectory(
        [
            _FakeSchemaResource("x.schema.json", file=False),
            schema_b,
            _FakeSchemaResource("note.txt"),
            schema_a,
        ]
    )
    monkeypatch.setattr(schema_catalog, "files", lambda _package: directory)

    assert [resource.name for resource in schema_catalog._schema_resources()] == [
        "a.schema.json",
        "b.schema.json",
    ]
    assert schema_catalog.list_schema_names() == ("a.schema.json", "b.schema.json")
    assert schema_catalog.read_schema("b.schema.json") == '{"name":"b"}'
    assert schema_b.read_encoding == "utf-8"
