"""Security-boundary regressions for untrusted local evidence documents."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.io import (
    MAX_DOCUMENT_BYTES,
    MAX_DOCUMENT_ITEMS,
    MAX_DOCUMENT_NESTING,
    load_document,
)
from trustweave.models import InputOutputError, ValidationError


def test_loader_rejects_documents_larger_than_the_declared_byte_limit(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + (b" " * MAX_DOCUMENT_BYTES) + b"}")

    with pytest.raises(ValidationError, match="maximum supported size"):
        load_document(oversized)


def test_loader_rejects_documents_deeper_than_the_declared_nesting_limit(tmp_path: Path) -> None:
    document: dict[str, object] = {"leaf": "value"}
    for index in range(MAX_DOCUMENT_NESTING + 1):
        document = {f"layer_{index}": document}
    deep_document = tmp_path / "deep.json"
    deep_document.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValidationError, match="maximum supported nesting"):
        load_document(deep_document)


def test_loader_rejects_symbolic_link_inputs(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"declared": "local"}', encoding="utf-8")
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation requires privileges unavailable on this platform")

    with pytest.raises(InputOutputError, match="symbolic link"):
        load_document(linked)


def test_loader_rejects_documents_with_more_than_the_declared_item_limit(tmp_path: Path) -> None:
    oversized_array = tmp_path / "oversized-array.json"
    oversized_array.write_text(
        '{"items": [' + ("0," * MAX_DOCUMENT_ITEMS) + "0]}", encoding="utf-8"
    )

    with pytest.raises(ValidationError, match="maximum supported item count"):
        load_document(oversized_array)


def test_loader_rejects_invalid_utf8_nonstring_yaml_keys_and_unsafe_yaml_tags(
    tmp_path: Path,
) -> None:
    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    with pytest.raises(ValidationError, match="valid UTF-8"):
        load_document(invalid_utf8)

    nonstring_key = tmp_path / "nonstring-key.yaml"
    nonstring_key.write_text("? 1\n: declared\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="keys must be strings"):
        load_document(nonstring_key)

    unsafe_yaml = tmp_path / "unsafe.yaml"
    unsafe_yaml.write_text("!!python/object/apply:os.system ['false']\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="safe YAML"):
        load_document(unsafe_yaml)


def test_runtime_source_has_no_network_process_or_dynamic_execution_primitives() -> None:
    import ast

    source_root = Path(__file__).resolve().parents[1] / "src" / "trustweave"
    forbidden_modules = {"http", "http.client", "requests", "socket", "subprocess", "urllib"}
    forbidden_calls = {
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("os", "system"),
        ("importlib", "import_module"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("subprocess", "Popen"),
        ("subprocess", "run"),
    }
    violations: list[str] = []

    for source_path in sorted(source_root.rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for imported in node.names:
                    aliases[imported.asname or imported.name.split(".")[0]] = imported.name
                    if imported.name in forbidden_modules:
                        violations.append(f"{source_path.name}: import {imported.name}")
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                if node.module in forbidden_modules:
                    violations.append(f"{source_path.name}: from {node.module} import")
                for imported in node.names:
                    aliases[imported.asname or imported.name] = f"{node.module}.{imported.name}"

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                resolved = aliases.get(node.func.id, f"builtins.{node.func.id}")
                module, _, name = resolved.rpartition(".")
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module = aliases.get(node.func.value.id, node.func.value.id)
                name = node.func.attr
            else:
                continue
            if (module, name) in forbidden_calls:
                violations.append(f"{source_path.name}: {module}.{name}()")

    assert violations == []


def test_manifest_rejects_unicode_declared_identifiers() -> None:
    from trustweave.models import parse_manifest

    document = {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "identifier-boundary",
        "description": "A local declaration used to test identifier validation.",
        "sources": [
            {
                "name": "inbox",
                "trust": "untrusted",
                "data_classification": "confidential",
                "description": "Declared source.",
            }
        ],
        "tools": [
            {
                "name": "send_email",
                "action_class": "external",
                "capabilities": ["email.send"],
                "description": "Declared tool.",
            }
        ],
        "flows": [
            {
                "source": "inbox",
                "tool": "send_email",
                "purpose": "notify_customer",
                "purpose_tags": ["outbound"],
            }
        ],
    }

    for field, value in (
        ("sources", "inböx"),
        ("tools", "send-émail"),
        ("purpose_tags", "outbøund"),
    ):
        candidate = json.loads(json.dumps(document))
        if field == "sources":
            candidate["sources"][0]["name"] = value
            candidate["flows"][0]["source"] = value
        elif field == "tools":
            candidate["tools"][0]["name"] = value
            candidate["flows"][0]["tool"] = value
        else:
            candidate["flows"][0]["purpose_tags"] = [value]

        with pytest.raises(ValidationError, match="ASCII identifier"):
            parse_manifest(candidate)
