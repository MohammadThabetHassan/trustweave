"""Regression contracts for the bounded audit-remediation verifier."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_audit_remediation.py"
AUDIT_RECORD_PATH = ROOT / "docs" / "archive" / "AUDIT_REMEDIATION_2026-08-19.md"


def _verifier_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "audit_remediation_verifier", VERIFIER_PATH
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_audit_verifier_maps_exactly_every_documented_audit_id() -> None:
    """The one-command verifier cannot silently omit or add an audit finding identifier."""

    verifier = _verifier_module()

    assert tuple(verifier.AUDIT_TEST_NODES) == verifier.EXPECTED_AUDIT_IDS
    assert verifier._mapping_failures() == []


def test_audit_verifier_collects_every_mapped_node_and_cites_it_in_the_record() -> None:
    """Every mapped evidence node exists and is named by the tracked remediation record."""

    verifier = _verifier_module()
    nodes = verifier._all_test_nodes()
    record = AUDIT_RECORD_PATH.read_text(encoding="utf-8")

    assert verifier._node_collection_failures(nodes) == []
    for audit_id, audit_nodes in verifier.AUDIT_TEST_NODES.items():
        assert audit_id in record
        for node in audit_nodes:
            assert node in record


def test_audit_verifier_rejects_missing_or_unknown_audit_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mapping edits fail closed instead of weakening the bounded evidence contract."""

    verifier = _verifier_module()
    missing = dict(verifier.AUDIT_TEST_NODES)
    missing.pop("TW-AUDIT-010")
    monkeypatch.setattr(verifier, "AUDIT_TEST_NODES", missing)
    assert verifier._mapping_failures() == [
        "Audit node mapping keys must be exactly TW-AUDIT-001 through TW-AUDIT-010 in order."
    ]

    unknown = dict(verifier.AUDIT_TEST_NODES)
    unknown["TW-AUDIT-011"] = (
        "tests/test_diff.py::test_bundle_diff_rejects_unsupported_bundle_schema",
    )
    monkeypatch.setattr(verifier, "AUDIT_TEST_NODES", unknown)
    assert verifier._mapping_failures() == [
        "Audit node mapping keys must be exactly TW-AUDIT-001 through TW-AUDIT-010 in order."
    ]


def test_audit_verifier_returns_nonzero_when_mapped_evidence_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifier failure is observable to automation before it attempts any test command."""

    verifier = _verifier_module()
    monkeypatch.setattr(verifier, "_mapping_failures", lambda: ["forced mapping failure"])
    monkeypatch.setattr(verifier, "_node_collection_failures", lambda _: [])

    assert verifier.main() == 1
