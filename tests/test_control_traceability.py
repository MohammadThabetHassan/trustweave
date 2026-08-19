"""Regression tests for deterministic threat-control-test traceability."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
TRACEABILITY_VERIFIER = ROOT / "scripts" / "verify_control_traceability.py"


def _traceability_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "verify_control_traceability", TRACEABILITY_VERIFIER
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_traceability_contract_matches_threat_model_and_checked_in_paths() -> None:
    traceability = _traceability_module()

    assert traceability._validate_contract(traceability._load_contract()) == []
    assert traceability.main([]) == 0


def test_traceability_rejects_stale_generated_document(monkeypatch: object, tmp_path: Path) -> None:
    traceability = _traceability_module()
    stale = tmp_path / "CONTROL_TRACEABILITY.md"
    stale.write_text("stale\n", encoding="utf-8")
    monkeypatch.setattr(traceability, "OUTPUT_PATH", stale)

    assert traceability.main([]) == 1
