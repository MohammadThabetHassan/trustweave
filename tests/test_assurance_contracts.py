"""Regression tests for versioned compatibility and assurance contracts."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
ASSURANCE_CHECK = ROOT / "scripts" / "verify_assurance_contracts.py"


def _assurance_contract_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "verify_assurance_contracts", ASSURANCE_CHECK
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_assurance_contract_matches_repository_implementation() -> None:
    assurance_contracts = _assurance_contract_module()
    assert assurance_contracts._check_compatibility_contract() == []


def test_assurance_contract_rejects_published_v1alpha3_boundary_drift(
    monkeypatch: object, tmp_path: Path
) -> None:
    """Published 0.3.0 must retain its reviewed v1alpha3 bundle-diff writer."""

    assurance_contracts = _assurance_contract_module()
    contract = json.loads(assurance_contracts.COMPATIBILITY_PATH.read_text(encoding="utf-8"))
    contract["artifact_contracts"]["published_release"]["writers"]["bundle_diff"] = (
        "trustweave.dev/bundle-diff/v1alpha2"
    )
    replacement = tmp_path / "compatibility-v1.json"
    replacement.write_text(json.dumps(contract), encoding="utf-8")
    monkeypatch.setattr(assurance_contracts, "COMPATIBILITY_PATH", replacement)

    assert "Compatibility published 0.3.0 bundle_diff writer must be v1alpha3" in (
        assurance_contracts._check_compatibility_contract()
    )


def test_assurance_contract_rejects_unreviewed_cli_surface(
    monkeypatch: object, tmp_path: Path
) -> None:
    assurance_contracts = _assurance_contract_module()
    contract = json.loads(assurance_contracts.COMPATIBILITY_PATH.read_text(encoding="utf-8"))
    contract["interfaces"]["top_level_commands"] = ["scan"]
    replacement = tmp_path / "compatibility-v1.json"
    replacement.write_text(json.dumps(contract), encoding="utf-8")
    monkeypatch.setattr(assurance_contracts, "COMPATIBILITY_PATH", replacement)

    assert "Compatibility top-level commands differ from the authoritative CLI parser" in (
        assurance_contracts._check_compatibility_contract()
    )
