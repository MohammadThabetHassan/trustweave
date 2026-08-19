"""Regression tests for configured package-attestation release controls."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_VERIFIER = ROOT / "scripts" / "verify_package_provenance_controls.py"


def _provenance_verifier_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "verify_package_provenance_controls", PROVENANCE_VERIFIER
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_package_provenance_controls_match_checked_in_workflows() -> None:
    provenance = _provenance_verifier_module()

    assert provenance._validate_contract(provenance._load_contract()) == []
    assert provenance.main() == 0


def test_package_provenance_controls_reject_disabled_attestations(
    monkeypatch: object, tmp_path: Path
) -> None:
    provenance = _provenance_verifier_module()
    contract = provenance._load_contract()
    contract["workflow_controls"][0]["attestations"] = False
    replacement = tmp_path / "package-provenance-v1.json"
    replacement.write_text(json.dumps(contract), encoding="utf-8")
    monkeypatch.setattr(provenance, "CONTRACT_PATH", replacement)

    assert provenance.main() == 1
