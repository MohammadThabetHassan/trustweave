"""Regression tests for the checked-in synthetic golden evidence corpus."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_VERIFIER = ROOT / "scripts" / "verify_golden_evidence.py"


def _golden_verifier_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "verify_golden_evidence", GOLDEN_VERIFIER
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_golden_evidence_matches_reviewed_manifest() -> None:
    golden_evidence = _golden_verifier_module()

    assert golden_evidence.main([]) == 0


def test_golden_evidence_update_requires_explicit_confirmation() -> None:
    golden_evidence = _golden_verifier_module()

    assert golden_evidence.main(["--update"]) == 2


def test_golden_evidence_detects_reviewed_digest_drift(monkeypatch: object, tmp_path: Path) -> None:
    golden_evidence = _golden_verifier_module()
    manifest = json.loads(golden_evidence.CORPUS_PATH.read_text(encoding="utf-8"))
    manifest["cases"][0]["artifacts"][0]["digest"] = "0" * 64
    replacement = tmp_path / "corpus-v1.json"
    replacement.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(golden_evidence, "CORPUS_PATH", replacement)

    assert golden_evidence.main([]) == 1
