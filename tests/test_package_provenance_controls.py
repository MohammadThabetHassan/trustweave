"""Regression tests for configured package-attestation release controls."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

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


@pytest.mark.parametrize(
    "required_marker",
    (
        'test "$GITHUB_REF_TYPE" = "tag"',
        "refs/tags/v${EXPECTED_VERSION}",
        'git cat-file -t "refs/tags/${GITHUB_REF_NAME}"',
        'test "$tag_target_sha" = "$GITHUB_SHA"',
        "needs.release-gate.outputs.target_sha == github.sha",
        "pytest",
    ),
)
def test_package_provenance_controls_reject_missing_release_binding_control(
    required_marker: str,
) -> None:
    """Publication must fail closed if a required tag, SHA, or gate control disappears."""

    provenance = _provenance_verifier_module()
    for workflow_path in (
        ROOT / ".github" / "workflows" / "publish-pypi.yml",
        ROOT / ".github" / "workflows" / "publish-testpypi.yml",
    ):
        workflow = workflow_path.read_text(encoding="utf-8")
        assert required_marker in workflow
        weakened_workflow = workflow.replace(required_marker, "REMOVED_RELEASE_CONTROL")
        assert provenance._release_binding_failures(workflow) == []
        assert (
            f"missing release-binding control: {required_marker}"
            in provenance._release_binding_failures(weakened_workflow)
        )


def test_package_provenance_controls_reject_observed_release_drift(
    monkeypatch: object, tmp_path: Path
) -> None:
    provenance = _provenance_verifier_module()
    contract = provenance._load_contract()
    contract["observed_release"]["commit"] = "0" * 40
    replacement = tmp_path / "package-provenance-v1.json"
    replacement.write_text(json.dumps(contract), encoding="utf-8")
    monkeypatch.setattr(provenance, "CONTRACT_PATH", replacement)

    assert provenance.main() == 1
