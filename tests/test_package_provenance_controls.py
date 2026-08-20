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
    ("required_marker", "expected_failure"),
    (
        ('test "$GITHUB_REF_TYPE" = "tag"', "annotated tag target command"),
        ("refs/tags/v${EXPECTED_VERSION}", "annotated tag target command"),
        ('git cat-file -t "refs/tags/${GITHUB_REF_NAME}"', "annotated tag target command"),
        ('test "$tag_target_sha" = "$GITHUB_SHA"', "annotated tag target command"),
        ("needs.release-gate.outputs.target_sha == github.sha", "build exact target SHA condition"),
        ("pytest", "local release gate command"),
    ),
)
def test_package_provenance_controls_reject_missing_release_binding_control(
    required_marker: str, expected_failure: str
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
        assert any(
            expected_failure in failure
            for failure in provenance._release_binding_failures(weakened_workflow)
        )


@pytest.mark.parametrize(
    ("find", "replace", "expected_failure"),
    (
        (
            "on:\n  workflow_dispatch:",
            "on:\n  push:\n    branches: [main]\n  workflow_dispatch:",
            "manual workflow_dispatch-only trigger",
        ),
        (
            "needs: [release-gate, build]",
            "needs: [release-gate]",
            "publish needs release-gate and build",
        ),
        (
            "needs: release-gate",
            "needs: []",
            "build needs only release-gate",
        ),
    ),
)
def test_package_provenance_controls_reject_semantically_weakened_job_graph(
    find: str, replace: str, expected_failure: str
) -> None:
    """Parsed workflow validation rejects unsafe triggers and dependency graph changes."""

    provenance = _provenance_verifier_module()
    workflow = (ROOT / ".github" / "workflows" / "publish-pypi.yml").read_text(encoding="utf-8")
    assert find in workflow
    weakened = workflow.replace(find, replace, 1)

    assert any(
        expected_failure in failure for failure in provenance._release_binding_failures(weakened)
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
