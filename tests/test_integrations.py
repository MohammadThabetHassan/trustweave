"""Contract tests for repository-local integration assets."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION_PATH = ROOT / ".github" / "actions" / "trustweave" / "action.yml"


def test_repository_local_action_declares_generated_artifact_outputs() -> None:
    action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))

    assert action["name"] == "TrustWeave local evidence"
    assert "summary" not in action
    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["fail-on-review"] == {
        "description": "Return a failing status when policy review requires human review.",
        "required": False,
        "default": "false",
    }
    assert action["outputs"] == {
        "bundle": {
            "description": "Path to the generated local agent-security bundle.",
            "value": "${{ steps.artifacts.outputs.bundle }}",
        },
        "test-results": {
            "description": "Path to the generated local synthetic test results.",
            "value": "${{ steps.artifacts.outputs.test-results }}",
        },
        "policy-review": {
            "description": "Path to the generated local policy review.",
            "value": "${{ steps.artifacts.outputs.policy-review }}",
        },
    }
    rendered = ACTION_PATH.read_text(encoding="utf-8")
    assert 'python -m pip install "$GITHUB_WORKSPACE"' in rendered
    assert "id: artifacts" in rendered
    assert '>> "$GITHUB_OUTPUT"' in rendered


def test_release_integration_assets_cover_local_validation_code_scanning_and_container_safety() -> (
    None
):
    hooks = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    hook_ids = {hook["id"] for repository in hooks["repos"] for hook in repository["hooks"]}
    assert {
        "trustweave-config",
        "trustweave-manifest",
        "trustweave-policy",
        "trustweave-scenarios",
        "trustweave-chain-manifest",
    }.issubset(hook_ids)

    codeql = ROOT / ".github" / "workflows" / "codeql.yml"
    assert codeql.is_file()
    codeql_document = codeql.read_text(encoding="utf-8")
    assert "github/codeql-action" in codeql_document
    assert "python" in codeql_document

    container = ROOT / "Dockerfile"
    assert container.is_file()
    container_text = container.read_text(encoding="utf-8")
    assert "FROM python:3.13-slim@sha256:" in container_text
    assert "USER trustweave" in container_text
    assert "--no-cache-dir" in container_text
    assert "trustweave --help" in container_text


def test_quality_workflow_smoke_tests_built_source_distribution() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "Verify the built source distribution in isolation" in workflow
    assert ".sdist-check/bin/pip install dist/*.tar.gz" in workflow
    assert ".sdist-check/bin/trustweave --help" in workflow
    assert "rm -rf .sdist-check" in workflow


def test_quality_workflow_executes_real_container_build_and_smoke_contract() -> None:
    """The shipped Dockerfile must be exercised in hosted CI, not only inspected."""

    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "Container build and smoke test" in workflow
    assert "docker build --pull=false -t trustweave:0.2.0 ." in workflow
    assert "docker run --rm trustweave:0.2.0 --help" in workflow
    assert "docker run --rm trustweave:0.2.0 schema list" in workflow
    assert "id -u" in workflow
    assert "trustweave.__version__" in workflow
    assert 'find / -xdev -type d -name "__pycache__"' in workflow
