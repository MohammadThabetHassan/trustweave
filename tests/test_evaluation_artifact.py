from __future__ import annotations

import importlib.util
import json
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "scripts" / "build_evaluation_artifact.py"
REVISION = "a" * 40


def _builder_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "evaluation_artifact_builder", BUILDER_PATH
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_reviewer_packet_manifest_and_archive_are_deterministic_and_local(tmp_path: Path) -> None:
    builder = _builder_module()

    manifest = builder.build_manifest("reviewer-packet", REVISION)
    manifest_path, archive_path = builder.write_artifact(manifest, tmp_path)

    assert manifest["schema_version"] == "trustweave.dev/evaluation-artifact-manifest/v1alpha1"
    assert manifest["source_revision"] == REVISION
    assert manifest["corpus"]["corpus_version"] == "v1alpha1"
    paths = [entry["path"] for entry in manifest["files"]]
    assert paths == sorted(paths)
    assert "examples/evaluation-corpus/reviewer-packet/README.md" in paths
    assert "examples/evaluation-corpus/reviewer-packet/FEEDBACK_TEMPLATE.md" in paths
    assert manifest_path.is_file()
    assert archive_path.is_file()
    assert builder.verify_manifest(manifest_path) == manifest

    with zipfile.ZipFile(archive_path) as archive:
        assert archive.namelist() == ["evaluation-artifact-manifest.json", *paths]
        assert archive.read("evaluation-artifact-manifest.json") == manifest_path.read_bytes()


def test_artifact_manifest_rejects_tampered_hashes(tmp_path: Path) -> None:
    builder = _builder_module()
    manifest = builder.build_manifest("reviewer-packet", REVISION)
    manifest["files"][0]["sha256"] = "0" * 64
    path = tmp_path / "evaluation-artifact-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(builder.ArtifactError, match="does not match"):
        builder.verify_manifest(path)


def test_artifact_builder_rejects_prohibited_allowlist_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    builder = _builder_module()
    unsafe_allowlist = tmp_path / "allowlist.json"
    unsafe_allowlist.write_text(
        json.dumps(
            {
                "schema_version": "trustweave.dev/evaluation-artifact-allowlist/v1alpha1",
                "kinds": {"reviewer-packet": [".venv/secret.txt"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(builder, "ALLOWLIST_PATH", unsafe_allowlist)

    with pytest.raises(builder.ArtifactError, match="prohibited component"):
        builder.build_manifest("reviewer-packet", REVISION)


def test_artifact_builder_remains_non_networked_and_does_not_run_commands() -> None:
    source = BUILDER_PATH.read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "requests" not in source
    assert "httpx" not in source
    assert "urllib" not in source
    assert "socket" not in source
    assert "shutil.make_archive" not in source


def test_reviewer_packet_archive_bytes_are_stable_across_repeated_builds(tmp_path: Path) -> None:
    builder = _builder_module()
    manifest = builder.build_manifest("reviewer-packet", REVISION)
    _, first_archive = builder.write_artifact(manifest, tmp_path / "first")
    _, second_archive = builder.write_artifact(manifest, tmp_path / "second")

    assert first_archive.read_bytes() == second_archive.read_bytes()


def test_artifact_builder_rejects_credential_like_allowlisted_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    builder = _builder_module()
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'fixture'\nversion = '0.0.0'\n", encoding="utf-8"
    )
    (tmp_path / "corpus.json").write_text(
        json.dumps(
            {
                "schema_version": "trustweave.dev/evaluation-corpus/v1alpha1",
                "corpus_id": "fixture-corpus",
                "corpus_version": "v1alpha1",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "unsafe.txt").write_text('api_key = "ABCDEFGHIJKLMNOP"\n', encoding="utf-8")
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(
        json.dumps(
            {
                "schema_version": "trustweave.dev/evaluation-artifact-allowlist/v1alpha1",
                "kinds": {"reviewer-packet": ["unsafe.txt"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    monkeypatch.setattr(builder, "ALLOWLIST_PATH", allowlist)
    monkeypatch.setattr(builder, "PROJECT_PATH", tmp_path / "pyproject.toml")
    monkeypatch.setattr(builder, "CORPUS_PATH", tmp_path / "corpus.json")

    with pytest.raises(builder.ArtifactError, match="secret-like assignment"):
        builder.build_manifest("reviewer-packet", REVISION)
