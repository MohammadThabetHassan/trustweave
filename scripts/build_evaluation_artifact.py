#!/usr/bin/env python3
"""Build and verify deterministic local-only evaluation artifact packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = ROOT / "docs" / "evaluation" / "artifact-allowlist.json"
CORPUS_PATH = ROOT / "examples" / "evaluation-corpus" / "corpus.json"
PROJECT_PATH = ROOT / "pyproject.toml"
MANIFEST_SCHEMA_VERSION = "trustweave.dev/evaluation-artifact-manifest/v1alpha1"
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|password)\b\s*[:=]\s*[\"']?[A-Za-z0-9_./+=-]{12,}"
)
SENSITIVE_LITERAL_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
)
PROHIBITED_PATH_COMPONENTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "artifacts",
    "dist",
    "site",
}
ARCHIVE_DATE_TIME = (1980, 1, 1, 0, 0, 0)


class ArtifactError(ValueError):
    """Raised when an artifact contract is invalid or unsafe."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArtifactError(f"Could not load JSON document {path}: {error}") from error
    if not isinstance(document, dict):
        raise ArtifactError(f"JSON document must be an object: {path}")
    return document


def _safe_relative_path(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ArtifactError("Artifact allowlist paths must be non-empty strings")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ArtifactError(f"Artifact allowlist path is not a safe relative path: {value!r}")
    if any(component in PROHIBITED_PATH_COMPONENTS for component in path.parts):
        raise ArtifactError(f"Artifact allowlist path includes a prohibited component: {value}")
    return path


def _allowlisted_paths(kind: str) -> tuple[PurePosixPath, ...]:
    document = _load_json(ALLOWLIST_PATH)
    if document.get("schema_version") != "trustweave.dev/evaluation-artifact-allowlist/v1alpha1":
        raise ArtifactError("Artifact allowlist has an unsupported schema version")
    kinds = document.get("kinds")
    if not isinstance(kinds, dict):
        raise ArtifactError("Artifact allowlist must define a kinds object")
    values = kinds.get(kind)
    if not isinstance(values, list) or not values:
        raise ArtifactError(f"Artifact allowlist has no non-empty entry for kind: {kind}")
    paths = tuple(_safe_relative_path(value) for value in values)
    if len(paths) != len(set(paths)):
        raise ArtifactError(f"Artifact allowlist contains duplicate paths for kind: {kind}")
    return tuple(sorted(paths, key=str))


def _checked_file(relative_path: PurePosixPath) -> Path:
    path = ROOT.joinpath(*relative_path.parts)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ArtifactError(f"Artifact allowlist file is missing: {relative_path}") from error
    if not resolved.is_relative_to(ROOT.resolve()):
        raise ArtifactError(f"Artifact allowlist path escapes the repository root: {relative_path}")
    if not resolved.is_file():
        raise ArtifactError(f"Artifact allowlist path is not a file: {relative_path}")
    return resolved


def _reject_sensitive_content(relative_path: PurePosixPath, content: bytes) -> None:
    if b"\x00" in content:
        raise ArtifactError(f"Artifact file must be UTF-8 text, not binary: {relative_path}")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArtifactError(f"Artifact file must be UTF-8 text: {relative_path}") from error
    if SENSITIVE_VALUE_PATTERN.search(text):
        raise ArtifactError(f"Artifact file contains a secret-like assignment: {relative_path}")
    if any(pattern.search(text) for pattern in SENSITIVE_LITERAL_PATTERNS):
        raise ArtifactError(f"Artifact file contains a credential-like literal: {relative_path}")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _project_version() -> str:
    try:
        with PROJECT_PATH.open("rb") as project_file:
            project = tomllib.load(project_file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ArtifactError(f"Could not load project metadata: {error}") from error
    version = project.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ArtifactError("Project metadata must declare a non-empty version")
    return version


def _corpus_identity() -> dict[str, str]:
    corpus = _load_json(CORPUS_PATH)
    identity: dict[str, str] = {}
    for key in ("schema_version", "corpus_id", "corpus_version"):
        value = corpus.get(key)
        if not isinstance(value, str) or not value:
            raise ArtifactError(f"Corpus manifest must declare a non-empty {key}")
        identity[key] = value
    return identity


def build_manifest(kind: str, revision: str) -> dict[str, Any]:
    """Return a deterministic manifest for one approved artifact kind."""

    if not REVISION_PATTERN.fullmatch(revision):
        raise ArtifactError("Artifact revision must be a 40-character lower-case Git commit SHA")
    files: list[dict[str, Any]] = []
    for relative_path in _allowlisted_paths(kind):
        content = _checked_file(relative_path).read_bytes()
        _reject_sensitive_content(relative_path, content)
        files.append(
            {
                "path": str(relative_path),
                "sha256": _sha256(content),
                "size_bytes": len(content),
            }
        )
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": kind,
        "source_revision": revision,
        "package_version": _project_version(),
        "corpus": _corpus_identity(),
        "claim_boundary": (
            "This local package contains allowlisted synthetic and public-safe materials only. "
            "It is not a completed study, external assessment, publication, DOI, or security claim."
        ),
        "files": files,
    }


def _canonical_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ARCHIVE_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def write_artifact(manifest: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write a deterministic manifest and ZIP archive to an owner-selected local directory."""

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "evaluation-artifact-manifest.json"
    manifest_content = _canonical_json(manifest)
    manifest_path.write_bytes(manifest_content)

    kind = manifest.get("kind")
    if not isinstance(kind, str):
        raise ArtifactError("Artifact manifest kind must be a string")
    archive_path = output_dir / f"trustweave-{kind}.zip"
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ArtifactError("Artifact manifest files must be a list")
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_zip_info("evaluation-artifact-manifest.json"), manifest_content)
        for entry in files:
            if not isinstance(entry, dict):
                raise ArtifactError("Artifact manifest file entries must be objects")
            relative_path = _safe_relative_path(entry.get("path"))
            content = _checked_file(relative_path).read_bytes()
            _reject_sensitive_content(relative_path, content)
            archive.writestr(_zip_info(str(relative_path)), content)
    return manifest_path, archive_path


def verify_manifest(manifest_path: Path) -> dict[str, Any]:
    """Fail closed unless a local manifest exactly matches current approved repository bytes."""

    manifest = _load_json(manifest_path)
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ArtifactError("Artifact manifest has an unsupported schema version")
    kind = manifest.get("kind")
    revision = manifest.get("source_revision")
    if not isinstance(kind, str) or not isinstance(revision, str):
        raise ArtifactError("Artifact manifest must declare string kind and source_revision values")
    expected = build_manifest(kind, revision)
    if manifest != expected:
        raise ArtifactError(
            "Artifact manifest does not match current approved repository materials"
        )
    return expected


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build or verify a deterministic local-only TrustWeave evaluation artifact."
    )
    parser.add_argument(
        "--kind",
        choices=("reviewer-packet", "technical-report-supplement"),
        help="Approved local artifact kind to build.",
    )
    parser.add_argument(
        "--revision",
        help="Exact 40-character lower-case Git commit SHA selected by the owner.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Owner-selected local directory for the manifest and ZIP archive.",
    )
    parser.add_argument(
        "--verify-manifest",
        type=Path,
        help="Verify an existing local manifest against current allowlisted repository bytes.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify_manifest is not None:
            if args.kind is not None or args.revision is not None or args.output_dir is not None:
                raise ArtifactError("--verify-manifest cannot be combined with build arguments")
            manifest = verify_manifest(args.verify_manifest)
            print(
                "Evaluation artifact manifest verified: "
                f"{manifest['kind']} at {manifest['source_revision']}."
            )
            return 0
        if args.kind is None or args.revision is None or args.output_dir is None:
            raise ArtifactError(
                "--kind, --revision, and --output-dir are required to build an artifact"
            )
        manifest = build_manifest(args.kind, args.revision)
        manifest_path, archive_path = write_artifact(manifest, args.output_dir)
        print(f"Evaluation artifact manifest: {manifest_path}")
        print(f"Evaluation artifact archive: {archive_path}")
        return 0
    except ArtifactError as error:
        print(f"Evaluation artifact error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
