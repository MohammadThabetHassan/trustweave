from __future__ import annotations

import json
import subprocess
import sys
import venv
import zipfile
from hashlib import sha256
from pathlib import Path

import pytest

from trustweave.cli import (
    EXIT_INPUT_OUTPUT,
    EXIT_INVALID_INPUT,
    EXIT_SUCCESS,
    main,
)
from trustweave.evidence import (
    ATTESTATION_SCHEMA_VERSION,
    LEGACY_ATTESTATION_SCHEMA_VERSION,
    build_attestation,
    verify_attestation,
)
from trustweave.io import load_document, write_json
from trustweave.models import InputOutputError, ValidationError
from trustweave.provenance import generation_timestamp

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
SCENARIOS = ROOT / "scenarios" / "default-scenarios.json"


def test_source_date_epoch_and_explicit_timestamp_are_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    assert generation_timestamp() == "1970-01-01T00:00:00+00:00"
    assert generation_timestamp("2026-08-13T04:00:00+04:00") == "2026-08-13T00:00:00+00:00"


def test_cli_reproducible_mode_produces_identical_evidence_bytes(tmp_path: Path) -> None:
    output_dir = tmp_path / "artifacts"
    arguments = ["--generated-at", "2026-08-13T00:00:00+00:00"]

    assert (
        main(
            [
                *arguments,
                "scan",
                "--manifest",
                str(MANIFEST),
                "--policy",
                str(POLICY),
                "--output-dir",
                str(output_dir),
            ]
        )
        == EXIT_SUCCESS
    )
    first_bundle = (output_dir / "agent-security-bundle.json").read_bytes()
    assert (
        main(
            [
                *arguments,
                "test",
                "--policy",
                str(POLICY),
                "--scenarios",
                str(SCENARIOS),
                "--output-dir",
                str(output_dir),
            ]
        )
        == EXIT_SUCCESS
    )
    first_results = (output_dir / "security-test-results.json").read_bytes()
    assert (
        main(
            [
                *arguments,
                "attest",
                "--source-revision",
                "test-revision",
                "--output-dir",
                str(output_dir),
            ]
        )
        == EXIT_SUCCESS
    )
    first_attestation = (output_dir / "attestation.json").read_bytes()

    assert (
        main(
            [
                *arguments,
                "scan",
                "--manifest",
                str(MANIFEST),
                "--policy",
                str(POLICY),
                "--output-dir",
                str(output_dir),
            ]
        )
        == EXIT_SUCCESS
    )
    assert (
        main(
            [
                *arguments,
                "test",
                "--policy",
                str(POLICY),
                "--scenarios",
                str(SCENARIOS),
                "--output-dir",
                str(output_dir),
            ]
        )
        == EXIT_SUCCESS
    )
    assert (
        main(
            [
                *arguments,
                "attest",
                "--source-revision",
                "test-revision",
                "--output-dir",
                str(output_dir),
            ]
        )
        == EXIT_SUCCESS
    )

    assert (output_dir / "agent-security-bundle.json").read_bytes() == first_bundle
    assert (output_dir / "security-test-results.json").read_bytes() == first_results
    assert (output_dir / "attestation.json").read_bytes() == first_attestation


def test_cli_writes_expected_errors_to_stderr_and_returns_stable_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing.json"
    code = main(["scan", "--manifest", str(missing), "--policy", str(POLICY)])
    captured = capsys.readouterr()
    assert code == EXIT_INPUT_OUTPUT
    assert captured.out == ""
    assert "Input/output error" in captured.err

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    code = main(["scan", "--manifest", str(invalid), "--policy", str(POLICY)])
    captured = capsys.readouterr()
    assert code == EXIT_INVALID_INPUT
    assert captured.out == ""
    assert "Validation error" in captured.err

    code = main(["scan"])
    captured = capsys.readouterr()
    assert code == EXIT_INVALID_INPUT
    assert captured.out == ""
    assert "required" in captured.err


def test_cli_debug_mode_preserves_traceback_for_expected_failures(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(ValidationError):
        main(["--debug", "scan", "--manifest", str(invalid), "--policy", str(POLICY)])


def test_loader_rejects_directories_and_invalid_utf8(tmp_path: Path) -> None:
    with pytest.raises(InputOutputError, match="not a file"):
        load_document(tmp_path)

    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    with pytest.raises(ValidationError, match="UTF-8"):
        load_document(invalid_utf8)


def test_atomic_writer_reports_unwritable_parent_without_creating_target(tmp_path: Path) -> None:
    blocked_parent = tmp_path / "blocked"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    target = blocked_parent / "artifact.json"
    with pytest.raises(InputOutputError, match="Could not write artifact"):
        write_json(target, {"schema_version": "test"})
    assert not target.exists()


def test_built_wheel_contains_and_installs_py_typed(tmp_path: Path) -> None:
    distribution_directory = tmp_path / "dist"
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(distribution_directory)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    wheel = next(distribution_directory.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        assert "trustweave/py.typed" in archive.namelist()

    environment = tmp_path / "wheel-environment"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    install = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", str(wheel)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stdout + install.stderr
    check = subprocess.run(
        [
            str(python),
            "-c",
            (
                "import pathlib, trustweave; "
                "assert (pathlib.Path(trustweave.__file__).parent / 'py.typed').is_file()"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr


def test_stable_attestation_payload_digest_ignores_generation_metadata(tmp_path: Path) -> None:
    bundle_path = write_json(
        tmp_path / "bundle.json", {"generated_at": "2026-08-13T00:00:00+00:00", "value": 1}
    )
    results_path = write_json(
        tmp_path / "results.json", {"generated_at": "2026-08-13T00:00:01+00:00", "value": 2}
    )
    attestation = build_attestation(bundle_path, results_path, source_revision="test")
    assert attestation["schema_version"] == ATTESTATION_SCHEMA_VERSION
    assert "generated_at" not in attestation
    assert verify_attestation(attestation)[0]

    tampered = json.loads(json.dumps(attestation))
    tampered["predicate"]["bundle_document_sha256"] = "tampered"
    assert not verify_attestation(tampered)[0]


def test_legacy_attestation_verification_and_invalid_shapes() -> None:
    bundle_hash = "bundle"
    test_hash = "tests"
    revision = "legacy"
    chain = "|".join([LEGACY_ATTESTATION_SCHEMA_VERSION, bundle_hash, test_hash, revision])
    legacy = {
        "schema_version": LEGACY_ATTESTATION_SCHEMA_VERSION,
        "predicate": {
            "bundle_sha256": bundle_hash,
            "test_results_sha256": test_hash,
            "source_revision": revision,
        },
        "integrity": {"chain_sha256": sha256(chain.encode("utf-8")).hexdigest()},
    }
    assert verify_attestation(legacy)[0]
    assert verify_attestation({"schema_version": "unknown"}) == (
        False,
        "Attestation is missing predicate or integrity data",
    )
    assert verify_attestation({"schema_version": "unknown", "predicate": {}, "integrity": {}}) == (
        False,
        "Unsupported attestation schema version",
    )


def test_provenance_and_safe_yaml_validation_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-an-epoch")
    with pytest.raises(ValidationError, match="integer"):
        generation_timestamp()
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "-1")
    with pytest.raises(ValidationError, match="negative"):
        generation_timestamp()
    with pytest.raises(ValidationError, match="ISO 8601"):
        generation_timestamp("invalid")
    with pytest.raises(ValidationError, match="UTC offset"):
        generation_timestamp("2026-08-13T00:00:00")

    yaml_document = tmp_path / "document.yaml"
    yaml_document.write_text("name: local-review\n", encoding="utf-8")
    assert load_document(yaml_document) == {"name": "local-review"}


def test_atomic_writer_replaces_existing_complete_artifact(tmp_path: Path) -> None:
    target = tmp_path / "artifact.json"
    target.write_text("old", encoding="utf-8")
    write_json(target, {"value": "new"})
    assert target.read_text(encoding="utf-8") == '{\n  "value": "new"\n}\n'
