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
    PREVIOUS_ATTESTATION_SCHEMA_VERSION,
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


def test_v1alpha3_attestation_binds_stable_payloads_exact_files_subjects_and_revision(
    tmp_path: Path,
) -> None:
    bundle_path = write_json(
        tmp_path / "bundle.json", {"generated_at": "2026-08-13T00:00:00+00:00", "value": 1}
    )
    results_path = write_json(
        tmp_path / "results.json", {"generated_at": "2026-08-13T00:00:01+00:00", "value": 2}
    )
    attestation = build_attestation(
        bundle_path,
        results_path,
        source_revision="test",
        generated_at="2026-08-13T00:00:02+00:00",
    )
    assert attestation["schema_version"] == ATTESTATION_SCHEMA_VERSION
    assert verify_attestation(attestation)[0]
    assert verify_attestation(attestation, bundle_path, results_path)[0]

    def tampered_copy() -> dict[str, object]:
        return json.loads(json.dumps(attestation))

    subject_tampered = tampered_copy()
    subject_tampered["subject"][0]["digest"]["sha256"] = "f" * 64
    assert not verify_attestation(subject_tampered)[0]

    file_tampered = tampered_copy()
    file_tampered["predicate"]["exact_files"]["bundle"]["sha256"] = "e" * 64
    assert not verify_attestation(file_tampered)[0]

    stable_tampered = tampered_copy()
    stable_tampered["predicate"]["stable_payload"]["bundle_sha256"] = "d" * 64
    assert not verify_attestation(stable_tampered)[0]

    revision_tampered = tampered_copy()
    revision_tampered["predicate"]["source_revision"] = "other-revision"
    assert not verify_attestation(revision_tampered)[0]

    provenance_tampered = tampered_copy()
    provenance_tampered["generated_at"] = "2026-08-13T00:00:03+00:00"
    assert verify_attestation(provenance_tampered)[0]

    bundle_path.write_text('{"value": 9}\n', encoding="utf-8")
    assert not verify_attestation(attestation, bundle_path, results_path)[0]


def test_v1alpha2_attestation_remains_readable() -> None:
    bundle_hash = "bundle"
    test_hash = "tests"
    revision = "previous"
    chain = "|".join([PREVIOUS_ATTESTATION_SCHEMA_VERSION, bundle_hash, test_hash, revision])
    previous = {
        "schema_version": PREVIOUS_ATTESTATION_SCHEMA_VERSION,
        "predicate": {
            "bundle_document_sha256": bundle_hash,
            "test_results_document_sha256": test_hash,
            "source_revision": revision,
        },
        "integrity": {"chain_sha256": sha256(chain.encode("utf-8")).hexdigest()},
    }
    assert verify_attestation(previous)[0]


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


def test_v1alpha3_verification_reports_internal_limit_and_individual_supplied_file_checks(
    tmp_path: Path,
) -> None:
    bundle_path = write_json(tmp_path / "bundle.json", {"value": 1})
    results_path = write_json(tmp_path / "results.json", {"value": 2})
    attestation = build_attestation(bundle_path, results_path, source_revision="test")

    valid, message = verify_attestation(attestation)
    assert valid
    assert "supplied files were not verified" in message
    assert verify_attestation(attestation, bundle_path=bundle_path)[0]
    assert verify_attestation(attestation, test_results_path=results_path)[0]

    malformed_subject = json.loads(json.dumps(attestation))
    malformed_subject["subject"] = [{"name": "bundle", "digest": {"sha256": "a" * 64}}]
    assert not verify_attestation(malformed_subject)[0]

    malformed_exact = json.loads(json.dumps(attestation))
    malformed_exact["predicate"]["exact_files"]["bundle"]["name"] = "other.json"
    assert not verify_attestation(malformed_exact)[0]


def test_cli_verify_v1alpha3_accepts_supplied_evidence_files(tmp_path: Path) -> None:
    bundle_path = write_json(tmp_path / "bundle.json", {"value": 1})
    results_path = write_json(tmp_path / "results.json", {"value": 2})
    attestation_path = write_json(
        tmp_path / "attestation.json",
        build_attestation(bundle_path, results_path, source_revision="test"),
    )
    assert (
        main(
            [
                "verify",
                "--attestation",
                str(attestation_path),
                "--bundle",
                str(bundle_path),
                "--test-results",
                str(results_path),
            ]
        )
        == EXIT_SUCCESS
    )


def test_v1alpha3_rejects_malformed_internal_bindings_and_test_results_bytes(
    tmp_path: Path,
) -> None:
    bundle_path = write_json(tmp_path / "bundle.json", {"value": 1})
    results_path = write_json(tmp_path / "results.json", {"value": 2})
    attestation = build_attestation(bundle_path, results_path, source_revision="test")

    duplicate_subject = json.loads(json.dumps(attestation))
    duplicate_subject["subject"][1]["name"] = duplicate_subject["subject"][0]["name"]
    assert not verify_attestation(duplicate_subject)[0]

    invalid_subject_digest = json.loads(json.dumps(attestation))
    invalid_subject_digest["subject"][0]["digest"]["sha256"] = "invalid"
    assert not verify_attestation(invalid_subject_digest)[0]

    missing_file_binding = json.loads(json.dumps(attestation))
    del missing_file_binding["predicate"]["exact_files"]["test_results"]
    assert not verify_attestation(missing_file_binding)[0]

    results_path.write_text('{"value": 3}\n', encoding="utf-8")
    assert not verify_attestation(attestation, test_results_path=results_path)[0]


def test_legacy_versions_fail_closed_when_predicates_are_incomplete() -> None:
    assert not verify_attestation(
        {
            "schema_version": LEGACY_ATTESTATION_SCHEMA_VERSION,
            "predicate": {"bundle_sha256": "bundle"},
            "integrity": {"chain_sha256": "chain"},
        }
    )[0]
    assert not verify_attestation(
        {
            "schema_version": PREVIOUS_ATTESTATION_SCHEMA_VERSION,
            "predicate": {"bundle_document_sha256": "bundle"},
            "integrity": {"chain_sha256": "chain"},
        }
    )[0]


def test_v1alpha3_attestation_verification_preserves_exact_result_contracts(tmp_path: Path) -> None:
    """Verification messages distinguish internal bindings from supplied-file evidence checks."""

    bundle_path = write_json(tmp_path / "bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "results.json", {"results": 1})
    attestation = build_attestation(
        bundle_path,
        results_path,
        source_revision="verification-contract",
        generated_at="2026-08-15T00:00:00+00:00",
        bundle_name="bundle.json",
        test_results_name="results.json",
    )

    assert verify_attestation(attestation) == (
        True,
        "v1alpha3 attestation bindings are internally consistent; supplied files were not verified",
    )
    assert verify_attestation(attestation, bundle_path, results_path) == (
        True,
        "v1alpha3 attestation bindings are internally consistent with supplied-file verification",
    )

    bundle_path.write_text('{"bundle":2}\n', encoding="utf-8")
    assert verify_attestation(attestation, bundle_path=bundle_path) == (
        False,
        "Supplied bundle file does not match v1alpha3 exact-file and stable-payload digests",
    )
    assert verify_attestation({"schema_version": "unknown"}) == (
        False,
        "Attestation is missing predicate or integrity data",
    )
    assert verify_attestation({"schema_version": "unknown", "predicate": {}, "integrity": {}}) == (
        False,
        "Unsupported attestation schema version",
    )
