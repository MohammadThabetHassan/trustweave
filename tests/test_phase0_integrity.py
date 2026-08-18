from __future__ import annotations

import json
import subprocess
import sys
import venv
import zipfile
from hashlib import sha256
from pathlib import Path, PureWindowsPath

import pytest

import trustweave.evidence as evidence_module
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


def test_attestation_builder_binds_documented_logical_name_resolution_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default logical artifact names are derived from their matching local paths and roles."""

    bundle_path = write_json(tmp_path / "actual-bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "actual-results.json", {"results": 1})
    observed: list[tuple[object, object, object]] = []
    original = evidence_module._logical_name

    def capture(name: object, path: object, role: object) -> str:
        observed.append((name, path, role))
        return original(name, path, role)

    monkeypatch.setattr(evidence_module, "_logical_name", capture)
    attestation = build_attestation(bundle_path, results_path, source_revision="name-resolution")

    assert observed == [
        (None, bundle_path, "bundle"),
        (None, results_path, "test-results"),
    ]
    assert [subject["name"] for subject in attestation["subject"]] == [
        str(bundle_path),
        str(results_path),
    ]


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


def test_v1alpha3_individual_supplied_file_verification_reports_exact_success_contract(
    tmp_path: Path,
) -> None:
    """Supplying either referenced file performs and reports supplied-file verification."""

    bundle_path = write_json(tmp_path / "bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "results.json", {"results": 1})
    attestation = build_attestation(
        bundle_path,
        results_path,
        source_revision="partial-supplied-file-contract",
        generated_at="2026-08-18T00:00:00+00:00",
        bundle_name="bundle.json",
        test_results_name="results.json",
    )
    expected = (
        True,
        "v1alpha3 attestation bindings are internally consistent with supplied-file verification",
    )

    assert verify_attestation(attestation, bundle_path=bundle_path) == expected
    assert verify_attestation(attestation, test_results_path=results_path) == expected


def test_v1alpha3_attestation_binds_explicit_logical_artifact_names(tmp_path: Path) -> None:
    """The signed local binding records supplied logical file identities, not temporary paths."""

    bundle_path = write_json(tmp_path / "physical-bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "physical-results.json", {"results": 1})
    attestation = build_attestation(
        bundle_path,
        results_path,
        source_revision="logical-name-contract",
        generated_at="2026-08-18T00:00:00+00:00",
        bundle_name="agent-security-bundle.json",
        test_results_name="security-test-results.json",
    )

    assert attestation["subject"] == [
        {
            "name": "agent-security-bundle.json",
            "digest": {"sha256": sha256(bundle_path.read_bytes()).hexdigest()},
        },
        {
            "name": "security-test-results.json",
            "digest": {"sha256": sha256(results_path.read_bytes()).hexdigest()},
        },
    ]
    assert attestation["predicate"]["exact_files"] == {
        "bundle": {
            "name": "agent-security-bundle.json",
            "sha256": sha256(bundle_path.read_bytes()).hexdigest(),
        },
        "test_results": {
            "name": "security-test-results.json",
            "sha256": sha256(results_path.read_bytes()).hexdigest(),
        },
    }


def test_v1alpha3_attestation_rejects_duplicate_logical_artifact_names(tmp_path: Path) -> None:
    """A local attestation cannot ambiguously bind both evidence roles to one logical name."""

    bundle_path = write_json(tmp_path / "bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "results.json", {"results": 1})

    with pytest.raises(ValidationError) as error:
        build_attestation(
            bundle_path,
            results_path,
            source_revision="duplicate-logical-name",
            bundle_name="evidence.json",
            test_results_name="evidence.json",
        )
    assert str(error.value) == "bundle and test-results logical artifact names must be distinct"


def test_legacy_attestation_verification_preserves_exact_schema_specific_result_contracts() -> None:
    """Supported historical attestation versions remain explicit about valid and broken chains."""

    v1alpha2_chain = "|".join([PREVIOUS_ATTESTATION_SCHEMA_VERSION, "bundle", "tests", "previous"])
    v1alpha2 = {
        "schema_version": PREVIOUS_ATTESTATION_SCHEMA_VERSION,
        "predicate": {
            "bundle_document_sha256": "bundle",
            "test_results_document_sha256": "tests",
            "source_revision": "previous",
        },
        "integrity": {"chain_sha256": sha256(v1alpha2_chain.encode("utf-8")).hexdigest()},
    }
    v1alpha1_chain = "|".join([LEGACY_ATTESTATION_SCHEMA_VERSION, "bundle", "tests", "legacy"])
    v1alpha1 = {
        "schema_version": LEGACY_ATTESTATION_SCHEMA_VERSION,
        "predicate": {
            "bundle_sha256": "bundle",
            "test_results_sha256": "tests",
            "source_revision": "legacy",
        },
        "integrity": {"chain_sha256": sha256(v1alpha1_chain.encode("utf-8")).hexdigest()},
    }

    assert verify_attestation(v1alpha2) == (
        True,
        "v1alpha2 attestation hash chain is internally consistent",
    )
    assert verify_attestation({**v1alpha2, "integrity": {"chain_sha256": "invalid"}}) == (
        False,
        "v1alpha2 attestation hash chain does not match its predicate",
    )
    assert verify_attestation(v1alpha1) == (
        True,
        "v1alpha1 attestation hash chain is internally consistent",
    )
    assert verify_attestation({**v1alpha1, "integrity": {"chain_sha256": "invalid"}}) == (
        False,
        "v1alpha1 attestation hash chain does not match its predicate",
    )


def test_v1alpha3_verifier_fails_closed_for_every_required_binding_shape(tmp_path: Path) -> None:
    """Every mandatory v1alpha3 predicate, subject, and exact-file binding must be well formed."""

    bundle_path = write_json(tmp_path / "bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "results.json", {"results": 1})
    attestation = build_attestation(bundle_path, results_path, source_revision="strict-bindings")

    malformed: list[dict[str, object]] = []
    invalid_revision = json.loads(json.dumps(attestation))
    invalid_revision["predicate"]["source_revision"] = 1
    malformed.append(invalid_revision)
    invalid_stable = json.loads(json.dumps(attestation))
    invalid_stable["predicate"]["stable_payload"] = []
    malformed.append(invalid_stable)
    invalid_exact = json.loads(json.dumps(attestation))
    invalid_exact["predicate"]["exact_files"] = []
    malformed.append(invalid_exact)
    invalid_stable_digest = json.loads(json.dumps(attestation))
    invalid_stable_digest["predicate"]["stable_payload"]["bundle_sha256"] = "invalid"
    malformed.append(invalid_stable_digest)
    invalid_subject_collection = json.loads(json.dumps(attestation))
    invalid_subject_collection["subject"] = 1
    malformed.append(invalid_subject_collection)
    invalid_subject_digest = json.loads(json.dumps(attestation))
    invalid_subject_digest["subject"][0]["digest"] = []
    malformed.append(invalid_subject_digest)
    invalid_exact_binding = json.loads(json.dumps(attestation))
    invalid_exact_binding["predicate"]["exact_files"]["bundle"]["sha256"] = "invalid"
    malformed.append(invalid_exact_binding)

    for candidate in malformed:
        valid, message = verify_attestation(candidate)
        assert valid is False
        assert message in {
            "v1alpha3 attestation bindings do not match their predicate",
            "v1alpha3 attestation integrity does not match its bindings",
        }


@pytest.mark.parametrize("logical_name", ("", ".", "..", "/", "nested/bundle.json"))
def test_v1alpha3_attestation_rejects_non_file_logical_artifact_names(
    tmp_path: Path, logical_name: str
) -> None:
    """Logical artifact names are single stable file identities, never paths or dot segments."""

    bundle_path = write_json(tmp_path / "bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "results.json", {"results": 1})

    with pytest.raises(ValidationError) as error:
        build_attestation(
            bundle_path,
            results_path,
            source_revision="logical-name-boundary",
            bundle_name=logical_name,
        )
    assert str(error.value) == "bundle logical artifact name must be one relative file name"


def test_v1alpha3_attestation_rejects_each_malformed_top_level_binding_half(
    tmp_path: Path,
) -> None:
    """Verification must reject a malformed predicate or integrity envelope independently."""

    bundle_path = write_json(tmp_path / "bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "results.json", {"results": 1})
    attestation = build_attestation(bundle_path, results_path, source_revision="malformed-half")

    malformed_predicate = {**attestation, "predicate": "not-a-mapping"}
    malformed_integrity = {**attestation, "integrity": "not-a-mapping"}
    expected = (False, "Attestation is missing predicate or integrity data")

    assert verify_attestation(malformed_predicate) == expected
    assert verify_attestation(malformed_integrity) == expected


def test_v1alpha3_attestation_preserves_exact_test_results_mismatch_diagnostic(
    tmp_path: Path,
) -> None:
    """Supplied test-results byte drift remains distinguishable from bundle drift."""

    bundle_path = write_json(tmp_path / "bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "results.json", {"results": 1})
    attestation = build_attestation(
        bundle_path,
        results_path,
        source_revision="test-results-mismatch",
        generated_at="2026-08-18T00:00:00+00:00",
    )
    results_path.write_text('{"results":2}\n', encoding="utf-8")

    assert verify_attestation(attestation, test_results_path=results_path) == (
        False,
        "Supplied test-results file does not match v1alpha3 exact-file and stable-payload digests",
    )


def test_evidence_digest_and_required_file_validation_boundaries(tmp_path: Path) -> None:
    """Integrity helpers accept only lowercase 64-character SHA-256 strings and real files."""

    assert evidence_module._valid_digest("0" * 64)
    assert not evidence_module._valid_digest(list("0" * 64))
    assert not evidence_module._valid_digest("short")
    assert not evidence_module._valid_digest("X" * 64)

    missing = tmp_path / "missing.json"
    with pytest.raises(ValidationError) as error:
        evidence_module._file_hash(missing)
    assert str(error.value) == f"Required generated artifact is missing: {missing}"


def test_v1alpha3_default_revision_and_internal_malformed_digest_checks(tmp_path: Path) -> None:
    """Default provenance and malformed digest branches remain explicit and fail closed."""

    bundle_path = write_json(tmp_path / "bundle.json", {"bundle": 1})
    results_path = write_json(tmp_path / "results.json", {"results": 1})
    attestation = build_attestation(bundle_path, results_path)
    assert attestation["predicate"]["source_revision"] == "local-uncommitted"

    assert not evidence_module._verify_supplied_file(bundle_path, "bad", "a" * 64)
    assert not evidence_module._verify_supplied_file(bundle_path, "bad", "also_bad")
    assert not evidence_module._verify_v1alpha3_attestation(
        {
            "stable_payload": {"bundle_sha256": "bad", "test_results_sha256": "a" * 64},
            "exact_files": {},
        },
        {},
        {},
    )
    assert not evidence_module._verify_v1alpha3_attestation(
        {
            "stable_payload": {"bundle_sha256": "a" * 64, "test_results_sha256": "a" * 64},
            "exact_files": {"files": [{"name": 123, "sha256": "a" * 64}]},
        },
        {},
        {},
    )


def test_evidence_logical_names_reject_windows_rooted_separator_forms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logical artifact names reject separators independent of the host path parser."""

    monkeypatch.setattr(evidence_module, "Path", PureWindowsPath)
    for name in ("/", "\\"):
        with pytest.raises(ValidationError) as error:
            evidence_module._logical_name(name, PureWindowsPath("bundle.json"), "bundle")
        assert str(error.value) == "bundle logical artifact name must be one relative file name"


def test_evidence_helpers_reject_invalid_logical_names_and_digest_halves(tmp_path: Path) -> None:
    """Evidence helpers fail closed for dot logical names and either invalid digest half."""

    with pytest.raises(ValidationError) as error:
        evidence_module._logical_name(".", tmp_path / "bundle.json", "bundle")
    assert str(error.value) == "bundle logical artifact name must be one relative file name"

    assert not evidence_module._verify_supplied_file(tmp_path / "missing.json", "bad", "a" * 64)

    subjects = [
        {"name": "bundle.json", "digest": {"sha256": "a" * 64}},
        {"name": "test-results.json", "digest": {"sha256": "b" * 64}},
    ]
    predicate = {
        "source_revision": "local-revision",
        "stable_payload": {
            "bundle_sha256": "invalid",
            "test_results_sha256": "c" * 64,
        },
        "exact_files": {
            "bundle": {"name": "bundle.json", "sha256": "a" * 64},
            "test_results": {"name": "test-results.json", "sha256": "b" * 64},
        },
    }
    integrity = {"chain_sha256": evidence_module._chain_digest_v3(predicate, subjects)}
    assert not evidence_module._verify_v1alpha3_attestation(predicate, integrity, subjects)
