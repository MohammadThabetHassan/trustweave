from __future__ import annotations

from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.evidence import build_attestation
from trustweave.io import read_json, write_json
from trustweave.models import ValidationError
from trustweave.statement import build_unsigned_statement

ROOT = Path(__file__).resolve().parents[1]


def _attestation(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle.json"
    results = tmp_path / "results.json"
    write_json(bundle, {"bundle": True})
    write_json(results, {"results": True})
    path = tmp_path / "attestation.json"
    write_json(path, build_attestation(bundle, results, source_revision="statement-test"))
    return path


def test_unsigned_statement_preserves_local_evidence_without_provenance_claim(
    tmp_path: Path,
) -> None:
    statement = build_unsigned_statement(read_json(_attestation(tmp_path)))

    assert statement["unsigned"] is True
    assert statement["schema_version"] == "trustweave.dev/unsigned-statement/v1alpha1"
    assert "no signature" in statement["limits"][0]
    assert "does not establish provenance" in statement["limits"][1]


def test_statement_rejects_non_attestation() -> None:
    with pytest.raises(ValidationError, match="local attestation"):
        build_unsigned_statement({})


def test_cli_writes_unsigned_statement(tmp_path: Path) -> None:
    attestation = _attestation(tmp_path)
    output_dir = tmp_path / "output"

    assert (
        main(["statement", "--attestation", str(attestation), "--output-dir", str(output_dir)]) == 0
    )
    assert read_json(output_dir / "unsigned-statement.json")["unsigned"] is True


@pytest.mark.parametrize(
    "attestation",
    [
        {"schema_version": "trustweave.dev/attestation/v1alpha3"},
        {
            "schema_version": "trustweave.dev/attestation/v1alpha3",
            "subject": {},
            "predicate": {},
            "integrity": {},
        },
    ],
)
def test_unsigned_statement_rejects_incomplete_attestation_envelopes(
    attestation: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="missing subject"):
        build_unsigned_statement(attestation)
