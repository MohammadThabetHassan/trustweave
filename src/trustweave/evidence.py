"""Local, hash-linked evidence statements for TrustWeave artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

from trustweave.io import read_json
from trustweave.models import ValidationError
from trustweave.provenance import add_generated_at, stable_document_hash

ATTESTATION_SCHEMA_VERSION = "trustweave.dev/attestation/v1alpha2"
LEGACY_ATTESTATION_SCHEMA_VERSION = "trustweave.dev/attestation/v1alpha1"


def _file_hash(path: Path) -> str:
    if not path.is_file():
        raise ValidationError(f"Required generated artifact is missing: {path}")
    return sha256(path.read_bytes()).hexdigest()


def _chain_digest(
    schema_version: str, bundle_hash: str, test_hash: str, source_revision: str
) -> str:
    chain_input = "|".join([schema_version, bundle_hash, test_hash, source_revision])
    return sha256(chain_input.encode("utf-8")).hexdigest()


def build_attestation(
    bundle_path: Path,
    test_results_path: Path,
    source_revision: str = "local-uncommitted",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Create local integrity evidence for stable payloads and optional provenance metadata.

    The attestation is hash-linked but intentionally unsigned. File hashes retain a reference to
    the exact generated files, while the integrity chain is computed from canonical evidence
    payloads after excluding volatile ``generated_at`` metadata.
    """

    bundle = dict(read_json(bundle_path))
    test_results = dict(read_json(test_results_path))
    bundle_file_hash = _file_hash(bundle_path)
    test_file_hash = _file_hash(test_results_path)
    bundle_payload_hash = stable_document_hash(bundle)
    test_payload_hash = stable_document_hash(test_results)
    predicate = {
        "bundle_file_sha256": bundle_file_hash,
        "test_results_file_sha256": test_file_hash,
        "bundle_document_sha256": bundle_payload_hash,
        "test_results_document_sha256": test_payload_hash,
        "source_revision": source_revision,
    }
    attestation: dict[str, object] = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "subject": [
            {"name": str(bundle_path), "digest": {"sha256": bundle_file_hash}},
            {"name": str(test_results_path), "digest": {"sha256": test_file_hash}},
        ],
        "predicate_type": "https://trustweave.dev/attestation/local-evidence/v1alpha2",
        "predicate": predicate,
        "integrity": {
            "chain_sha256": _chain_digest(
                ATTESTATION_SCHEMA_VERSION,
                bundle_payload_hash,
                test_payload_hash,
                source_revision,
            ),
            "covers": "canonical stable evidence payloads excluding generated_at",
        },
        "limits": [
            (
                "This is a local hash-linked statement, not an externally signed or "
                "transparency-log-backed attestation."
            ),
            (
                "The integrity chain covers canonical stable evidence payloads; file hashes "
                "remain available to identify the exact local files used at generation time."
            ),
        ],
    }
    return add_generated_at(attestation, generated_at)


def _verify_legacy_attestation(predicate: Mapping[str, Any], integrity: Mapping[str, Any]) -> bool:
    required_fields = ("bundle_sha256", "test_results_sha256", "source_revision")
    if any(not isinstance(predicate.get(field), str) for field in required_fields):
        return False
    expected = _chain_digest(
        LEGACY_ATTESTATION_SCHEMA_VERSION,
        str(predicate["bundle_sha256"]),
        str(predicate["test_results_sha256"]),
        str(predicate["source_revision"]),
    )
    return integrity.get("chain_sha256") == expected


def _verify_current_attestation(predicate: Mapping[str, Any], integrity: Mapping[str, Any]) -> bool:
    required_fields = ("bundle_document_sha256", "test_results_document_sha256", "source_revision")
    if any(not isinstance(predicate.get(field), str) for field in required_fields):
        return False
    expected = _chain_digest(
        ATTESTATION_SCHEMA_VERSION,
        str(predicate["bundle_document_sha256"]),
        str(predicate["test_results_document_sha256"]),
        str(predicate["source_revision"]),
    )
    return integrity.get("chain_sha256") == expected


def verify_attestation(attestation: Mapping[str, Any]) -> tuple[bool, str]:
    """Verify a local attestation's schema and internal hash-chain relationship."""

    schema_version = attestation.get("schema_version")
    predicate = attestation.get("predicate")
    integrity = attestation.get("integrity")
    if not isinstance(predicate, Mapping) or not isinstance(integrity, Mapping):
        return False, "Attestation is missing predicate or integrity data"
    if schema_version == ATTESTATION_SCHEMA_VERSION:
        valid = _verify_current_attestation(predicate, integrity)
    elif schema_version == LEGACY_ATTESTATION_SCHEMA_VERSION:
        valid = _verify_legacy_attestation(predicate, integrity)
    else:
        return False, "Unsupported attestation schema version"
    if not valid:
        return False, "Attestation hash chain does not match its predicate"
    return True, "Attestation hash chain is internally consistent"
