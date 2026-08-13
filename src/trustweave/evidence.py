"""Local, hash-linked evidence statements for TrustWeave artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from trustweave.io import document_hash, read_json
from trustweave.models import ValidationError


def _file_hash(path: Path) -> str:
    if not path.is_file():
        raise ValidationError(f"Required generated artifact is missing: {path}")
    return sha256(path.read_bytes()).hexdigest()


def build_attestation(
    bundle_path: Path,
    test_results_path: Path,
    source_revision: str = "local-uncommitted",
) -> dict[str, Any]:
    """Create a deterministic evidence statement linked to existing local artifacts.

    The statement is hash-linked but intentionally not externally signed. It is useful for
    local review and can later be upgraded to DSSE or Sigstore-backed attestations.
    """

    bundle = read_json(bundle_path)
    test_results = read_json(test_results_path)
    bundle_hash = _file_hash(bundle_path)
    test_hash = _file_hash(test_results_path)
    predicate = {
        "bundle_sha256": bundle_hash,
        "test_results_sha256": test_hash,
        "bundle_document_sha256": document_hash(bundle),
        "test_results_document_sha256": document_hash(test_results),
        "source_revision": source_revision,
    }
    chain_input = "|".join(
        [
            "trustweave.dev/attestation/v1alpha1",
            predicate["bundle_sha256"],
            predicate["test_results_sha256"],
            source_revision,
        ]
    )
    return {
        "schema_version": "trustweave.dev/attestation/v1alpha1",
        "generated_at": datetime.now(UTC).isoformat(),
        "subject": [
            {"name": str(bundle_path), "digest": {"sha256": bundle_hash}},
            {"name": str(test_results_path), "digest": {"sha256": test_hash}},
        ],
        "predicate_type": "https://trustweave.dev/attestation/local-evidence/v1alpha1",
        "predicate": predicate,
        "integrity": {"chain_sha256": sha256(chain_input.encode("utf-8")).hexdigest()},
        "limits": [
            (
                "This is a local hash-linked statement, not an externally signed or "
                "transparency-log-backed attestation."
            ),
            (
                "The statement verifies artifact integrity after generation only when "
                "the verifier has access to the same files."
            ),
        ],
    }


def verify_attestation(attestation: Mapping[str, Any]) -> tuple[bool, str]:
    """Verify the structure and hash-chain relationship of an attestation document."""

    if attestation.get("schema_version") != "trustweave.dev/attestation/v1alpha1":
        return False, "Unsupported attestation schema version"
    predicate = attestation.get("predicate")
    integrity = attestation.get("integrity")
    if not isinstance(predicate, Mapping) or not isinstance(integrity, Mapping):
        return False, "Attestation is missing predicate or integrity data"
    required_fields = ("bundle_sha256", "test_results_sha256", "source_revision")
    if any(not isinstance(predicate.get(field), str) for field in required_fields):
        return False, "Attestation predicate is incomplete"
    chain_input = "|".join(
        [
            "trustweave.dev/attestation/v1alpha1",
            str(predicate["bundle_sha256"]),
            str(predicate["test_results_sha256"]),
            str(predicate["source_revision"]),
        ]
    )
    expected = sha256(chain_input.encode("utf-8")).hexdigest()
    observed = integrity.get("chain_sha256")
    if observed != expected:
        return False, "Attestation hash chain does not match its predicate"
    return True, "Attestation hash chain is internally consistent"
