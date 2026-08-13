"""Local, hash-linked evidence statements for TrustWeave artifacts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import Any

from trustweave.io import canonical_json, read_json
from trustweave.models import ValidationError
from trustweave.provenance import add_generated_at, stable_document_hash

ATTESTATION_SCHEMA_VERSION = "trustweave.dev/attestation/v1alpha3"
PREVIOUS_ATTESTATION_SCHEMA_VERSION = "trustweave.dev/attestation/v1alpha2"
LEGACY_ATTESTATION_SCHEMA_VERSION = "trustweave.dev/attestation/v1alpha1"


def _file_hash(path: Path) -> str:
    if not path.is_file():
        raise ValidationError(f"Required generated artifact is missing: {path}")
    return sha256(path.read_bytes()).hexdigest()


def _chain_digest_v1_or_v2(
    schema_version: str, bundle_hash: str, test_hash: str, source_revision: str
) -> str:
    chain_input = "|".join([schema_version, bundle_hash, test_hash, source_revision])
    return sha256(chain_input.encode("utf-8")).hexdigest()


def _chain_digest_v3(predicate: Mapping[str, Any], subjects: Sequence[Mapping[str, Any]]) -> str:
    """Bind all local v1alpha3 integrity claims without volatile provenance metadata."""

    material = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "predicate": predicate,
        "subject": list(subjects),
    }
    return sha256(canonical_json(material).encode("utf-8")).hexdigest()


def _subject(path: Path, digest: str) -> dict[str, Any]:
    return {"name": str(path), "digest": {"sha256": digest}}


def build_attestation(
    bundle_path: Path,
    test_results_path: Path,
    source_revision: str = "local-uncommitted",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Create unsigned local integrity evidence with stable and exact-file claims separated."""

    bundle = dict(read_json(bundle_path))
    test_results = dict(read_json(test_results_path))
    subjects = [
        _subject(bundle_path, _file_hash(bundle_path)),
        _subject(test_results_path, _file_hash(test_results_path)),
    ]
    predicate: dict[str, Any] = {
        "source_revision": source_revision,
        "stable_payload": {
            "bundle_sha256": stable_document_hash(bundle),
            "test_results_sha256": stable_document_hash(test_results),
        },
        "exact_files": {
            "bundle": {"name": str(bundle_path), "sha256": subjects[0]["digest"]["sha256"]},
            "test_results": {
                "name": str(test_results_path),
                "sha256": subjects[1]["digest"]["sha256"],
            },
        },
    }
    attestation: dict[str, Any] = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "subject": subjects,
        "predicate_type": "https://trustweave.dev/attestation/local-evidence/v1alpha3",
        "predicate": predicate,
        "integrity": {
            "chain_sha256": _chain_digest_v3(predicate, subjects),
            "covers": (
                "stable payload digests, exact file digests, subject bindings, source revision, "
                "and generated_at exclusion"
            ),
        },
        "limits": [
            (
                "This is a local hash-linked statement, not an externally signed or "
                "transparency-log-backed attestation."
            ),
            (
                "Exact-file verification requires the referenced local files to be supplied to "
                "the verifier; an internal-only check cannot establish their current bytes."
            ),
        ],
    }
    return add_generated_at(attestation, generated_at)


def _valid_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _verify_legacy_attestation(predicate: Mapping[str, Any], integrity: Mapping[str, Any]) -> bool:
    required_fields = ("bundle_sha256", "test_results_sha256", "source_revision")
    if any(not isinstance(predicate.get(field), str) for field in required_fields):
        return False
    expected = _chain_digest_v1_or_v2(
        LEGACY_ATTESTATION_SCHEMA_VERSION,
        str(predicate["bundle_sha256"]),
        str(predicate["test_results_sha256"]),
        str(predicate["source_revision"]),
    )
    return integrity.get("chain_sha256") == expected


def _verify_v1alpha2_attestation(
    predicate: Mapping[str, Any], integrity: Mapping[str, Any]
) -> bool:
    required_fields = ("bundle_document_sha256", "test_results_document_sha256", "source_revision")
    if any(not isinstance(predicate.get(field), str) for field in required_fields):
        return False
    expected = _chain_digest_v1_or_v2(
        PREVIOUS_ATTESTATION_SCHEMA_VERSION,
        str(predicate["bundle_document_sha256"]),
        str(predicate["test_results_document_sha256"]),
        str(predicate["source_revision"]),
    )
    return integrity.get("chain_sha256") == expected


def _verify_v1alpha3_attestation(
    predicate: Mapping[str, Any], integrity: Mapping[str, Any], subjects: Any
) -> bool:
    if not isinstance(predicate.get("source_revision"), str):
        return False
    stable = predicate.get("stable_payload")
    exact = predicate.get("exact_files")
    if not isinstance(stable, Mapping) or not isinstance(exact, Mapping):
        return False
    if not _valid_digest(stable.get("bundle_sha256")) or not _valid_digest(
        stable.get("test_results_sha256")
    ):
        return False
    if not isinstance(subjects, Sequence) or isinstance(subjects, (str, bytes, bytearray)):
        return False
    subject_entries = [entry for entry in subjects if isinstance(entry, Mapping)]
    if len(subject_entries) != 2:
        return False
    subjects_by_name: dict[str, str] = {}
    for subject in subject_entries:
        name = subject.get("name")
        digest = subject.get("digest")
        if (
            not isinstance(name, str)
            or not isinstance(digest, Mapping)
            or not _valid_digest(digest.get("sha256"))
        ):
            return False
        if name in subjects_by_name:
            return False
        subjects_by_name[name] = str(digest["sha256"])
    for label in ("bundle", "test_results"):
        file_binding = exact.get(label)
        if not isinstance(file_binding, Mapping):
            return False
        name = file_binding.get("name")
        digest = file_binding.get("sha256")
        if not isinstance(name, str) or not _valid_digest(digest):
            return False
        if subjects_by_name.get(name) != digest:
            return False
    expected = _chain_digest_v3(predicate, subject_entries)
    return integrity.get("chain_sha256") == expected


def _verify_supplied_file(path: Path, exact_digest: Any, stable_digest: Any) -> bool:
    if not _valid_digest(exact_digest) or not _valid_digest(stable_digest):
        return False
    exact = str(exact_digest)
    stable = str(stable_digest)
    if _file_hash(path) != exact:
        return False
    return stable_document_hash(dict(read_json(path))) == stable


def verify_attestation(
    attestation: Mapping[str, Any],
    bundle_path: Path | None = None,
    test_results_path: Path | None = None,
) -> tuple[bool, str]:
    """Verify versioned local integrity claims and supplied-file bytes when available."""

    schema_version = attestation.get("schema_version")
    predicate = attestation.get("predicate")
    integrity = attestation.get("integrity")
    if not isinstance(predicate, Mapping) or not isinstance(integrity, Mapping):
        return False, "Attestation is missing predicate or integrity data"
    if schema_version == ATTESTATION_SCHEMA_VERSION:
        if not _verify_v1alpha3_attestation(predicate, integrity, attestation.get("subject")):
            return False, "v1alpha3 attestation integrity does not match its bindings"
        stable = predicate["stable_payload"]
        exact = predicate["exact_files"]
        if bundle_path is not None and not _verify_supplied_file(
            bundle_path,
            _mapping_value(exact, "bundle", "sha256"),
            _mapping_value(stable, None, "bundle_sha256"),
        ):
            return (
                False,
                "Supplied bundle file does not match v1alpha3 exact-file and stable-payload "
                "digests",
            )
        if test_results_path is not None and not _verify_supplied_file(
            test_results_path,
            _mapping_value(exact, "test_results", "sha256"),
            _mapping_value(stable, None, "test_results_sha256"),
        ):
            return (
                False,
                "Supplied test-results file does not match v1alpha3 exact-file and stable-payload "
                "digests",
            )
        supplied = bundle_path is not None or test_results_path is not None
        limitation = (
            " with supplied-file verification" if supplied else "; supplied files were not verified"
        )
        return True, f"v1alpha3 attestation bindings are internally consistent{limitation}"
    if schema_version == PREVIOUS_ATTESTATION_SCHEMA_VERSION:
        valid = _verify_v1alpha2_attestation(predicate, integrity)
        return (
            (True, "v1alpha2 attestation hash chain is internally consistent")
            if valid
            else (False, "v1alpha2 attestation hash chain does not match its predicate")
        )
    if schema_version == LEGACY_ATTESTATION_SCHEMA_VERSION:
        valid = _verify_legacy_attestation(predicate, integrity)
        return (
            (True, "v1alpha1 attestation hash chain is internally consistent")
            if valid
            else (False, "v1alpha1 attestation hash chain does not match its predicate")
        )
    return False, "Unsupported attestation schema version"


def _mapping_value(value: Any, nested: str | None, key: str) -> Any:
    if not isinstance(value, Mapping):
        return None
    target = value.get(nested) if nested is not None else value
    return target.get(key) if isinstance(target, Mapping) else None
