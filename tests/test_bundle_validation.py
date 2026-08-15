"""Behavioral tests for strict local bundle evidence validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.bundles import validate_bundle
from trustweave.engine import build_bundle
from trustweave.io import load_document
from trustweave.models import ValidationError, parse_manifest, parse_policy

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"


def _bundle() -> dict[str, object]:
    return build_bundle(
        parse_manifest(load_document(MANIFEST)),
        parse_policy(load_document(POLICY)),
        "2026-08-15T00:00:00+00:00",
    )


def _copy_bundle() -> dict[str, object]:
    return json.loads(json.dumps(_bundle()))


def test_validate_bundle_accepts_real_generated_evidence() -> None:
    """A bundle emitted by the local deterministic generator is a valid supplied bundle input."""

    validate_bundle(_bundle())


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda bundle: bundle.update({"schema_version": "unsupported"}), "schema_version"),
        (lambda bundle: bundle.update({"unexpected": True}), "unknown field"),
        (lambda bundle: bundle.pop("policy"), "missing required fields"),
        (lambda bundle: bundle.update({"generated_at": "2026-08-15"}), "UTC offset"),
        (lambda bundle: bundle.update({"findings": "not-a-list"}), "findings must be a list"),
        (lambda bundle: bundle.update({"limits": []}), "limits must contain between"),
        (
            lambda bundle: bundle["summary"].update({"allow": -1}),  # type: ignore[index]
            "non-negative integer",
        ),
    ],
)
def test_validate_bundle_rejects_invalid_top_level_contracts(mutate: object, message: str) -> None:
    """Version, envelope, timestamp, collection, and summary defects fail closed."""

    bundle = _copy_bundle()
    assert callable(mutate)
    mutate(bundle)

    with pytest.raises(ValidationError, match=message):
        validate_bundle(bundle)


def test_validate_bundle_rejects_inconsistent_finding_and_summary() -> None:
    """Finding snapshots must match declared manifest evidence and deterministic summary counts."""

    bundle = _copy_bundle()
    findings = bundle["findings"]
    assert isinstance(findings, list) and findings
    finding = findings[0]
    assert isinstance(finding, dict)
    finding["source"] = {"name": "unknown"}

    with pytest.raises(ValidationError, match="source and tool must match"):
        validate_bundle(bundle)

    bundle = _copy_bundle()
    summary = bundle["summary"]
    assert isinstance(summary, dict)
    summary["deny"] = 99
    with pytest.raises(ValidationError, match="must match bundle findings"):
        validate_bundle(bundle)


def test_validate_bundle_rejects_unknown_nested_policy_and_finding_fields() -> None:
    """The parser rejects non-contract extensions in normalized policy and findings evidence."""

    bundle = _copy_bundle()
    policy = bundle["policy"]
    assert isinstance(policy, dict)
    policy["unexpected"] = True
    with pytest.raises(ValidationError, match="unknown field"):
        validate_bundle(bundle)

    bundle = _copy_bundle()
    findings = bundle["findings"]
    assert isinstance(findings, list) and findings
    finding = findings[0]
    assert isinstance(finding, dict)
    finding["unexpected"] = True
    with pytest.raises(ValidationError, match="unknown field"):
        validate_bundle(bundle)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda bundle: bundle.update({"generated_at": "not-a-date"}), "ISO 8601"),
        (
            lambda bundle: bundle["policy"].update({"schema_version": "trustweave.dev/v1alpha1"}),  # type: ignore[index]
            "",
        ),
        (
            lambda bundle: bundle["policy"].update({"rules": "not-a-list"}),  # type: ignore[index]
            "rules must be a list",
        ),
        (
            lambda bundle: bundle["findings"][0]["flow"].update({"purpose_tags": [""]}),  # type: ignore[index]
            "purpose_tags",
        ),
        (
            lambda bundle: bundle["findings"][0]["flow"].update({"source": "unknown"}),  # type: ignore[index]
            "declared manifest source and tool",
        ),
        (
            lambda bundle: bundle["findings"][0].update({"decision": "invalid"}),  # type: ignore[index]
            "decision must be one of",
        ),
        (
            lambda bundle: bundle["findings"][0].update({"severity": "invalid"}),  # type: ignore[index]
            "severity must be one of",
        ),
        (
            lambda bundle: bundle["findings"][0].update({"rule_id": "TW-UNKNOWN"}),  # type: ignore[index]
            "declared policy rule",
        ),
        (
            lambda bundle: bundle["summary"].pop("deny"),  # type: ignore[index]
            "summary is missing required fields",
        ),
        (
            lambda bundle: bundle.update({"summary": []}),
            "summary must be an object",
        ),
        (
            lambda bundle: bundle["summary"].update({"allow": True}),  # type: ignore[index]
            "non-negative integer",
        ),
        (lambda bundle: bundle.update({"limits": "not-a-list"}), "limits must be a list"),
        (
            lambda bundle: bundle["limits"].__setitem__(0, ""),  # type: ignore[index]
            r"limits\[0\] must be a non-empty string",
        ),
    ],
)
def test_validate_bundle_rejects_semantically_invalid_nested_evidence(
    mutate: object, message: str
) -> None:
    """Nested evidence decisions, bindings, summary data, and limits fail closed."""

    bundle = _copy_bundle()
    assert callable(mutate)
    result = mutate(bundle)
    if message:
        with pytest.raises(ValidationError, match=message):
            validate_bundle(bundle)
    else:
        assert result is None
        validate_bundle(bundle)
