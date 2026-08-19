"""Behavioral tests for strict local bundle evidence validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.bundles import validate_bundle
from trustweave.cli import main
from trustweave.diff import diff_bundles
from trustweave.engine import build_bundle
from trustweave.io import load_document
from trustweave.models import ValidationError, parse_manifest, parse_policy

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
HISTORICAL_V011_BUNDLE = (
    ROOT / "tests" / "fixtures" / "historical-v011" / "authentic-v0.1.1-bundle.json"
)


def _bundle() -> dict[str, object]:
    return build_bundle(
        parse_manifest(load_document(MANIFEST)),
        parse_policy(load_document(POLICY)),
        "2026-08-15T00:00:00+00:00",
    )


def _copy_bundle() -> dict[str, object]:
    return json.loads(json.dumps(_bundle()))


def _legacy_v011_bundle() -> dict[str, object]:
    return json.loads(HISTORICAL_V011_BUNDLE.read_text(encoding="utf-8"))


def test_validate_bundle_accepts_real_generated_evidence() -> None:
    """A bundle emitted by the local deterministic generator is a valid supplied bundle input."""

    validate_bundle(_bundle())


def test_validate_bundle_accepts_authentic_v011_bundle_shape() -> None:
    """An authentic bundle emitted by the published 0.1.1 CLI remains a supported legacy input."""

    validate_bundle(_legacy_v011_bundle())


def test_validate_bundle_rejects_malformed_v011_false_clear() -> None:
    """An empty legacy manifest and policy must not pass semantic bundle validation."""

    malformed = {
        "schema_version": "trustweave.dev/bundle/v1alpha1",
        "manifest": {},
        "policy": {},
        "findings": [],
        "summary": {},
        "limits": ["Historical declared-evidence limitation."],
    }

    with pytest.raises(ValidationError, match="manifest"):
        validate_bundle(malformed)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda bundle: bundle.update({"manifest": {}}), "manifest"),
        (lambda bundle: bundle.update({"policy": {}}), "policy"),
        (lambda bundle: bundle.pop("limits"), "missing required fields"),
        (lambda bundle: bundle.update({"unexpected": True}), "unknown field"),
        (
            lambda bundle: bundle["manifest"]["sources"][0].update({"trust": "unknown"}),  # type: ignore[index]
            "trust must be one of",
        ),
        (
            lambda bundle: bundle["manifest"]["flows"][0].update({"source": "unknown"}),  # type: ignore[index]
            "references unknown source",
        ),
        (
            lambda bundle: bundle["policy"]["rules"][0].update({"decision": "invalid"}),  # type: ignore[index]
            "decision must be one of",
        ),
        (
            lambda bundle: bundle["findings"][0].update({"decision": "invalid"}),  # type: ignore[index]
            "decision must be one of",
        ),
        (
            lambda bundle: bundle["findings"][0].update({"rule_id": "TW-UNKNOWN"}),  # type: ignore[index]
            "rule_id must match",
        ),
        (
            lambda bundle: bundle["summary"].update({"allow": 99}),  # type: ignore[index]
            "summary.allow must match",
        ),
        (lambda bundle: bundle.update({"generated_at": "not-a-timestamp"}), "ISO 8601"),
        (lambda bundle: bundle.update({"limits": []}), "limits must contain between"),
    ],
)
def test_validate_bundle_rejects_malformed_v011_nested_evidence(
    mutate: object, message: str
) -> None:
    """Legacy evidence is parsed with the released shape's strict declaration and linkage rules."""

    bundle = _legacy_v011_bundle()
    assert callable(mutate)
    mutate(bundle)

    with pytest.raises(ValidationError, match=message):
        validate_bundle(bundle)


def test_validate_bundle_rejects_oversized_v011_findings() -> None:
    """Legacy supplied evidence remains bounded before any downstream review operation."""

    bundle = _legacy_v011_bundle()
    findings = bundle["findings"]
    assert isinstance(findings, list) and findings
    bundle["findings"] = findings * 2_501

    with pytest.raises(ValidationError, match="findings must contain at most"):
        validate_bundle(bundle)


@pytest.mark.parametrize("bundle_field", ("baseline_bundle", "candidate_bundle"))
def test_ci_validate_stage_rejects_malformed_legacy_bundle_without_publication(
    tmp_path: Path, bundle_field: str
) -> None:
    """Validate-only CI must fail closed before publishing when any legacy bundle is malformed."""

    malformed = _legacy_v011_bundle()
    malformed["manifest"] = {}
    bundle_path = tmp_path / "malformed-v011.json"
    bundle_path.write_text(json.dumps(malformed), encoding="utf-8")
    output_dir = tmp_path / "artifacts"
    config = tmp_path / "trustweave.toml"
    config.write_text(
        "[tool.trustweave]\n"
        f'{bundle_field} = "{bundle_path.name}"\n'
        f'output_dir = "{output_dir.name}"\n'
        'enabled_stages = ["validate", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--generated-at",
                "2026-08-17T00:00:00+00:00",
                "ci",
                "--config",
                str(config),
                "--quiet",
            ]
        )
        == 2
    )
    assert not output_dir.exists()


def test_cross_version_bundle_diff_is_deterministic_for_authentic_legacy_evidence() -> None:
    """Compare declared historical evidence deterministically without upgrading it."""

    legacy = _legacy_v011_bundle()
    current = _bundle()
    generated_at = "2026-08-17T00:00:00+00:00"

    assert diff_bundles(legacy, current, generated_at) == diff_bundles(
        legacy, current, generated_at
    )


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


def test_validate_current_bundle_rejects_a_missing_declared_finding() -> None:
    """An internally consistent summary cannot conceal a missing declared flow decision."""

    bundle = _copy_bundle()
    findings = bundle["findings"]
    summary = bundle["summary"]
    assert isinstance(findings, list) and findings
    assert isinstance(summary, dict)
    removed = findings.pop()
    assert isinstance(removed, dict)
    summary[str(removed["decision"])] -= 1

    with pytest.raises(ValidationError, match="fresh evaluation"):
        validate_bundle(bundle)


def test_validate_current_bundle_rejects_a_fabricated_policy_result() -> None:
    """Valid enums and a coherent summary do not make an altered policy result authentic."""

    bundle = _copy_bundle()
    findings = bundle["findings"]
    summary = bundle["summary"]
    assert isinstance(findings, list) and findings
    assert isinstance(summary, dict)
    finding = findings[0]
    assert isinstance(finding, dict)
    original_decision = str(finding["decision"])
    fabricated_decision = "deny" if original_decision != "deny" else "allow"
    finding["decision"] = fabricated_decision
    finding["severity"] = "high" if fabricated_decision == "deny" else "info"
    finding["rule_id"] = None
    finding["rationale"] = "Fabricated but validly shaped local evidence."
    summary[original_decision] -= 1
    summary[fabricated_decision] += 1

    with pytest.raises(ValidationError, match="fresh evaluation"):
        validate_bundle(bundle)


def test_validate_current_bundle_rejects_duplicate_substitution_for_a_declared_flow() -> None:
    """Duplicating one finding cannot replace a different declared flow finding."""

    bundle = _copy_bundle()
    findings = bundle["findings"]
    summary = bundle["summary"]
    assert isinstance(findings, list) and len(findings) >= 2
    assert isinstance(summary, dict)
    replacement = json.loads(json.dumps(findings[0]))
    removed = findings[1]
    assert isinstance(replacement, dict) and isinstance(removed, dict)
    findings[1] = replacement
    summary[str(removed["decision"])] -= 1
    summary[str(replacement["decision"])] += 1

    with pytest.raises(ValidationError, match="fresh evaluation"):
        validate_bundle(bundle)


def test_validate_current_bundle_accepts_reordered_authentic_findings() -> None:
    """Semantic collection equality allows ordering differences without allowing omissions."""

    bundle = _copy_bundle()
    findings = bundle["findings"]
    assert isinstance(findings, list)
    findings.reverse()

    validate_bundle(bundle)


def test_validate_current_bundle_rejects_changed_purpose_tags() -> None:
    """Purpose tags are part of the declared flow identity and cannot be altered in evidence."""

    bundle = _copy_bundle()
    findings = bundle["findings"]
    assert isinstance(findings, list) and findings
    finding = findings[0]
    assert isinstance(finding, dict)
    flow = finding["flow"]
    assert isinstance(flow, dict)
    flow["purpose_tags"] = ["fabricated-purpose-tag"]

    with pytest.raises(ValidationError, match="flow must match|fresh evaluation"):
        validate_bundle(bundle)
