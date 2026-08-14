from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.diff import diff_bundles
from trustweave.findings import FINDING_SCHEMA_VERSION, LocalFinding, finding, parse_finding
from trustweave.io import load_document
from trustweave.mcp_profile import parse_mcp_profile, review_mcp_profile
from trustweave.models import parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.trace_review import review_trace

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
CANDIDATE = ROOT / "examples" / "support-agent.capability-growth.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"


def test_canonical_finding_omits_unavailable_fields_and_orders_safe_sequences() -> None:
    result = finding(
        "TW-TEST-001",
        "medium",
        "A local review observation.",
        "declared_configuration",
        subject={"tools": ["zeta", "alpha"], "policy": "support-policy"},
        properties={"labels": ["zeta", "alpha"], "active": True},
    )
    assert FINDING_SCHEMA_VERSION == "trustweave.dev/finding/v1alpha1"
    assert result == {
        "id": "TW-TEST-001",
        "severity": "medium",
        "message": "A local review observation.",
        "evidence_kind": "declared_configuration",
        "subject": {"policy": "support-policy", "tools": ["alpha", "zeta"]},
        "properties": {"active": True, "labels": ["alpha", "zeta"]},
    }
    with pytest.raises(ValueError, match="unsupported"):
        finding("TW-TEST-002", "urgent", "Invalid severity.", "declared_configuration")


def test_local_finding_renders_ordered_optional_location_and_references() -> None:
    rendered = LocalFinding(
        identifier="TW-TEST-LOCATION",
        severity="low",
        message="A local metadata reference.",
        evidence_kind="declared_configuration",
        location={"path": "b", "kind": "declared"},
        references=({"uri": "z"}, {"uri": "a"}),
    ).as_dict()

    assert rendered["location"] == {"kind": "declared", "path": "b"}
    assert rendered["references"] == [{"uri": "a"}, {"uri": "z"}]


def test_local_finding_is_deeply_immutable_and_defensively_copies_metadata() -> None:
    subject = {"path": ["source", "sink"]}
    references = [{"uri": "local://evidence"}]
    properties = {"budget": 1}
    local = LocalFinding(
        identifier="TW-TEST-IMMUTABLE",
        severity="review",
        message="A bounded local finding.",
        evidence_kind="declared_configuration",
        subject=subject,
        references=references,
        properties=properties,
    )

    subject["path"].append("mutated")
    references[0]["uri"] = "local://mutated"
    properties["budget"] = 2

    assert local.as_dict()["subject"] == {"path": ["source", "sink"]}
    assert local.as_dict()["references"] == [{"uri": "local://evidence"}]
    assert local.as_dict()["properties"] == {"budget": 1}
    with pytest.raises(TypeError):
        local.subject["path"] = ("mutated",)
    with pytest.raises(TypeError):
        local.references[0]["uri"] = "local://mutated"


def test_canonical_finding_runtime_rejects_arbitrary_nested_metadata() -> None:
    with pytest.raises(ValueError, match="string array"):
        parse_finding(
            {
                "id": "TW-TEST-NESTED",
                "severity": "review",
                "message": "Nested metadata must not be accepted.",
                "evidence_kind": "declared_configuration",
                "subject": {"path": [{"nested": "object"}]},
            }
        )


def test_trace_and_mcp_producers_emit_additive_canonical_metadata() -> None:
    manifest = parse_manifest(load_document(MANIFEST))
    policy = parse_policy(load_document(POLICY))
    trace = load_document(ROOT / "examples" / "traces" / "review-required-support-trace.json")
    trace_review = review_trace(manifest, policy, trace)
    trace_finding = trace_review["findings"][0]
    assert trace_finding["evidence_kind"] == "pre_recorded_trace_metadata"
    assert set(trace_finding["subject"]) == {"source", "tool"}
    assert trace_finding["properties"] == {"call_index": "0"}

    profile = parse_mcp_profile(
        load_document(ROOT / "examples" / "mcp-profiles" / "review-required-support-profile.json")
    )
    profile_review = review_mcp_profile(profile, manifest)
    profile_finding = profile_review["findings"][0]
    assert profile_finding["evidence_kind"] == "pre_recorded_mcp_metadata"
    assert profile_finding["subject"]["profile"] == profile.name


def test_policy_and_diff_producers_emit_additive_canonical_metadata() -> None:
    policy_document = json.loads(POLICY.read_text(encoding="utf-8"))
    policy_document["default_decision"] = "allow"
    policy = parse_policy(policy_document)
    policy_result = review_policy(policy)
    policy_finding = next(item for item in policy_result["findings"] if item["id"] == "TW-POL-001")
    assert policy_finding["evidence_kind"] == "declared_policy_structure"
    assert policy_finding["subject"] == {"policy": policy.name}

    base = {
        "schema_version": "trustweave.dev/bundle/v1alpha1",
        "manifest": parse_manifest(load_document(MANIFEST)).as_dict(),
        "findings": [],
    }
    head = {
        "schema_version": "trustweave.dev/bundle/v1alpha1",
        "manifest": parse_manifest(load_document(CANDIDATE)).as_dict(),
        "findings": [],
    }
    signals = diff_bundles(base, head)["signals"]
    capability_signal = next(item for item in signals if item["id"] == "TW-DIFF-003")
    assert capability_signal["subject"] == {
        "tool": "lookup_customer_record",
        "action_class": "sensitive",
        "added_capabilities": ["customer-record.export"],
    }


def test_canonical_finding_renders_optional_rule_metadata_and_safe_scalars() -> None:
    rendered = finding(
        "TW-TEST-OPTIONAL",
        "high",
        "A bounded finding with reviewer metadata.",
        "declared_configuration",
        location={"path": "local.json"},
        references=({"uri": "local://first"},),
        properties={"count": 3, "reviewed": True, "labels": ["zeta", "alpha"]},
        title="Bounded finding",
        rationale="The local declaration requires review.",
        remediation="Confirm the declared boundary with a human reviewer.",
    )

    assert rendered["title"] == "Bounded finding"
    assert rendered["rationale"] == "The local declaration requires review."
    assert rendered["remediation"] == "Confirm the declared boundary with a human reviewer."
    assert rendered["properties"] == {"count": 3, "labels": ["alpha", "zeta"], "reviewed": True}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"identifier": "invalid"}, "id must match"),
        ({"message": ""}, "message must be"),
        ({"evidence_kind": "not-valid"}, "evidence_kind"),
        ({"subject": {"Not_Safe": "value"}}, "lower_snake_case"),
        ({"subject": {"nested": {"value": "object"}}}, "unsupported value type"),
        ({"location": {"path": ["not", "a", "string"]}}, "unsupported value type"),
        ({"references": "not-a-list"}, "references must be a list"),
        ({"properties": {"count": -1}}, "must be between"),
        ({"properties": {"nested": {"value": "object"}}}, "unsupported value type"),
    ],
)
def test_canonical_finding_rejects_invalid_bounded_metadata(
    kwargs: dict[str, object], message: str
) -> None:
    arguments: dict[str, object] = {
        "identifier": "TW-TEST-INVALID",
        "severity": "review",
        "message": "A bounded invalid-value fixture.",
        "evidence_kind": "declared_configuration",
    }
    arguments.update(kwargs)

    with pytest.raises(ValueError, match=message):
        finding(**arguments)  # type: ignore[arg-type]


def test_parse_finding_rejects_non_object_and_unknown_fields() -> None:
    with pytest.raises(ValueError, match="must be an object"):
        parse_finding([])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown fields"):
        parse_finding(
            {
                "id": "TW-TEST-UNKNOWN",
                "severity": "review",
                "message": "Unknown data must be rejected.",
                "evidence_kind": "declared_configuration",
                "unexpected": True,
            }
        )
