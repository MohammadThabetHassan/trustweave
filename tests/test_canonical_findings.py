from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.diff import diff_bundles
from trustweave.findings import FINDING_SCHEMA_VERSION, LocalFinding, finding
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
