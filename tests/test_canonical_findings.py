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

    from trustweave.engine import build_bundle

    base = build_bundle(parse_manifest(load_document(MANIFEST)), policy)
    head = build_bundle(parse_manifest(load_document(CANDIDATE)), policy)
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


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document.pop("id"),
            "canonical finding id must match ^TW-[A-Z0-9-]{1,120}$",
        ),
        (
            lambda document: document.update({"severity": "urgent"}),
            "unsupported canonical finding severity: urgent",
        ),
        (
            lambda document: document.update({"message": ""}),
            "canonical finding message must be a non-empty string up to 4096 characters",
        ),
        (
            lambda document: document.update({"evidence_kind": "Not_valid"}),
            "canonical finding evidence_kind must use lower_snake_case",
        ),
        (
            lambda document: document.update({"subject": []}),
            "canonical finding subject must be an object",
        ),
        (
            lambda document: document.update({"location": []}),
            "canonical finding location must be an object",
        ),
        (
            lambda document: document.update({"references": "not-a-list"}),
            "canonical finding references must be a list",
        ),
        (
            lambda document: document.update({"properties": []}),
            "canonical finding properties must be an object",
        ),
        (
            lambda document: document.update({"title": ""}),
            "canonical finding title must be a non-empty string up to 256 characters",
        ),
        (
            lambda document: document.update({"rationale": ""}),
            "canonical finding rationale must be a non-empty string up to 4096 characters",
        ),
        (
            lambda document: document.update({"remediation": ""}),
            "canonical finding remediation must be a non-empty string up to 4096 characters",
        ),
    ],
)
def test_parse_finding_preserves_exact_required_and_optional_diagnostics(
    mutate: object, message: str
) -> None:
    """Serialized public findings retain literal parser diagnostics for every public field class."""

    document: dict[str, object] = {
        "id": "TW-TEST-PARSE",
        "severity": "review",
        "message": "A bounded parser fixture.",
        "evidence_kind": "declared_configuration",
    }
    assert callable(mutate)
    mutate(document)
    with pytest.raises(ValueError) as error:
        parse_finding(document)
    assert str(error.value) == message


def test_parse_finding_round_trips_all_bounded_optional_metadata_deterministically() -> None:
    """Optional canonical evidence fields retain sorting, scalar types, and reviewer prose."""

    parsed = parse_finding(
        {
            "id": "TW-TEST-ROUND-TRIP",
            "severity": "high",
            "message": "A complete bounded local finding.",
            "evidence_kind": "declared_configuration",
            "title": "Complete finding",
            "rationale": "The declaration requires review.",
            "remediation": "Review the supplied metadata.",
            "subject": {"tools": ["zeta", "alpha"], "source": "customer"},
            "location": {"path": "declared.json", "kind": "manifest"},
            "references": [{"uri": "local://z"}, {"uri": "local://a"}],
            "properties": {"labels": ["zeta", "alpha"], "count": 3, "reviewed": True},
        }
    )

    assert parsed.as_dict() == {
        "id": "TW-TEST-ROUND-TRIP",
        "severity": "high",
        "message": "A complete bounded local finding.",
        "evidence_kind": "declared_configuration",
        "title": "Complete finding",
        "rationale": "The declaration requires review.",
        "remediation": "Review the supplied metadata.",
        "subject": {"source": "customer", "tools": ["alpha", "zeta"]},
        "location": {"kind": "manifest", "path": "declared.json"},
        "references": [{"uri": "local://a"}, {"uri": "local://z"}],
        "properties": {"count": 3, "labels": ["alpha", "zeta"], "reviewed": True},
    }


def test_canonical_finding_reference_limit_is_inclusive_and_reference_values_are_scalar() -> None:
    """Reference metadata admits exactly the bounded maximum and rejects unsafe value shapes."""

    maximum_references = tuple({"uri": f"local://reference-{index}"} for index in range(64))
    rendered = finding(
        "TW-TEST-REFERENCE-LIMIT",
        "low",
        "A bounded reference fixture.",
        "declared_configuration",
        references=maximum_references,
    )
    assert len(rendered["references"]) == 64

    with pytest.raises(ValueError) as error:
        finding(
            "TW-TEST-REFERENCE-OVERFLOW",
            "low",
            "An overflowing reference fixture.",
            "declared_configuration",
            references=maximum_references + ({"uri": "local://overflow"},),
        )
    assert str(error.value) == "canonical finding references may contain at most 64 entries"

    for value in (True, 1, ["local://nested"]):
        with pytest.raises(ValueError) as error:
            finding(
                "TW-TEST-REFERENCE-SHAPE",
                "low",
                "An invalid reference metadata fixture.",
                "declared_configuration",
                references=({"uri": value},),
            )
        assert (
            str(error.value) == "canonical finding references[].uri has an unsupported value type"
        )


def test_canonical_finding_metadata_bounds_are_inclusive_at_all_supported_endpoints() -> None:
    """Subject/property metadata preserves exact field, integer, and string-array bounds."""

    subject = {f"field_{index}": "value" for index in range(32)}
    properties = {f"property_{index}": "value" for index in range(61)}
    properties.update({"zero": 0, "maximum": 2_147_483_647, "labels": ["zeta", "alpha"]})
    rendered = finding(
        "TW-TEST-METADATA-BOUND",
        "low",
        "A metadata boundary fixture.",
        "declared_configuration",
        subject=subject,
        properties=properties,
    )
    assert len(rendered["subject"]) == 32
    assert rendered["properties"]["zero"] == 0
    assert rendered["properties"]["maximum"] == 2_147_483_647
    assert rendered["properties"]["labels"] == ["alpha", "zeta"]

    with pytest.raises(ValueError) as error:
        finding(
            "TW-TEST-SUBJECT-OVERFLOW",
            "low",
            "A subject overflow fixture.",
            "declared_configuration",
            subject={f"field_{index}": "value" for index in range(33)},
        )
    assert str(error.value) == "canonical finding subject may contain at most 32 fields"

    with pytest.raises(ValueError) as error:
        finding(
            "TW-TEST-PROPERTY-OVERFLOW",
            "low",
            "A property overflow fixture.",
            "declared_configuration",
            properties={f"property_{index}": "value" for index in range(65)},
        )
    assert str(error.value) == "canonical finding properties may contain at most 64 fields"

    with pytest.raises(ValueError) as error:
        finding(
            "TW-TEST-LABEL-OVERFLOW",
            "low",
            "A label overflow fixture.",
            "declared_configuration",
            properties={"labels": [f"label-{index}" for index in range(129)]},
        )
    assert (
        str(error.value)
        == "canonical finding properties.labels must be a string array with at most 128 entries"
    )
