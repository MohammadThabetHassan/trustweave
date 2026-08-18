"""Fail-closed parser boundary coverage for declared manifests and policies."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from trustweave.models import (
    ValidationError,
    parse_manifest,
    parse_policy,
    validate_capability_pattern,
    validate_identifier,
    validate_rule_identifier,
)


def _manifest() -> dict[str, Any]:
    return {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "contract-manifest",
        "description": "Declared local parser contract fixture.",
        "sources": [
            {
                "name": "source",
                "trust": "trusted",
                "data_classification": "public",
                "description": "Declared source.",
            }
        ],
        "tools": [
            {
                "name": "tool",
                "action_class": "read",
                "capabilities": ["record.read"],
                "description": "Declared tool.",
            }
        ],
        "flows": [{"source": "source", "tool": "tool", "purpose": "Declared purpose."}],
    }


def _policy() -> dict[str, Any]:
    return {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "contract-policy",
        "default_decision": "deny",
        "rules": [
            {
                "id": "TW-CONTRACT-001",
                "description": "Deny untrusted external declared flow.",
                "source_trust": ["untrusted"],
                "tool_action_classes": ["external"],
                "decision": "deny",
                "rationale": "Declared contract fixture.",
            }
        ],
    }


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda document: document.update({"schema_version": "unsupported"}), "schema_version"),
        (lambda document: document["sources"][0].update({"trust": "unknown"}), "trust must be"),
        (lambda document: document.update({"sources": []}), "at least one source"),
        (lambda document: document["tools"][0].update({"action_class": "unknown"}), "action_class"),
        (lambda document: document["tools"][0].update({"capabilities": []}), "must not be empty"),
        (lambda document: document.update({"tools": []}), "at least one tool"),
        (lambda document: document["flows"][0].update({"source": "unknown"}), "unknown source"),
        (lambda document: document["flows"][0].update({"tool": "unknown"}), "unknown tool"),
        (lambda document: document.update({"flows": []}), "at least one flow"),
    ],
)
def test_manifest_parser_rejects_invalid_declared_contracts(mutate: object, message: str) -> None:
    document = copy.deepcopy(_manifest())
    assert callable(mutate)
    mutate(document)

    with pytest.raises(ValidationError, match=message):
        parse_manifest(document)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda document: document.update({"schema_version": "unsupported"}), "schema_version"),
        (lambda document: document.update({"default_decision": "unknown"}), "default_decision"),
        (
            lambda document: document["rules"][0].update({"source_trust": []}),
            "requires source_trust",
        ),
        (
            lambda document: document["rules"][0].update({"source_trust": ["unknown"]}),
            "unknown trust",
        ),
        (
            lambda document: document["rules"][0].update({"tool_action_classes": ["unknown"]}),
            "unknown action",
        ),
        (lambda document: document["rules"][0].update({"decision": "unknown"}), "decision must be"),
    ],
)
def test_policy_parser_rejects_invalid_declared_contracts(mutate: object, message: str) -> None:
    document = copy.deepcopy(_policy())
    assert callable(mutate)
    mutate(document)

    with pytest.raises(ValidationError, match=message):
        parse_policy(document)


@given(st.sampled_from([".leading", "trailing.", "doubled..segment", "UPPER", "wild*card"]))
def test_capability_grammar_rejects_noncanonical_patterns(value: str) -> None:
    with pytest.raises(ValidationError):
        validate_capability_pattern(value, "capability")


@pytest.mark.parametrize(
    ("validator", "valid", "invalid"),
    [
        (validate_identifier, "a" * 64, "a" * 65),
        (validate_rule_identifier, "T" + "a" * 63, "T" + "a" * 64),
    ],
)
def test_identifier_validators_enforce_exact_declared_length_boundaries(
    validator: object, valid: str, invalid: str
) -> None:
    """Identifier bounds accept exactly 64 characters and reject the next character."""

    assert callable(validator)
    assert validator(valid, "identifier") == valid
    with pytest.raises(ValidationError, match="at most 64"):
        validator(invalid, "identifier")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document["sources"].append(copy.deepcopy(document["sources"][0])),
            "manifest.sources.name contains duplicate",
        ),
        (
            lambda document: document["tools"].append(copy.deepcopy(document["tools"][0])),
            "manifest.tools.name contains duplicate",
        ),
        (
            lambda document: document["tools"][0].update(
                {"capabilities": ["record.read", "record.read"]}
            ),
            r"manifest\.tools\[0\]\.capabilities contains duplicate",
        ),
        (
            lambda document: document["flows"][0].update({"purpose_tags": ["review", "review"]}),
            r"manifest\.flows\[0\]\.purpose_tags contains duplicate",
        ),
        (lambda document: document.update({"unexpected": True}), "manifest: unknown field"),
    ],
)
def test_manifest_parser_preserves_unique_declared_identity_invariants(
    mutate: object, message: str
) -> None:
    """Distinct declared names, capabilities, purpose tags, and fields are contract data."""

    document = copy.deepcopy(_manifest())
    assert callable(mutate)
    mutate(document)

    with pytest.raises(ValidationError, match=message):
        parse_manifest(document)


def _v2_policy() -> dict[str, Any]:
    document = copy.deepcopy(_policy())
    document["schema_version"] = "trustweave.dev/policy/v1alpha2"
    document["classification_taxonomy"] = ["public", "internal", "confidential", "restricted"]
    document["rules"][0].update(
        {
            "source_data_classifications": ["confidential"],
            "source_identifiers": ["source"],
            "tool_identifiers": ["tool"],
            "purpose_tags": ["review"],
            "source_data_classification_at_least": "internal",
            "source_data_classification_at_most": "restricted",
            "required_controls": ["approval"],
            "severity": "high",
        }
    )
    return document


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda document: document.update({"classification_taxonomy": []}), "must not be empty"),
        (
            lambda document: document.update({"classification_taxonomy": ["public", "public"]}),
            "contains duplicate",
        ),
        (
            lambda document: document["rules"][0].update(
                {"source_data_classifications": ["unknown"]}
            ),
            "must be in policy.classification_taxonomy",
        ),
        (
            lambda document: document["rules"][0].update(
                {
                    "source_data_classification_at_least": "restricted",
                    "source_data_classification_at_most": "internal",
                }
            ),
            "impossible classification",
        ),
        (
            lambda document: document["rules"][0].update(
                {
                    "source_data_classifications": ["public"],
                    "source_data_classification_at_least": "confidential",
                }
            ),
            "empty classification intersection",
        ),
        (
            lambda document: document["rules"][0].update({"required_controls": ["unknown"]}),
            "unknown required controls",
        ),
        (lambda document: document["rules"][0].update({"severity": "unknown"}), "severity must be"),
        (lambda document: document.update({"unexpected": True}), "policy: unknown field"),
        (lambda document: document["rules"][0].update({"unexpected": True}), "unknown field"),
    ],
)
def test_v2_policy_parser_enforces_taxonomy_and_advanced_predicate_invariants(
    mutate: object, message: str
) -> None:
    """v1alpha2 policy predicates reject unsatisfiable or undeclared local evidence constraints."""

    document = _v2_policy()
    assert callable(mutate)
    mutate(document)

    with pytest.raises(ValidationError, match=message):
        parse_policy(document)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document.update(
                {"approval_control": {"mechanism": "review", "binds_to": [], "fail_closed": True}}
            ),
            "binds_to must not be empty",
        ),
        (
            lambda document: document.update(
                {
                    "approval_control": {
                        "mechanism": "review",
                        "binds_to": ["actor", "actor"],
                        "fail_closed": True,
                    }
                }
            ),
            "binds_to contains duplicate",
        ),
        (
            lambda document: document.update(
                {
                    "approval_control": {
                        "mechanism": "review",
                        "binds_to": ["actor"],
                        "fail_closed": "true",
                    }
                }
            ),
            "fail_closed must be a boolean",
        ),
    ],
)
def test_policy_parser_enforces_approval_control_identity_and_boolean_contract(
    mutate: object, message: str
) -> None:
    """Approval metadata is bounded local evidence, not an implicit or weakly typed control."""

    document = _v2_policy()
    assert callable(mutate)
    mutate(document)

    with pytest.raises(ValidationError, match=message):
        parse_policy(document)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (None, "manifest must be an object"),
        ({"schema_version": "trustweave.dev/v1alpha1"}, "manifest.sources must be a list"),
        (
            {
                **_manifest(),
                "sources": ["not-an-object"],
            },
            "manifest.sources[0] must be an object",
        ),
        (
            {
                **_manifest(),
                "sources": [{**_manifest()["sources"][0], "trust": None}],
            },
            "manifest.sources[0].trust must be a non-empty string",
        ),
        (
            {
                **_manifest(),
                "sources": [{**_manifest()["sources"][0], "data_classification": ""}],
            },
            "manifest.sources[0].data_classification must be a non-empty string",
        ),
        (
            {
                **_manifest(),
                "sources": [{**_manifest()["sources"][0], "description": None}],
            },
            "manifest.sources[0].description must be a non-empty string",
        ),
        ({**_manifest(), "tools": "tool"}, "manifest.tools must be a list"),
        (
            {
                **_manifest(),
                "tools": ["not-an-object"],
            },
            "manifest.tools[0] must be an object",
        ),
        (
            {
                **_manifest(),
                "tools": [{**_manifest()["tools"][0], "action_class": None}],
            },
            "manifest.tools[0].action_class must be a non-empty string",
        ),
        (
            {
                **_manifest(),
                "tools": [{**_manifest()["tools"][0], "capabilities": "record.read"}],
            },
            "manifest.tools[0].capabilities must be a list",
        ),
        (
            {
                **_manifest(),
                "tools": [{**_manifest()["tools"][0], "capabilities": ["record.*"]}],
            },
            "manifest.tools[0].capabilities must be an exact capability, not a namespace wildcard",
        ),
        ({**_manifest(), "flows": "flow"}, "manifest.flows must be a list"),
        (
            {
                **_manifest(),
                "flows": ["not-an-object"],
            },
            "manifest.flows[0] must be an object",
        ),
        (
            {
                **_manifest(),
                "flows": [{**_manifest()["flows"][0], "purpose": None}],
            },
            "manifest.flows[0].purpose must be a non-empty string",
        ),
    ],
)
def test_manifest_parser_reports_exact_structural_diagnostics(
    document: object, message: str
) -> None:
    """Structural manifest failures retain their public field path and failure class."""

    with pytest.raises(ValidationError) as error:
        parse_manifest(document)
    assert str(error.value) == message


def test_capability_parser_enforces_exact_length_and_error_contract() -> None:
    """Capability constraints retain their declared 128-character limit and grammar diagnostics."""

    assert validate_capability_pattern("a" * 128, "capability") == "a" * 128
    with pytest.raises(ValidationError, match="capability must be at most 128 characters long"):
        validate_capability_pattern("a" * 129, "capability")
    with pytest.raises(
        ValidationError,
        match="capability allows only a final namespace wildcard '.*'",
    ):
        validate_capability_pattern("record*", "capability")
    with pytest.raises(
        ValidationError,
        match="capability must use lowercase ASCII letters, numbers, '.', '_', or '-' only",
    ):
        validate_capability_pattern("UPPER", "capability")


def test_unknown_field_diagnostics_keep_path_type_and_single_best_suggestion() -> None:
    """Fail-closed parser diagnostics are part of the declared authoring contract."""

    manifest = _manifest()
    manifest["nane"] = "misspelled"
    with pytest.raises(ValidationError) as manifest_error:
        parse_manifest(manifest)
    assert str(manifest_error.value) == "manifest: unknown field 'nane'; did you mean 'name'?"

    policy = _policy()
    policy["nane"] = "misspelled"
    with pytest.raises(ValidationError) as policy_error:
        parse_policy(policy)
    assert str(policy_error.value) == "policy: unknown field 'nane'; did you mean 'name'?"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda document: document.update({"rules": "rule"}), "policy.rules must be a list"),
        (
            lambda document: document.update({"rules": ["not-an-object"]}),
            "policy.rules[0] must be an object",
        ),
        (
            lambda document: document["rules"][0].update({"source_trust": "trusted"}),
            "policy.rules[0].source_trust must be a list",
        ),
        (
            lambda document: document["rules"][0].update({"tool_action_classes": None}),
            "policy.rules[0].tool_action_classes must be a list",
        ),
        (
            lambda document: document["rules"][0].update({"description": None}),
            "policy.rules[0].description must be a non-empty string",
        ),
        (
            lambda document: document["rules"][0].update({"rationale": ""}),
            "policy.rules[0].rationale must be a non-empty string",
        ),
        (
            lambda document: document["rules"][0].update({"tool_capabilities": "record.read"}),
            "policy.rules[0].tool_capabilities must be a list",
        ),
    ],
)
def test_policy_parser_reports_exact_structural_diagnostics(mutate: object, message: str) -> None:
    """Policy parser shape failures retain precise public paths before evidence is produced."""

    document = _policy()
    assert callable(mutate)
    mutate(document)
    with pytest.raises(ValidationError) as error:
        parse_policy(document)
    assert str(error.value) == message


def test_v2_policy_parser_preserves_all_advanced_predicates_on_success() -> None:
    """Every v1alpha2 predicate is retained in the immutable policy evidence model."""

    document = _v2_policy()
    document["rules"][0]["tool_capabilities"] = ["record.*"]
    document["approval_control"] = {
        "mechanism": "review",
        "binds_to": ["actor", "request"],
        "fail_closed": True,
    }

    parsed = parse_policy(document)
    rule = parsed.rules[0]
    assert parsed.classification_taxonomy == ("public", "internal", "confidential", "restricted")
    assert parsed.approval_control is not None
    assert parsed.approval_control.mechanism == "review"
    assert parsed.approval_control.binds_to == ("actor", "request")
    assert parsed.approval_control.fail_closed is True
    assert rule.source_data_classifications == ("confidential",)
    assert rule.tool_capabilities == ("record.*",)
    assert rule.source_identifiers == ("source",)
    assert rule.tool_identifiers == ("tool",)
    assert rule.purpose_tags == ("review",)
    assert rule.source_data_classification_at_least == "internal"
    assert rule.source_data_classification_at_most == "restricted"
    assert rule.required_controls == ("approval",)
    assert rule.severity == "high"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document.update({"name": None}),
            "manifest.name must be a non-empty string",
        ),
        (
            lambda document: document.update({"description": ""}),
            "manifest.description must be a non-empty string",
        ),
        (
            lambda document: document.update({"tools": []}),
            "manifest.tools must contain at least one tool",
        ),
        (
            lambda document: document.update({"flows": []}),
            "manifest.flows must contain at least one flow",
        ),
        (
            lambda document: document["tools"][0].update({"description": None}),
            "manifest.tools[0].description must be a non-empty string",
        ),
        (
            lambda document: document["flows"][0].update({"source": None}),
            "manifest.flows[0].source must be a non-empty string",
        ),
        (
            lambda document: document["flows"][0].update({"tool": ""}),
            "manifest.flows[0].tool must be a non-empty string",
        ),
        (
            lambda document: document["flows"][0].update({"purpose_tags": "review"}),
            "manifest.flows[0].purpose_tags must be a list",
        ),
        (
            lambda document: document["flows"][0].update({"purpose_tags": ["Invalid"]}),
            (
                "manifest.flows[0].purpose_tags must be a lowercase ASCII identifier of at most "
                "64 characters"
            ),
        ),
        (
            lambda document: document["flows"][0].update({"unxpected": True}),
            "manifest.flows[0]: unknown field 'unxpected'",
        ),
    ],
)
def test_manifest_parser_preserves_remaining_exact_field_diagnostics(
    mutate: object, message: str
) -> None:
    """Manifest identity, tool, and flow diagnostics retain their exact authoring field paths."""

    document = _manifest()
    assert callable(mutate)
    mutate(document)
    with pytest.raises(ValidationError) as error:
        parse_manifest(document)
    assert str(error.value) == message


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: (
                document.pop("classification_taxonomy"),
                document.update({"schema_version": "unsupported"}),
            ),
            (
                "policy.schema_version must be trustweave.dev/v1alpha1 or "
                "trustweave.dev/policy/v1alpha2"
            ),
        ),
        (
            lambda document: document.update({"classification_taxonomy": "public"}),
            "policy.classification_taxonomy must be a list",
        ),
        (
            lambda document: document.update({"classification_taxonomy": [""]}),
            "policy.classification_taxonomy must be a non-empty string",
        ),
        (
            lambda document: document.update({"default_decision": None}),
            "policy.default_decision must be a non-empty string",
        ),
        (
            lambda document: document.update({"rules": "not-a-list"}),
            "policy.rules must be a list",
        ),
        (
            lambda document: document["rules"][0].update({"id": None}),
            "policy.rules[0].id must be a non-empty string",
        ),
        (
            lambda document: document["rules"][0].update({"source_data_classifications": "public"}),
            "policy.rules[0].source_data_classifications must be a list",
        ),
        (
            lambda document: document["rules"][0].update({"severity": None}),
            "policy.rules[0].severity must be a non-empty string",
        ),
        (
            lambda document: document["rules"][0].update({"source_identifiers": "source"}),
            "policy.rules[0].source_identifiers must be a list",
        ),
        (
            lambda document: document["rules"][0].update({"tool_identifiers": "tool"}),
            "policy.rules[0].tool_identifiers must be a list",
        ),
        (
            lambda document: document["rules"][0].update({"purpose_tags": "review"}),
            "policy.rules[0].purpose_tags must be a list",
        ),
        (
            lambda document: document["rules"][0].update({"required_controls": "approval"}),
            "policy.rules[0].required_controls must be a list",
        ),
        (
            lambda document: document.update({"approval_control": "review"}),
            "policy.approval_control must be an object",
        ),
        (
            lambda document: document.update({"approval_control": {"mechanism": "review"}}),
            "policy.approval_control.binds_to must be a list",
        ),
        (
            lambda document: document.update(
                {
                    "approval_control": {
                        "mechanism": None,
                        "binds_to": ["actor"],
                        "fail_closed": True,
                    }
                }
            ),
            "policy.approval_control.mechanism must be a non-empty string",
        ),
    ],
)
def test_v2_policy_parser_preserves_remaining_exact_field_diagnostics(
    mutate: object, message: str
) -> None:
    """All advanced v1alpha2 policy fields retain literal authoring diagnostics."""

    document = _v2_policy()
    assert callable(mutate)
    mutate(document)
    with pytest.raises(ValidationError) as error:
        parse_policy(document)
    assert str(error.value) == message


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document.update({"name": None}),
            "policy.name must be a non-empty string",
        ),
        (
            lambda document: document["rules"][0].update({"description": None}),
            "policy.rules[0].description must be a non-empty string",
        ),
        (
            lambda document: document["rules"][0].update({"rationale": ""}),
            "policy.rules[0].rationale must be a non-empty string",
        ),
        (
            lambda document: document["rules"][0].update({"source_trust": []}),
            "policy.rules[0] requires source_trust and tool_action_classes",
        ),
        (
            lambda document: document["rules"][0].update({"tool_action_classes": []}),
            "policy.rules[0] requires source_trust and tool_action_classes",
        ),
        (
            lambda document: document["rules"][0].update({"source_trust": ["unknown"]}),
            "policy.rules[0] has unknown trust labels: ['unknown']",
        ),
        (
            lambda document: document["rules"][0].update({"tool_action_classes": ["unknown"]}),
            "policy.rules[0] has unknown action classes: ['unknown']",
        ),
        (
            lambda document: document["rules"][0].update({"decision": None}),
            "policy.rules[0].decision must be a non-empty string",
        ),
        (
            lambda document: document["rules"][0].update({"decision": "unknown"}),
            "policy.rules[0].decision must be one of ['allow', 'deny', 'require_approval']",
        ),
        (
            lambda document: document["rules"][0].update({"tool_capabilities": ["record*"]}),
            "policy.rules[0].tool_capabilities allows only a final namespace wildcard '.*'",
        ),
        (
            lambda document: document["rules"][0].update({"source_identifiers": ["Invalid"]}),
            (
                "policy.rules[0].source_identifiers must be a lowercase ASCII identifier of at "
                "most 64 characters"
            ),
        ),
        (
            lambda document: document["rules"][0].update({"tool_identifiers": ["Invalid"]}),
            (
                "policy.rules[0].tool_identifiers must be a lowercase ASCII identifier of at most "
                "64 characters"
            ),
        ),
        (
            lambda document: document["rules"][0].update({"purpose_tags": ["Invalid"]}),
            (
                "policy.rules[0].purpose_tags must be a lowercase ASCII identifier of at most 64 "
                "characters"
            ),
        ),
        (
            lambda document: document["rules"][0].update({"required_controls": ["unknown"]}),
            "policy.rules[0] has unknown required controls: ['unknown']",
        ),
        (
            lambda document: document["rules"][0].update({"severity": "unknown"}),
            "policy.rules[0].severity must be one of ['critical', 'high', 'info', 'low', 'medium']",
        ),
        (
            lambda document: document.update(
                {
                    "approval_control": {
                        "mechanism": "review",
                        "binds_to": [],
                        "fail_closed": True,
                    }
                }
            ),
            "policy.approval_control.binds_to must not be empty",
        ),
        (
            lambda document: document.update(
                {
                    "approval_control": {
                        "mechanism": "review",
                        "binds_to": ["actor"],
                        "fail_closed": "true",
                    }
                }
            ),
            "policy.approval_control.fail_closed must be a boolean",
        ),
    ],
)
def test_v2_policy_parser_preserves_exact_rule_and_control_diagnostics(
    mutate: object, message: str
) -> None:
    """Policy rule and approval failures retain literal bounded local authoring messages."""

    document = _v2_policy()
    assert callable(mutate)
    mutate(document)
    with pytest.raises(ValidationError) as error:
        parse_policy(document)
    assert str(error.value) == message


def test_policy_parser_preserves_remaining_root_and_identity_diagnostics() -> None:
    """Root policy shape and duplicate advanced predicate identities fail with exact paths."""

    with pytest.raises(ValidationError) as root_error:
        parse_policy([])
    assert str(root_error.value) == "policy must be an object"

    with pytest.raises(ValidationError) as version_error:
        parse_policy({})
    assert str(version_error.value) == "policy.schema_version must be a non-empty string"

    duplicate_rules = _v2_policy()
    duplicate_rules["rules"].append(copy.deepcopy(duplicate_rules["rules"][0]))
    with pytest.raises(ValidationError) as duplicate_rule_error:
        parse_policy(duplicate_rules)
    assert (
        str(duplicate_rule_error.value)
        == "policy.rules.id contains duplicate values: TW-CONTRACT-001"
    )

    duplicate_identifiers = _v2_policy()
    duplicate_identifiers["rules"][0]["source_identifiers"] = ["source", "source"]
    with pytest.raises(ValidationError) as duplicate_identifier_error:
        parse_policy(duplicate_identifiers)
    assert str(duplicate_identifier_error.value) == (
        "policy.rules[0].source_identifiers contains duplicate values: source"
    )

    duplicate_controls = _v2_policy()
    duplicate_controls["rules"][0]["required_controls"] = ["approval", "approval"]
    with pytest.raises(ValidationError) as duplicate_control_error:
        parse_policy(duplicate_controls)
    assert str(duplicate_control_error.value) == (
        "policy.rules[0].required_controls contains duplicate values: approval"
    )

    unexpected_control = _v2_policy()
    unexpected_control["approval_control"] = {
        "mechanism": "review",
        "binds_to": ["actor"],
        "fail_closed": True,
        "unexpected": True,
    }
    with pytest.raises(ValidationError) as unexpected_control_error:
        parse_policy(unexpected_control)
    assert (
        str(unexpected_control_error.value) == "policy.approval_control: unknown field 'unexpected'"
    )


def test_v2_policy_unbounded_classification_intersection_remains_possible() -> None:
    """A declared taxonomy classification remains possible when neither rank bound is supplied."""

    document = _v2_policy()
    rule = document["rules"][0]
    rule["source_data_classifications"] = ["public"]
    rule.pop("source_data_classification_at_least")
    rule.pop("source_data_classification_at_most")

    parsed = parse_policy(document)
    assert parsed.rules[0].source_data_classifications == ("public",)
    assert parsed.rules[0].source_data_classification_at_least is None
    assert parsed.rules[0].source_data_classification_at_most is None


def test_v2_policy_classification_rank_boundaries_and_approval_binding_items() -> None:
    """Equal and omitted taxonomy bounds preserve valid declared intersections and exact errors."""

    equal_bounds = _v2_policy()
    equal_rule = equal_bounds["rules"][0]
    equal_rule["source_data_classifications"] = ["confidential"]
    equal_rule["source_data_classification_at_least"] = "confidential"
    equal_rule["source_data_classification_at_most"] = "confidential"
    parsed_equal = parse_policy(equal_bounds)
    assert parsed_equal.rules[0].source_data_classification_at_least == "confidential"
    assert parsed_equal.rules[0].source_data_classification_at_most == "confidential"

    unbounded_upper = _v2_policy()
    unbounded_rule = unbounded_upper["rules"][0]
    unbounded_rule["source_data_classifications"] = ["restricted"]
    unbounded_rule.pop("source_data_classification_at_least")
    unbounded_rule.pop("source_data_classification_at_most")
    assert parse_policy(unbounded_upper).rules[0].source_data_classifications == ("restricted",)

    invalid_upper = _v2_policy()
    invalid_upper["rules"][0]["source_data_classification_at_most"] = "unknown"
    with pytest.raises(ValidationError) as invalid_upper_error:
        parse_policy(invalid_upper)
    assert str(invalid_upper_error.value) == (
        "policy.rules[0].source_data_classification_at_most must be in "
        "policy.classification_taxonomy"
    )

    invalid_binding = _v2_policy()
    invalid_binding["approval_control"] = {
        "mechanism": "review",
        "binds_to": [None],
        "fail_closed": True,
    }
    with pytest.raises(ValidationError) as invalid_binding_error:
        parse_policy(invalid_binding)
    assert str(invalid_binding_error.value) == (
        "policy.approval_control.binds_to must be a non-empty string"
    )


def test_remaining_manifest_and_policy_parser_diagnostics_are_literal() -> None:
    """Final parser field paths, enum envelopes, and advanced predicate diagnostics are stable."""

    manifest = _manifest()
    manifest.pop("schema_version")
    with pytest.raises(ValidationError) as manifest_version_error:
        parse_manifest(manifest)
    assert str(manifest_version_error.value) == "manifest.schema_version must be a non-empty string"

    empty_sources = _manifest()
    empty_sources["sources"] = []
    with pytest.raises(ValidationError) as empty_sources_error:
        parse_manifest(empty_sources)
    assert str(empty_sources_error.value) == "manifest.sources must contain at least one source"

    invalid_action = _manifest()
    invalid_action["tools"][0]["action_class"] = "unknown"
    with pytest.raises(ValidationError) as invalid_action_error:
        parse_manifest(invalid_action)
    assert str(invalid_action_error.value) == (
        "manifest.tools[0].action_class must be one of ['external', 'read', 'sensitive', 'write']"
    )

    missing_tool_name = _manifest()
    missing_tool_name["tools"][0].pop("name")
    with pytest.raises(ValidationError) as missing_tool_name_error:
        parse_manifest(missing_tool_name)
    assert str(missing_tool_name_error.value) == (
        "manifest.tools[0].name must be a non-empty string"
    )

    taxonomy_duplicate = _v2_policy()
    taxonomy_duplicate["classification_taxonomy"] = ["public", "public"]
    with pytest.raises(ValidationError) as taxonomy_duplicate_error:
        parse_policy(taxonomy_duplicate)
    assert str(taxonomy_duplicate_error.value) == (
        "policy.classification_taxonomy contains duplicate values: public"
    )

    rule_values = _v2_policy()
    rule_values["rules"][0]["source_trust"] = [None]
    with pytest.raises(ValidationError) as source_trust_error:
        parse_policy(rule_values)
    assert str(source_trust_error.value) == (
        "policy.rules[0].source_trust must be a non-empty string"
    )

    rule_values = _v2_policy()
    rule_values["rules"][0]["tool_action_classes"] = [None]
    with pytest.raises(ValidationError) as action_class_error:
        parse_policy(rule_values)
    assert str(action_class_error.value) == (
        "policy.rules[0].tool_action_classes must be a non-empty string"
    )

    rule_values = _v2_policy()
    rule_values["rules"][0]["required_controls"] = [None]
    with pytest.raises(ValidationError) as control_error:
        parse_policy(rule_values)
    assert str(control_error.value) == (
        "policy.rules[0].required_controls must be a non-empty string"
    )

    invalid_lower = _v2_policy()
    invalid_lower["rules"][0]["source_data_classification_at_least"] = "unknown"
    with pytest.raises(ValidationError) as lower_error:
        parse_policy(invalid_lower)
    assert str(lower_error.value) == (
        "policy.rules[0].source_data_classification_at_least must be in "
        "policy.classification_taxonomy"
    )


def test_capability_parser_preserves_final_namespace_and_rejects_dot_segment_gaps() -> None:
    """Capability grammar accepts a one-character namespace and rejects every empty dot segment."""

    assert validate_capability_pattern("a.*", "capability", allow_namespace=True) == "a.*"

    for invalid in (".records", "records.", "records..read"):
        with pytest.raises(ValidationError) as error:
            validate_capability_pattern(invalid, "capability")
        assert (
            str(error.value)
            == "capability must not contain empty, leading, or trailing dot segments"
        )


def test_manifest_parser_preserves_exact_schema_tool_and_capability_diagnostics() -> None:
    """Manifest validation preserves stable paths for schema, tool fields, and capabilities."""

    invalid_schema = _manifest()
    invalid_schema["schema_version"] = "trustweave.dev/v1alpha0"
    with pytest.raises(ValidationError) as error:
        parse_manifest(invalid_schema)
    assert str(error.value) == "manifest.schema_version must be trustweave.dev/v1alpha1"

    unknown_tool_field = _manifest()
    unknown_tool_field["tools"][0]["unexpected"] = True
    with pytest.raises(ValidationError) as error:
        parse_manifest(unknown_tool_field)
    assert str(error.value) == "manifest.tools[0]: unknown field 'unexpected'"

    namespace_capability = _manifest()
    namespace_capability["tools"][0]["capabilities"] = ["records.*"]
    with pytest.raises(ValidationError) as error:
        parse_manifest(namespace_capability)
    assert (
        str(error.value)
        == "manifest.tools[0].capabilities must be an exact capability, not a namespace wildcard"
    )


def test_manifest_parser_rejects_non_string_field_names_with_exact_type_diagnostic() -> None:
    """Manifest mappings expose only string field names for deterministic parsing."""

    document = _manifest()
    document[1] = "invalid-key"

    with pytest.raises(ValidationError) as error:
        parse_manifest(document)
    assert str(error.value) == "manifest: field names must be strings; received int key 1"
