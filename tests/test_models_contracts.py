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
