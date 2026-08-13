from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import suppress
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from jsonschema import Draft202012Validator

from trustweave.framework_import import normalize_framework_declaration
from trustweave.mcp_import import normalize_mcp_tools_list
from trustweave.mcp_profile import parse_mcp_profile
from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.scenarios import parse_scenarios
from trustweave.trace_review import parse_trace

ROOT = Path(__file__).resolve().parents[1]


def _document(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(schema_name: str) -> Draft202012Validator:
    return Draft202012Validator(_document(ROOT / "schemas" / schema_name))


@pytest.mark.parametrize(
    ("schema_name", "paths", "parser"),
    [
        (
            "agent-manifest.schema.json",
            sorted((ROOT / "examples").glob("*.manifest.json")),
            parse_manifest,
        ),
        ("policy.schema.json", [ROOT / "policies" / "default-policy.json"], parse_policy),
        (
            "trace.schema.json",
            sorted((ROOT / "examples" / "traces").glob("*.json")),
            parse_trace,
        ),
        (
            "mcp-profile.schema.json",
            sorted((ROOT / "examples" / "mcp-profiles").glob("*.json")),
            parse_mcp_profile,
        ),
    ],
)
def test_checked_in_contract_examples_validate_in_schema_and_runtime(
    schema_name: str,
    paths: list[Path],
    parser: Callable[[Mapping[str, Any]], object],
) -> None:
    validator = _validator(schema_name)
    assert paths, f"No fixtures matched {schema_name}"
    for path in paths:
        document = _document(path)
        assert not list(validator.iter_errors(document)), path
        parser(document)


@pytest.mark.parametrize(
    ("document_path", "mutate", "parser", "message"),
    [
        (
            ROOT / "examples" / "support-agent.manifest.json",
            lambda document: document["sources"][0].update({"trst": "trusted"}),
            parse_manifest,
            r"manifest\.sources\[0\]: unknown field 'trst'; did you mean 'trust'",
        ),
        (
            ROOT / "policies" / "default-policy.json",
            lambda document: document["rules"][0].update({"decison": "allow"}),
            parse_policy,
            r"policy\.rules\[0\]: unknown field 'decison'; did you mean 'decision'",
        ),
    ],
)
def test_manifest_and_policy_unknown_fields_include_paths_and_suggestions(
    document_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    parser: Callable[[Mapping[str, Any]], object],
    message: str,
) -> None:
    document = deepcopy(_document(document_path))
    mutate(document)
    with pytest.raises(ValidationError, match=message):
        parser(document)


def test_remaining_local_input_parsers_reject_unknown_fields() -> None:
    scenarios = _document(ROOT / "scenarios" / "default-scenarios.json")
    scenarios["scenarios"][0]["unknown"] = True
    with pytest.raises(ValidationError, match=r"scenario_pack\.scenarios\[0\]: unknown field"):
        parse_scenarios(scenarios)

    trace = _document(ROOT / "examples" / "traces" / "clear-support-trace.json")
    trace["tool_calls"][0]["unexpected"] = True
    with pytest.raises(ValidationError, match=r"trace\.tool_calls\[0\]: unknown field"):
        parse_trace(trace)

    profile = _document(ROOT / "examples" / "mcp-profiles" / "clear-support-profile.json")
    profile["tools"][0]["unexpected"] = True
    with pytest.raises(ValidationError, match=r"mcp_profile\.tools\[0\]: unknown field"):
        parse_mcp_profile(profile)

    inventory = _document(ROOT / "examples" / "mcp-tools" / "support-tools-list.json")
    inventory["tools"][0]["unexpected"] = True
    with pytest.raises(ValidationError, match=r"mcp_tools_list\.tools\[0\]: unknown field"):
        normalize_mcp_tools_list(inventory)

    with pytest.raises(ValidationError, match=r"openai_agents\.agents\[0\]: unknown field"):
        normalize_framework_declaration(
            "openai-agents", {"agents": [{"name": "reviewer", "unknown": True}]}
        )


def test_schema_and_runtime_reject_the_same_unknown_manifest_field() -> None:
    document = _document(ROOT / "examples" / "support-agent.manifest.json")
    document["unexpected"] = True
    assert list(_validator("agent-manifest.schema.json").iter_errors(document))
    with pytest.raises(ValidationError, match="manifest: unknown field"):
        parse_manifest(document)


@given(
    st.dictionaries(
        st.text(max_size=16), st.one_of(st.none(), st.booleans(), st.integers()), max_size=8
    )
)
def test_manifest_parser_fails_with_validation_error_for_arbitrary_object_input(
    document: dict[str, object],
) -> None:
    with suppress(ValidationError):
        parse_manifest(document)
