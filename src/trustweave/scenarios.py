"""Synthetic, non-executing security scenarios for TrustWeave regression evidence."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from trustweave.engine import decision_for_scenario
from trustweave.models import (
    VALID_ACTION_CLASSES,
    VALID_DECISIONS,
    VALID_TRUST_LABELS,
    Policy,
    ValidationError,
    reject_unknown_fields,
    validate_capability_pattern,
)
from trustweave.provenance import add_generated_at


@dataclass(frozen=True)
class ScenarioReference:
    """A public taxonomy or standards reference for a synthetic scenario."""

    title: str
    url: str


@dataclass(frozen=True)
class Scenario:
    """One fully synthetic assertion about policy behavior."""

    id: str
    description: str
    source_trust: str
    tool_action_class: str
    expected_decision: str
    title: str
    category: str
    rationale: str
    references: tuple[ScenarioReference, ...]
    source_data_classification: str | None = None
    tool_capabilities: tuple[str, ...] = ()
    source_identifier: str | None = None
    tool_identifier: str | None = None


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _optional_text(value: Any, default: str, path: str) -> str:
    if value is None:
        return default
    return _text(value, path)


def _capabilities(value: Any, path: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{path} must be a list")
    return tuple(
        validate_capability_pattern(capability, path, allow_namespace=False) for capability in value
    )


def _parse_references(value: Any, path: str) -> tuple[ScenarioReference, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValidationError(f"{path} must be a list")
    references: list[ScenarioReference] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping):
            raise ValidationError(f"{path}[{index}] must be an object")
        reject_unknown_fields(raw, {"title", "url"}, f"{path}[{index}]")
        url = _text(raw.get("url"), f"{path}[{index}].url")
        if not url.startswith("https://"):
            raise ValidationError(f"{path}[{index}].url must use https")
        references.append(
            ScenarioReference(
                title=_text(raw.get("title"), f"{path}[{index}].title"),
                url=url,
            )
        )
    return tuple(references)


def parse_scenarios(document: Mapping[str, Any]) -> tuple[Scenario, ...]:
    """Validate a scenario-pack document without loading executable content."""

    reject_unknown_fields(document, {"schema_version", "name", "scenarios"}, "scenario_pack")
    if "name" in document:
        _text(document["name"], "scenario_pack.name")
    if document.get("schema_version") != "trustweave.dev/v1alpha1":
        raise ValidationError("scenario_pack.schema_version must be trustweave.dev/v1alpha1")
    raw_scenarios = document.get("scenarios")
    if not isinstance(raw_scenarios, Sequence) or isinstance(raw_scenarios, (str, bytes)):
        raise ValidationError("scenario_pack.scenarios must be a list")

    scenarios: list[Scenario] = []
    for index, raw in enumerate(raw_scenarios):
        if not isinstance(raw, Mapping):
            raise ValidationError(f"scenario_pack.scenarios[{index}] must be an object")
        reject_unknown_fields(
            raw,
            {
                "id",
                "description",
                "source_trust",
                "tool_action_class",
                "expected_decision",
                "title",
                "category",
                "rationale",
                "references",
                "source_data_classification",
                "tool_capabilities",
                "source_identifier",
                "tool_identifier",
            },
            f"scenario_pack.scenarios[{index}]",
        )
        source_trust = _text(
            raw.get("source_trust"), f"scenario_pack.scenarios[{index}].source_trust"
        )
        action_class = _text(
            raw.get("tool_action_class"), f"scenario_pack.scenarios[{index}].tool_action_class"
        )
        expected = _text(
            raw.get("expected_decision"), f"scenario_pack.scenarios[{index}].expected_decision"
        )
        if source_trust not in VALID_TRUST_LABELS:
            raise ValidationError(f"scenario_pack.scenarios[{index}] has invalid source_trust")
        if action_class not in VALID_ACTION_CLASSES:
            raise ValidationError(f"scenario_pack.scenarios[{index}] has invalid tool_action_class")
        if expected not in VALID_DECISIONS:
            raise ValidationError(f"scenario_pack.scenarios[{index}] has invalid expected_decision")
        identifier = _text(raw.get("id"), f"scenario_pack.scenarios[{index}].id")
        description = _text(raw.get("description"), f"scenario_pack.scenarios[{index}].description")
        scenarios.append(
            Scenario(
                id=identifier,
                description=description,
                source_trust=source_trust,
                tool_action_class=action_class,
                expected_decision=expected,
                title=_optional_text(
                    raw.get("title"), identifier, f"scenario_pack.scenarios[{index}].title"
                ),
                category=_optional_text(
                    raw.get("category"), "general", f"scenario_pack.scenarios[{index}].category"
                ),
                rationale=_optional_text(
                    raw.get("rationale"), description, f"scenario_pack.scenarios[{index}].rationale"
                ),
                references=_parse_references(
                    raw.get("references"), f"scenario_pack.scenarios[{index}].references"
                ),
                source_data_classification=(
                    _text(
                        raw["source_data_classification"],
                        f"scenario_pack.scenarios[{index}].source_data_classification",
                    )
                    if "source_data_classification" in raw
                    else None
                ),
                tool_capabilities=_capabilities(
                    raw.get("tool_capabilities"),
                    f"scenario_pack.scenarios[{index}].tool_capabilities",
                ),
                source_identifier=(
                    _text(
                        raw["source_identifier"],
                        f"scenario_pack.scenarios[{index}].source_identifier",
                    )
                    if "source_identifier" in raw
                    else None
                ),
                tool_identifier=(
                    _text(
                        raw["tool_identifier"],
                        f"scenario_pack.scenarios[{index}].tool_identifier",
                    )
                    if "tool_identifier" in raw
                    else None
                ),
            )
        )

    if not scenarios:
        raise ValidationError("scenario_pack.scenarios must include at least one scenario")
    ids = [scenario.id for scenario in scenarios]
    duplicates = sorted(identifier for identifier, count in Counter(ids).items() if count > 1)
    if duplicates:
        raise ValidationError(f"scenario_pack.scenarios has duplicate ids: {', '.join(duplicates)}")
    return tuple(scenarios)


def run_scenarios(
    policy: Policy, scenarios: Sequence[Scenario], generated_at: str | None = None
) -> dict[str, Any]:
    """Evaluate synthetic policy assertions with optional application-layer provenance."""

    results: list[dict[str, Any]] = []
    for scenario in scenarios:
        observed, rule_id = decision_for_scenario(
            policy,
            scenario.source_trust,
            scenario.tool_action_class,
            scenario.source_data_classification,
            scenario.tool_capabilities,
        )
        results.append(
            {
                "id": scenario.id,
                "description": scenario.description,
                "title": scenario.title,
                "category": scenario.category,
                "rationale": scenario.rationale,
                "references": [
                    {"title": reference.title, "url": reference.url}
                    for reference in scenario.references
                ],
                "input": {
                    "source_trust": scenario.source_trust,
                    "tool_action_class": scenario.tool_action_class,
                    **(
                        {"source_data_classification": scenario.source_data_classification}
                        if scenario.source_data_classification is not None
                        else {}
                    ),
                    **(
                        {"tool_capabilities": list(scenario.tool_capabilities)}
                        if scenario.tool_capabilities
                        else {}
                    ),
                    **(
                        {"source_identifier": scenario.source_identifier}
                        if scenario.source_identifier is not None
                        else {}
                    ),
                    **(
                        {"tool_identifier": scenario.tool_identifier}
                        if scenario.tool_identifier is not None
                        else {}
                    ),
                },
                "expected_decision": scenario.expected_decision,
                "observed_decision": observed,
                "rule_id": rule_id,
                "status": "passed" if observed == scenario.expected_decision else "failed",
            }
        )
    passed = sum(result["status"] == "passed" for result in results)
    result: dict[str, object] = {
        "schema_version": "trustweave.dev/test-results/v1alpha1",
        "policy": policy.name,
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "status": "passed" if passed == len(results) else "failed",
        },
        "results": results,
        "limits": [
            (
                "Scenarios are synthetic policy assertions and do not invoke tools, models, "
                "or network resources."
            ),
            (
                "A passing scenario demonstrates this policy's local decision only, not "
                "deployed-system security."
            ),
        ],
    }
    return add_generated_at(result, generated_at)


def explain_scenario(scenarios: Sequence[Scenario], scenario_id: str) -> str:
    """Render one cited synthetic scenario without invoking an agent or external system."""

    scenario = next((item for item in scenarios if item.id == scenario_id), None)
    if scenario is None:
        raise ValidationError(f"Scenario id not found: {scenario_id}")
    lines = [
        f"# {scenario.title}",
        "",
        f"**Scenario ID:** `{scenario.id}`  ",
        f"**Category:** `{scenario.category}`  ",
        f"**Expected policy decision:** `{scenario.expected_decision}`",
        "",
        "## Synthetic boundary assertion",
        "",
        scenario.description,
        "",
        "## Why it matters",
        "",
        scenario.rationale,
        "",
        "## Policy labels",
        "",
        "| Source trust | Data classification | Tool action class | Tool capabilities |",
        "|---|---|---|---|",
        (
            f"| `{scenario.source_trust}` | "
            f"`{scenario.source_data_classification or 'not declared'}` | "
            f"`{scenario.tool_action_class}` | "
            f"`{', '.join(scenario.tool_capabilities) or 'not declared'}` |"
        ),
        "",
        "## References",
        "",
    ]
    if scenario.references:
        lines.extend(f"- [{reference.title}]({reference.url})" for reference in scenario.references)
    else:
        lines.append("- No external taxonomy reference was declared for this synthetic scenario.")
    lines.extend(
        [
            "",
            "> This is a local synthetic policy assertion. It does not execute a prompt, tool, "
            "model, MCP server, or network request and does not demonstrate a deployed-system "
            "compromise.",
            "",
        ]
    )
    return "\n".join(lines)
