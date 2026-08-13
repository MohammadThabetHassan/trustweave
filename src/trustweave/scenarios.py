"""Synthetic, non-executing security scenarios for TrustWeave regression evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from trustweave.engine import decision_for_labels
from trustweave.models import (
    VALID_ACTION_CLASSES,
    VALID_DECISIONS,
    VALID_TRUST_LABELS,
    Policy,
    ValidationError,
)


@dataclass(frozen=True)
class Scenario:
    """One fully synthetic assertion about policy behavior."""

    id: str
    description: str
    source_trust: str
    tool_action_class: str
    expected_decision: str


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def parse_scenarios(document: Mapping[str, Any]) -> tuple[Scenario, ...]:
    """Validate a scenario-pack document without loading executable content."""

    if document.get("schema_version") != "trustweave.dev/v1alpha1":
        raise ValidationError("scenario_pack.schema_version must be trustweave.dev/v1alpha1")
    raw_scenarios = document.get("scenarios")
    if not isinstance(raw_scenarios, Sequence) or isinstance(raw_scenarios, (str, bytes)):
        raise ValidationError("scenario_pack.scenarios must be a list")

    scenarios: list[Scenario] = []
    for index, raw in enumerate(raw_scenarios):
        if not isinstance(raw, Mapping):
            raise ValidationError(f"scenario_pack.scenarios[{index}] must be an object")
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
        scenarios.append(
            Scenario(
                id=_text(raw.get("id"), f"scenario_pack.scenarios[{index}].id"),
                description=_text(
                    raw.get("description"), f"scenario_pack.scenarios[{index}].description"
                ),
                source_trust=source_trust,
                tool_action_class=action_class,
                expected_decision=expected,
            )
        )

    if not scenarios:
        raise ValidationError("scenario_pack.scenarios must include at least one scenario")
    ids = [scenario.id for scenario in scenarios]
    duplicates = sorted({scenario_id for scenario_id in ids if ids.count(scenario_id) > 1})
    if duplicates:
        raise ValidationError(f"scenario_pack.scenarios has duplicate ids: {', '.join(duplicates)}")
    return tuple(scenarios)


def run_scenarios(policy: Policy, scenarios: Sequence[Scenario]) -> dict[str, Any]:
    """Evaluate synthetic policy assertions without invoking an agent or external system."""

    results: list[dict[str, Any]] = []
    for scenario in scenarios:
        observed, rule_id = decision_for_labels(
            policy, scenario.source_trust, scenario.tool_action_class
        )
        results.append(
            {
                "id": scenario.id,
                "description": scenario.description,
                "input": {
                    "source_trust": scenario.source_trust,
                    "tool_action_class": scenario.tool_action_class,
                },
                "expected_decision": scenario.expected_decision,
                "observed_decision": observed,
                "rule_id": rule_id,
                "status": "passed" if observed == scenario.expected_decision else "failed",
            }
        )
    passed = sum(result["status"] == "passed" for result in results)
    return {
        "schema_version": "trustweave.dev/test-results/v1alpha1",
        "generated_at": datetime.now(UTC).isoformat(),
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
