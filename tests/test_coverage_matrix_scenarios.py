from __future__ import annotations

import itertools
import json
from pathlib import Path

from trustweave.engine import decision_for_labels
from trustweave.io import load_document
from trustweave.models import parse_policy
from trustweave.scenarios import parse_scenarios, run_scenarios

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "default-policy.json"
MATRIX = ROOT / "scenarios" / "coverage-matrix-scenarios.json"
ADVERSARIAL = ROOT / "scenarios" / "adversarial-scenarios.json"

TRUST_LEVELS = ("trusted", "conditional", "untrusted")
ACTION_CLASSES = ("read", "write", "sensitive", "external")


def _policy() -> object:
    return parse_policy(load_document(POLICY))


def test_matrix_covers_every_trust_and_action_combination() -> None:
    """The suite must pin the whole decision surface, not a chosen corner of it."""
    scenarios = parse_scenarios(load_document(MATRIX))
    pairs = {(s.source_trust, s.tool_action_class) for s in scenarios}

    assert pairs == set(itertools.product(TRUST_LEVELS, ACTION_CLASSES))
    assert len(scenarios) == len(TRUST_LEVELS) * len(ACTION_CLASSES)


def test_matrix_expectations_match_the_engine() -> None:
    """Every expected decision is the one the engine actually returns."""
    policy = _policy()
    for scenario in parse_scenarios(load_document(MATRIX)):
        decision, _ = decision_for_labels(policy, scenario.source_trust, scenario.tool_action_class)
        assert decision == scenario.expected_decision, scenario.id


def test_matrix_passes_the_reference_policy() -> None:
    scenarios = parse_scenarios(load_document(MATRIX))
    results = run_scenarios(_policy(), scenarios)

    assert results["summary"] == {"total": 12, "passed": 12, "failed": 0, "status": "passed"}


def test_matrix_contains_a_permitted_flow_that_adversarial_suite_lacks() -> None:
    """The reason this suite exists.

    Every adversarial case expects deny or require_approval, so a policy that
    blocks all legitimate work passes it in full. Detecting that needs at least
    one case that must be allowed.
    """
    adversarial = parse_scenarios(load_document(ADVERSARIAL))
    assert not any(s.expected_decision == "allow" for s in adversarial)

    matrix = parse_scenarios(load_document(MATRIX))
    assert any(s.expected_decision == "allow" for s in matrix)


def test_matrix_fails_a_policy_that_never_allows_anything() -> None:
    """An over-restrictive policy must be visible, not silently safe."""
    document = json.loads(POLICY.read_text(encoding="utf-8"))
    document["rules"] = [r for r in document["rules"] if r["decision"] != "allow"]
    over_restrictive = parse_policy(document)

    matrix = run_scenarios(over_restrictive, parse_scenarios(load_document(MATRIX)))
    adversarial = run_scenarios(over_restrictive, parse_scenarios(load_document(ADVERSARIAL)))

    assert matrix["summary"]["status"] == "failed"
    assert adversarial["summary"]["status"] == "passed"
