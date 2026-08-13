from __future__ import annotations

from pathlib import Path

from trustweave.cli import main
from trustweave.io import load_document
from trustweave.models import parse_policy
from trustweave.scenarios import explain_scenario, parse_scenarios, run_scenarios

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "default-policy.json"
SCENARIOS = ROOT / "scenarios" / "adversarial-scenarios.json"


def test_adversarial_scenario_library_is_cited_synthetic_and_passes_reference_policy() -> None:
    scenarios = parse_scenarios(load_document(SCENARIOS))
    results = run_scenarios(parse_policy(load_document(POLICY)), scenarios)

    assert len(scenarios) == 13
    assert results["summary"] == {"total": 13, "passed": 13, "failed": 0, "status": "passed"}
    assert all(scenario.references for scenario in scenarios)
    assert all(
        reference.url.startswith("https://")
        for scenario in scenarios
        for reference in scenario.references
    )
    assert all(result["references"] for result in results["results"])


def test_explain_scenario_renders_cited_offline_boundary() -> None:
    scenarios = parse_scenarios(load_document(SCENARIOS))

    explanation = explain_scenario(scenarios, "TW-ADV-001")

    assert "# Indirect prompt-injection-shaped retrieved context" in explanation
    assert "OWASP LLM01:2025 Prompt Injection" in explanation
    assert "does not execute a prompt, tool, model, MCP server, or network request" in explanation


def test_cli_explain_returns_a_rendered_scenario_and_rejects_unknown_id(capsys: object) -> None:
    assert main(["explain", "--scenarios", str(SCENARIOS), "--scenario-id", "TW-ADV-010"]) == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "High-impact approval-bypass-shaped path" in output
    assert "OWASP AI Agent Security Cheat Sheet" in output

    assert main(["explain", "--scenarios", str(SCENARIOS), "--scenario-id", "missing"]) == 2
