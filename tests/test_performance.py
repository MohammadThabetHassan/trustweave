"""Broad deterministic performance gates for bounded local evidence processing."""

from __future__ import annotations

import json
from time import perf_counter
from typing import Any

from trustweave.chain import review_declared_chains
from trustweave.engine import decision_for_scenario, evaluate_manifest
from trustweave.models import parse_manifest, parse_policy
from trustweave.sarif import build_sarif


def _elapsed(operation: Any) -> float:
    started = perf_counter()
    operation()
    return perf_counter() - started


def _flow_manifest(flow_count: int) -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": f"flow-scale-{flow_count}",
        "description": "A bounded generated declaration used only for deterministic scale checks.",
        "sources": [
            {
                "name": "source",
                "trust": "trusted",
                "data_classification": "internal",
                "description": "Declared local source.",
            }
        ],
        "tools": [
            {
                "name": "tool",
                "action_class": "read",
                "capabilities": ["records.read"],
                "description": "Declared local tool metadata.",
            }
        ],
        "flows": [
            {"source": "source", "tool": "tool", "purpose": f"flow-{index}"}
            for index in range(flow_count)
        ],
    }


def _allow_policy() -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/v1alpha1",
        "name": "flow-scale-policy",
        "default_decision": "deny",
        "rules": [
            {
                "id": "TW-SCALE-ALLOW",
                "description": "Allow the declared read-only flow.",
                "source_trust": ["trusted"],
                "tool_action_classes": ["read"],
                "decision": "allow",
                "rationale": "Synthetic scale fixture only.",
            }
        ],
    }


def test_declared_flow_scale_gate_covers_10_1000_and_50000_flows() -> None:
    policy = parse_policy(_allow_policy())
    observed: dict[int, tuple[int, float]] = {}
    for flow_count in (10, 1_000, 50_000):
        manifest = parse_manifest(_flow_manifest(flow_count))
        started = perf_counter()
        findings = evaluate_manifest(manifest, policy)
        duration = perf_counter() - started

        observed[flow_count] = (len(manifest.flows), duration)
        assert len(findings) == flow_count
        assert all(finding.decision == "allow" for finding in findings)

    assert observed[10][0] == 10
    assert observed[1_000][0] == 1_000
    assert observed[50_000][0] == 50_000
    assert observed[50_000][1] < 15.0


def test_policy_rule_scale_gate_covers_10_and_1000_rules() -> None:
    for rule_count in (10, 1_000):
        rules = [
            {
                "id": f"TW-SCALE-{index:04d}",
                "description": "A non-matching synthetic rule.",
                "source_trust": ["trusted"],
                "tool_action_classes": ["read"],
                "decision": "deny",
                "rationale": "Synthetic scale fixture only.",
            }
            for index in range(rule_count - 1)
        ]
        rules.append(
            {
                "id": "TW-SCALE-MATCH",
                "description": "The final matching synthetic rule.",
                "source_trust": ["untrusted"],
                "tool_action_classes": ["external"],
                "decision": "deny",
                "rationale": "Synthetic scale fixture only.",
            }
        )
        policy = parse_policy(
            {
                "schema_version": "trustweave.dev/v1alpha1",
                "name": f"policy-scale-{rule_count}",
                "default_decision": "allow",
                "rules": rules,
            }
        )
        started = perf_counter()
        decision = decision_for_scenario(policy, "untrusted", "external")
        duration = perf_counter() - started
        assert decision == ("deny", "TW-SCALE-MATCH")
        assert duration < 5.0


def test_dense_cyclic_and_exponential_chain_shapes_stop_at_declared_budgets() -> None:
    nodes: list[dict[str, object]] = [{"id": "source", "kind": "source", "trust": "untrusted"}]
    edges: list[dict[str, str]] = []
    previous = ["source"]
    for layer in range(12):
        current = [f"left-{layer}", f"right-{layer}"]
        nodes.extend(
            {"id": identifier, "kind": "tool", "action_class": "read"} for identifier in current
        )
        edges.extend({"from": origin, "to": target} for origin in previous for target in current)
        previous = current
    nodes.append({"id": "sink", "kind": "sink", "action_class": "external"})
    edges.extend({"from": origin, "to": "sink"} for origin in previous)
    edges.append({"from": "right-11", "to": "left-0"})

    document = {
        "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
        "name": "bounded-dense-cyclic-diamond-chain",
        "nodes": nodes,
        "edges": edges,
    }
    review: dict[str, object] = {}
    duration = _elapsed(
        lambda: review.update(
            review_declared_chains(
                document,
                max_paths=128,
                max_states=2_000,
                max_edges=2_000,
                generated_at="2026-08-14T00:00:00+00:00",
            )
        )
    )

    assert duration < 10.0
    assert len(review["paths"]) <= 128
    assert any(finding["id"] == "TW-CHAIN-004" for finding in review["findings"])


def test_large_sarif_conversion_has_stable_size_and_runtime_budget() -> None:
    finding_count = 5_000
    review = {
        "schema_version": "trustweave.dev/risk-review/v1alpha1",
        "findings": [
            {
                "id": "TW-POL-001",
                "message": f"Synthetic local review finding {index}.",
                "severity": "review",
                "risk_state": "new",
                "fingerprint": f"{index:064x}",
            }
            for index in range(finding_count)
        ],
    }
    sarif: dict[str, object] = {}
    duration = _elapsed(lambda: sarif.update(build_sarif({"risk": ("risk.json", review)})))

    serialized = json.dumps(sarif, sort_keys=True)
    assert duration < 15.0
    assert len(sarif["runs"][0]["results"]) == finding_count
    assert len(serialized.encode("utf-8")) < 10 * 1024 * 1024
