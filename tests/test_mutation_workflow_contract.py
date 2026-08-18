from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_hosted_mutation_workflow_enforces_final_survivor_triage_acceptance_gate() -> None:
    """The hosted mutation gate cannot regress below the required score and parity contract."""

    workflow = yaml.safe_load((ROOT / ".github/workflows/mutation.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["mutation-quality"]
    assert job["name"] == "Mutation quality and survivor gate"
    gate = next(
        step for step in job["steps"] if step["name"] == "Mutation quality and survivor gate"
    )
    script = gate["run"]

    for required_contract in (
        "generated * 95",
        'threshold_percent": 95',
        "docs/mutation-survivor-triage-v1.json",
        "Survivor-triage exact diff parity failed",
        "untriaged_count",
        "needs_regression",
        "Equivalent/defensive survivor lacks a rationale",
        'survivor_triage_parity": "exact_normalized_diff"',
    ):
        assert required_contract in script
