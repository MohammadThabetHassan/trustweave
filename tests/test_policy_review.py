from __future__ import annotations

import json
from pathlib import Path

from trustweave.cli import main
from trustweave.io import load_document
from trustweave.models import parse_policy
from trustweave.policy_review import review_policy
from trustweave.report import render_policy_review_report

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "default-policy.json"


def _copy_policy_document() -> dict[str, object]:
    return json.loads(json.dumps(load_document(POLICY)))


def test_default_policy_has_no_static_review_findings() -> None:
    review = review_policy(parse_policy(_copy_policy_document()))

    assert review["summary"] == {"rules": 4, "review_findings": 0, "status": "clear"}
    assert "No deterministic structural review findings" in render_policy_review_report(review)


def test_policy_review_flags_allow_default_shadowed_rule_and_untrusted_external_allow() -> None:
    document = _copy_policy_document()
    document["default_decision"] = "allow"
    rules = document["rules"]
    assert isinstance(rules, list)
    rules.append(
        {
            "id": "TW-TEST-001",
            "description": "A deliberately broad test-only rule.",
            "source_trust": ["untrusted"],
            "tool_action_classes": ["external"],
            "decision": "allow",
            "rationale": "Test-only review control.",
        }
    )
    rules.append(
        {
            "id": "TW-TEST-002",
            "description": "A deliberately shadowed test-only rule.",
            "source_trust": ["untrusted"],
            "tool_action_classes": ["external"],
            "decision": "deny",
            "rationale": "Test-only review control.",
        }
    )

    review = review_policy(parse_policy(document))

    ids = {finding["id"] for finding in review["findings"]}
    assert {"TW-POL-001", "TW-POL-002", "TW-POL-003"}.issubset(ids)
    assert review["summary"]["status"] == "review_required"


def test_cli_policy_check_writes_json_and_markdown_artifacts(tmp_path: Path) -> None:
    assert main(["policy-check", "--policy", str(POLICY), "--output-dir", str(tmp_path)]) == 0
    assert (tmp_path / "policy-review.json").is_file()
    assert (tmp_path / "policy-review.md").is_file()
