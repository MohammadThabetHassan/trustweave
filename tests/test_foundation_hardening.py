from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from trustweave.engine import decision_for_labels, matching_rule
from trustweave.io import load_document
from trustweave.models import (
    VALID_ACTION_CLASSES,
    VALID_DECISIONS,
    VALID_TRUST_LABELS,
    InputOutputError,
    ValidationError,
    parse_policy,
)
from trustweave.sarif import build_sarif
from trustweave.scenarios import parse_scenarios

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "default-policy.json"


def _policy_document() -> dict[str, object]:
    return json.loads(json.dumps(load_document(POLICY)))


def test_load_document_rejects_missing_non_object_invalid_json_and_empty_yaml(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(InputOutputError, match="does not exist"):
        load_document(missing)

    list_document = tmp_path / "list.json"
    list_document.write_text("[]", encoding="utf-8")
    with pytest.raises(ValidationError, match="top-level object"):
        load_document(list_document)

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{", encoding="utf-8")
    with pytest.raises(ValidationError, match="not valid JSON"):
        load_document(invalid_json)

    empty_yaml = tmp_path / "empty.yaml"
    empty_yaml.write_text("", encoding="utf-8")
    with pytest.raises(ValidationError, match="empty"):
        load_document(empty_yaml)


def test_scenario_parser_rejects_malformed_and_duplicate_synthetic_inputs() -> None:
    with pytest.raises(ValidationError, match="schema_version"):
        parse_scenarios({"schema_version": "unsupported", "scenarios": []})
    with pytest.raises(ValidationError, match="must be a list"):
        parse_scenarios({"schema_version": "trustweave.dev/v1alpha1", "scenarios": {}})
    with pytest.raises(ValidationError, match="must be an object"):
        parse_scenarios({"schema_version": "trustweave.dev/v1alpha1", "scenarios": ["bad"]})

    base = {
        "id": "TW-FOUNDATION-001",
        "description": "Synthetic validation fixture.",
        "source_trust": "trusted",
        "tool_action_class": "read",
        "expected_decision": "allow",
    }
    for field, value, message in (
        ("source_trust", "unknown", "invalid source_trust"),
        ("tool_action_class", "unknown", "invalid tool_action_class"),
        ("expected_decision", "unknown", "invalid expected_decision"),
    ):
        invalid = dict(base)
        invalid[field] = value
        with pytest.raises(ValidationError, match=message):
            parse_scenarios({"schema_version": "trustweave.dev/v1alpha1", "scenarios": [invalid]})

    with pytest.raises(ValidationError, match="include at least one"):
        parse_scenarios({"schema_version": "trustweave.dev/v1alpha1", "scenarios": []})
    with pytest.raises(ValidationError, match="duplicate ids"):
        parse_scenarios(
            {"schema_version": "trustweave.dev/v1alpha1", "scenarios": [base, dict(base)]}
        )


@given(
    source_trust=st.sampled_from(sorted(VALID_TRUST_LABELS)),
    action_class=st.sampled_from(sorted(VALID_ACTION_CLASSES)),
)
def test_policy_label_evaluation_matches_first_matching_rule_or_default(
    source_trust: str, action_class: str
) -> None:
    policy = parse_policy(_policy_document())

    rule = matching_rule(policy, source_trust, action_class)
    decision, rule_id = decision_for_labels(policy, source_trust, action_class)

    if rule is None:
        assert (decision, rule_id) == (policy.default_decision, None)
    else:
        assert (decision, rule_id) == (rule.decision, rule.id)


@given(
    value=st.text(min_size=1).filter(
        lambda text: bool(text.strip()) and text not in VALID_TRUST_LABELS
    )
)
def test_policy_parser_fails_closed_for_unknown_trust_labels(value: str) -> None:
    document = _policy_document()
    rules = document["rules"]
    assert isinstance(rules, list)
    rule = rules[0]
    assert isinstance(rule, dict)
    rule["source_trust"] = [value]

    with pytest.raises(ValidationError, match="unknown trust labels"):
        parse_policy(document)


def test_sarif_export_rejects_unknown_review_kind_and_unknown_severity() -> None:
    with pytest.raises(ValidationError, match="Unsupported SARIF review kinds"):
        build_sarif({"unknown": ("artifact.json", {})})

    exported = build_sarif(
        {
            "policy": (
                "policy-review.json",
                {
                    "schema_version": "trustweave.dev/policy-review/v1alpha1",
                    "findings": [
                        {"id": "TW-POL-FOUNDATION", "severity": "unexpected", "message": "Test."}
                    ],
                },
            )
        }
    )
    assert exported["runs"][0]["results"][0]["level"] == "note"


def test_policy_contract_preserves_known_decision_vocabularies() -> None:
    assert {"trusted", "untrusted", "conditional"} == VALID_TRUST_LABELS
    assert {"read", "write", "sensitive", "external"} == VALID_ACTION_CLASSES
    assert {"allow", "deny", "require_approval"} == VALID_DECISIONS


def test_repository_reality_check_accepts_tracked_public_contracts() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/reality_check.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "issue forms, public documentation, release metadata" in completed.stdout
