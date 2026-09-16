"""The Kyverno membership instrument is checked against the engine, and that check is tested.

`scripts/oracle_kyverno.py` runs every measured policy's own suite under the Kyverno CLI,
as shipped and perturbed, and reads what each suite had to stub. The committed artifact is
the record of the last run; these tests hold it to what the paper says of it and exercise
the comparison rules on small suites, so that the adjudications stay made.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import yaml

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "oracle-kyverno-v1.json"


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


oracle = _load("oracle_kyverno")


def _artifact() -> dict:
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


# --- the artifact --------------------------------------------------------------------


def test_the_engine_disagrees_with_the_adapter_nowhere() -> None:
    artifact = _artifact()

    assert artifact["disagreements"] == 0
    assert artifact["disagreeing_policies"] == []
    assert artifact["engine"]["name"] == "kyverno"
    assert artifact["agreements"] + artifact["not_judged"] == artifact["policies"]


def test_the_oracle_covers_exactly_the_policies_the_membership_artifact_judged() -> None:
    artifact = _artifact()
    wide = json.loads(
        (ROOT / "docs" / "fragment-membership-kyverno-wide-v1.json").read_text(encoding="utf-8")
    )

    judged = {entry["subject"]: entry["adapter_verdict"] for entry in artifact["detail"]}
    measured = {entry["subject"]: entry["verdict"] for entry in wide["policies"]}
    assert judged == measured
    assert artifact["corpus"] == wide["corpus"]


def test_every_inside_policy_is_invariant_under_injected_cluster_state() -> None:
    artifact = _artifact()
    dynamic = artifact["dynamic"]

    assert dynamic["inside_policies_whose_outcomes_changed"] == 0
    assert (
        dynamic["inside_policies_invariant_under_injected_labels"]
        == (dynamic["inside_policies_checked"])
    )
    inside = [entry for entry in artifact["detail"] if entry["adapter_verdict"] == "inside"]
    assert dynamic["inside_policies_checked"] == len(inside)
    assert all(entry["outcomes_identical_under_injected_labels"] for entry in inside)
    assert not any(entry["suite_stubs"]["external"] for entry in inside)


def test_the_engine_needed_what_the_adapter_says_outside_policies_read() -> None:
    artifact = _artifact()
    outside = [entry for entry in artifact["detail"] if entry["adapter_verdict"] == "outside"]
    changed = [
        entry
        for entry in outside
        if entry.get("outcomes_identical_with_external_stubs_removed") is False
    ]

    assert changed, "no outside policy's suite depended on its stubs"
    assert artifact["dynamic"][
        "outside_policies_whose_outcomes_changed_when_stubs_were_removed"
    ] == len(changed)
    for entry in outside:
        assert entry["status"] in ("agree", "not judged"), entry


# --- the comparison rules --------------------------------------------------------------


def test_result_rows_are_cut_out_of_the_engines_log() -> None:
    output = (
        "Loading test  ( kyverno-test.yaml ) ...\n  Applying 1 policy to 2 resources ...\n\n"
        '[\n  {"ID": 1, "POLICY": "p", "RULE": "r", "RESOURCE": "v1/Pod/default/a", '
        '"RESULT": "Pass", "REASON": "Ok"},\n'
        '  {"ID": 2, "POLICY": "p", "RULE": "r", "RESOURCE": "v1/Pod/default/b", '
        '"RESULT": "Fail", "REASON": "Want fail, got pass"}\n]\n\nTest Summary: 1 passed\n'
    )

    assert oracle.parse_outcomes(output) == {
        "p|r|v1/Pod/default/a": "Pass",
        "p|r|v1/Pod/default/b": "Fail",
    }
    assert oracle.parse_outcomes("Error: no test found\n") is None


def test_a_stubbed_name_is_classified_by_what_the_policy_declares() -> None:
    declared = {"podcounts": "apiCall", "imageSize": "imageRegistry", "hostList": "variable"}

    assert oracle.classify_stub("request.operation", declared) == "request"
    assert oracle.classify_stub("request.object.spec.serviceAccountName", declared) == "request"
    assert oracle.classify_stub("hostList", declared) == "declared-variable"
    assert oracle.classify_stub("podcounts", declared) == "declared-context"
    assert oracle.classify_stub("imageSize", declared) == "declared-context"
    assert oracle.classify_stub("imageData.configData.created", declared) == "implicit-external"
    assert oracle.classify_stub("something", declared) == "undeclared"


def test_declared_context_reads_classic_and_cel_shapes() -> None:
    classic = (
        "spec:\n  rules:\n  - name: r\n    context:\n"
        "    - name: podcounts\n      apiCall:\n        urlPath: /api/v1/pods\n"
        "    - name: hosts\n      variable:\n        jmesPath: request.object.spec.rules[].host\n"
    )
    cel = (
        "spec:\n  variables:\n  - name: cm\n    expression: resource.Get('v1', 'configmaps', 'a')\n"
    )

    assert oracle.declared_context(classic) == {"podcounts": "apiCall", "hosts": "variable"}
    assert oracle.declared_context(cel) == {"cm": "variable"}


def test_only_stubs_outside_the_request_count_as_external(tmp_path: Path) -> None:
    suite = tmp_path / "policy" / ".kyverno-test"
    suite.mkdir(parents=True)
    (suite / "kyverno-test.yaml").write_text(
        "kind: Test\npolicies:\n- ../p.yaml\nresources:\n- r.yaml\nvariables: values.yaml\n",
        encoding="utf-8",
    )
    (suite / "values.yaml").write_text(
        yaml.safe_dump(
            {
                **oracle.VALUES_HEADER,
                "policies": [
                    {
                        "name": "p",
                        "rules": [
                            {
                                "name": "r",
                                "values": {"request.namespace": "x", "podcounts": "3", "h": "y"},
                            }
                        ],
                    }
                ],
                "namespaceSelector": [{"name": "default", "labels": {"env": "prod"}}],
            }
        ),
        encoding="utf-8",
    )

    stubs = oracle.stubs_of(suite)
    declared = {"podcounts": "apiCall", "h": "variable"}

    assert stubs.namespace_labels is True
    assert sorted(stubs.rule_values) == ["h", "podcounts", "request.namespace"]
    assert oracle.external_stubs(stubs, declared) == [
        "podcounts (declared-context)",
        "namespace labels (namespaceSelector)",
    ]


def test_stripping_keeps_request_fields_and_drops_the_rest(tmp_path: Path) -> None:
    suite = tmp_path / "policy" / ".kyverno-test"
    suite.mkdir(parents=True)
    (suite / "kyverno-test.yaml").write_text(
        "kind: Test\ncontext: context.yaml\npolicies:\n- ../p.yaml\nresources:\n- r.yaml\n"
        "variables: values.yaml\n",
        encoding="utf-8",
    )
    (suite / "context.yaml").write_text("kind: Context\n", encoding="utf-8")
    (suite / "values.yaml").write_text(
        yaml.safe_dump(
            {
                **oracle.VALUES_HEADER,
                "policies": [
                    {
                        "name": "p",
                        "rules": [
                            {
                                "name": "r",
                                "values": {"request.operation": "CREATE", "podcounts": "3"},
                            }
                        ],
                    }
                ],
                "namespaceSelector": [{"name": "default", "labels": {"env": "prod"}}],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "policy" / "p.yaml").write_text("kind: ClusterPolicy\n", encoding="utf-8")
    (suite / "r.yaml").write_text("kind: Pod\nmetadata:\n  name: a\n", encoding="utf-8")

    stripped = oracle.stripped_suite(suite, tmp_path / "work", {"podcounts": "apiCall"})
    manifest = yaml.safe_load((stripped / "kyverno-test.yaml").read_text(encoding="utf-8"))
    values = yaml.safe_load((stripped / "values.yaml").read_text(encoding="utf-8"))

    assert "context" not in manifest
    assert values["policies"][0]["rules"][0]["values"] == {"request.operation": "CREATE"}
    assert "namespaceSelector" not in values


def test_injection_labels_every_namespace_the_resources_name(tmp_path: Path) -> None:
    suite = tmp_path / "policy" / ".kyverno-test"
    suite.mkdir(parents=True)
    (suite / "kyverno-test.yaml").write_text(
        "kind: Test\npolicies:\n- ../p.yaml\nresources:\n- r.yaml\n", encoding="utf-8"
    )
    (tmp_path / "policy" / "p.yaml").write_text("kind: ClusterPolicy\n", encoding="utf-8")
    (suite / "r.yaml").write_text(
        "kind: Pod\nmetadata:\n  name: a\n  namespace: payments\n---\n"
        "kind: Pod\nmetadata:\n  name: b\n",
        encoding="utf-8",
    )

    injected = oracle.injected_suite(suite, tmp_path / "work", seed=7)
    manifest = yaml.safe_load((injected / "kyverno-test.yaml").read_text(encoding="utf-8"))
    values = yaml.safe_load((injected / manifest["variables"]).read_text(encoding="utf-8"))

    assert {entry["name"] for entry in values["namespaceSelector"]} == {"default", "payments"}
    assert all("trustweave-oracle/7" in entry["labels"] for entry in values["namespaceSelector"])
    assert values["globalValues"]
    # The shipped suite is untouched: the perturbation lives in the workspace copy.
    assert not (suite / manifest["variables"]).exists()
