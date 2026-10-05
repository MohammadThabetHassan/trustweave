"""The exact Kyverno study: its protocol, its population, its engine wrapper and its measures."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


study = _load("kyverno_exact_study")


def _policy(rule: dict, kind: str = "ClusterPolicy") -> list[dict]:
    return [{"kind": kind, "metadata": {"name": "p"}, "spec": {"rules": [rule]}}]


def _rule(**validate: object) -> dict:
    return {
        "name": "r",
        "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
        "validate": {"message": "m", **validate},
    }


def test_the_protocol_is_the_one_fixed_before_the_study() -> None:
    assert study.protocol_digest() == study.PROTOCOL_SHA256


def test_conditions_one_to_four() -> None:
    assert study.exclusion(_policy(_rule(pattern={"spec": {"a": "?*"}}))) is None
    assert study.exclusion(_policy(_rule(pattern={}), kind="Policy")).startswith("1:")
    assert study.exclusion(_policy(_rule(foreach=[]))).startswith("2:")
    with_context = _rule(pattern={})
    with_context["context"] = [{"name": "x", "configMap": {}}]
    assert study.exclusion(_policy(with_context)).startswith("2:")
    unmodelled = _rule(
        deny={
            "conditions": [
                {"key": "{{ length(request.object.spec.c) }}", "operator": "Equals", "value": 1}
            ]
        }
    )
    assert study.exclusion(_policy(unmodelled)).startswith("3:")
    assert study.exclusion(_policy(_rule(pattern={"a": "{{ request.x }}"}))).startswith("3:")
    by_subject = _rule(pattern={})
    by_subject["match"] = {"any": [{"resources": {"kinds": ["Pod"]}, "subjects": []}]}
    assert study.exclusion(_policy(by_subject)).startswith("4:")


def test_a_policy_condition_must_use_a_default_not_a_conjunction() -> None:
    conjunction = _rule(
        deny={
            "conditions": [
                {"key": "{{ request.object.spec.a && 'x' }}", "operator": "Equals", "value": "y"}
            ]
        }
    )
    assert study.exclusion(_policy(conjunction)).startswith("3:")


def test_mutants_are_grouped_by_the_operator_that_made_them() -> None:
    assert study.family("L3:NotEquals->Equals") == "condition operator"
    assert study.family("L4:||->&&") == "expression operator"
    assert study.family('L5:">->"<') == "threshold"
    assert study.family('L6:"?*"->"*"') == "weakening"
    assert study.family("L7:=(->(") == "anchor"
    assert study.family("L8:true->false") == "boolean"


def test_no_batch_holds_one_identity_twice() -> None:
    resources = [
        {"kind": "Pod", "metadata": {"name": "a"}},
        {"kind": "Pod", "metadata": {"name": "a", "namespace": "default"}},
        {"kind": "Pod", "metadata": {"name": "b"}},
        {"kind": "Service", "metadata": {"name": "a"}},
    ]
    batches = study._batches(resources)
    assert sorted(i for batch in batches for i in batch) == [0, 1, 2, 3]
    assert not any({0, 1} <= set(batch) for batch in batches)


def test_the_measures_follow_the_protocol() -> None:
    record = {
        "mutants": [
            {"status": "killed", "equivalent": False, "family": "anchor"},
            {"status": "survived", "equivalent": True, "family": "anchor"},
            {"status": "survived", "equivalent": False, "family": "weakening"},
            {"status": "stillborn", "family": "boolean"},
        ]
    }
    counts = study.tally(record)
    assert counts["killed"] == 1 and counts["survived"] == 2 and counts["stillborn"] == 1
    assert counts["equivalent_survivors"] == 1 and counts["real"] == 1
    scored = study.scores(counts)
    assert scored["raw"] == pytest.approx(1 / 3, abs=1e-6)
    assert scored["exact"] == pytest.approx(1 / 2, abs=1e-6)
    assert scored["share_of_survivors_equivalent"] == pytest.approx(1 / 2, abs=1e-6)
    summary = study.summarise([record, record])
    assert summary["pooled"]["mutants"] == 8
    assert summary["mean_over_policies"]["difference"] == pytest.approx(1 / 6, abs=1e-6)


def _kyverno() -> str | None:
    return os.environ.get("TRUSTWEAVE_KYVERNO") or shutil.which("kyverno")


@pytest.mark.skipif(_kyverno() is None, reason="needs the kyverno CLI")
def test_the_engine_decides_each_resource() -> None:
    policy = (
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata: {name: p}\n"
        "spec:\n  rules:\n  - name: r\n    match: {any: [{resources: {kinds: [Pod]}}]}\n"
        "    validate: {message: m, pattern: {metadata: {labels: {app: '?*'}}}}\n"
    )
    resources = [
        {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "good", "labels": {"app": "x"}}},
        {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "bad"}},
    ]
    decided = study.Engine(str(_kyverno())).decide(policy, resources, None)
    assert decided == [{"r": "pass"}, {"r": "fail"}]
