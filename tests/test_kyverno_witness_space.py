"""The Kyverno witness space: candidates, observables, cells and drawn resources."""

from __future__ import annotations

import importlib.util
import random
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


ws = _load("kyverno_witness_space")


def _pod_rule(pattern: dict, **extra: object) -> dict:
    return {
        "name": "r",
        "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
        "validate": {"message": "m", "pattern": pattern},
        **extra,
    }


def _policy(*rules: dict) -> dict:
    return {"kind": "ClusterPolicy", "metadata": {"name": "p"}, "spec": {"rules": list(rules)}}


def test_wildcards_yield_a_match_a_longer_match_and_a_near_miss() -> None:
    assert ws.pattern_candidates("?*") == ["a", "atw"]
    assert ws.pattern_candidates("*:*") == [":", "tw:tw", "x"]
    assert ws.pattern_candidates("!*:latest") == [":latest", "tw:latest", ":latesx"]


def test_alternatives_comparisons_and_ranges_are_split_and_bounded() -> None:
    assert ws.pattern_candidates("HAProxy | nginx") == ["HAProxy", "HAProxyx", "nginx", "nginxx"]
    assert ws.pattern_candidates(">0") == [-1, 0, 1]
    assert ws.pattern_candidates("<=4Gi") == ["3Gi", "4Gi", "5Gi"]
    assert ws.pattern_candidates("1-10") == [0, 1, 2, 9, 10, 11]
    assert ws.pattern_candidates("!NodePort") == ["NodePort", "NodePortx"]


def test_booleans_written_either_way_are_tried_both_ways() -> None:
    assert ws.pattern_candidates(True) == [True, False]
    assert ws.pattern_candidates("false") == [True, False]
    assert ws.pattern_candidates(3) == [2, 3, 4]


def test_anchors_are_stripped_and_every_leaf_may_be_absent() -> None:
    spaces = ws.rule_spaces(_policy(_pod_rule({"spec": {"=(hostNetwork)": "false"}})), [])
    node = spaces[0].root.children["spec"].children["hostNetwork"]
    values = ws.options(node)
    assert values[0] is ws.ABSENT
    assert {True, False, "", ws.FRESH} <= {v for v in values[1:]}


def test_a_list_is_absent_empty_or_one_element() -> None:
    pattern = {"spec": {"containers": [{"=(securityContext)": {"=(privileged)": "false"}}]}}
    spaces = ws.rule_spaces(_policy(_pod_rule(pattern)), [])
    containers = ws.options(spaces[0].root.children["spec"].children["containers"])
    assert containers[0] is ws.ABSENT and containers[1] == []
    assert all(isinstance(v, list) and len(v) == 1 for v in containers[2:])
    assert [{"securityContext": {"privileged": False}}] in containers


def test_conditions_contribute_their_paths_and_the_operation() -> None:
    rule = _pod_rule(
        {},
        preconditions={
            "all": [
                {
                    "key": "{{request.operation || 'BACKGROUND'}}",
                    "operator": "NotEquals",
                    "value": "DELETE",
                }
            ]
        },
    )
    rule["validate"] = {
        "message": "m",
        "deny": {
            "conditions": {
                "any": [
                    {
                        "key": "{{ request.object.spec.type }}",
                        "operator": "Equals",
                        "value": "NodePort",
                    }
                ]
            }
        },
    }
    space = ws.rule_spaces(_policy(rule), [])[0]
    assert space.reads_operation
    assert "NodePort" in ws.options(space.root.children["spec"].children["type"])


def test_a_mutant_that_turns_a_default_into_a_conjunction_still_reads_its_path() -> None:
    assert ws.object_path("{{ request.object.metadata.labels.\"a/b\" && 'x' }}") == [
        "metadata",
        "labels",
        "a/b",
    ]
    with pytest.raises(ws.Unsupported):
        rule = _pod_rule({})
        rule["validate"] = {
            "message": "m",
            "deny": {
                "conditions": [
                    {
                        "key": "{{ length(request.object.spec.containers) }}",
                        "operator": "Equals",
                        "value": 1,
                    }
                ]
            },
        }
        ws.rule_spaces(_policy(rule), [])


def test_selectors_make_the_name_and_namespace_observables() -> None:
    rule = _pod_rule({"spec": {"x": "y"}})
    rule["exclude"] = {"any": [{"resources": {"namespaces": ["kube-system"], "names": ["sys-*"]}}]}
    space = ws.rule_spaces(_policy(rule), [])[0]
    metadata = space.root.children["metadata"]
    assert "kube-system" in ws.options(metadata.children["namespace"])
    names = ws.options(metadata.children["name"])
    assert ws.ABSENT not in names and "sys-" in names


def test_cells_take_the_kind_from_the_suite_and_the_cap_excludes() -> None:
    policy = _policy(_pod_rule({"metadata": {"labels": {"app": "?*"}}}))
    spaces = ws.rule_spaces(policy, [])
    suite = [{"apiVersion": "v9", "kind": "Pod", "metadata": {"name": "a", "namespace": "n"}}]
    cells = ws.cells(spaces, suite, cap=1000)
    assert {c.resource["apiVersion"] for c in cells} == {"v9"}
    assert len({c.resource["metadata"]["name"] for c in cells}) == len(cells)
    with pytest.raises(ws.Unsupported, match="cap"):
        ws.cells(spaces, suite, cap=2)


def test_a_rule_that_reads_no_field_still_has_a_cell() -> None:
    spaces = ws.rule_spaces(_policy(_pod_rule({})), [])
    assert len(ws.cells(spaces, [], cap=10)) == 1


def test_an_unknown_kind_without_a_suite_resource_is_unsupported() -> None:
    rule = _pod_rule({"spec": {"a": "b"}})
    rule["match"] = {"any": [{"resources": {"kinds": ["Widget"]}}]}
    with pytest.raises(ws.Unsupported, match="kind"):
        ws.cells(ws.rule_spaces(_policy(rule), []), [], cap=100)


def test_drawn_resources_never_change_their_identity() -> None:
    base = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "n", "namespace": "d", "labels": {"a": "b"}},
        "spec": {"containers": [{"name": "c", "image": "i"}]},
    }
    perturber = ws.Perturber([base], random.Random(1))
    for _ in range(300):
        drawn = perturber.draw(base)
        assert drawn["apiVersion"] == "v1" and drawn["kind"] == "Pod"
        assert drawn["metadata"]["name"] == "n" and drawn["metadata"]["namespace"] == "d"
