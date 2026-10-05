"""The real-faults study: the parts of it that need no engine and no corpus.

Its population is the protocol's table, so the table is parsed from the hashed file and held to
its stated counts; the Config Validator view of a module must rename the input keys and the rule
and nothing else; and the exposure probabilities must be what enumerating the suites gives.
"""

from __future__ import annotations

import importlib.util
import itertools
import sys
from fractions import Fraction
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "rego_real_faults_study", ROOT / "scripts" / "rego_real_faults_study.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["rego_real_faults_study"] = module
    specification.loader.exec_module(module)
    return module


study = _module()


def test_the_protocol_is_the_one_the_study_was_fixed_under() -> None:
    study.require_protocol(development_only=False)


def test_the_population_is_the_protocols_table() -> None:
    rows = study.candidates()
    assert [r["number"] for r in rows] == list(range(1, 73))
    faults = study.population()
    assert len(faults) == 34
    assert {f["corpus"] for f in faults} == {"gatekeeper", "gcp"}
    development = [f["number"] for f in faults if (f["corpus"], f["commit"]) in study.DEVELOPMENT]
    assert development == [2, 34]


def _ref(*parts: str) -> dict:
    head = [{"type": "var", "value": parts[0]}]
    return {"type": "ref", "value": head + [{"type": "string", "value": p} for p in parts[1:]]}


def test_the_config_validator_view_renames_the_inputs_and_the_rule_only() -> None:
    profile = study.PROFILES["gcp"]
    rule = {
        "head": {"name": "deny", "ref": [{"type": "var", "value": "deny"}]},
        "body": [
            _ref("input", "asset", "name"),
            _ref("input", "constraint"),
            _ref("data", "asset"),
        ],
    }
    seen = study.renamed({"rules": [rule]}, profile)["rules"][0]
    assert seen["head"]["name"] == "violation"
    assert seen["head"]["ref"][0]["value"] == "violation"
    assert [p["value"] for p in seen["body"][0]["value"]] == ["input", "review", "name"]
    assert [p["value"] for p in seen["body"][1]["value"]] == ["input", "parameters"]
    assert [p["value"] for p in seen["body"][2]["value"]] == ["data", "asset"]
    assert study.renamed({"rules": [rule]}, study.PROFILES["gatekeeper"]) == {"rules": [rule]}


def test_an_authors_input_reads_in_the_analysis_convention() -> None:
    profile = study.PROFILES["gcp"]
    item = {"asset": {"name": "a"}, "constraint": {"spec": {}}}
    assert study.as_review(profile, item) == {"review": {"name": "a"}, "parameters": {"spec": {}}}


def _enumerate(setting: dict, groups: list[list[int]]) -> Fraction:
    suites = list(itertools.product(*groups))
    return Fraction(sum(1 for s in suites if set(s) & set(setting["delta"])), len(suites))


def test_exposure_multiplies_the_settings_misses_and_matches_enumeration() -> None:
    first = {
        "cells": 4,
        "classes": [[0, 1], [2, 3]],
        "decision_groups": [[0, 1, 2], [3]],
        "delta": [1],
    }
    second = {"cells": 3, "classes": [[0], [1, 2]], "decision_groups": [[0, 1, 2]], "delta": [2]}
    chance = study.exposure([first, second])
    for strategy, key in (("quotient", "classes"), ("decision", "decision_groups")):
        miss = (1 - _enumerate(first, first[key])) * (1 - _enumerate(second, second[key]))
        assert chance[strategy] == 1 - miss
    random_miss = Fraction(1)
    for setting in (first, second):
        size = len(setting["classes"])
        draws = list(itertools.combinations(range(setting["cells"]), size))
        random_miss *= Fraction(
            sum(1 for d in draws if not set(d) & set(setting["delta"])), len(draws)
        )
    assert chance["random_quotient"] == 1 - random_miss
    assert chance["refinement"] == 1


def test_a_difference_set_is_a_union_of_classes_only_when_it_splits_none() -> None:
    whole = {"classes": [[0, 1], [2]], "delta": [0, 1]}
    split = {"classes": [[0, 1], [2]], "delta": [0, 2]}
    nothing = {"classes": [[0, 1], [2]], "delta": []}
    assert study.union_of_classes([whole])
    assert not study.union_of_classes([split])
    assert not study.union_of_classes([nothing])
    assert study.union_of_classes([whole, nothing])
