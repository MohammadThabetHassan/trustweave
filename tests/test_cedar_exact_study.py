"""The Cedar replication: its eligibility rule, its witness space, and its completeness check.

The study's figures are exact only if every cell the script builds is a request the engine
accepts, and no request separates what no cell separates. Both are held here on small
policies, and the completeness check is held to failing when a cell really is missing.
These tests need the Cedar engine's bindings and skip without them.
"""

from __future__ import annotations

import importlib.util
import json
import random
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytest.importorskip("cedarpy")
from cedarpy import _internal as cedar  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "cedar_exact_study", ROOT / "scripts" / "cedar_exact_study.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["cedar_exact_study"] = module
    specification.loader.exec_module(module)
    return module


study = _module()
LEVELS = (
    'permit(principal, action == Action::"read", resource) '
    "when { principal.level >= 3 && context.mfa };\n"
    'forbid(principal in Group::"banned", action, resource);'
)
SETS = (
    'permit(principal is User, action in [Action::"view", Action::"edit"], resource) '
    'when { resource.tags.contains("public") || principal.dept == "eng" };'
)


def _est(text: str) -> dict:
    return json.loads(cedar.policies_to_json_str(text))


def test_the_protocol_is_the_one_the_study_was_fixed_under() -> None:
    study.require_protocol()


@pytest.mark.parametrize(
    ("text", "eligible"),
    [
        (LEVELS, True),
        (SETS, True),
        ("permit(principal, action, resource) when { resource.owner == principal };", False),
        ('permit(principal, action, resource) when { context.path like "/a/*" };', False),
        ("permit(principal == ?principal, action, resource);", False),
    ],
)
def test_only_atoms_against_literals_are_eligible(text: str, eligible: bool) -> None:
    assert (study.eligibility(_est(text)) == []) is eligible


@pytest.mark.parametrize("text", [LEVELS, SETS])
def test_every_cell_is_a_request_the_engine_accepts(text: str) -> None:
    """A witness the engine cannot read would be scored as a decision; none may exist."""

    est = _est(text)
    space = study.WitnessSpace(study.observables_of(est))
    policy = study._policy_text(est)
    built = 0
    for cell in space.cells():
        made = study.request_of(space, cell)
        assert made is not None
        decision, _ = study.decide(policy, *made)
        assert decision in ("Allow", "Deny")
        built += 1
    assert built == space.size()


@pytest.mark.parametrize("text", [LEVELS, SETS])
def test_an_intact_witness_space_passes_the_completeness_check(text: str) -> None:
    result = study.analyse_file(_est(text), generator=random.Random(1))

    assert result["status"] == "scored"
    assert result["fuzz_requests_in_no_class"] == 0
    assert result["missing_cells_for"] == []
    assert study._score(result)["refinement"] == 1


def test_a_missing_cell_fails_the_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """The check is only worth having if it fails when it should."""

    original = study.chain_candidates

    def without_values_below_the_threshold(found: object, path: tuple[str, ...]) -> list:
        return [
            value
            for value in original(found, path)
            if not (isinstance(value, int) and not isinstance(value, bool) and value < 3)
        ]

    monkeypatch.setattr(study, "chain_candidates", without_values_below_the_threshold)
    result = study.analyse_file(_est(LEVELS), generator=random.Random(1))

    assert result["status"] == "missing cells"
    assert result["fuzz_requests_in_no_class"] > 0


def test_a_real_edit_is_classified_by_what_it_decides() -> None:
    before = _est("permit(principal, action, resource) when { principal.level >= 3 };")
    weaker = _est("permit(principal, action, resource) when { principal.level >= 2 };")
    restated = _est("permit(principal, action, resource) when { 3 <= principal.level };")

    weakening = study.edit_pair(before, weaker)
    refactoring = study.edit_pair(before, restated)

    assert weakening["changes_a_decision"] and weakening["weakens_a_decision"]
    assert weakening["detection"]["refinement"] == 1.0
    assert not refactoring["changes_a_decision"]
    assert refactoring["detection"]["quotient"] == 0.0


def test_a_cell_with_a_cyclic_hierarchy_is_no_request() -> None:
    """Cedar refuses a cyclic entity store, so a cell that would need one stands for nothing."""

    text = (
        'permit(principal in Group::"a", action, resource in Group::"b") '
        'when { principal == Group::"b" && resource == Group::"a" };'
    )
    est = _est(text)
    space = study.WitnessSpace(study.observables_of(est))
    policy = study._policy_text(est)
    omitted = 0
    for cell in space.cells():
        made = study.request_of(space, cell)
        if made is None:
            omitted += 1
            continue
        assert study.decide(policy, *made)[0] in ("Allow", "Deny")
    assert omitted > 0
