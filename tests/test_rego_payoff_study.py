"""The suite-strategy study on real Rego: the parts of it that need no engine.

Its figures are exact only if the closed forms it scores with are the probabilities they claim
to be, and its quotient groups reviews by the truth values of the module's atoms and nothing
else. Both are held here: the closed forms against enumerating what they summarise, and the
signature on reviews built to agree or differ in one respect at a time.
"""

from __future__ import annotations

import importlib.util
import itertools
import sys
from fractions import Fraction
from pathlib import Path
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "rego_payoff_study", ROOT / "scripts" / "rego_payoff_study.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["rego_payoff_study"] = module
    specification.loader.exec_module(module)
    return module


study = _module()


def test_the_protocol_is_the_one_the_study_was_fixed_under() -> None:
    study.require_protocol(development_only=False)


def test_one_witness_per_group_detects_with_the_probability_enumeration_gives() -> None:
    groups = [[0, 1, 2], [3], [4, 5], [6, 7, 8, 9]]
    for hits in ({1}, {0, 3}, {4, 5, 7}, {2, 8, 9}, set()):
        suites = list(itertools.product(*groups))
        caught = sum(1 for suite in suites if hits & set(suite))
        assert study._detection(groups, hits) == Fraction(caught, len(suites))


def test_a_random_suite_detects_with_the_probability_enumeration_gives() -> None:
    cells = 9
    for hits, size in ((1, 3), (2, 4), (4, 2), (0, 5), (9, 1)):
        suites = list(itertools.combinations(range(cells), size))
        caught = sum(1 for suite in suites if set(suite) & set(range(hits)))
        assert study._random_detection(cells, hits, size) == Fraction(caught, len(suites))


def test_holm_multiplies_by_rank_and_keeps_the_adjusted_values_monotone() -> None:
    adjusted = study.holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adjusted == {"a": 0.03, "c": 0.06, "b": 0.06}


def test_a_difference_of_one_sign_reaches_the_permutation_floor() -> None:
    p = study.sign_flip_p([0.1 + 0.01 * i for i in range(20)], "greater")
    assert round(p, 4) == round(1 / (1 + study.RESAMPLES), 4)


def test_every_atom_kind_the_analysis_records_has_an_expression_or_is_left_unmerged() -> None:
    assert study.atom_expression(("cmp", "equal", '"a"'), "x") == 'x == "a"'
    assert study.atom_expression(("size", "gt", 0), "x") == "count(x) > 0"
    assert study.atom_expression(("affix", "startswith", '"k"'), "x") == 'startswith(x, "k")'
    assert study.atom_expression(("glob", '"a/*"'), "x") == 'glob.match("a/*", [], x)'
    assert study.atom_expression(("type", "is_string"), "x") == "is_string(x)"
    assert study.atom_expression(("truthy",), "x") == "x"
    assert study.atom_expression(("cmp", "between", 1), "x") is None


def _quotient() -> ModuleType:
    # A module that tests one container field against a literal and reads a flag beside it.
    containers = ("review", "object", "spec", "containers")
    image = (*containers, "*", "image")
    privileged = (*containers, "*", "privileged")
    analyzer = SimpleNamespace(
        atoms={image: {("cmp", "equal", '"nginx"')}, privileged: {("truthy",)}},
        unmerged=set(),
        read={image, privileged},
    )
    quotient = study.Quotient(analyzer, shapes={})
    # The truth values OPA would give, set by hand.
    for value, outcome in (('"nginx"', True), ('"redis"', False), ('"busybox"', False)):
        quotient.outcomes[(repr(("cmp", "equal", '"nginx"')), value)] = outcome
    for value, outcome in (("true", True), ("false", False)):
        quotient.outcomes[(repr(("truthy",)), value)] = outcome
    return quotient


def _review(*containers: tuple[str, bool]) -> dict:
    return {
        "object": {"spec": {"containers": [{"image": i, "privileged": p} for i, p in containers]}}
    }


def test_reviews_that_agree_on_every_atom_share_a_class() -> None:
    quotient = _quotient()
    # redis and busybox both fail the one atom on images, so they are one class.
    assert quotient.signature(_review(("redis", False))) == quotient.signature(
        _review(("busybox", False))
    )


def test_reviews_that_differ_on_an_atom_are_in_different_classes() -> None:
    quotient = _quotient()
    plain = quotient.signature(_review(("redis", False)))
    assert plain != quotient.signature(_review(("nginx", False)))
    assert plain != quotient.signature(_review(("redis", True)))


def test_a_collection_is_read_as_the_set_of_its_elements_classes() -> None:
    quotient = _quotient()
    one_order = _review(("nginx", False), ("redis", True))
    other_order = _review(("redis", True), ("nginx", False))
    assert quotient.signature(one_order) == quotient.signature(other_order)
    # Two elements of one class read as one element of it.
    assert quotient.signature(_review(("redis", False), ("busybox", False))) == quotient.signature(
        _review(("redis", False))
    )


def test_an_unmerged_path_makes_every_value_a_class_of_its_own() -> None:
    quotient = _quotient()
    image = ("review", "object", "spec", "containers", "*", "image")
    quotient.unmerged.add(image)
    assert quotient.signature(_review(("redis", False))) != quotient.signature(
        _review(("busybox", False))
    )


def test_the_values_to_decide_are_those_the_atoms_read_and_a_scalar_has_no_elements() -> None:
    quotient = _quotient()
    wanted = quotient.values_to_decide([_review(("redis", False), ("nginx", True))])
    assert {value for _, value in wanted} == {'"redis"', '"nginx"', "false", "true"}
    scalar = {"object": {"spec": {"containers": "not a list"}}}
    assert quotient.values_to_decide([scalar]) == set()
    assert quotient.signature(scalar)[0] == "present"
