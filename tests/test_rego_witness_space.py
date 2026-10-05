"""The Rego witness space's construction, on the parts that need no engine.

The study itself (`scripts/rego_exact_study.py`) needs `opa`; these tests pin the candidate rules
the protocol states (`docs/EXACT_ADEQUACY_PROTOCOL_REGO.md`), so a change to them fails here
before it can change a study's cells.
"""

from __future__ import annotations

import importlib.util
import random
import re
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _module() -> ModuleType:
    name = "rego_witness_space"
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


space = _module()


def test_a_string_compared_for_equality_gets_itself_a_non_string_and_the_mutant_literal() -> None:
    found = space.candidates({("eq", '"false"')})
    assert "false" in found
    assert False in found  # a value that is not a string: the boolean a suite might send
    assert space.MUTANT in found  # the literal rego_source_mutation substitutes
    assert space.FRESH in found


def test_a_number_threshold_gets_both_sides_and_the_mutated_threshold() -> None:
    found = space.candidates({("ord", 3)})
    assert {2, 3, 4, 5} <= set(found)


def test_a_size_comparison_gets_collections_around_the_threshold() -> None:
    found = space.candidates({("size", 1)})
    lengths = sorted(len(v) for v in found if isinstance(v, list))
    assert lengths == [0, 1, 2, 3]


def test_affixes_get_a_value_on_each_side_of_the_operator() -> None:
    assert "gcr.io/tw" in space.candidates({("startswith", "gcr.io/")})
    assert "twlatest" in space.candidates({("endswith", "latest")})
    assert "twxtw" in space.candidates({("contains", "x")})


def test_every_alternative_of_a_pattern_gets_a_matching_sample() -> None:
    pattern = r"^(extensions|networking\.k8s\.io)/"
    samples = space.regex_samples(pattern)
    assert sorted(samples) == ["extensions/", "networking.k8s.io/"]
    assert all(re.match(pattern, sample) for sample in samples)


def test_a_drawn_review_is_reproducible_from_its_seed() -> None:
    review = {"object": {"kind": "Pod", "spec": {"containers": [{"image": "a"}]}}}
    pool = space.leaf_pool([review])
    first = space.perturb(review, pool, random.Random("seed"))
    second = space.perturb(review, pool, random.Random("seed"))
    assert first == second
    assert review == {"object": {"kind": "Pod", "spec": {"containers": [{"image": "a"}]}}}


def test_collection_shapes_follow_the_authors_inputs() -> None:
    inputs = [{"review": {"object": {"metadata": {"labels": {"a": "b"}}, "spec": {"c": [1]}}}}]
    shapes = space.shapes_from(inputs)
    assert shapes[("review", "object", "metadata", "labels")] == "map"
    assert shapes[("review", "object", "spec", "c")] == "array"
