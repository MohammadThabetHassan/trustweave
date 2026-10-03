"""The located-span Rego mutation operators, and the suite-adequacy study's arithmetic.

The operators and the kill measurement need the Rego engine and skip without it; the
arithmetic over the committed artifact does not, so the figures the manuscript pins are held
to adding up on every run.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import statistics
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "rego-suite-adequacy-v1.json"
OPA = shutil.which("opa") is not None


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


MODULE = (
    "package t\n\n"
    'violation[{"msg": msg}] {\n'
    "  input.review.object.replicas > 3\n"
    '  msg := "too many"\n'
    "}\n"
)


# --------------------------------------------------------------------------------------- #
# The located-span mutation operators (need the engine)
# --------------------------------------------------------------------------------------- #


@pytest.mark.skipif(not OPA, reason="opa is not installed")
def test_every_mutant_parses_and_differs() -> None:
    mutation = _load("rego_source_mutation")
    found = mutation.mutants(MODULE)
    assert found, "a rule with a comparison and literals should yield mutants"
    assert len({m.source for m in found}) == len(found), "mutants are distinct"
    for mutant in found:
        assert mutant.source != MODULE
        assert mutation.parse(mutant.source) is not None, mutant.detail


@pytest.mark.skipif(not OPA, reason="opa is not installed")
def test_the_operators_cover_the_protocol_list() -> None:
    mutation = _load("rego_source_mutation")
    found = mutation.mutants(MODULE)
    operators = {m.operator for m in found}
    details = {m.detail for m in found}
    assert "delete a rule" in operators
    assert "flip a comparison" in operators
    assert "change a comparison" in operators  # the bucket the strictness edit falls in
    assert "change a comparison's strictness" in details
    assert "drop a condition" in operators
    assert {"change a number literal", "change a string literal"} <= operators


@pytest.mark.skipif(not OPA, reason="opa is not installed")
def test_an_assignment_is_never_dropped_or_negated() -> None:
    # Dropping `msg := ...` would leave msg unbound; the rule head reads it, so such a mutant
    # is a load failure, not a behaviour change, and the protocol excludes it.
    mutation = _load("rego_source_mutation")
    for mutant in mutation.mutants(MODULE):
        assert "msg := true" not in mutant.source
        assert "not msg :=" not in mutant.source


@pytest.mark.skipif(not OPA, reason="opa is not installed")
def test_a_comparison_flip_changes_the_operator_token() -> None:
    mutation = _load("rego_source_mutation")
    flips = [m for m in mutation.mutants(MODULE) if m.operator == "flip a comparison"]
    assert any("<=" in m.source for m in flips), "> should flip to <="


@pytest.mark.skipif(not OPA, reason="opa is not installed")
def test_an_operator_inside_a_string_literal_is_not_swapped() -> None:
    # The hazard the fixed-text set hit: `>` here is message text, not a comparison, so it is
    # never turned into `>=` or `<=`. Replacing the whole string literal is a separate, allowed
    # operator, so the test checks the operator was not swapped, not that the string is intact.
    mutation = _load("rego_source_mutation")
    module = 'package t\n\nviolation[{"msg": msg}] {\n  input.x\n  msg := "a > b required"\n}\n'
    for mutant in mutation.mutants(module):
        for swapped in ("a >= b required", "a <= b required", "a != b required", "a < b required"):
            assert swapped not in mutant.source


def test_parse_rejects_nonsense() -> None:
    if not OPA:
        pytest.skip("opa is not installed")
    mutation = _load("rego_source_mutation")
    assert mutation.parse("this is not rego {{{") is None


# --------------------------------------------------------------------------------------- #
# The study's arithmetic (no engine)
# --------------------------------------------------------------------------------------- #


def test_passes_reads_opa_json() -> None:
    study = _load("rego_suite_study")

    class Result:
        def __init__(self, out: str) -> None:
            self.stdout = out

    assert study._passes(Result('[{"name": "test_a"}]'))
    assert not study._passes(Result('[{"name": "test_a", "fail": true}]'))
    assert not study._passes(Result('[{"name": "test_a", "error": "boom"}]'))
    assert not study._passes(Result("[]")), "no tests is not a pass"
    assert not study._passes(Result("not json")), "a non-loading mutant is killed"


def test_the_committed_artifact_adds_up() -> None:
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    measured = {s: r for s, r in data["modules"].items() if r["status"] == "measured"}
    assert data["population"]["measured"] == len(measured)

    headline = {s: r for s, r in measured.items() if s != data["development_module"]}
    reported = data["headline"]
    assert reported["modules"] == len(headline)
    assert reported["mutants"] == sum(r["mutants"] for r in headline.values())
    assert reported["killed"] == sum(r["killed"] for r in headline.values())

    scores = [r["mutation_score"] for r in headline.values()]
    coverage = [r["coverage"] for r in headline.values() if r["coverage"] is not None]
    assert reported["mean_mutation_score"] == round(statistics.fmean(scores), 4)
    assert reported["median_mutation_score"] == round(statistics.median(scores), 4)
    assert reported["mean_coverage"] == round(statistics.fmean(coverage), 4)

    for record in measured.values():
        assert record["mutation_score"] == round(record["killed"] / record["mutants"], 4)
        assert sum(record["killed_by_operator"].values()) == record["killed"]
        assert sum(record["total_by_operator"].values()) == record["mutants"]


def test_coverage_exceeds_mutation_score_is_the_whole_point() -> None:
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    headline = data["headline"]
    assert headline["mean_coverage"] / 100 > headline["mean_mutation_score"]
    assert headline["mean_gap"] > 0
    low, high = headline["gap_bootstrap_95"]
    assert 0 < low <= headline["mean_gap"] <= high


def test_protocol_hash_matches_the_file() -> None:
    import hashlib

    study = _load("rego_suite_study")
    found = hashlib.sha256(study.PROTOCOL.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    assert found == study.PROTOCOL_SHA256
