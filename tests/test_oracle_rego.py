"""The Rego membership instrument is checked against the engine, and that check is tested.

`scripts/oracle_rego.py` asks OPA's own compiler what each module reads and compares the
answer with the adapter's verdict on every module of every measured corpus. The committed
artifact is the record of the last run; these tests hold it to what the paper says of it and
exercise the comparison rules on the shapes the first run disagreed about, so that the
adjudications made then stay made.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _docs() -> Path:
    for candidate in (ROOT, *ROOT.parents):
        if (candidate / "docs" / "oracle-rego-v1.json").is_file():
            return candidate / "docs"
    raise AssertionError("docs/oracle-rego-v1.json is missing")


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


opa_required = pytest.mark.skipif(
    shutil.which("opa") is None, reason="opa is not installed; the oracle needs the engine"
)


def _artifact() -> dict:
    return json.loads((_docs() / "oracle-rego-v1.json").read_text(encoding="utf-8"))


def test_the_engine_agrees_with_the_adapter_on_every_measured_module() -> None:
    artifact = _artifact()

    assert artifact["disagreements"] == 0
    assert artifact["engine_could_not_load"] == 0
    assert artifact["agreements"] == artifact["modules"] == 273
    for corpus in artifact["static"]:
        assert corpus["disagreeing_modules"] == []
        assert corpus["root"] in ("gcp", "rego"), "corpus roots are names, not machine paths"


def test_the_oracle_covers_exactly_the_modules_the_membership_artifacts_judged() -> None:
    """A check over fewer modules than the measurement would be a check of something else."""

    docs = _docs()
    measured = sum(
        json.loads((docs / f"{stem}.json").read_text(encoding="utf-8"))["policies_considered"]
        for stem in ("fragment-membership-rego-gcp-v1", "fragment-membership-rego-wide-v1")
    )

    assert _artifact()["modules"] == measured


def test_the_engine_flags_more_nondeterministic_builtins_than_the_hand_list_did() -> None:
    """Recorded as a finding: the adapter now takes the set from the engine."""

    builtins = _artifact()["builtins"]

    assert set(builtins["hand_listed"]) < set(builtins["engine_flagged"])
    assert "io.jwt.decode_verify" in builtins["engine_flagged_not_hand_listed"]
    assert set(builtins["adapter_now_uses"]) >= set(builtins["engine_flagged"])
    assert builtins["called_in_measured_corpora"] == {"http.send": 1, "time.now_ns": 2}


def test_every_inside_template_with_a_suite_is_invariant_under_injected_cluster_state() -> None:
    artifact = _artifact()
    inside = sum(entry["inside_modules_checked"] for entry in artifact["dynamic"])
    invariant = sum(
        entry["inside_modules_invariant_under_injected_data"] for entry in artifact["dynamic"]
    )
    tests = sum(entry["tests_compared"] for entry in artifact["dynamic"])

    assert inside == invariant == 23
    assert tests == 230
    assert all(entry["inside_modules_whose_outcomes_changed"] == 0 for entry in artifact["dynamic"])


def test_the_agreement_rule_keeps_the_adjudications_of_the_first_run() -> None:
    """Fetching a parameter block is not reading a key; a defaulted read is still a read."""

    oracle = _load("oracle_rego")

    def engine(verdict: str, **found: list[str]) -> dict:
        base = {
            "reads_injected": [],
            "reads_undefined_data": [],
            "reads_parameter_keys": [],
            "fetches_parameters": [],
            "nondeterministic_calls": [],
        }
        base.update(found)
        return {"verdict": verdict, **base}

    inside = {"kind": "inside", "verdict": "inside", "reason": ""}
    defaulted = {"kind": "inside, parameters defaulted", "verdict": "inside", "reason": ""}
    schema = {"kind": "schema", "verdict": "outside", "reason": "policy schema"}
    network = {"kind": "outside: nondeterministic builtin", "verdict": "outside", "reason": ""}
    reads = {
        "kind": "outside: reads state the subject does not carry",
        "verdict": "outside",
        "reason": "",
    }

    fetch = engine(
        "fetches the parameter block", fetches_parameters=["data.lib.get_constraint_params"]
    )
    assert oracle.agree(inside, fetch), "four templates bind the block and never index it"
    assert not oracle.agree(inside, engine("external", reads_injected=["data.inventory"]))
    assert oracle.agree(defaulted, fetch)
    assert oracle.agree(schema, fetch)
    assert not oracle.agree(schema, engine("request and literals only"))
    assert oracle.agree(network, engine("external", nondeterministic_calls=["http.send"]))
    assert not oracle.agree(network, engine("external", reads_injected=["data.inventory"]))
    assert oracle.agree(reads, engine("external", reads_undefined_data=["data.kubernetes.pods"]))
    assert not oracle.agree(reads, engine("request and literals only"))


def test_the_engine_view_separates_defining_the_fetcher_from_calling_it() -> None:
    oracle = _load("oracle_rego")

    library = oracle.engine_view(
        set(),
        {"data.validator.gcp.lib.get_constraint_params", "data.validator.gcp.lib.has_field"},
        {"validator.gcp.lib"},
        "get_constraint_params(c) = p { p := c.spec.parameters }",
        frozenset(),
        own_package="validator.gcp.lib",
    )
    template = oracle.engine_view(
        {"input.constraint"},
        {"data.validator.gcp.lib.get_constraint_params"},
        {"validator.gcp.lib", "templates.gcp.X"},
        "deny { lib.get_constraint_params(input.constraint, p) }",
        frozenset(),
        own_package="templates.gcp.X",
    )

    assert library["verdict"] == "request and literals only"
    assert template["verdict"] == "fetches the parameter block"


@opa_required
def test_a_bundle_records_the_dialect_of_every_module_that_needs_one(tmp_path: Path) -> None:
    """A corpus mixing Rego v0 and v1 files gets a manifest the engine reads correctly."""

    oracle = _load("oracle_rego")
    (tmp_path / "old.rego").write_text(
        'package a\n\nviolation[msg] {\n  input.x == 1\n  msg := "v0"\n}\n'
    )
    (tmp_path / "new.rego").write_text(
        "package b\n\nimport rego.v1\n\n"
        'violation contains msg if {\n  input.x == 2\n  msg := "v1"\n}\n'
    )
    (tmp_path / "old_test.rego").write_text("package a\n\ntest_x {\n  true\n}\n")

    summary = oracle.build_bundle(tmp_path, tmp_path / "bundle.tar.gz")
    dependencies = oracle.dependencies(tmp_path / "bundle.tar.gz", "a")

    assert summary["modules"] == 2, "the test module is not a policy"
    assert summary["unparsed"] == []
    assert not isinstance(dependencies, str), dependencies
    assert {"input.x"} <= dependencies[0]
