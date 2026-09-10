"""The harness's decision map is checked against the engine that ships, and the check is tested.

`scripts/policy_mutation.py` decides every subject class with its own first-match loop. The
engine users run is `trustweave.engine.evaluate_flow`. Until the oracle existed nothing
compared the two -- the theory tests' "engine's own evaluation" called the harness -- and its
first run found two places where the harness disagreed with itself or with the engine on
policies the shipped one never exercises. Both are pinned here as the smallest policy that
shows each.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


oracle = _load("interpreter_oracle")
harness = oracle.harness

from trustweave.models import parse_policy  # noqa: E402


def _artifact() -> dict:
    for candidate in (ROOT, *ROOT.parents):
        path = candidate / "docs" / "interpreter-oracle-v1.json"
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    raise AssertionError("docs/interpreter-oracle-v1.json is missing")


def _policy(**changes: object) -> dict:
    document = json.loads((ROOT / "policies" / "default-policy.json").read_text(encoding="utf-8"))
    document["schema_version"] = "trustweave.dev/policy/v1alpha2"
    for index, rule in enumerate(document["rules"]):
        for key, value in changes.items():
            if key.startswith(f"rule{index}_"):
                rule[key.split("_", 1)[1]] = value
    return document


def test_the_committed_oracle_run_found_no_disagreement() -> None:
    """The figure the paper quotes: every witness and every sampled subject decided alike."""

    artifact = _artifact()

    assert artifact["engine_entry_point"] == "trustweave.engine.evaluate_flow"
    assert artifact["disagreements"] == []
    assert artifact["policies_checked"] == artifact["generated_policies"] + 2
    assert artifact["cells_checked"] > 100_000
    assert artifact["subjects_checked"] == artifact["policies_checked"] * 40


def test_the_committed_run_reproduces_from_its_seed() -> None:
    """A recorded seed that does not reproduce the recorded counts is decoration."""

    artifact = _artifact()
    fresh = oracle.measure(policies=5, subjects=10, seed=artifact["seed"])

    assert fresh["disagreements"] == []
    assert fresh["policies_checked"] == 7
    assert fresh["subjects_checked"] == 70


def test_a_subject_holding_a_nested_capability_lands_on_an_enumerated_cell() -> None:
    """Placement goes by signature, not by collecting every witness the subject matches.

    Under a policy naming `net.*` and `net.http`, a subject holding `net.http` matches both.
    The enumeration represents that signature by `("net.http",)`; the first placement built
    the pair, a cell no decision map contained, and the oracle reported `harness None`.
    """

    document = _policy(rule1_tool_capabilities=["net.*", "net.http", "fs.read"])
    space = harness.witness_space(document)
    reference = harness.decision_map(document)
    subject = (
        "trusted",
        "read",
        "unspecified",
        "synthetic-source",
        "synthetic-tool",
        (),
        ("net.http",),
    )

    witness = harness.abstract_cell(space, *subject)

    assert witness in reference
    assert witness[6] == ("net.http",)
    assert oracle.engine_decision(parse_policy(document), subject) == reference[witness]


def test_a_classification_the_policy_does_not_know_is_its_own_class() -> None:
    """The engine admits `customer-provided`; it fails every bound and matches no set.

    The witness space once had no value for it and the placement fell back on the first
    taxonomy entry, `public`, which a rule bound `at_most: internal` matches. The engine
    said allow, the harness said require_approval, and the oracle said so.
    """

    document = _policy(rule0_source_data_classification_at_most="internal")
    document["rules"][0]["decision"] = "allow"
    document["default_decision"] = "require_approval"
    space = harness.witness_space(document)
    reference = harness.decision_map(document)
    subject = ("trusted", "read", "customer-provided", "synthetic-source", "synthetic-tool", (), ())

    witness = harness.abstract_cell(space, *subject)

    assert harness.OUTSIDER in space["source_data_classification"]
    assert witness[2] == harness.OUTSIDER
    assert oracle.engine_decision(parse_policy(document), subject) == reference[witness]
    assert reference[witness] == "require_approval", "an unknown classification fails the bound"


def test_generated_policies_are_the_parser_s_policies() -> None:
    """The generator is only as good as the parser's acceptance of what it makes."""

    import random

    generator = random.Random(7)
    accepted = [oracle.generate_policy(generator) for _ in range(40)]
    documents = [document for document in accepted if document is not None]

    assert len(documents) >= 30
    for document in documents:
        parse_policy(document)
