"""Rego equivalence under every shipped Constraint: the protocol's table, the new settings."""

from __future__ import annotations

import importlib.util
import json
import re
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


study = _load("rego_shipped_constraints_study")


def test_the_protocol_is_the_one_fixed_before_the_study() -> None:
    assert study.protocol_digest() == study.PROTOCOL_SHA256


def test_the_frozen_table_is_the_protocols() -> None:
    text = study.PROTOCOL.read_text(encoding="utf-8")
    rows = re.findall(r"^\| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \| (yes|no) \|$", text, re.M)
    table: dict[str, list[tuple[str, str, bool]]] = {}
    for module, constraint, parameters, new in rows:
        table.setdefault(f"src/{module}/src.rego", []).append(
            (constraint, parameters, new == "yes")
        )
    assert table == study.FROZEN
    # Five headline modules gain a setting; the development module gains none.
    gaining = {s for s, rows in study.FROZEN.items() if any(new for _, _, new in rows)}
    assert len(gaining) == 5 and "src/general/httpsonly/src.rego" not in gaining


def test_shipped_constraints_are_read_from_the_samples(tmp_path: Path) -> None:
    samples = tmp_path / "library" / "general" / "thing" / "samples"
    (samples / "a").mkdir(parents=True)
    (samples / "b").mkdir(parents=True)
    (samples / "a" / "constraint.yaml").write_text(
        'kind: K\nspec:\n  parameters:\n    exemptImages: ["x/*"]\n', encoding="utf-8"
    )
    (samples / "b" / "constraint.yaml").write_text("kind: K\nspec: {}\n", encoding="utf-8")
    found = study.shipped_constraints(tmp_path, "src/general/thing/src.rego")
    assert found == [("a", json.dumps({"exemptImages": ["x/*"]}, sort_keys=True)), ("b", "absent")]


MODULE = """package k8sshippedtest

violation[{"msg": msg}] {
    c := input.review.object.spec.containers[_]
    c.securityContext.privileged
    not is_exempt(c)
    msg := sprintf("privileged container %v", [c.name])
}

is_exempt(container) {
    exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])
    img := container.image
    exemption := exempt_images[_]
    _matches_exemption(img, exemption)
}

_matches_exemption(img, exemption) {
    not endswith(exemption, "*")
    exemption == img
}

_matches_exemption(img, exemption) {
    endswith(exemption, "*")
    prefix := trim_suffix(exemption, "*")
    startswith(img, prefix)
}
"""

TESTS = """package k8sshippedtest

review(containers) = {"object": {"kind": "Pod", "spec": {"containers": containers}}}

test_privileged_is_denied {
    r := review([{"name": "a", "image": "nginx", "securityContext": {"privileged": true}}])
    count(violation) == 1 with input as {"review": r}
}

test_an_exact_exemption_allows {
    r := review([{"name": "a", "image": "nginx", "securityContext": {"privileged": true}}])
    count(violation) == 0 with input as {"review": r, "parameters": {"exemptImages": ["nginx"]}}
}

test_unprivileged_is_allowed {
    r := review([{"name": "a", "image": "nginx", "securityContext": {"privileged": false}}])
    count(violation) == 0 with input as {"review": r}
}
"""


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa is not on PATH")
def test_a_wildcard_constraint_separates_what_exact_matches_leave_equivalent(
    tmp_path: Path,
) -> None:
    module = tmp_path / "src.rego"
    test = tmp_path / "src_test.rego"
    module.write_text(MODULE, encoding="utf-8")
    test.write_text(TESTS, encoding="utf-8")
    opa = shutil.which("opa")
    shipped = [
        ("exact", json.dumps({"exemptImages": ["nginx"]}, sort_keys=True)),
        ("wild", json.dumps({"exemptImages": ["safe.example/*"]}, sort_keys=True)),
    ]
    record = study.settle(("synthetic/src.rego", MODULE, str(test), [], opa, shipped))
    assert record["reproduces"] is None  # nothing committed to reproduce
    rows = {row["constraint"]: row for row in record["shipped"]}
    assert rows["exact"]["status"] == "a tested setting" and not rows["exact"]["new"]
    assert rows["wild"]["new"] and rows["wild"]["status"] == "decided"
    # The suite tests only an exact exemption, so a mutant of the wildcard branch is
    # equivalent under its settings; the wildcard Constraint separates it.
    separated = record["newly_separated"]
    assert separated and all(n["constraint"] == "wild" for n in separated)
    assert all(n["mutant"] in record["equivalents_tested"] for n in separated)
    assert any(
        "startswith" in n["detail"] or n["operator"] == "drop a condition" for n in separated
    )
    remaining = record["equivalents_under_every_shipped_constraint"]
    assert remaining is not None and not set(remaining) & {n["mutant"] for n in separated}
