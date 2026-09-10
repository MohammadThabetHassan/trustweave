"""Tests for the fragment-stratified reading of the Kyverno predictive result.

The pooled arm must keep reproducing the published figure. If it ever stopped, the strata
would stop being comparable with the claim they qualify, and the qualification would be
about a different number than the one the study reports.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

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


stratified = _load("fragment_stratified_test")


class TestStratifiedAssociation:
    def test_every_scored_policy_carries_a_fragment_verdict(self) -> None:
        assert len(stratified.joined_rows()) == 49

    def test_the_pooled_arm_reproduces_the_published_figure(self) -> None:
        """If it did not, the strata would not be comparable with the published claim."""

        findings = stratified.run(seed=0)
        pooled = next(entry for entry in findings["strata"] if entry["stratum"] == "all")

        assert pooled["test"]["observed_difference"] == 0.149
        assert pooled["test"]["p_value"] == pytest.approx(0.0428, abs=0.004)

    def test_the_association_is_confined_to_the_policies_outside_the_fragment(self) -> None:
        """The finding, and it is a caveat on a published claim rather than support for it."""

        findings = stratified.run(seed=0)

        assert findings["association_significant_inside_the_fragment"] is False
        assert findings["association_significant_outside_the_fragment"] is True

    def test_the_committed_artifact_matches_a_fresh_run(self) -> None:
        committed = json.loads(
            (ROOT / "docs" / "fragment-stratified-test-v1.json").read_text(encoding="utf-8")
        )

        assert committed == stratified.run(seed=0)
