"""A ratchet on the tool classifier, so an improvement cannot be silently undone.

The classifier moved a long way in a short time, and every step was justified by the same
three headline numbers. Nothing held those numbers in place: a later change could trade
accuracy for coverage, or answer more often by answering worse, and the suite would stay
green because no test asserts anything about the whole benchmark.

`docs/classifier-evaluation-v1.json` records where it stands. These tests re-run the
benchmark and compare. They are a ratchet rather than an equality check -- getting better is
always allowed, and the artifact is refreshed when it does -- because pinning exact values
would make every genuine improvement look like a failure.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs" / "classifier-evaluation-v1.json"

_spec = importlib.util.spec_from_file_location(
    "classifier_evaluation", ROOT / "scripts" / "evaluate_classifier.py"
)
assert _spec and _spec.loader
evaluate_classifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluate_classifier)


def _baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _current() -> dict:
    return evaluate_classifier.evaluate()


def test_accuracy_does_not_regress() -> None:
    assert _current()["overall"]["accuracy"] >= _baseline()["overall"]["accuracy"]


def test_precision_when_answering_does_not_regress() -> None:
    """The number that matters: a confident wrong answer is worse than a refusal."""

    current = _current()["overall"]["precision_when_answering"]
    recorded = _baseline()["overall"]["precision_when_answering"]

    assert current >= recorded


def test_no_tool_becomes_undiscoverable_again() -> None:
    """A tool the analyzer cannot see has its effects attributed to nothing."""

    assert _current()["overall"]["not_discovered"] <= _baseline()["overall"]["not_discovered"]


def test_no_action_class_loses_recall() -> None:
    """Overall accuracy can hide a class collapsing, so each one is held separately."""

    current = _current()["per_class"]
    recorded = _baseline()["per_class"]

    for action_class, stats in recorded.items():
        assert current[action_class]["recall"] >= stats["recall"], action_class


def test_the_recorded_baseline_matches_the_report_the_harness_produces() -> None:
    """A baseline whose shape has drifted from the report compares nothing."""

    assert set(_current()) == set(_baseline())
    assert set(_current()["overall"]) == set(_baseline()["overall"])


def test_every_registration_form_the_benchmark_uses_is_discovered() -> None:
    """`none` is the framework recorded for a tool that was never found."""

    frameworks = _current()["by_framework"]

    assert frameworks.get("none", {}).get("cases", 0) <= _baseline()["by_framework"].get(
        "none", {}
    ).get("cases", 0)
