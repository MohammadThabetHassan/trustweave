"""Read what a Cedar integration test pins.

Cedar's decision domain is binary, like Gatekeeper's, but its request space is not: every
request names a principal, an action and a resource, so the space a suite must witness
grows with the product of those, not with the number of policy lines. That is the same
shape as TrustWeave's own policy, which decides over trust level times action class, and it
is the regime where decision-class coverage stops being trivially satisfied.

So this adapter reports two things. The primary measure, comparable across ecosystems, is
whether a policy set's suite witnesses both decisions. The secondary measure, recorded
under `extra`, is how many distinct request cells the suite witnesses and how many of those
it witnesses under both decisions.

The cell denominator is deliberately absent. Knowing how many cells the policy could decide
differently needs the Cedar schema and the entity store, and a fraction printed against a
guessed denominator would be worse than no fraction.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from suite_coverage import Observation, Reading

NAME = "cedar"
DECISION_DOMAINS = {"cedar_decision": ["allow", "deny"]}


def _load(path: Path) -> dict[str, Any] | None:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _is_suite(document: dict[str, Any]) -> bool:
    return isinstance(document.get("requests"), list) and bool(document.get("requests"))


def discover(root: Path) -> list[Path]:
    """Only files that actually carry requests.

    A Cedar checkout holds entity stores, schemas and compiled policy ASTs as JSON too.
    Those are not suites, so counting them as suites this adapter failed to read would
    understate extraction against a denominator of files that were never tests.
    """

    if not root.is_dir():
        return [root]
    found = []
    for path in sorted(root.rglob("*.json")):
        document = _load(path)
        if document is not None and _is_suite(document):
            found.append(path)
    return found


def _entity(request: dict[str, Any], key: str) -> str:
    value = request.get(key)
    if not isinstance(value, dict):
        return "?"
    kind = value.get("type")
    return kind if isinstance(kind, str) else "?"


def _action(request: dict[str, Any]) -> str:
    value = request.get("action")
    if not isinstance(value, dict):
        return "?"
    identifier = value.get("id")
    return identifier if isinstance(identifier, str) else "?"


def read(path: Path, relative: str) -> Reading:
    document = _load(path)
    if document is None:
        return Reading(path=relative, not_extracted="not readable as JSON")
    if not _is_suite(document):
        return Reading(path=relative, not_extracted="no requests block")

    # The policy set is the subject: the question is whether its suite ever saw it both
    # permit and deny. Several test files may exercise the same policy file.
    policies = document.get("policies")
    subject = policies if isinstance(policies, str) else relative

    observations: list[Observation] = []
    cells: dict[str, set[str]] = defaultdict(set)
    unlabelled = 0
    for request in document["requests"]:
        if not isinstance(request, dict):
            continue
        decision = request.get("decision")
        if not isinstance(decision, str):
            unlabelled += 1
            continue
        decision = decision.lower()
        observations.append(
            Observation(
                domain="cedar_decision",
                subject=subject,
                decision=decision,
                test=str(request.get("description") or relative),
            )
        )
        cell = f"{_entity(request, 'principal')}|{_action(request)}|{_entity(request, 'resource')}"
        cells[cell].add(decision)

    if not observations:
        return Reading(path=relative, not_extracted=f"{unlabelled} requests, none with a decision")

    # Raw cells only. Several suites may exercise one policy set, and the counts are
    # meaningful over their union rather than per file, so folding happens in fold_extra.
    return Reading(
        path=relative,
        observations=observations,
        extra={subject: {"cells": {cell: sorted(d) for cell, d in sorted(cells.items())}}},
    )


def fold_extra(readings: list[Reading]) -> dict[str, Any]:
    """Union the request cells each suite witnessed, per policy set, then count."""

    merged: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for reading in readings:
        for subject, payload in reading.extra.items():
            for cell, decisions in payload["cells"].items():
                merged[subject][cell].update(decisions)

    folded: dict[str, Any] = {}
    for subject, cells in sorted(merged.items()):
        both = [cell for cell, decisions in cells.items() if len(decisions) > 1]
        folded[subject] = {
            "request_cells_witnessed": len(cells),
            "request_cells_witnessing_both_decisions": len(both),
            "cells": {cell: sorted(decisions) for cell, decisions in sorted(cells.items())},
        }
    return folded
