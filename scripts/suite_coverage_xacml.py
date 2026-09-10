"""Read what an XACML test suite pins.

XACML is the case the measure was designed for. Its decision domain has four values --
`Permit`, `Deny`, `NotApplicable` and `Indeterminate` -- where Gatekeeper and Cedar have
two, so full decision coverage is a real requirement rather than a bar cleared by writing
one negative test. This is the regime `docs/DECISION_CLASS_COVERAGE.md` argues the measure
earns its keep in, and the other three ecosystems do not contain it.

A suite here is a directory holding `requests/` and `responses/`, with files named
`response_<policy>_<case>.xml`, so several cases exercise one policy and the policy is the
subject.

Single-case conformance directories -- one `policy.xml` beside one `request.xml` and one
`response.xml` -- are deliberately not measured. The OASIS conformance material is a
conformance suite for PDP *implementations*, one case per language feature, not a test suite
for a policy. Every such case would score as witnessing one decision, and reporting that as
decision-blindness would be a category error rather than a finding.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from suite_coverage import Observation, Reading

NAME = "xacml"
# The four values a XACML 3.0 PDP may return for a request.
DECISION_DOMAINS = {
    "xacml_decision": ["Deny", "Indeterminate", "NotApplicable", "Permit"],
}

RESPONSE_NAME = re.compile(r"response_(?P<policy>\d+)_(?P<case>\d+)\.xml$", re.IGNORECASE)
DECISION = re.compile(r"<Decision>\s*([A-Za-z]+)\s*</Decision>")


def discover(root: Path) -> list[Path]:
    """Response files that belong to a multi-case suite."""

    if not root.is_dir():
        return [root]
    return sorted(
        path
        for path in root.rglob("response_*.xml")
        if path.parent.name.lower() == "responses" and RESPONSE_NAME.search(path.name)
    )


def read(path: Path, relative: str) -> Reading:
    match = RESPONSE_NAME.search(path.name)
    if match is None:
        return Reading(path=relative, not_extracted="not a numbered suite response")
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return Reading(path=relative, not_extracted="not readable")

    decisions = DECISION.findall(text)
    if not decisions:
        return Reading(path=relative, not_extracted="no Decision element")

    # The suite is the directory above `responses`, and the policy index in the file name
    # identifies which policy the case exercises. Cases for one policy therefore unify.
    suite = path.parent.parent
    subject = f"{suite.name}/policy_{match.group('policy')}"
    if suite.parent.name:
        subject = f"{suite.parent.name}/{subject}"

    return Reading(
        path=relative,
        observations=[
            Observation(
                domain="xacml_decision",
                subject=subject,
                decision=decision,
                test=path.name,
            )
            for decision in decisions
        ],
        extra={subject: {"cases": 1}},
    )


def fold_extra(readings: list[Reading]) -> dict[str, dict[str, int]]:
    """Count how many cases exercise each policy, across the files that mention it."""

    cases: dict[str, int] = defaultdict(int)
    for reading in readings:
        for subject, payload in reading.extra.items():
            cases[subject] += int(payload["cases"])
    return {subject: {"cases": count} for subject, count in sorted(cases.items())}
