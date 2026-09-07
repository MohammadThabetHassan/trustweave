"""Which published policies lie inside the decidable fragment, across ecosystems.

docs/DECISION_CLASS_COVERAGE.md section 4b locates the obstacle to the exactness results
in a policy's *guards*: a guard is inside the fragment when the partition it induces on
the subject space is fixed by the policy text, so finitely many classes exist and a
witness for each is constructible. Theorem 1b shows the evaluation rule is irrelevant, so
membership is decided per ecosystem by looking at guards and nothing else.

This is the instrument. One adapter per ecosystem reads policies -- not test suites, which
is what scripts/suite_coverage.py reads -- and returns one of three verdicts:

    inside        every guard's partition is fixed by a literal in the policy
    outside       some guard depends on data the policy does not contain
    undetermined  some construct this adapter does not judge

Every adapter refuses rather than guesses, and the undetermined count is printed before
any share, because a share computed over the policies an adapter happened to understand
is the error that made an early revision of the Rego measurement support the opposite of
its conclusion.

Usage:
    python scripts/fragment_membership.py <ecosystem> <corpus-root> [--json out.json]
"""

from __future__ import annotations

import argparse
import importlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

INSIDE = "inside"
OUTSIDE = "outside"
UNDETERMINED = "undetermined"
VERDICTS = (INSIDE, OUTSIDE, UNDETERMINED)

ADAPTERS = {
    "xacml": "fragment_membership_xacml",
    "kyverno": "fragment_membership_kyverno",
    "cedar": "fragment_membership_cedar",
}


@dataclass
class Verdict:
    """One policy's membership, with the evidence that decided it."""

    verdict: str
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {self.verdict!r}")


class Adapter(Protocol):
    """What an ecosystem adapter must provide."""

    ECOSYSTEM: str

    def discover(self, root: Path) -> list[tuple[str, Path]]:
        """(subject, policy file) pairs for the measured corpus.

        The subject is returned rather than inferred from the path, because the name a
        study records for a policy is not always recoverable from where the file sits.
        Kyverno resolves a policy through its test manifest, and the manifest may point
        anywhere.
        """

    def classify(self, text: str) -> Verdict:
        """Decide membership from the policy text alone."""


def load_adapter(ecosystem: str) -> Adapter:
    if ecosystem not in ADAPTERS:
        raise SystemExit(f"unknown ecosystem {ecosystem!r}; known: {sorted(ADAPTERS)}")
    return importlib.import_module(ADAPTERS[ecosystem])  # type: ignore[return-value]


def measure(adapter: Adapter, root: Path, restrict_to: set[str] | None = None) -> dict[str, Any]:
    """Classify every discovered policy, optionally restricted to measured subjects."""

    policies: list[dict[str, Any]] = []
    seen: set[str] = set()
    for subject, path in adapter.discover(root):
        if restrict_to is not None and subject not in restrict_to:
            continue
        if subject in seen:
            continue
        seen.add(subject)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as error:
            outcome = Verdict(UNDETERMINED, f"not readable: {error}")
        else:
            outcome = adapter.classify(text)
        policies.append(
            {
                "subject": subject,
                "verdict": outcome.verdict,
                "reason": outcome.reason,
                **outcome.detail,
            }
        )
    policies.sort(key=lambda entry: entry["subject"])
    counts = Counter(entry["verdict"] for entry in policies)
    total = len(policies)
    judged = total - counts.get(UNDETERMINED, 0)
    return {
        "schema_version": "v1",
        "ecosystem": adapter.ECOSYSTEM,
        "policies_considered": total,
        "counts": {name: counts.get(name, 0) for name in VERDICTS},
        "share_inside": round(counts.get(INSIDE, 0) / total, 4) if total else None,
        "share_inside_of_judged": round(counts.get(INSIDE, 0) / judged, 4) if judged else None,
        "policies": policies,
    }


def subjects_of(artifact: dict[str, Any]) -> set[str]:
    """The subject names an artifact measured, from either study artifact shape.

    A suite-coverage artifact names subjects directly. A mutation artifact names policies
    under `detail`, which is the shape the Kyverno experiment records, and joining against
    that is how a fragment verdict reaches a measured mutation score.
    """

    if "subjects" in artifact:
        return {subject["subject"] for subject in artifact["subjects"]}
    if "detail" in artifact:
        return {entry["policy"] for entry in artifact["detail"] if "policy" in entry}
    raise SystemExit("artifact names neither subjects nor scored policies")


def missing_subjects(findings: dict[str, Any], restrict_to: set[str] | None) -> list[str]:
    """Measured subjects the adapter could not find a policy for."""

    if restrict_to is None:
        return []
    return sorted(restrict_to - {entry["subject"] for entry in findings["policies"]})


def render(findings: dict[str, Any], absent: list[str]) -> str:
    counts = findings["counts"]
    lines = [
        f"{findings['ecosystem']}: {findings['policies_considered']} policies",
        f"  undetermined:        {counts[UNDETERMINED]}",
        f"  inside the fragment: {counts[INSIDE]}",
        f"  outside:             {counts[OUTSIDE]}",
        f"  share inside:        {findings['share_inside']}",
    ]
    if absent:
        lines.append(f"  measured subjects with no policy found: {len(absent)}")
        lines.extend(f"    {subject}" for subject in absent[:10])
    for entry in findings["policies"]:
        if entry["verdict"] != INSIDE:
            lines.append(f"    {entry['verdict']:12s} {entry['subject']}: {entry['reason']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ecosystem", choices=sorted(ADAPTERS))
    parser.add_argument("root", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--only-measured",
        type=Path,
        help="a suite-coverage or mutation artifact whose subjects bound this measurement",
    )
    args = parser.parse_args(argv)

    adapter = load_adapter(args.ecosystem)
    restrict_to: set[str] | None = None
    if args.only_measured and args.only_measured.is_file():
        restrict_to = subjects_of(json.loads(args.only_measured.read_text(encoding="utf-8")))

    findings = measure(adapter, args.root, restrict_to)
    absent = missing_subjects(findings, restrict_to)
    findings["measured_subjects_not_found"] = absent
    print(render(findings, absent))
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
