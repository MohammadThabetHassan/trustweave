"""Which published policies lie inside the decidable fragment, across ecosystems.

the decision-class coverage write-up section 4b locates the obstacle to the exactness results
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
import importlib.util
import json
import sys
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
    "rego": "fragment_membership_rego",
    "iam": "fragment_membership_iam",
    "azure": "fragment_membership_azure",
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

    def discover_wide(self, root: Path) -> list[tuple[str, Path]]:
        """Every policy in the corpus, not only the ones a study could score.

        Optional. `discover` returns the corpus that joins to a suite-coverage or
        mutation measurement, and that corpus is narrow for a reason: measuring decision
        coverage needs a suite with more than one case, and measuring a mutation score
        needs a suite at all. Membership needs neither -- it is decided from policy text
        -- so restricting it to the scorable policies understates how much of an
        ecosystem the fragment covers. An adapter that can enumerate more implements
        this; `measure_wide` falls back to `discover` for one that cannot.
        """


def load_adapter(ecosystem: str) -> Adapter:
    if ecosystem not in ADAPTERS:
        raise SystemExit(f"unknown ecosystem {ecosystem!r}; known: {sorted(ADAPTERS)}")
    return importlib.import_module(ADAPTERS[ecosystem])  # type: ignore[return-value]


def provenance(root: Path) -> list[dict[str, str]]:
    """Pin the corpus to exact commits, so a reported verdict can be reproduced.

    The suite-coverage artifacts have recorded this from the start; the membership
    artifacts did not, which left the corpus of the fragment measurement named only in
    prose. The same function is borrowed rather than copied, so the two cannot drift, and
    it is loaded by path at call time because these scripts are run directly and are not a
    package -- a top-level import would only resolve when `scripts/` happened to be on the
    path.
    """

    module_path = Path(__file__).resolve().parent / "suite_coverage.py"
    specification = importlib.util.spec_from_file_location("suite_coverage", module_path)
    if specification is None or specification.loader is None:  # pragma: no cover
        raise SystemExit(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(specification)
    # Register before executing. `suite_coverage` declares a dataclass, and under
    # `from __future__ import annotations` dataclasses resolves field annotations through
    # `sys.modules[cls.__module__]` -- which is None for a module that was executed but
    # never registered, and the decorator raises rather than the import failing cleanly.
    sys.modules.setdefault("suite_coverage", module)
    specification.loader.exec_module(module)
    repositories: list[dict[str, str]] = module.provenance(root)
    return repositories


def discovery_for(adapter: Adapter, wide: bool) -> Any:
    """The narrow corpus that joins to a study, or the widest the adapter can enumerate."""

    if wide:
        return getattr(adapter, "discover_wide", adapter.discover)
    return adapter.discover


def measure(
    adapter: Adapter,
    root: Path,
    restrict_to: set[str] | None = None,
    wide: bool = False,
) -> dict[str, Any]:
    """Classify every discovered policy, optionally restricted to measured subjects."""

    policies: list[dict[str, Any]] = []
    seen: set[str] = set()
    for subject, path in discovery_for(adapter, wide)(root):
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
        "--wide",
        action="store_true",
        help="every policy in the corpus, not only those a study could score",
    )
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

    if args.wide and restrict_to is not None:
        raise SystemExit("--wide and --only-measured ask for opposite corpora")
    findings = measure(adapter, args.root, restrict_to, wide=args.wide)
    findings["corpus_scope"] = "wide" if args.wide else "joined-to-study"
    findings["corpus"] = provenance(args.root)
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
