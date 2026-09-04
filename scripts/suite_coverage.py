"""Measure decision-class coverage of policy test suites across policy ecosystems.

Structural coverage tells you a line ran. It does not tell you the suite constrained what
that line returns, and `benchmark/orthogonality-witness` exhibits a suite at 100% coverage
that cannot detect its policy's default changing.

This instrument measures the thing coverage misses. A policy decides over a finite domain,
so a suite either witnesses a given decision for a given policy subject or it does not. A
subject the suite only ever witnesses one decision for is blind: the policy could be
rewritten to return that decision unconditionally and every test would still pass.

Three ecosystems are supported, chosen because their decision domains differ in size --
which is the variable the measure is sensitive to:

    rego      Gatekeeper constraints. A violation set: empty permits, non-empty denies.
    kyverno   The Kyverno CLI test manifest, which labels each result pass, fail or skip.
    cedar     Cedar integration tests, which label each request allow or deny.

Run: python scripts/suite_coverage.py <ecosystem> PATH [PATH ...] [--json out.json]
"""

from __future__ import annotations

import argparse
import importlib
import json
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

SCHEMA_VERSION = "trustweave.dev/suite-coverage/v1alpha1"

# Below this, the measured files are whichever ones the adapter happens to understand,
# which is not a sample of the ecosystem. An earlier revision of the Rego adapter read 19%
# of its corpus and supported the opposite of the conclusion fuller extraction produced.
MINIMUM_EXTRACTION_FOR_SUMMARY = 0.80

ADAPTER_MODULES = {
    "rego": "suite_coverage_rego",
    "kyverno": "suite_coverage_kyverno",
    "cedar": "suite_coverage_cedar",
}


@dataclass(frozen=True)
class Observation:
    """One decision a suite pins, and the policy subject it pins it for."""

    domain: str
    subject: str
    decision: str
    test: str


@dataclass
class Reading:
    """What one suite file yielded, or why it yielded nothing."""

    path: str
    observations: list[Observation] = field(default_factory=list)
    not_extracted: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Adapter(Protocol):
    """What every ecosystem adapter must provide."""

    NAME: str
    DECISION_DOMAINS: dict[str, list[str]]

    def discover(self, root: Path) -> list[Path]: ...

    def read(self, path: Path, relative: str) -> Reading: ...


def _git(repository: Path, *arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def provenance(root: Path) -> list[dict[str, str]]:
    """Pin the corpus to exact commits, so a reported number can be reproduced."""

    if not root.is_dir():
        return []
    repositories = []
    for candidate in [root, *sorted(child for child in root.iterdir() if child.is_dir())]:
        if not (candidate / ".git").exists():
            continue
        remote = _git(candidate, "remote", "get-url", "origin")
        commit = _git(candidate, "rev-parse", "HEAD")
        if remote and commit:
            repositories.append({"name": candidate.name, "remote": remote, "commit": commit})
    return repositories


def _subjects(
    observations: list[Observation], domains: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Fold observations into one row per policy subject, with what its suite witnessed."""

    witnessed: dict[tuple[str, str], set[str]] = defaultdict(set)
    for observation in observations:
        witnessed[(observation.domain, observation.subject)].add(observation.decision)

    rows = []
    for (domain, subject), decisions in sorted(witnessed.items()):
        # A domain the adapter declares has a known size. One it does not (an open set of
        # decision labels) is reported without a denominator rather than with a made-up one.
        declared = domains.get(domain)
        row: dict[str, Any] = {
            "domain": domain,
            "subject": subject,
            "decisions_witnessed": sorted(decisions),
            "blind": len(decisions) < 2,
        }
        if declared:
            row["domain_size"] = len(declared)
            row["decisions_unwitnessed"] = sorted(set(declared) - decisions)
        rows.append(row)
    return rows


def measure(adapter: Adapter, paths: list[Path]) -> dict[str, Any]:
    """Read every suite the adapter recognises under each path, and fold the result."""

    corpus: list[dict[str, str]] = []
    readings: list[Reading] = []
    for root in paths:
        corpus.extend(provenance(root))
        # Paths are recorded relative to the root supplied, so the artifact describes the
        # corpus rather than the machine that happened to measure it.
        base = root if root.is_dir() else root.parent
        for path in adapter.discover(root):
            # The adapter is given the corpus-relative name because subject scoping differs
            # by ecosystem: a Rego rule name is package-local and means nothing without its
            # file, while a Kyverno policy/rule pair is a global identifier that should
            # unify across every suite that exercises it.
            relative = str(path.relative_to(base))
            reading = adapter.read(path, relative)
            reading.path = relative
            readings.append(reading)

    measured = [reading for reading in readings if reading.observations]
    refused = [reading for reading in readings if not reading.observations]
    observations = [o for reading in measured for o in reading.observations]
    subjects = _subjects(observations, adapter.DECISION_DOMAINS)
    blind = [row for row in subjects if row["blind"]]
    # Domains are not interchangeable -- a Kyverno mutate rule has no failure outcome the
    # way a validate rule does -- so the per-domain split is reported, not just the total.
    by_domain: dict[str, dict[str, Any]] = {}
    for row in subjects:
        bucket = by_domain.setdefault(row["domain"], {"subjects": 0, "blind": 0})
        bucket["subjects"] += 1
        bucket["blind"] += int(row["blind"])
    for bucket in by_domain.values():
        covered = bucket["subjects"] - bucket["blind"]
        bucket["witnessing_more_than_one"] = covered
        bucket["share_witnessing_more_than_one"] = round(covered / bucket["subjects"], 4)
    extraction = len(measured) / len(readings) if readings else 0.0

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "ecosystem": adapter.NAME,
        "corpus": corpus,
        "decision_domains": adapter.DECISION_DOMAINS,
        # This number gates every other number here.
        "extraction_rate": round(extraction, 4),
        "sufficient_for_summary": extraction >= MINIMUM_EXTRACTION_FOR_SUMMARY,
        "files_considered": len(readings),
        "files_measured": len(measured),
        "observations": len(observations),
        "subjects_measured": len(subjects),
        "subjects_blind": len(blind),
        "by_domain": dict(sorted(by_domain.items())),
        "not_extracted": [
            {"file": reading.path, "reason": reading.not_extracted or "no assertions found"}
            for reading in sorted(refused, key=lambda r: r.path)
        ],
        "subjects": subjects,
    }
    extras = _fold_extra(adapter, measured)
    if extras:
        report["extra"] = extras
    return report


def _fold_extra(adapter: Adapter, measured: list[Reading]) -> dict[str, Any]:
    """Combine per-file supplementary data without letting one file overwrite another.

    Subjects deliberately unify across files -- a policy set exercised by two suites is one
    subject -- so per-file extras keyed by subject collide, and a plain dict merge silently
    keeps whichever file was read last. An adapter that emits extras must therefore say how
    to combine them; without that, a collision is an error rather than a quiet loss.
    """

    fold = getattr(adapter, "fold_extra", None)
    if callable(fold):
        folded = fold(measured)
        return folded if isinstance(folded, dict) else {}

    extras: dict[str, Any] = {}
    for reading in measured:
        for key, value in reading.extra.items():
            if key in extras:
                raise ValueError(
                    f"{adapter.NAME}: two files supply extra data for {key!r} and the adapter "
                    "declares no fold_extra to combine them"
                )
            extras[key] = value
    return extras


def render(report: dict[str, Any]) -> str:
    """A short human summary, refusing to draw a conclusion from a thin sample."""

    lines = [
        f"ecosystem: {report['ecosystem']}",
        f"files measured: {report['files_measured']} of {report['files_considered']} "
        f"({report['extraction_rate']:.0%} extraction)",
    ]
    if not report["sufficient_for_summary"]:
        lines.append(
            "  WARNING: extraction is below "
            f"{MINIMUM_EXTRACTION_FOR_SUMMARY:.0%}. The measured files are whichever ones\n"
            "  this adapter understands, which is not a sample of the ecosystem. Treat the\n"
            "  figures below as adapter diagnostics, not as a result."
        )
    measured = report["subjects_measured"]
    blind = report["subjects_blind"]
    covered = measured - blind
    share = f"{covered / measured:.0%}" if measured else "n/a"
    lines += [
        f"  decisions pinned          {report['observations']}",
        f"  policy subjects           {measured}",
        f"  witnessing >1 decision    {covered}  ({share})",
        f"  blind (one decision only) {blind}",
    ]
    for domain, bucket in report["by_domain"].items():
        lines.append(
            f"    {domain:24} {bucket['witnessing_more_than_one']:4}/{bucket['subjects']:<4}"
            f" witness >1  ({bucket['share_witnessing_more_than_one']:.0%})"
            f"   blind {bucket['blind']}"
        )
    return "\n".join(lines)


def load_adapter(name: str) -> Adapter:
    """Adapters are plain modules; each supplies the attributes the protocol names."""

    return cast(Adapter, importlib.import_module(ADAPTER_MODULES[name]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ecosystem", choices=sorted(ADAPTER_MODULES))
    parser.add_argument("paths", type=Path, nargs="+")
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)

    report = measure(load_adapter(arguments.ecosystem), arguments.paths)
    print(render(report))
    if arguments.json:
        arguments.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
