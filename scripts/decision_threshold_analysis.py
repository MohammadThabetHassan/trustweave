"""How much a decision-coverage threshold actually tells you about a corpus.

`scripts/suite_coverage.py` reports one verdict per subject: does the suite witness every
decision the language admits. That is the threshold k = |D|. This script asks whether that
is the right threshold, by measuring the information each threshold carries on the corpora
already recorded under docs/suite-coverage-*.json.

A threshold partitions subjects into flagged and unflagged. If it flags almost none, or
almost all, it carries almost no information about which subject is which, whatever its
theoretical standing. The binary entropy of the flagged share measures exactly that, in
bits, and it is a property of the corpus rather than an inference from a sample.

The script also reports the within-ecosystem satisfaction curve -- the share of subjects
witnessing at least k decisions, for every k -- because that curve is measured inside one
ecosystem, holding the tool, the community and the subject definition fixed, and so carries
none of the confounding that a comparison across ecosystems does.

Usage:
    python scripts/decision_threshold_analysis.py [--json out.json]
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from math import log2
from pathlib import Path
from typing import Any

DOCS = Path(__file__).resolve().parents[1] / "docs"
ECOSYSTEMS = ("rego", "kyverno", "cedar", "xacml")
MINIMUM_SUBJECTS_FOR_A_CURVE = 20


def binary_entropy(share: float) -> float:
    """Bits carried by a partition that flags *share* of the corpus."""
    if share <= 0.0 or share >= 1.0:
        return 0.0
    return -(share * log2(share) + (1 - share) * log2(1 - share))


def load_groups(ecosystem: str) -> dict[tuple[str, int], list[int]]:
    """Witnessed-decision counts per subject, grouped so |D| is fixed within a group."""
    path = DOCS / f"suite-coverage-{ecosystem}-v1.json"
    reading = json.loads(path.read_text(encoding="utf-8"))
    groups: dict[tuple[str, int], list[int]] = defaultdict(list)
    for subject in reading["subjects"]:
        groups[(subject["domain"], subject["domain_size"])].append(
            len(subject["decisions_witnessed"])
        )
    return dict(groups)


def analyse_group(counts: list[int], domain_size: int) -> dict[str, Any]:
    """Satisfaction curve and per-threshold information for one decision domain."""
    total = len(counts)
    curve = {k: sum(count >= k for count in counts) / total for k in range(1, domain_size + 1)}
    thresholds = []
    for k in range(2, domain_size + 1):
        flagged = sum(count < k for count in counts) / total
        thresholds.append(
            {
                "k": k,
                "share_flagged": round(flagged, 4),
                "bits": round(binary_entropy(flagged), 4),
            }
        )
    best = max(thresholds, key=lambda entry: entry["bits"])
    published = next(entry for entry in thresholds if entry["k"] == domain_size)
    return {
        "subjects": total,
        "domain_size": domain_size,
        "satisfaction_curve": {str(k): round(share, 4) for k, share in curve.items()},
        "thresholds": thresholds,
        "most_informative_threshold": best["k"],
        "most_informative_bits": best["bits"],
        "published_threshold_bits": published["bits"],
        "published_threshold_share_flagged": published["share_flagged"],
        "published_threshold_is_most_informative": published["k"] == best["k"],
    }


def analyse() -> dict[str, Any]:
    findings: dict[str, Any] = {"schema_version": "v1", "domains": []}
    for ecosystem in ECOSYSTEMS:
        for (domain, domain_size), counts in sorted(load_groups(ecosystem).items()):
            if len(counts) < MINIMUM_SUBJECTS_FOR_A_CURVE:
                continue
            entry = {"ecosystem": ecosystem, "domain": domain}
            entry.update(analyse_group(counts, domain_size))
            findings["domains"].append(entry)
    vacuous = [entry for entry in findings["domains"] if entry["published_threshold_bits"] < 0.3]
    findings["domains_measured"] = len(findings["domains"])
    findings["domains_where_published_threshold_is_most_informative"] = sum(
        entry["published_threshold_is_most_informative"] for entry in findings["domains"]
    )
    findings["domains_where_published_threshold_carries_under_0_3_bits"] = len(vacuous)
    return findings


def render(findings: dict[str, Any]) -> str:
    lines = [
        "Information carried by the threshold 'witnesses at least k of |D| decisions'.",
        "",
        f"{'ecosystem / domain':34s} {'|D|':>3s} {'n':>5s}  threshold report",
    ]
    for entry in findings["domains"]:
        label = f"{entry['ecosystem']} / {entry['domain']}"
        lines.append(f"{label:34s} {entry['domain_size']:3d} {entry['subjects']:5d}")
        curve = "  ".join(
            f">={k}:{share:.3f}" for k, share in sorted(entry["satisfaction_curve"].items())
        )
        lines.append(f"{'':34s} curve  {curve}")
        for threshold in entry["thresholds"]:
            marker = " <- published" if threshold["k"] == entry["domain_size"] else ""
            best = (
                " (most informative)"
                if threshold["k"] == entry["most_informative_threshold"]
                else ""
            )
            lines.append(
                f"{'':34s} k={threshold['k']}: flags {threshold['share_flagged']:6.1%} "
                f"{threshold['bits']:.3f} bits{marker}{best}"
            )
        lines.append("")
    best_count = findings["domains_where_published_threshold_is_most_informative"]
    thin_count = findings["domains_where_published_threshold_carries_under_0_3_bits"]
    lines.append(
        f"Domains measured: {findings['domains_measured']}. The published threshold is the "
        f"most informative one in {best_count} of them, and carries under 0.3 bits "
        f"in {thin_count}."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="write the findings as JSON")
    args = parser.parse_args(argv)
    findings = analyse()
    print(render(findings))
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
