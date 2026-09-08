"""Check that the manuscript's numbers are the artifacts' numbers.

A paper is the one place where a figure can be wrong without any test noticing, because
prose is not executed. Every quantitative claim in the manuscript is therefore derived
here from the JSON an instrument wrote, and the check fails if the two disagree.

**The manuscript is deliberately not in this repository.** Journals treat a publicly
posted full text as prior dissemination, so it is kept outside the working tree and this
script is pointed at it:

    TRUSTWEAVE_PAPER=/path/to/main.tex python scripts/check_manuscript.py
    python scripts/check_manuscript.py --paper /path/to/main.tex [--docs docs]

With no manuscript to find, the check reports that and succeeds -- the artifacts are the
source of truth either way, and a checkout without the paper is not a checkout with a
wrong paper.

Each claim is an anchored pattern rather than a substring, because a substring search
only asks whether the right number appears *somewhere*: it passes a paper that states
the figure correctly in one section and wrongly in another, which is the drift most
likely to happen during revision. Every occurrence of a claim's phrasing must carry the
artifact's value, and a claim whose phrasing has been edited away fails as "not stated"
rather than passing silently.

Structural checks come first -- a citation with no bibliography entry, an unbalanced
environment, a `\\ref` to a label that does not exist -- because those break a build the
authors cannot run locally, so they have to be caught by reading.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

Claim = tuple[str, tuple[str, ...], str]


class ManuscriptError(AssertionError):
    """A claim in the manuscript that its artifact does not support."""


def _load(docs: Path, name: str) -> Any:
    return json.loads((docs / f"{name}.json").read_text(encoding="utf-8"))


def flatten(tex: str) -> str:
    """The manuscript with emphasis and line breaks removed.

    Claims are matched against this so that a phrasing may wrap across lines or put a
    number in bold without the pattern having to know.
    """
    # One level of nesting has to be allowed: the paper groups thousands as `2{,}642`, so
    # `\textbf{2{,}642}` contains braces and a `[^{}]*` body silently leaves it unstripped,
    # which is how a table row stopped matching its pin.
    body = tex
    for _ in range(3):
        replaced = re.sub(r"\\(?:textbf|emph|textit)\{((?:[^{}]|\{[^{}]*\})*)\}", r"\1", body)
        if replaced == body:
            break
        body = replaced
    return re.sub(r"\s+", " ", body)


def _grouped(value: int) -> str:
    """A count as the paper prints it: LaTeX's thin space groups thousands.

    `2{,}642` rather than `2,642`, because a bare comma in maths mode picks up the wrong
    spacing. The pins have to match what is written, so the grouping lives here.
    """

    if value < 1000:
        return str(value)
    return f"{value:,}".replace(",", "{,}")


def _pct(value: float) -> str:
    return f"{value * 100:.1f}"


def structural_findings(tex: str, bib: str) -> list[str]:
    problems: list[str] = []

    cited: set[str] = set()
    for group in re.findall(r"\\cite\{([^}]*)\}", tex):
        cited |= {key.strip() for key in group.split(",") if key.strip()}
    defined = set(re.findall(r"@\w+\{([^,]+),", bib))
    for key in sorted(cited - defined):
        problems.append(f"cited but absent from the bibliography: {key}")
    for key in sorted(defined - cited):
        problems.append(f"in the bibliography but never cited: {key}")

    opened = Counter(re.findall(r"\\begin\{(\w+\*?)\}", tex))
    closed = Counter(re.findall(r"\\end\{(\w+\*?)\}", tex))
    for name, count in sorted((opened - closed).items()):
        problems.append(f"environment opened {count} more times than closed: {name}")
    for name, count in sorted((closed - opened).items()):
        problems.append(f"environment closed {count} more times than opened: {name}")

    if tex.count("{") != tex.count("}"):
        problems.append(f"unbalanced braces: {tex.count('{')} open, {tex.count('}')} close")

    labels = set(re.findall(r"\\label\{([^}]*)\}", tex))
    for target in sorted(set(re.findall(r"\\ref\{([^}]*)\}", tex)) - labels):
        problems.append(f"reference to a label that is not defined: {target}")

    return problems


def numeric_claims(docs: Path) -> list[Claim]:
    """(anchored pattern, the artifact's values, what the claim is)."""
    claims: list[Claim] = []

    estimator = _load(docs, "estimator-comparison-v1")
    suites = {entry["suite"]: entry for entry in estimator["suites"]}
    reference = next(iter(suites.values()))
    claims += [
        (
            r"generates (\d+)\s*mutants, of which",
            (str(reference["mutants_generated"]),),
            "mutants generated (worked example)",
        ),
        (
            r"of (\d+) mutants of our reference policy",
            (str(reference["mutants_generated"]),),
            "mutants generated (abstract)",
        ),
        (
            r"(\d+) are provably equivalent",
            (str(reference["mutants_equivalent"]),),
            "mutants provably equivalent",
        ),
        (
            r"(\d+) non-equivalent mutants",
            (str(reference["mutants_live"]),),
            "mutants left live",
        ),
        (
            r"by Theorem~\\ref\{thm:equivalence\} --- (\d+\.\d)\\%",
            (_pct(estimator["equivalent_share"]),),
            "equivalent share of the mutant set",
        ),
    ]
    for name, entry in sorted(suites.items()):
        label = name.removesuffix("-scenarios.json")
        claims.append(
            (
                rf"{re.escape(label)} & (\d+\.\d)\\% & (\d+\.\d)\\% & (\d+\.\d) pt",
                (
                    _pct(entry["exact_score"]),
                    _pct(entry["score_without_equivalence_detection"]),
                    f"{entry['understatement_points']:.1f}",
                ),
                f"{label}: exact, approximate and understatement",
            )
        )

    # Rego is measured at whole-corpus scope only: that study's Rego subjects are
    # individual rules, while membership is a property of a policy module's guards.
    ecosystems = {
        "xacml": "XACML",
        "kyverno": "Kyverno",
        "cedar": "Cedar",
        "rego": "Rego",
        "iam": "AWS IAM",
    }
    joined_scopes = {"xacml", "kyverno", "cedar"}
    totals: Counter[str] = Counter()
    for slug, printed in ecosystems.items():
        wide = _load(docs, f"fragment-membership-{slug}-wide-v1")
        assert wide["corpus_scope"] == "wide", slug
        scopes = [("whole-corpus", wide)]
        if slug in joined_scopes:
            narrow = _load(docs, f"fragment-membership-{slug}-v1")
            assert narrow["corpus_scope"] == "joined-to-study", slug
            scopes.append(("joined", narrow))
        for scope, findings in scopes:
            counts = findings["counts"]
            inside, outside = counts["inside"], counts["outside"]
            undetermined = counts["undetermined"]
            total = inside + outside + undetermined
            if scope == "whole-corpus":
                totals.update(
                    {
                        "policies": total,
                        "inside": inside,
                        "outside": outside,
                        "undetermined": undetermined,
                    }
                )
            printed_total = re.escape(_grouped(total))
            claims.append(
                (
                    rf"{printed}(?: \\cite\{{\w+\}})? & {printed_total} & ([\d{{,}}]+) & "
                    rf"(\d+) & (\d+) & (\d+\.\d)\\%",
                    (
                        _grouped(inside),
                        str(outside),
                        str(undetermined),
                        _pct(inside / total),
                    ),
                    f"{slug} ({scope}): membership table row",
                )
            )
        wide_counts = wide["counts"]
        claims.append(
            (
                rf"([\d{{,}}]+) of {re.escape(_grouped(sum(wide_counts.values())))} "
                rf"{printed} policies",
                (_grouped(wide_counts["inside"]),),
                f"{slug}: whole-corpus inside, stated in prose",
            )
        )

    claims += [
        (
            r"([\d{,}]+) of ([\d{,}]+) policies lie\s*inside",
            (_grouped(totals["inside"]), _grouped(totals["policies"])),
            "abstract: pooled membership",
        ),
        (
            r"met by ([\d{,}]+) of the ([\d{,}]+) published policies",
            (_grouped(totals["inside"]), _grouped(totals["policies"])),
            "conclusion: pooled membership",
        ),
        (
            r"Total & ([\d{,}]+) & ([\d{,}]+) & (\d+) & (\d+) & (\d+\.\d)\\%",
            (
                _grouped(totals["policies"]),
                _grouped(totals["inside"]),
                str(totals["outside"]),
                str(totals["undetermined"]),
                _pct(totals["inside"] / totals["policies"]),
            ),
            "membership table: total row",
        ),
    ]

    rego = _load(docs, "fragment-membership-rego-wide-v1")
    rego_reasons = Counter(entry["reason"] for entry in rego["policies"])

    def outside_because(fragment: str) -> int:
        return sum(count for reason, count in rego_reasons.items() if fragment in reason)

    # Two kinds of exclusion, deliberately not pooled: an artifact that is not a policy,
    # and a policy whose guard reads state the subject does not carry.
    schemas = outside_because("policy schema")
    injected_directly = outside_because("the host injects")
    via_library = outside_because("reaches outside")
    inventory = injected_directly + via_library
    outside_total = rego["counts"]["outside"]
    reads_outside = outside_total - schemas
    other_data = reads_outside - inventory
    policies = rego["policies_considered"] - schemas
    claims += [
        (
            r"(\d+) are policies with a guard that reads state",
            (str(reads_outside),),
            "rego: policies whose guard reads outside the subject",
        ),
        (
            r"(\d+) reach \\texttt\{data\.inventory\}.{0,90}?"
            r"(\d+) directly, and (\d+)\s*by importing",
            (str(inventory), str(injected_directly), str(via_library)),
            "rego: policies reaching the injected inventory",
        ),
        (
            r"remaining (\d+) read some other \\texttt\{data\} document",
            (str(other_data),),
            "rego: other data documents",
        ),
        (
            r"(\d+) are not policies at all",
            (str(schemas),),
            "rego: policy schemas",
        ),
        (
            r"parameters for all (\d+)",
            (str(schemas),),
            "rego: schemas with an instantiating constraint",
        ),
        (
            r"Over the (\d+) artifacts that are policies, (\d+) are inside, or "
            r"(\d+\.\d)\\%",
            (
                str(policies),
                str(rego["counts"]["inside"]),
                _pct(rego["counts"]["inside"] / policies),
            ),
            "rego: share over artifacts that are policies",
        ),
        (
            r"(\d+) of the (\d+) are outside only because",
            (str(via_library), str(reads_outside)),
            "rego: outside only via an imported library",
        ),
    ]

    third_party = _load(docs, "fragment-membership-kyverno-thirdparty-v1")
    tp_counts = third_party["counts"]
    tp_reasons = Counter(
        entry["reason"] for entry in third_party["policies"] if entry["verdict"] == "outside"
    )
    image_verification = sum(
        count for reason, count in tp_reasons.items() if "verifies an image" in reason
    )
    claims += [
        (
            r"excluded: (\d+) policies from (\d+)\s*repositories and (\d+) distinct "
            r"owners",
            (
                str(third_party["policies_considered"]),
                str(third_party["repositories"]),
                str(third_party["owners"]),
            ),
            "third-party: corpus size and breadth",
        ),
        (
            r"(\d+) are inside, (\d+) outside, none\s*undetermined",
            (str(tp_counts["inside"]), str(tp_counts["outside"])),
            "third-party: verdicts",
        ),
        (
            r"All (\d+) exclusions are the same\s*construct",
            (str(image_verification),),
            "third-party: exclusions are image verification",
        ),
        (
            r"and (\d+) policies answer",
            (str(third_party["policies_considered"]),),
            "third-party: sample size restated in threats",
        ),
    ]

    witness = _load(docs, "witness-space-verification-v1")
    claims.append(
        (
            rf"(\d+) of {witness['capability_cases']} pattern sets",
            (str(witness["capability_cases_agreeing"]),),
            "pattern sets agreeing with the solver",
        )
    )
    by_patterns = {tuple(entry["patterns"]): entry for entry in witness["capabilities"]}
    nested = by_patterns[("net.*", "net.http")]
    chain = by_patterns[("net.*", "net.http", "net.http.get")]
    claims += [
        (
            r"nested patterns give (\d+) candidates and (\d+) achievable",
            (
                str(nested["candidate_signatures"]),
                str(nested["achievable_by_solver"]),
            ),
            "nested patterns: candidates and achievable",
        ),
        (
            r"a chain of three gives (\d+) and (\d+)",
            (str(chain["candidate_signatures"]), str(chain["achievable_by_solver"])),
            "chained patterns: candidates and achievable",
        ),
    ]

    stratified = _load(docs, "fragment-stratified-test-v1")
    strata = {entry["stratum"]: entry for entry in stratified["strata"]}

    def difference(stratum: str) -> str:
        entry = strata[stratum]
        return f"{entry['covered_mean'] - entry['blind_mean']:.3f}"

    def p_value(stratum: str) -> str:
        return f"{strata[stratum]['test']['p_value']:.3f}"

    claims += [
        (
            r"difference in means of (\d\.\d+) at \$p = (\d\.\d+)\$ one-sided over "
            r"(\d+) policies",
            (difference("all"), p_value("all"), str(strata["all"]["policies"])),
            "pooled stratum",
        ),
        (
            r"larger arm of (\d+) policies, the difference is (\d\.\d+) at "
            r"\$p = (\d\.\d+)\$",
            (str(strata["inside"]["policies"]), difference("inside"), p_value("inside")),
            "inside-the-fragment stratum",
        ),
        (
            r"outside it, over (\d+), it is (\d\.\d+) at \$p = (\d\.\d+)\$",
            (
                str(strata["outside"]["policies"]),
                difference("outside"),
                p_value("outside"),
            ),
            "outside-the-fragment stratum",
        ),
    ]

    trend = _load(docs, "decision-trend-test-v1")
    claims.append(
        (
            r"at \$p = (\d\.\d+)\$ by a Jonckheere",
            (f"{trend['p_value_one_sided']:.3f}",),
            "graded trend test",
        )
    )

    threshold = _load(docs, "decision-threshold-analysis-v1")
    measured = threshold["domains_measured"]
    domains = {entry["domain"]: entry for entry in threshold["domains"]}
    mutate = domains["kyverno_mutate"]
    xacml = domains["xacml_decision"]
    claims += [
        (
            rf"most informative available in (\d+) of {measured}",
            (str(threshold["domains_where_published_threshold_is_most_informative"]),),
            "domains where the published threshold is most informative",
        ),
        (
            rf"carries under 0\.3 bits in (\d+) of {measured}",
            (str(threshold["domains_where_published_threshold_carries_under_0_3_bits"]),),
            "domains carrying under 0.3 bits",
        ),
        (
            r"flags all (\d+) subjects and carries (\d\.\d+) bits",
            (str(mutate["subjects"]), f"{mutate['published_threshold_bits']:.3f}"),
            "kyverno mutate: subjects and bits",
        ),
        (
            r"carries (\d\.\d+) bits, against (\d\.\d+) for all four",
            (
                f"{xacml['most_informative_bits']:.3f}",
                f"{xacml['published_threshold_bits']:.3f}",
            ),
            "xacml: informative and published thresholds",
        ),
    ]

    return claims


MECHANISM_COUNT = re.compile(r"is unobservable \((\d+) mutants\)")


def decomposition_findings(flat: str, docs: Path) -> list[str]:
    """The worked example claims to explain every equivalent mutant. Check the arithmetic.

    Section \ref{sec:example} attributes the equivalent mutants to two mechanisms and gives
    a count for each. Those counts are prose, so nothing else would notice if a later
    revision changed one: the claim that they account for *every* equivalent mutant is only
    as good as their sum.
    """

    equivalent = _load(docs, "estimator-comparison-v1")["suites"][0]["mutants_equivalent"]
    counts = [int(found) for found in MECHANISM_COUNT.findall(flat)]
    if not counts:
        return [
            "the manuscript no longer decomposes the equivalent mutants by mechanism; "
            "the pattern that pinned that decomposition matches nothing"
        ]
    if sum(counts) != equivalent:
        return [
            f"the worked example's mechanisms account for {sum(counts)} equivalent mutants "
            f"({' + '.join(str(count) for count in counts)}) where the artifact reports "
            f"{equivalent}"
        ]
    return []


def corpus_findings(bib: str, docs: Path) -> list[str]:
    """The commits the bibliography cites must be the commits an artifact measured.

    A paper that names a corpus commit no instrument read is unreproducible in the one way
    a reader would actually try to check, so the abbreviated hashes in `refs.bib` are
    matched against the `corpus` block of every membership artifact. Both directions
    matter: a cited commit nothing measured is a fabrication, and a measured commit
    nothing cites is a corpus the reader cannot reconstruct.
    """

    measured: dict[str, str] = {}
    for slug in ("xacml", "kyverno", "cedar", "rego", "iam"):
        findings = _load(docs, f"fragment-membership-{slug}-wide-v1")
        for repository in findings.get("corpus") or []:
            measured[repository["commit"]] = repository["remote"]
    if not measured:
        return ["no membership artifact records the corpus it measured"]

    cited = set(re.findall(r"\\texttt\{([0-9a-f]{8})\}", bib))
    problems: list[str] = []
    for short in sorted(cited):
        if not any(commit.startswith(short) for commit in measured):
            problems.append(
                f"the bibliography cites corpus commit {short}, which no artifact measured"
            )
    for commit, remote in sorted(measured.items()):
        if not any(commit.startswith(short) for short in cited):
            problems.append(
                f"{remote} was measured at {commit[:8]}, which the bibliography does not cite"
            )
    return problems


def claim_findings(flat: str, claims: list[Claim]) -> list[str]:
    problems: list[str] = []
    for pattern, expected, provenance in claims:
        matches = re.findall(pattern, flat)
        if not matches:
            problems.append(
                f"the manuscript no longer states {provenance}; the pattern that "
                f"pinned it to its artifact matches nothing ({pattern!r})"
            )
            continue
        for match in matches:
            found = match if isinstance(match, tuple) else (match,)
            if found != expected:
                problems.append(
                    f"{provenance}: the manuscript says {found} where the artifact says {expected}"
                )
    return problems


def check(paper: Path, docs: Path) -> list[str]:
    tex = paper.read_text(encoding="utf-8")
    bib = (paper.parent / "refs.bib").read_text(encoding="utf-8")
    flat = flatten(tex)
    problems = structural_findings(tex, bib)
    problems += claim_findings(flat, numeric_claims(docs))
    problems += decomposition_findings(flat, docs)
    problems += corpus_findings(bib, docs)
    return problems


def default_paper() -> Path:
    """Where to look for the manuscript when the caller does not say.

    `TRUSTWEAVE_PAPER` first, because the manuscript lives outside the repository; then
    the in-tree location, so a checkout that does carry one is still checked.
    """

    from_environment = os.environ.get("TRUSTWEAVE_PAPER")
    if from_environment:
        return Path(from_environment)
    return ROOT / "paper" / "main.tex"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paper", type=Path, default=None)
    parser.add_argument("--docs", type=Path, default=ROOT / "docs")
    args = parser.parse_args(argv)

    paper = args.paper or default_paper()
    if not paper.is_file():
        print(
            f"no manuscript at {paper}: nothing to check. Point --paper or "
            "TRUSTWEAVE_PAPER at it to check its figures against docs/*.json."
        )
        return 0
    args.paper = paper

    problems = check(args.paper, args.docs)
    if problems:
        print(f"{len(problems)} problem(s) in {args.paper}:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    claims = len(numeric_claims(args.docs))
    print(f"{args.paper}: structure is sound and {claims} pinned claims agree with their artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
