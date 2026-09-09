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


# A count as the paper prints it: digits, optionally grouped with LaTeX's thin space.
_GROUPED = r"\d+(?:\{,\}\d+)*"


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

    # One entry per row of the membership table, keyed by the label the paper prints.
    # The table carries an author column, so a row is
    #   <label> [\cite{...}] & <author> & <artifacts> & <inside> & <outside> & <und> & <share>
    TABLE_ROWS = (
        ("Azure Policy built-ins", "fragment-membership-azure-wide-v1"),
        ("AWS IAM managed", "fragment-membership-iam-wide-v1"),
        ("XACML conformance", "fragment-membership-xacml-wide-v1"),
        ("Kyverno library", "fragment-membership-kyverno-wide-v1"),
        ("Rego, four corpora", "fragment-membership-rego-wide-v1"),
        ("Rego, GCP library", "fragment-membership-rego-gcp-v1"),
        ("Kyverno, third-party", "fragment-membership-kyverno-thirdparty-v1"),
        ("Cedar integration", "fragment-membership-cedar-wide-v1"),
    )
    for label, stem in TABLE_ROWS:
        findings = _load(docs, stem)
        counts = findings["counts"]
        total = sum(counts.values())
        claims.append(
            (
                rf"{re.escape(label)}(?: \\cite\{{\w+\}})? & [^&]+ & "
                rf"({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & (\d+) & (\d+\.\d)\\%",
                (
                    _grouped(total),
                    _grouped(counts["inside"]),
                    _grouped(counts["outside"]),
                    str(counts["undetermined"]),
                    _pct(counts["inside"] / total),
                ),
                f"membership table row: {label}",
            )
        )

    rego = _load(docs, "fragment-membership-rego-wide-v1")
    rego_outside = [entry for entry in rego["policies"] if entry["verdict"] == "outside"]
    reasons = [entry["reason"] for entry in rego_outside]

    # The kinds of exclusion, deliberately not pooled: an artifact that is not a policy; a
    # policy reading the injected inventory in its own body or through a library rule; a
    # policy reading a document the bundle does not define, directly or through a sibling
    # package's rule; and a builtin that reaches past its arguments.
    schemas = sum("policy schema" in reason for reason in reasons)
    injected_directly = sum(
        reason.startswith("reads a document the host injects") for reason in reasons
    )
    via_rule = [reason for reason in reasons if reason.startswith("reaches outside through")]
    via_rule_injected = sum("the host injects" in reason for reason in via_rule)
    via_rule_undefined = sum("does not define" in reason for reason in via_rule)
    undefined_directly = sum(
        reason.startswith("reads a data document the bundle does not") for reason in reasons
    )
    network = sum("http.send" in reason for reason in reasons)
    inventory = injected_directly + via_rule_injected
    other_data = undefined_directly + via_rule_undefined
    reads_outside = rego["counts"]["outside"] - schemas
    assert reads_outside == inventory + other_data + network, "an exclusion of no known kind"
    policies = rego["policies_considered"] - schemas
    defaults_some = sum(
        1
        for entry in rego_outside
        if "policy schema" in entry["reason"]
        and (entry.get("parameter_reads") or {}).get("with_default")
    )
    claims += [
        (
            r"(\d+) are policies with a guard that reads state",
            (str(reads_outside),),
            "rego: policies whose guard reads outside the subject",
        ),
        (
            r"(\d+) reach \\texttt\{data\.inventory\}.{0,90}?"
            r"(\d+) directly, and (\d+)\s*through a library rule",
            (str(inventory), str(injected_directly), str(via_rule_injected)),
            "rego: policies reaching the injected inventory",
        ),
        (
            r"(\d+) read some other \\texttt\{data\} document the bundle does not\s*define, "
            r"(\d+) in their own body and (\d+) through a rule",
            (str(other_data), str(undefined_directly), str(via_rule_undefined)),
            "rego: other data documents, directly and through a rule",
        ),
        (
            r"and (\d+) calls\s*\\texttt\{http\.send\}",
            (str(network),),
            "rego: the network call",
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
            r"(\d+) of the 28 do for some parameter",
            (str(defaults_some),),
            "rego: schemas that default some parameter but not all",
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
            (str(via_rule_injected), str(reads_outside)),
            "rego: outside only through a library rule",
        ),
    ]

    # Google's library, under the same criterion as Gatekeeper's.
    gcp = _load(docs, "fragment-membership-rego-gcp-v1")
    gcp_schemas = sum("policy schema" in entry["reason"] for entry in gcp["policies"])
    gcp_clock = sum("time.now_ns" in entry["reason"] for entry in gcp["policies"])
    gcp_inside = [entry for entry in gcp["policies"] if entry["verdict"] == "inside"]
    gcp_complete = sum(
        1
        for entry in gcp_inside
        if (entry.get("parameter_reads") or {}).get("with_default")
        or (entry.get("parameter_reads") or {}).get("guarded")
    )
    gcp_no_parameter = sum(1 for entry in gcp_inside if not entry.get("parameter_reads"))
    gcp_policies = gcp["policies_considered"] - gcp_schemas
    claims += [
        (
            r"(\d+) of the (\d+) artifacts read a parameter the template gives no default for",
            (str(gcp_schemas), str(gcp["policies_considered"])),
            "gcp: schemas",
        ),
        (
            r"(\d+) read every parameter they use through",
            (str(gcp_complete),),
            "gcp: templates complete by their own defaults",
        ),
        (
            r"(\d+) read no parameter; and (\d+) read the clock",
            (str(gcp_no_parameter), str(gcp_clock)),
            "gcp: templates reading no parameter, and the clock",
        ),
        (
            r"Over the (\d+) Config Validator artifacts that are policies, (\d+) are inside, "
            r"or (\d+\.\d)\\%",
            (
                str(gcp_policies),
                str(gcp["counts"]["inside"]),
                _pct(gcp["counts"]["inside"] / gcp_policies),
            ),
            "gcp: share over artifacts that are policies",
        ),
        (
            r"instantiating every one of the (\d+)",
            (str(gcp_schemas),),
            "gcp: schemas with a sample constraint",
        ),
        (
            r"all (\d+) Config Validator templates a sample Constraint",
            (str(gcp_schemas),),
            "gcp: schemas restated in the taxonomy discussion",
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

    taxonomy = _load(docs, "exclusion-taxonomy-v1")
    kinds = taxonomy["exclusions_by_kind"]
    assert taxonomy["taxonomy_is_exhaustive"], taxonomy["exclusions_unclassified"]
    schemas = kinds["not a policy"]
    lookups = kinds["the subject does not determine the guard"]
    evaluation_time = kinds["reads evaluation-time state"]
    exclusions = taxonomy["exclusions"]
    policies = taxonomy["policies_considered"]
    artifacts = taxonomy["artifacts_considered"]
    inside = taxonomy["artifacts_inside"]

    def share(part: int) -> str:
        return f"{100 * part / exclusions:.1f}"

    claims += [
        (
            rf"a schema awaiting parameters & ({_GROUPED}) & (\d+\.\d)\\%",
            (_grouped(schemas), share(schemas)),
            "taxonomy: schemas",
        ),
        (
            rf"subject does not determine the guard & ({_GROUPED}) & (\d+\.\d)\\%",
            (_grouped(lookups), share(lookups)),
            "taxonomy: lookups",
        ),
        (
            rf"A guard reads state that exists only at evaluation time & ({_GROUPED}) & "
            r"(\d+\.\d)\\%",
            (_grouped(evaluation_time), share(evaluation_time)),
            "taxonomy: evaluation-time state",
        ),
        (
            r"(\d+)\\% of exclusions are artifacts that are not yet policies",
            (str(round(100 * schemas / exclusions)),),
            "taxonomy: schema share restated in prose",
        ),
        (
            rf"of the ({_GROUPED}) that are policies, ({_GROUPED}) lie inside: (\d+\.\d)\\%",
            (_grouped(policies), _grouped(inside), _pct(inside / policies)),
            "abstract: policies inside",
        ),
        (
            rf"met by ({_GROUPED}) of the ({_GROUPED}) published policies",
            (_grouped(inside), _grouped(policies)),
            "conclusion: policies inside",
        ),
        (
            r"(\d+)\\% is not policy that is too expressive",
            (str(round(100 * schemas / exclusions)),),
            "conclusion: schema share",
        ),
        (
            rf"Total exclusions & ({_GROUPED}) & 100\.0\\%",
            (_grouped(exclusions),),
            "taxonomy: total exclusions",
        ),
        (
            rf"the ({_GROUPED}) exclusions across six languages",
            (_grouped(exclusions),),
            "taxonomy: total restated in prose",
        ),
        (
            rf"artifacts that are policies\}} & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & "
            rf"(\d+) & (\d+\.\d)\\%",
            (
                _grouped(policies),
                _grouped(inside),
                str(policies - inside),
                "0",
                _pct(inside / policies),
            ),
            "membership table: the policies row",
        ),
        (
            rf"policy schemas, not policies\}} & ({_GROUPED}) &",
            (_grouped(schemas),),
            "membership table: the schemas row",
        ),
        (
            rf"({_GROUPED}) artifacts, none left undetermined --- ({_GROUPED}) turn out",
            (_grouped(artifacts), _grouped(schemas)),
            "abstract: corpus size and schemas",
        ),
    ]

    cost = _load(docs, "coverage-cost-v1")
    azure_cost, iam_cost = cost["azure"], cost["iam"]
    claims += [
        (
            rf"two guards and at most ({_GROUPED}) cells",
            (_grouped(azure_cost["median_cells"]),),
            "coverage cost: azure median cells",
        ),
        (
            rf"the median is ({_GROUPED}) cells",
            (_grouped(iam_cost["median_cells"]),),
            "coverage cost: iam median cells",
        ),
        (
            r"(\d+\.\d)\\% of them need at most eight",
            (f"{100 * azure_cost['share_at_most']['8']:.1f}",),
            "coverage cost: azure share at most eight",
        ),
        (
            rf"and (\d+) of ({_GROUPED}) have a quotient too large",
            (
                str(azure_cost["at_or_above_intractable"]),
                _grouped(azure_cost["policies"]),
            ),
            "coverage cost: azure intractable",
        ),
        (
            rf"(\d+\.\d)\\% need at most 64, with (\d+) of ({_GROUPED}) out of reach",
            (
                f"{100 * iam_cost['share_at_most']['64']:.1f}",
                str(iam_cost["at_or_above_intractable"]),
                _grouped(iam_cost["policies"]),
            ),
            "coverage cost: iam share and intractable",
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

    rego_oracle = _load(docs, "oracle-rego-v1")
    interpreter = _load(docs, "interpreter-oracle-v1")
    assert rego_oracle["disagreements"] == 0 and interpreter["disagreements"] == []
    dynamic_inside = sum(entry["inside_modules_checked"] for entry in rego_oracle["dynamic"])
    dynamic_tests = sum(entry["tests_compared"] for entry in rego_oracle["dynamic"])
    claims += [
        (
            r"dependency analysis on all (\d+) Rego modules",
            (str(rego_oracle["modules"]),),
            "oracle: modules the engine was asked about (abstract)",
        ),
        (
            r"agree on every one of the (\d+) modules",
            (str(rego_oracle["modules"]),),
            "oracle: modules the engine was asked about",
        ),
        (
            r"(\d+) templates with a suite of their own that we call inside, (\d+) tests",
            (str(dynamic_inside), str(dynamic_tests)),
            "oracle: templates and tests run under injected data",
        ),
        (
            rf"({_GROUPED}) class\s*witnesses and ({_GROUPED}) sampled subjects",
            (_grouped(interpreter["cells_checked"]), _grouped(interpreter["subjects_checked"])),
            "interpreter oracle: witnesses and subjects",
        ),
        (
            r"over (\d+) policies\s*--- the shipped one, a richer variant and (\d+) generated",
            (str(interpreter["policies_checked"]), str(interpreter["generated_policies"])),
            "interpreter oracle: policies",
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
    for stem in (
        "fragment-membership-xacml-wide-v1",
        "fragment-membership-kyverno-wide-v1",
        "fragment-membership-cedar-wide-v1",
        "fragment-membership-rego-wide-v1",
        "fragment-membership-rego-gcp-v1",
        "fragment-membership-iam-wide-v1",
        "fragment-membership-azure-wide-v1",
    ):
        findings = _load(docs, stem)
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
