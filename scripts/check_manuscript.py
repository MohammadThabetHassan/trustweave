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
import importlib.util
import json
import os
import re
import statistics
from collections import Counter
from decimal import ROUND_HALF_UP, Decimal
from fractions import Fraction
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

# The four-corpus Rego row mixes the engine project's own libraries with third-party ones,
# and the paper's external-validity claim turns on the split, so the split is derived from
# the artifact rather than asserted in prose.
_ENGINE_AUTHORED_REGO = frozenset({"gatekeeper-library", "opa-library"})

# A spelled-out count, for pins on prose that writes small numbers as words.
_WORD_PATTERN = r"[a-z]+"


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


def _share(numerator: int, denominator: int) -> str:
    """A percentage of two counts, rounded once and half up, as a reader dividing them would.

    An artifact's stored score is already rounded, and rounding it again can move the last
    digit (15/19 is 78.9%, its stored 0.7895 prints 79.0), so a table of counts is checked
    against the counts.
    """

    value = Fraction(100 * numerator, denominator)
    exact = Decimal(value.numerator) / Decimal(value.denominator)
    return str(exact.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


_WORDS = (
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
)


def _word(value: int) -> str:
    """A small count as the paper spells it. Prose numbers drift like printed ones."""

    return _WORDS[value]


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


def _evaluation_time_rows(docs: Path) -> list[tuple[str, dict]]:
    """Every exclusion the taxonomy counts in its evaluation-time row, with its corpus."""

    module = _taxonomy()
    found: list[tuple[str, dict]] = []
    for label, stem in module.CORPORA:
        artifact = json.loads((docs / f"{stem}.json").read_text(encoding="utf-8"))
        for entry in artifact["policies"]:
            if entry["verdict"] != "outside":
                continue
            if module.kind_of(entry) == "reads evaluation-time state":
                found.append((label, entry))
    return found


def _reads(entry: dict, *needles: str) -> bool:
    blob = json.dumps(entry).lower()
    return any(needle in blob for needle in needles)


def clock_readers(docs: Path) -> int:
    return sum(
        1
        for _, entry in _evaluation_time_rows(docs)
        if _reads(entry, "utcnow", "current-time", "current-date", "time.now_ns")
    )


def clock_languages(docs: Path) -> int:
    return len(
        {
            label
            for label, entry in _evaluation_time_rows(docs)
            if _reads(entry, "utcnow", "current-time", "current-date", "time.now_ns")
        }
    )


def network_readers(docs: Path) -> int:
    return sum(
        1 for _, entry in _evaluation_time_rows(docs) if _reads(entry, "http.send", "lookup_ip")
    )


def _taxonomy() -> Any:
    specification = importlib.util.spec_from_file_location(
        "exclusion_taxonomy_pins", Path(__file__).resolve().parent / "exclusion_taxonomy.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


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

    # The sampling paragraph quotes the default suite's rows. Every row is exact now, and the
    # number of samples a row is exact over is read from the row rather than recomputed here.
    default = suites["default-scenarios.json"]
    mirror = suites["adversarial-scenarios.json"]
    rows = {row["sample_size"]: row for row in default["sampling"] if "method" in row}

    def _samples(size: int) -> str:
        return _grouped(int(rows[size]["method"].split()[2]))

    first_within_ten = min(
        size for size, row in rows.items() if row["share_off_by_over_10_points"] == 0.0
    )
    claims += [
        (
            r"Against the (\d+\.\d)\\% suite, a sample of 4",
            (_pct(default["exact_score"]),),
            "sampling: the suite the paragraph samples",
        ),
        (
            r"non-equivalent mutants is off by (\d+) points on average",
            (f"{100 * rows[4]['mean_absolute_error']:.0f}",),
            "sampling: mean error of a sample of four",
        ),
        (
            r"by more than ten points in (every) sample",
            ("every" if rows[4]["share_off_by_over_10_points"] == 1.0 else "not every",),
            "sampling: every sample of four is more than ten points off",
        ),
        (
            rf"at 12 it exceeds ten points in (\d+\.\d)\\% of the ({_GROUPED}) samples",
            (_pct(rows[12]["share_off_by_over_10_points"]), _samples(12)),
            "sampling: exceedance share of a sample of twelve",
        ),
        (
            r"only at (\d+) of (\d+) does it reliably come within ten",
            (str(first_within_ten), str(default["mutants_live"])),
            "sampling: the first sample size never ten points off",
        ),
        (
            rf"The worst sample of eight is off by (\d+\.\d) points: it kills none of the eight, "
            rf"occurs with probability \$1/({_GROUPED})\$",
            (f"{100 * rows[8]['worst_absolute_error']:.1f}", _samples(8)),
            "sampling: the exact worst case of a sample of eight",
        ),
        (
            rf"exhaustive enumeration of all ({_GROUPED}) and ({_GROUPED}) samples",
            (_samples(8), _samples(12)),
            "sampling: the formerly simulated rows, checked by enumeration",
        ),
        (
            r"and its (\d+\.\d)\\% mirror image",
            (_pct(mirror["exact_score"]),),
            "sampling: the mirror-image suite",
        ),
    ]
    # The mirror-image claim is a claim about every row, so it is checked as one.
    assert default["sampling"] == mirror["sampling"], (
        "the default and adversarial suites no longer report identical sampling rows"
    )

    # One entry per row of the membership table, keyed by the label the paper prints.
    # The table carries an author column, so a row is
    #   <label> [\cite{...}] & <author> & <artifacts> & <inside> & <outside> & <und> & <share>
    TABLE_ROWS = (
        ("Azure Policy repository", "fragment-membership-azure-wide-v1"),
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
    # A template can be a schema and also read the inventory. The reported reason is the one
    # an assignment does not remove, so `schemas` counts fewer templates than are schemas;
    # both numbers appear in the paper and each is pinned to the one it means.
    schema_reasons = [
        entry
        for entry in rego_outside
        if any("policy schema" in reason for reason in (entry.get("reasons") or [entry["reason"]]))
    ]
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
    # The taxonomy counts a schema as not a policy whatever else is true of it, so the
    # denominator here is the count over every obstruction and not over the reported reason.
    policies = rego["policies_considered"] - len(schema_reasons)
    defaults_some = sum(
        1 for entry in schema_reasons if (entry.get("parameter_reads") or {}).get("with_default")
    )
    rego_doubly = [
        entry
        for entry in rego_outside
        if len(entry.get("reasons") or []) > 1
        and any("policy schema" in reason for reason in entry["reasons"])
    ]
    rego_sources = Counter(entry["subject"].split("/")[0] for entry in rego["policies"])
    rego_third_party = sum(
        count for name, count in rego_sources.items() if name not in _ENGINE_AUTHORED_REGO
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
            (str(len(schema_reasons)),),
            "rego: policy schemas, counted over every obstruction",
        ),
        (
            r"parameters for all (\d+)",
            (str(len(schema_reasons)),),
            "rego: schemas with an instantiating constraint",
        ),
        (
            rf"(\d+) of the {len(schema_reasons)} do for some parameter",
            (str(defaults_some),),
            "rego: schemas that default some parameter but not all",
        ),
        (
            r"In this sense (\d+) templates are schemas; (\w+) of them also",
            (str(len(schema_reasons)), _word(len(rego_doubly))),
            "rego: schemas that are also reported under a stronger reason",
        ),
        (
            r"(\d+) of the (\d+) four-corpus Rego modules \((\d+) from the Red Hat Community of "
            r"Practice, (\d+) from Instrumenta\)",
            (
                str(rego_third_party),
                str(rego["policies_considered"]),
                str(rego_sources["redhat-cop-rego-policies"]),
                str(rego_sources["instrumenta-policies"]),
            ),
            "rego: third-party modules in the four-corpus row",
        ),
        (
            r"Over the (\d+)\s*artifacts that are policies, (\d+) are inside, or (\d+\.\d)\\%",
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
    # The taxonomy counts a schema as not a policy whatever else is true of it, so this has to
    # read every reason and not just the reported one. Reading `reason` alone counted 31 where
    # `exclusion_taxonomy.kind_of()` counts 33 -- the two templates that are schemas and also
    # read the clock -- so the guard pinned the paragraph to one convention and the taxonomy
    # total in the same run to the other.
    gcp_schemas = sum(
        any("policy schema" in reason for reason in (entry.get("reasons") or [entry["reason"]]))
        for entry in gcp["policies"]
    )
    # The instantiation claim is narrower than the schema count and has to stay pinned to its
    # own set: it was checked against the templates whose only obstruction is the missing
    # binding, and a sample Constraint would not rescue the two that also read the clock.
    gcp_schemas_reported = sum("policy schema" in entry["reason"] for entry in gcp["policies"])
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
            (str(gcp_schemas_reported),),
            "gcp: schemas with a sample constraint",
        ),
        (
            r"all (\d+) Config Validator templates a sample Constraint",
            (str(gcp_schemas_reported),),
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

    # Azure carries the largest corpus and the paragraph explaining it carries the most
    # unpinned arithmetic in the paper, which is where 2{,}721 and 1{,}924 survived a
    # re-measurement that moved them.
    azure = _load(docs, "fragment-membership-azure-wide-v1")
    azure_rows = azure["policies"]
    azure_outside = [entry for entry in azure_rows if entry["verdict"] == "outside"]
    azure_external = sum(
        "runtime state of a resource" in entry["reason"] for entry in azure_outside
    )
    azure_nondeterministic = sum(
        "not a function of its arguments" in entry["reason"] for entry in azure_outside
    )
    azure_schemas = sum("policy schema" in entry["reason"] for entry in azure_outside)
    azure_parameterised = sum(1 for entry in azure_rows if entry.get("parameters_declared"))
    azure_undefaulted = sum(1 for entry in azure_rows if entry.get("parameters_without_defaults"))
    azure_related = [
        entry for entry in azure_outside if "related resource exists" in entry["reason"]
    ]
    # The caption counts exclusions, so it counts the schema obstruction among the artifacts
    # the procedure judged; `azure_undefaulted` counts every definition carrying it, judged
    # or not, and the two differ by the definitions whose guard is a program elsewhere.
    azure_outside_schemas = sum(
        1 for entry in azure_outside if entry.get("parameters_without_defaults")
    )
    azure_outside_both = sum(
        1
        for entry in azure_outside
        if entry.get("parameters_without_defaults") and "related resource exists" in entry["reason"]
    )
    azure_with_condition = sum(
        1
        for entry in azure_related
        if (entry.get("related_resource") or {}).get("has_existence_condition")
    )
    claims += [
        (
            r"Only (\d+) definitions read one of these from a guard\s*region",
            (str(azure_external),),
            "azure: definitions reading state outside the resource from a guard",
        ),
        (
            r"Another (\w+) definitions are excluded for something that is not a read",
            (_word(azure_nondeterministic),),
            "azure: definitions calling a nondeterministic function",
        ),
        (
            r"The interesting part is the other (\d+)",
            (str(azure_schemas),),
            "azure: definitions reported as schemas",
        ),
        (
            rf"({_GROUPED}) definitions decide this way",
            (_grouped(len(azure_related)),),
            "azure: definitions deciding on a related resource",
        ),
        (
            r"Azure row reads (\d+\.\d)\\% rather than the 76\.5\\% we first reported",
            (_pct(azure["counts"]["inside"] / azure["policies_considered"]),),
            "azure: the row's share after the guard regions were corrected",
        ),
        (
            rf"the existence condition, which decides ({_GROUPED})\s*definitions",
            (_grouped(azure_with_condition),),
            "azure: definitions with an existence condition",
        ),
        (
            r"Only (\d+) of them are reported as schemas, because (\d+) also",
            (str(azure_schemas), str(azure_undefaulted - azure_schemas)),
            "azure: schemas reported as such, and those reported under the existence test",
        ),
        (
            rf"({_GROUPED}) of\s*these definitions are parameterised and ({_GROUPED}) of them "
            rf"are complete in that sense",
            (
                _grouped(azure_parameterised),
                _grouped(azure_parameterised - azure_undefaulted),
            ),
            "azure: parameterised and complete by their own defaults",
        ),
        (
            r"other (\d+) are not, and the (\d+) of them the procedure could judge",
            (str(azure_undefaulted), str(azure_outside_schemas)),
            "azure: definitions awaiting an assignment, and those it could judge",
        ),
        (
            r"moved this row by (\d+) definitions when a second guard region",
            (str(azure_undefaulted - azure_schemas),),
            "azure: how far counting by the reported reason would move the row",
        ),
        (
            rf"({_GROUPED}) of its ({_GROUPED}) exclusions test whether a related resource\s*"
            rf"exists, ({_GROUPED}) are\s*parameterised definitions that are policy schemas "
            rf"rather than policies, and ({_GROUPED}) are both",
            (
                _grouped(len(azure_related)),
                _grouped(len(azure_outside)),
                _grouped(azure_outside_schemas),
                _grouped(azure_outside_both),
            ),
            "membership table caption: the Azure split",
        ),
    ]

    xacml_wide = _load(docs, "fragment-membership-xacml-wide-v1")
    xacml_clock = sum(
        1 for entry in xacml_wide["policies"] if "reads the clock" in entry.get("reason", "")
    )
    revalidation = _load(docs, "third-party-kyverno-revalidation-v1")
    claims += [
        (
            rf"({_GROUPED}) conformance\s*policies that read the clock were reported inside",
            (_grouped(xacml_clock),),
            "xacml: policies reading the clock",
        ),
        (
            rf"the corpus is ({_GROUPED}) documents rather than 548",
            (_grouped(xacml_wide["policies_considered"]),),
            "xacml: the corpus after selecting by root element",
        ),
        (
            rf"({_GROUPED}) policies were left out of it",
            (_grouped(xacml_wide["policies_considered"] - 548),),
            "xacml: policies the filename convention left out",
        ),
        (
            rf"reported ({_GROUPED}) of them unavailable",
            (_grouped(revalidation["supersedes"]["files_no_longer_available"]),),
            "third-party: what the superseded re-fetch reported",
        ),
        (
            rf"Re-fetched on (\d{{4}}-\d\d-\d\d) with a client that retries and records how each "
            rf"request fails, all ({_GROUPED}) hashed to their recorded digests",
            (
                revalidation["revalidated_on"],
                _grouped(revalidation["files_still_fetchable_at_their_commit"]),
            ),
            "third-party: the current re-fetch",
        ),
    ]
    # "All" is a claim about the rest, so it is checked as one.
    assert revalidation["files_no_longer_available"] == 0, revalidation["unavailable"]
    assert revalidation["verdicts_changed_among_those_refetched"] == []

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
    undetermined = sum(row["undetermined"] for row in taxonomy["rows"])

    rows = {entry["corpus"]: entry for entry in taxonomy["rows"]}
    iam_total = rows["AWS IAM"]["policies_considered"]
    iam_inside = rows["AWS IAM"]["inside"]
    azure_total = rows["Azure Policy"]["policies_considered"]
    xacml_total = rows["XACML"]["policies_considered"]

    crossed = _load(docs, "exclusion-crosstab-v1")
    combination = crossed["combinations"]
    subject_only = combination["the subject does not determine the guard"]
    subject_schema = combination["not a policy + the subject does not determine the guard"]
    clock_only = combination["reads evaluation-time state"]
    clock_schema = combination["not a policy + reads evaluation-time state"]
    schema_only = crossed["schema_only"]
    assert crossed["exclusions"] == exclusions and crossed["schemas"] == schemas
    assert subject_only == lookups and clock_only == evaluation_time
    surviving = crossed["guard_not_a_function_of_the_request"]

    claims += [
        (
            rf"A guard the subject does not determine & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED})",
            (
                _grouped(subject_only),
                _grouped(subject_schema),
                _grouped(subject_only + subject_schema),
            ),
            "cross-tabulation: a guard the subject does not determine",
        ),
        (
            rf"A guard reading evaluation-time state & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED})",
            (_grouped(clock_only), _grouped(clock_schema), _grouped(clock_only + clock_schema)),
            "cross-tabulation: evaluation-time state",
        ),
        (
            rf"Nothing but its missing parameters & --- & ({_GROUPED}) & ({_GROUPED})",
            (_grouped(schema_only), _grouped(schema_only)),
            "cross-tabulation: schemas and nothing else",
        ),
        (
            r"The (\d+) undetermined verdicts are Azure Policy definitions",
            (str(undetermined),),
            "membership: the undetermined verdicts, as the text beside the table restates them",
        ),
        (
            rf"the clock in ({_GROUPED}) policies across (\w+)\s*languages, the network in (\w+)",
            (
                _grouped(clock_readers(docs)),
                _word(clock_languages(docs)),
                _word(network_readers(docs)),
            ),
            "taxonomy: the composition of the evaluation-time row",
        ),
        (
            r"A schema-first count calls (\d+)\\% of\s*the exclusions schemas",
            (str(round(100 * schemas / exclusions)),),
            "taxonomy: the schema-first share, restated as such",
        ),
        (
            rf"eight corpora, our procedure places ({_GROUPED}) of ({_GROUPED}) artifacts inside "
            rf"\((\d+\.\d)\\%\)",
            (_grouped(inside), _grouped(artifacts), _pct(inside / artifacts)),
            "abstract: corpus size, artifacts inside",
        ),
        (
            rf"finds (?:that condition )?in ({_GROUPED}) of the ({_GROUPED})\s*published artifacts",
            (_grouped(inside), _grouped(artifacts)),
            "conclusion: artifacts inside",
        ),
        (
            rf"Total exclusions & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED})",
            (_grouped(exclusions - schemas), _grouped(schemas), _grouped(exclusions)),
            "cross-tabulation: the totals",
        ),
        (
            rf"({_GROUPED}) of (?:them|the {_GROUPED}), (\d+\.\d)\\%, have a guard the "
            r"request\s*does "
            r"not determine",
            (_grouped(surviving), _pct(surviving / exclusions)),
            "exclusions whose guard the request does not determine",
        ),
        (
            r"have a guard the request\s*does not determine, among them (\d+) of the (\d+) schemas",
            (str(subject_schema + clock_schema), str(schemas)),
            "schemas that stay outside whatever their parameters",
        ),
        (
            r"[Oo]nly (\d+)\s*are schemas that their\s*missing parameters alone keep out",
            (str(schema_only),),
            "schemas their missing parameters alone keep out",
        ),
        (
            r"(\w+) in ten,?\s*(?:exclusions|have a guard)",
            (_word(round(10 * surviving / exclusions)),),
            "the share of exclusions a guard the request does not determine accounts for",
        ),
        (
            rf"({_GROUPED}) of the ({_GROUPED}), nine in ten, have a guard the request does not "
            rf"determine, ({_GROUPED}) schemas among them",
            (_grouped(surviving), _grouped(exclusions), _grouped(subject_schema + clock_schema)),
            "cross-tabulation: its caption",
        ),
        (
            rf"less schema-only artifacts\}} & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & "
            r"(\d+) & "
            r"(\d+\.\d)\\%",
            (
                _grouped(artifacts - schema_only),
                _grouped(inside),
                _grouped(exclusions - schema_only),
                str(undetermined),
                _pct(inside / (artifacts - schema_only)),
            ),
            "membership table: less the schema-only artifacts",
        ),
        (
            rf"less every schema\}} & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & (\d+) & "
            r"(\d+\.\d)\\%",
            (
                _grouped(policies),
                _grouped(inside),
                _grouped(exclusions - schemas),
                str(undetermined),
                _pct(inside / policies),
            ),
            "membership table: less every schema",
        ),
        (
            rf"the ({_GROUPED}) exclusions across six languages",
            (_grouped(exclusions),),
            "taxonomy: total restated in prose",
        ),
        # The contributions list restates the headline in a different phrasing, which is how
        # it came to disagree with the abstract while every pin still passed: the pin
        # anchored on the abstract's wording and never reached this sentence.
        (
            rf"eight corpora: ({_GROUPED}) artifacts, (\d+) of which it declines to judge,\s*"
            rf"and ({_GROUPED}) inside",
            (_grouped(artifacts), str(undetermined), _grouped(inside)),
            "contributions: corpus, refusals and inside",
        ),
        (
            rf"of the ({_GROUPED}) artifacts outside the fragment,\s*({_GROUPED}) have a guard the "
            rf"request does not determine, and the other ({_GROUPED})",
            (_grouped(exclusions), _grouped(surviving), _grouped(schema_only)),
            "contributions: the exclusions crossed",
        ),
        (
            rf"none of these ({_GROUPED}) exclusions refutes it",
            (_grouped(exclusions),),
            "membership: exclusions restated where exhaustiveness is qualified",
        ),
        (
            r"IAM is (\d+\.\d)\\%\s*of the pooled artifacts and (\d+\.\d)\\% of the "
            r"artifacts that are policies",
            (_pct(iam_inside / artifacts), _pct(iam_inside / policies)),
            "IAM's share of the pool",
        ),
        (
            r"pooled share is (\d+\.\d)\\% of artifacts and (\d+\.\d)\\% of policies",
            (
                _pct((inside - iam_inside) / (artifacts - iam_total)),
                _pct((inside - iam_inside) / (policies - iam_total)),
            ),
            "the pooled share with IAM removed",
        ),
        (
            r"the pooled (\d+\.\d)\\% inherits that skew",
            (_pct((inside - iam_inside) / (artifacts - iam_total)),),
            "threats: the pooled share restated",
        ),
        (
            r"left after IAM and Azure, (\d+\.\d)\\% are XACML",
            (_pct(xacml_total / (artifacts - iam_total - azure_total)),),
            "threats: XACML's share of the remainder",
        ),
        (
            rf"Four of the ({_WORD_PATTERN}) corpora",
            (_word(len(taxonomy["rows"])),),
            "how many corpora there are, wherever the count is restated",
        ),
        (
            r"together they are (\d+)\\% of the corpus",
            (str(round(100 * (iam_total + azure_total) / artifacts)),),
            "the two cloud corpora as a share of the pool",
        ),
        (
            rf"({_GROUPED}) of the ({_GROUPED}) Azure Policy definitions the measurement\s*"
            rf"counts as policies",
            (
                _grouped(rows["Azure Policy"]["inside"]),
                _grouped(
                    rows["Azure Policy"]["policies_considered"]
                    - rows["Azure Policy"]["exclusions_by_kind"].get("not a policy", 0)
                ),
            ),
            "conclusion: the Azure definitions that are policies",
        ),
        (
            rf"The ({_WORD_PATTERN}) per-corpus shares are the",
            (_word(len(taxonomy["rows"])),),
            "threats: how many per-corpus shares there are",
        ),
    ]

    # No coverage-cost claims are pinned. `docs/coverage-cost-v1.json` carries an
    # `invalidated` block: its distribution rested on a guard grouping that under-counted
    # set-membership operators, so a guard that held the manuscript to those numbers would be
    # certifying a withdrawn measurement rather than checking one.

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
        (
            r"the criterion agrees with the solver on all (\d+) cases",
            (str(witness["cases_where_the_criterion_agrees_with_the_solver"]),),
            "witness criterion: cases agreeing with the solver",
        ),
    ]

    kyverno_oracle = _load(docs, "oracle-kyverno-v1")
    assert kyverno_oracle["disagreements"] == 0
    kyverno_dynamic = kyverno_oracle["dynamic"]
    claims += [
        (
            r"every one of the (\d+)\s*policies in Table~\\ref\{tab:membership\}'s Kyverno row",
            (str(kyverno_oracle["policies"]),),
            "kyverno oracle: policies judged",
        ),
        (
            rf"identical\s*outcomes: all (\d+) do, over ({_GROUPED}) tests",
            (
                str(kyverno_dynamic["inside_policies_invariant_under_injected_labels"]),
                _grouped(kyverno_dynamic["tests_compared"]),
            ),
            "kyverno oracle: inside policies invariant and tests compared",
        ),
        (
            r"for the (\d+) outside policies whose suites stub\s*external data",
            (str(kyverno_oracle["static"]["outside_policies_whose_suite_stubs_external_data"]),),
            "kyverno oracle: outside policies with stubs",
        ),
        (
            r"stubs kept: (\d+) change outcome, .*? and (\d+) do not",
            (
                str(
                    kyverno_dynamic[
                        "outside_policies_whose_outcomes_changed_when_stubs_were_removed"
                    ]
                ),
                str(kyverno_dynamic["outside_policies_unchanged_when_stubs_were_removed"]),
            ),
            "kyverno oracle: outside policies changed and unchanged under stub removal",
        ),
        (
            r"disagrees with the adapter on none of the (\d+)\.",
            (str(kyverno_oracle["policies"]),),
            "kyverno oracle: no disagreement",
        ),
    ]

    rego_oracle = _load(docs, "oracle-rego-v1")
    initiatives = _load(docs, "azure-initiative-bindings-v1")
    claims += [
        (
            r"(\d+) of the (\d+) Azure definitions with an\s*undefaulted parameter are "
            r"included in\s*a built-in initiative that binds every parameter they left "
            r"without a default",
            (
                str(initiatives["schemas_an_initiative_completes"]),
                str(initiatives["schemas"]),
            ),
            "azure: schemas an initiative instantiates completely",
        ),
        (
            r"The remaining (\d+) Azure schemas are in no initiative",
            (str(len(initiatives["schemas_left_uninstantiated"])),),
            "azure: schemas no initiative binds",
        ),
    ]

    provenance = _load(docs, "corpus-provenance-verification-v1")
    claims += [
        (
            r"reproduces all (\d+) of them\. The (\w+) it does not check",
            (str(provenance["reproduced"]), _word(provenance["artifacts"] - provenance["checked"])),
            "provenance: corpora re-measured and corpora not checked",
        ),
    ]

    interpreter = _load(docs, "interpreter-oracle-v1")
    interpreter["skipped"] = interpreter["generated_skipped_as_too_large"]
    assert rego_oracle["disagreements"] == 0 and interpreter["disagreements"] == []
    dynamic_inside = sum(entry["inside_modules_checked"] for entry in rego_oracle["dynamic"])
    dynamic_tests = sum(entry["tests_compared"] for entry in rego_oracle["dynamic"])
    claims += [
        (
            r"consistent on every one of the (\d+) modules",
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
        (
            rf"at ({_GROUPED}) classes one candidate of (\d+) was\s*skipped, at a quotient of "
            rf"({_GROUPED}), and the largest quotient actually decided twice has\s*"
            rf"({_GROUPED}) classes",
            (
                _grouped(interpreter["max_cells"]),
                str(interpreter["generated_policies"] + interpreter["skipped"]),
                _grouped(interpreter["smallest_quotient_skipped"]),
                _grouped(interpreter["largest_quotient_checked"]),
            ),
            "interpreter oracle: the cap and what it excludes",
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

    # The Kyverno harness caps the mutants it runs per policy, and the cap shapes the score.
    kyverno_run = _load(docs, "kyverno-mutation-v1")
    attempted = [
        entry["mutants_applied"] + entry.get("mutants_unrunnable", 0)
        for entry in kyverno_run["detail"]
    ]
    cap = max(attempted)
    claims.append(
        (
            rf"over at most ({_WORD_PATTERN}) mutants: the harness keeps the first "
            rf"({_WORD_PATTERN}) a policy "
            rf"yields, in line order, which is its default, and (\d+) of the (\d+) scored "
            rf"policies are at that cap",
            (_word(cap), _word(cap), str(attempted.count(cap)), str(len(attempted))),
            "kyverno mutation: the per-policy cap and how many policies reach it",
        )
    )
    claims.append(
        (
            rf"each score is over at most ({_WORD_PATTERN}) mutants, so for the (\d+) of "
            rf"(\d+) policies at that cap",
            (_word(cap), str(attempted.count(cap)), str(len(attempted))),
            "kyverno mutation: the cap, as the threats section restates it",
        )
    )

    # The Cedar archive is quoted in four sections and was pinned in none of them, which is
    # how a count that 651 annotation keys, keywords and string fragments had inflated went
    # unchecked through every one.
    archive = _load(docs, "fragment-membership-cedar-archive-v1")
    loose = _load(docs, "fragment-membership-cedar-wide-v1")
    held = _grouped(archive["policies_considered"])
    declined = _grouped(archive["counts"]["undetermined"])
    claims += [
        (
            rf"declines ({_GROUPED}) of ({_GROUPED}) policies rather than judging them",
            (declined, held),
            "cedar archive: declined, where the row's summary is qualified",
        ),
        (
            rf"returns undetermined on ({_GROUPED}) of the ({_GROUPED}) policies it holds",
            (declined, held),
            "cedar archive: declined, beside the undetermined column",
        ),
        (
            rf"over the ({_GROUPED}) Cedar policies the same repository seals in an archive "
            rf"\(Section~\\ref\{{sec:threats\}}\) the same adapter returns undetermined "
            rf"({_GROUPED}) times",
            (held, declined),
            "cedar archive: declined, in the caveat on the 100% rows",
        ),
        (
            rf"holding ({_GROUPED}) more\.",
            (held,),
            "cedar archive: policies the archive holds",
        ),
        (
            rf"over the archive gives ({_GROUPED}) inside, ({_GROUPED}) undetermined and "
            rf"({_GROUPED}) outside",
            (
                _grouped(archive["counts"]["inside"]),
                declined,
                _grouped(archive["counts"]["outside"]),
            ),
            "cedar archive: the three counts",
        ),
        (
            rf"Over the archive it fires ({_GROUPED}) times",
            (declined,),
            "cedar archive: refusals, every one an operator",
        ),
        (
            rf"stand silently for a ({_GROUPED})-file corpus",
            (_grouped(archive["policies_considered"] + loose["policies_considered"]),),
            "cedar: the loose files and the archive together",
        ),
        (
            rf"the ({_GROUPED}) policies in its sealed archive",
            (held,),
            "cedar archive: policies held, as the membership section restates it",
        ),
    ]

    claims += _payoff_claims(docs)
    claims += _review_claims(docs)
    claims += _third_party_claims(docs)
    claims += _summary_claims(docs)
    claims += _cedar_claims(docs)
    claims += _sample_oracle_claims(docs)
    claims += _rego_suite_claims(docs)
    claims += _rego_exact_claims(docs)
    claims += _rego_payoff_claims(docs)
    claims += _rego_schemas_claims(docs)
    claims += _rego_real_faults_claims(docs)
    claims += _cedar_symcc_claims(docs)
    claims += _xacml_criteria_claims(docs)
    claims += _round2_claims(docs)
    return claims


def _rego_exact_claims(docs: Path) -> list[Claim]:
    """The Gatekeeper suites decided exactly, and the stillborn kills of the suite study."""

    exact = _load(docs, "rego-exact-adequacy-v1")
    census = _load(docs, "rego-suite-stillborn-v1")["headline"]
    realism = _load(docs, "rego-exact-gaps-v1")["headline"]
    suite = _load(docs, "rego-suite-adequacy-v1")
    head = exact["headline"]
    development = exact["development_module"]
    measured = {
        s: r
        for s, r in exact["modules"].items()
        if r.get("status") == "measured" and s != development
    }
    statuses = [r["status"] for s, r in exact["modules"].items() if s != development]
    over_cap = sorted(
        (int(status.rsplit(" ", 2)[-2]), subject)
        for subject, status in ((s, r["status"]) for s, r in exact["modules"].items())
        if status.startswith("excluded: an object with")
    )
    missing = sum(status == "excluded: missing cell" for status in statuses)
    coverage = statistics.fmean(suite["modules"][s]["coverage"] / 100 for s in measured)
    exact_mean = statistics.fmean(r["exact_score"] for r in measured.values())
    raw_mean = statistics.fmean(r["raw_score"] for r in measured.values())
    outright = sum(
        r["suite_equivalent"] for r in measured.values() if r["instantiations"] == ["absent"]
    )
    ephemeral = [
        s
        for s, r in measured.items()
        if any(
            g["detail"] == "remove rule input_containers"
            and "ephemeralContainers" in g["kill_input"]["review"].get("object", {}).get("spec", {})
            for g in r["survivors"]
        )
    ]
    imagedigests = next(r for s, r in measured.items() if "/imagedigests/" in s)
    # The prose rounds three fractions; each is checked against the artifact here.
    assert abs(head["share_of_survivors_equivalent"] - 2 / 3) < 0.01, "no longer two thirds"
    assert 0.70 < 1 - (coverage - exact_mean) / (coverage - raw_mean) < 0.80, (
        "the equivalent share of the coverage gap is no longer three quarters"
    )
    # "kill every distinguishable mutant and no equivalent one"
    assert head["closing_the_gaps_holds_everywhere"]
    assert head["killed_without_a_decision_change"] == 0
    assert realism["killed_by_a_review_like_the_authors"] == realism["gaps"]
    distinguishable, killed = head["distinguishable"], head["killed_through_decision"]
    relative = head["suite_equivalent"] - outright
    worst = _share(killed, distinguishable + relative)
    claims: list[Claim] = [
        (
            r"(\d+\.\d)\\% if every equivalent in a module that reads parameters could be "
            r"separated by a setting no test uses",
            (worst,),
            "rego exact study: the score if the parameter-relative equivalents were separable",
        ),
        (
            r"The other (\d+) equivalents are in modules that read parameters",
            (str(relative),),
            "rego exact study: the equivalents relative to the tested settings",
        ),
        (
            r"so the range is \$\[(\d+\.\d), (\d+\.\d)\]\$",
            (worst, _share(killed, distinguishable)),
            "rego exact study: the range of the exact score",
        ),
        (
            r"the suites are between (\d+\.\d)\\% and (\d+\.\d)\\% adequate, not (\d+\.\d)\\%",
            (worst, _pct(head["pooled_exact_score"]), _pct(head["pooled_raw_score"])),
            "rego exact study: the abstract",
        ),
        (
            r"and by (\d+\.\d) against exact\s+adequacy on the (\d+) suites a further protocol "
            r"decides",
            (_pct(coverage - exact_mean), str(head["modules"])),
            "rego exact study: the contribution",
        ),
        (
            r"each of the other (\d+) comes with the input that kills it",
            (str(head["survivors_real"]),),
            "rego exact study: the real gaps, as the contribution states them",
        ),
        (
            rf"(\d+) of the ({_GROUPED}) do not compile",
            (str(census["stillborn"]), _grouped(census["mutants"])),
            "rego suite study: the stillborn kills",
        ),
        (
            r"over the mutants that load the suites kill (\d+\.\d)\\% in the mean",
            (_pct(census["mean_score_over_mutants_that_load"]),),
            "rego suite study: the kill rate over the mutants that load",
        ),
        (
            r"(\d+) of these (\d+) modules are inside (?:it|the fragment)",
            (
                str(exact["population"]["modules"]),
                str(suite["population"]["modules_with_a_suite_and_a_decision"]),
            ),
            "rego exact study: the population inside the fragment",
        ),
        (
            rf"(\d+) of the (\d+) pass; ({_WORD_PATTERN}) exceed the cap of ({_GROUPED}) cells, "
            rf"and in ({_WORD_PATTERN}) the check found an input no cell covers",
            (
                str(head["modules"]),
                str(len(statuses)),
                _word(len(over_cap)),
                _grouped(exact["max_cells"]),
                _word(missing),
            ),
            "rego exact study: the modules measured and excluded",
        ),
        (
            r"On the (\d+), (\d+) of the (\d+) mutants the suites leave alive are equivalent to "
            r"their module under every instantiation the suite tests, (\d+) of them outright",
            (
                str(head["modules"]),
                str(head["survivors_equivalent"]),
                str(head["survivors_suite_study"]),
                str(outright),
            ),
            "rego exact study: the equivalent survivors",
        ),
        (
            r"[Tt]he suites kill (\d+) of the (\d+) distinguishable mutants[:,] an exact score of "
            r"(\d+\.\d)\\% pooled against a raw (\d+\.\d)\\%",
            (
                str(head["killed_through_decision"]),
                str(head["distinguishable"]),
                _pct(head["pooled_exact_score"]),
                _pct(head["pooled_raw_score"]),
            ),
            "rego exact study: the pooled exact score",
        ),
        (
            r"\((\d+\.\d)\\% over the (\d+) that compile, so the whole gain is the equivalent "
            r"mutants\)",
            (
                _pct(
                    (head["killed"] - head["killed_stillborn"])
                    / (head["mutants"] - head["stillborn"])
                ),
                str(head["mutants"] - head["stillborn"]),
            ),
            "rego exact study: the raw score over the mutants that compile",
        ),
        (
            r"and (\d+\.\d)\\% against (\d+\.\d)\\% in the mean, a difference of (\d+\.\d) points "
            r"with a 95\\% bootstrap interval of \$\[(\d+\.\d), (\d+\.\d)\]\$",
            (
                _pct(head["mean_exact_score"]),
                _pct(head["mean_raw_score"]),
                _pct(head["mean_difference"]),
                _pct(head["difference_bootstrap_95"][0]),
                _pct(head["difference_bootstrap_95"][1]),
            ),
            "rego exact study: the mean exact score",
        ),
        (
            r"Line coverage, at (\d+\.\d)\\% on the same modules, overstates exact adequacy by "
            r"(\d+\.\d) points, not (\d+\.\d)",
            (_pct(coverage), _pct(coverage - exact_mean), _pct(coverage - raw_mean)),
            "rego exact study: line coverage against exact adequacy",
        ),
        (
            r"overstates exact adequacy by (\d+\.\d) points, not (\d+\.\d)",
            (_pct(coverage - exact_mean), _pct(coverage - raw_mean)),
            "rego exact study: line coverage against exact adequacy, restated",
        ),
        (
            r"Each of the (\d+) surviving mutants that are not equivalent comes with an input that "
            r"kills it, and the (\d+) inputs, added as tests, kill every distinguishable mutant",
            (str(head["survivors_real"]), str(head["survivors_real"])),
            "rego exact study: closing the gaps",
        ),
        (
            rf"in ({_WORD_PATTERN}) of the (\d+) suites, deleting the branch that reads ephemeral "
            r"containers goes undetected",
            (_word(len(ephemeral)), str(head["modules"])),
            "rego exact study: the ephemeral-container gap",
        ),
        (
            rf"all ({_WORD_PATTERN}) survivors of \\texttt\{{imagedigests\}} edit its rule for "
            r"ephemeral containers",
            (_word(len(imagedigests["survivors"])),),
            "rego exact study: the image-digest gaps",
        ),
        (
            r"found each of the (\d+) killed by a review whose every field occurs in the "
            r"authors' own inputs",
            (str(realism["gaps"]),),
            "rego exact study: the gaps a realistic review exposes",
        ),
        (
            r"each of the (\d+) gaps it reports is also killed by a review shaped like the "
            r"authors' own",
            (str(realism["gaps"]),),
            "rego exact study: the realistic gaps, as the threats restate them",
        ),
        (
            rf"\\texttt\{{host-filesystem\}} at ({_GROUPED})",
            (_grouped(over_cap[0][0]),),
            "rego exact study: the smallest space over the cap",
        ),
        (
            rf"finds (\d+) of the ({_GROUPED}) that do not, all among its kills: over the mutants "
            r"that load, the suites kill (\d+\.\d)\\% in the mean rather than (\d+\.\d)\\%, and "
            r"the gap to line coverage is (\d+\.\d) points rather than (\d+\.\d)",
            (
                str(census["stillborn"]),
                _grouped(census["mutants"]),
                _pct(census["mean_score_over_mutants_that_load"]),
                _pct(census["mean_raw_score"]),
                _pct(census["mean_coverage_gap_over_mutants_that_load"]),
                _pct(suite["headline"]["mean_gap"]),
            ),
            "rego suite study: the stillborn census",
        ),
    ]
    for subject, record in sorted(measured.items()):
        name = subject.split("/")[-2].replace("-", "\\allowbreak-")
        claims.append(
            (
                rf"\\texttt\{{{re.escape(name)}\}} & (\d+) & (\d+) & (\d+) & (\d+) & (\d+) & "
                r"(\d+\.\d) & (\d+\.\d) & (\d+)",
                (
                    str(record["mutants"]),
                    str(record["stillborn"]),
                    str(record["suite_equivalent"]),
                    str(record["distinguishable"]),
                    str(record["killed_through_decision"]),
                    _share(record["killed"], record["mutants"]),
                    _share(record["killed_through_decision"], record["distinguishable"]),
                    str(len(record["survivors"])),
                ),
                f"rego exact study: the row for {subject.split('/')[-2]}",
            )
        )
    claims.append(
        (
            r"(\d+) modules & (\d+) & (\d+) & (\d+) & (\d+) & (\d+) & "
            r"(\d+\.\d) & (\d+\.\d) & (\d+)",
            (
                str(head["modules"]),
                str(head["mutants"]),
                str(head["stillborn"]),
                str(head["suite_equivalent"]),
                str(head["distinguishable"]),
                str(head["killed_through_decision"]),
                _pct(head["pooled_raw_score"]),
                _pct(head["pooled_exact_score"]),
                str(head["survivors_real"]),
            ),
            "rego exact study: the table's total",
        )
    )
    return claims


def _rego_schemas_claims(docs: Path) -> list[Claim]:
    """The policy schemas, instantiated by their suites: the exact study's secondary population.

    Its protocol has it reported beside the primary population and never pooled with it, so the
    two artifacts are read apart and the paper's comparisons between them are asserted here.
    """

    schemas = _load(docs, "rego-exact-adequacy-schemas-v1")
    primary = _load(docs, "rego-exact-adequacy-v1")
    head, population = schemas["headline"], schemas["population"]
    assert schemas["population_kind"] == "schemas"
    measured = {s: r for s, r in schemas["modules"].items() if r.get("status") == "measured"}
    over_cap = sum(
        count for status, count in population.items() if status.startswith("excluded: an object")
    )
    missing = population["excluded: missing cell"]
    assert over_cap + missing + len(measured) == population["modules"]
    # "kill every distinguishable mutant and no equivalent one"
    assert head["closing_the_gaps_holds_everywhere"]
    assert head["killed_without_a_decision_change"] == 0
    # "The weakest suite of either population is here"
    both = [
        (record["exact_score"], subject)
        for artifact in (primary, schemas)
        for subject, record in artifact["modules"].items()
        if record.get("status") == "measured" and subject != artifact["development_module"]
    ]
    weakest = measured[min(both)[1]]
    # "none outright": every schema reads its parameters, so no equivalent holds without them.
    assert not any(record["instantiations"] == ["absent"] for record in measured.values())
    compiling = head["mutants"] - head["stillborn"]
    killed_compiling = head["killed"] - head["killed_stillborn"]
    worst = _share(
        head["killed_through_decision"], head["distinguishable"] + head["suite_equivalent"]
    )
    # "the raw rate over the mutants that compile"
    assert worst == _share(killed_compiling, compiling), (worst, killed_compiling, compiling)
    names = {26: "Twenty-six"}
    low, high = head["difference_bootstrap_95"]
    claims: list[Claim] = [
        (
            r"on the (\d+) of (\d+) whose witness spaces pass, (\d+) of the (\d+) survivors are "
            r"equivalent under them, none outright, and the suites are (\d+\.\d)\\% adequate, not "
            r"(\d+\.\d)\\%",
            (
                str(head["modules"]),
                str(population["modules"]),
                str(head["survivors_equivalent"]),
                str(head["survivors_suite_study"]),
                _pct(head["pooled_exact_score"]),
                _pct(head["pooled_raw_score"]),
            ),
            "rego schemas: the main text",
        ),
        (
            r"([\w-]+) of the suite study's other modules are policy schemas",
            (names[population["modules"]],),
            "rego schemas: the population",
        ),
        (
            rf"([A-Z][a-z]+) exceed the cap, and in ({_WORD_PATTERN}) the completeness check "
            rf"found an input no cell covers",
            (_word(over_cap).capitalize(), _word(missing)),
            "rego schemas: the exclusions",
        ),
        (
            rf"so ({_WORD_PATTERN}) are measured",
            (_word(len(measured)),),
            "rego schemas: modules measured",
        ),
        (
            r"On them (\d+) of the (\d+) survivors are equivalent, and of the (\d+) "
            r"distinguishable mutants the suites kill (\d+): (\d+\.\d)\\% exactly, pooled, where "
            r"the raw rate is (\d+\.\d)\\%; in the mean, (\d+\.\d)\\% against a raw (\d+\.\d)\\%, "
            r"(\d+\.\d) points apart with a 95\\% bootstrap interval of "
            r"\$\[(\d+\.\d), (\d+\.\d)\]\$",
            (
                str(head["survivors_equivalent"]),
                str(head["survivors_suite_study"]),
                str(head["distinguishable"]),
                str(head["killed_through_decision"]),
                _pct(head["pooled_exact_score"]),
                _pct(head["pooled_raw_score"]),
                _pct(head["mean_exact_score"]),
                _pct(head["mean_raw_score"]),
                _pct(head["mean_difference"]),
                _pct(low),
                _pct(high),
            ),
            "rego schemas: the result",
        ),
        (
            r"Each of the (\d+) real gaps comes with an input that kills it, and the inputs, added "
            r"as tests",
            (str(head["survivors_real"]),),
            "rego schemas: the gaps",
        ),
        (
            r"that of \\texttt\{(\w+)\} kills (\d+) of its (\d+) distinguishable mutants",
            (
                weakest["subject"].split("/")[-2],
                str(weakest["killed_through_decision"]),
                str(weakest["distinguishable"]),
            ),
            "rego schemas: the weakest suite of either population",
        ),
        (
            r"so all (\d+) equivalents hold only under the settings the suites test: were each "
            r"separable by another setting, the score would be (\d+\.\d)\\%",
            (str(head["suite_equivalent"]), worst),
            "rego schemas: the score if every equivalent were separable",
        ),
        (
            rf"([A-Z][a-z]+) schemas over the cell cap and ({_WORD_PATTERN}) failing the "
            r"completeness check",
            (_word(over_cap).capitalize(), _word(missing)),
            "rego schemas: the table's caption",
        ),
        (
            r"(\d+) schemas & (\d+) & (\d+) & (\d+) & (\d+) & (\d+) & (\d+\.\d) & "
            r"(\d+\.\d) & (\d+)",
            (
                str(head["modules"]),
                str(head["mutants"]),
                str(head["stillborn"]),
                str(head["suite_equivalent"]),
                str(head["distinguishable"]),
                str(head["killed_through_decision"]),
                _pct(head["pooled_raw_score"]),
                _pct(head["pooled_exact_score"]),
                str(head["survivors_real"]),
            ),
            "rego schemas: the table's total",
        ),
    ]
    for subject, record in sorted(measured.items()):
        name = subject.split("/")[-2].replace("-", "\\allowbreak-")
        claims.append(
            (
                rf"\\texttt\{{{re.escape(name)}\}} & (\d+) & (\d+) & (\d+) & (\d+) & (\d+) & "
                r"(\d+\.\d) & (\d+\.\d) & (\d+)",
                (
                    str(record["mutants"]),
                    str(record["stillborn"]),
                    str(record["suite_equivalent"]),
                    str(record["distinguishable"]),
                    str(record["killed_through_decision"]),
                    _share(record["killed"], record["mutants"]),
                    _share(record["killed_through_decision"], record["distinguishable"]),
                    str(len(record["survivors"])),
                ),
                f"rego schemas: the row for {subject.split('/')[-2]}",
            )
        )
    return claims


def _rego_real_faults_claims(docs: Path) -> list[Claim]:
    """The real faults in two Rego libraries' histories, exposed by the suite strategies.

    The candidate counts are read from the protocol's own table, which its hash fixed before the
    study ran; everything else from the artifact. The two main texts share the sentence that
    states the result, so one pin reaches both.
    """

    study = _load(docs, "rego-real-faults-v1")
    protocol = (docs / "REAL_FAULTS_PROTOCOL_REGO.md").read_text(encoding="utf-8")
    table = re.findall(
        r"^\| \d+ \| (\w+) \| `[0-9a-f]+` \| `[^`]+` \| (behaviour fix|excluded) \|",
        protocol,
        flags=re.M,
    )
    fixes = [corpus for corpus, klass in table if klass == "behaviour fix"]
    studied = [corpus for corpus in fixes if corpus in ("gatekeeper", "gcp")]
    head, h1, h2 = (
        study["headline"],
        study["headline"]["comparisons"]["H1"],
        study["headline"]["comparisons"]["H2"],
    )
    faults = study["faults"]
    pooled = [r for r in faults if not r.get("development")]
    scored = [r for r in pooled if r.get("status") == "scored"]
    development = [r for r in faults if r.get("development")]
    assert len(scored) == head["faults"] and len(pooled) == study["population"]
    assert all(
        r.get("status") == "scored" and r["quotient_exposes_with_certainty"] for r in development
    )
    new_field = [r for r in scored if r["fix_reads_paths_the_policy_does_not"]]
    by_chance = [r for r in new_field if not r["quotient_exposes_with_certainty"]]
    # "and it is so in every fault whose fix reads only what the policy in use already read"
    assert all(r["difference_is_a_union_of_classes"] for r in scored if r not in new_field)
    assert h2["losses"] == 0
    mean = head["mean_exposure"]

    def numbers(status: str) -> str:
        found = sorted(
            r["number"]
            for r in pooled
            if r.get("status", "").startswith(status) or status in r.get("status", "")
        )
        return ", ".join(f"\\#{n}" for n in found)

    def interval(hypothesis: dict[str, Any]) -> tuple[str, str, str]:
        low, high = hypothesis["bootstrap_95"]
        return (f"{hypothesis['mean_difference']:.3f}", f"{low:.3f}", f"{high:.3f}")

    claims: list[Claim] = [
        (
            r"On (\d+) real faults fixed by two Rego libraries' maintainers, "
            r"(\d+\.\d)\\%, (\d+\.\d)\\% and (\d+\.\d)\\%",
            (
                str(head["faults"]),
                _pct(mean["quotient"]),
                _pct(mean["random_quotient"]),
                _pct(mean["decision"]),
            ),
            "real faults: the abstract",
        ),
        (
            r"[Oo]n (\d+) behaviour fixes the maintainers of the Gatekeeper and Config Validator "
            r"libraries made to their own policies",
            (str(head["faults"]),),
            "real faults: the population, as both main texts state it",
        ),
        (
            r"one witness per class exposes (\d+\.\d)\\% in expectation, a random suite of that "
            r"size "
            r"(\d+\.\d)\\% and the proxy (\d+\.\d)\\%",
            (_pct(mean["quotient"]), _pct(mean["random_quotient"]), _pct(mean["decision"])),
            "real faults: the result, as both main texts state it",
        ),
        (
            r"In (\d+) of the (\d+), the difference is a union of the old policy's classes",
            (str(head["difference_is_a_union_of_classes"]), str(head["faults"])),
            "real faults: the unions, in the main text",
        ),
        (
            r"(\d+) of the (\d+) fixes that read a field the old policy never read are exposed "
            r"only "
            r"by chance",
            (str(len(by_chance)), str(len(new_field))),
            "real faults: the fixes the quotient exposes only by chance",
        ),
        (
            r"on (\d+) real faults that the maintainers of two Rego libraries fixed, (\d+\.\d)\\% "
            r"against (\d+\.\d)\\% and (\d+\.\d)\\%",
            (
                str(head["faults"]),
                _pct(mean["quotient"]),
                _pct(mean["random_quotient"]),
                _pct(mean["decision"]),
            ),
            "real faults: the contribution",
        ),
        (
            r"and on (\d+) real faults that the maintainers of two Rego libraries fixed, "
            r"(\d+\.\d)\\% "
            r"where the proxy detects (\d+\.\d)\\%",
            (str(head["faults"]), _pct(mean["quotient"]), _pct(mean["decision"])),
            "real faults: the conclusion",
        ),
        (
            r"(\d+) module changes in all once Red Hat's library is counted",
            (str(len(table)),),
            "real faults: the candidates",
        ),
        (
            r"(\d+) are behaviour fixes and (\d+) are messages",
            (str(len(fixes)), str(len(table) - len(fixes))),
            "real faults: the classification",
        ),
        (
            r"The (\d+) behaviour fixes in the two libraries whose suites run under",
            (str(len(studied)),),
            "real faults: the population",
        ),
        (
            r"Red Hat's (\d+) are tested through conftest",
            (str(len(fixes) - len(studied)),),
            "real faults: the corpus left out",
        ),
        (
            r"Of the (\d+) faults outside the two development ones, (\d+) are scored",
            (str(len(pooled)), str(len(scored))),
            "real faults: how many are scored",
        ),
        (
            r"reads \\texttt\{data\.inventory\}\s*\(([^)]*)\) and one because it reads the clock\s*"
            r"\(([^)]*)\)",
            (numbers("data.inventory"), numbers("time.now_ns")),
            "real faults: the faults outside the fragment",
        ),
        (
            r"found an input no cell covers "
            r"\(([^)]*)\); one exceeds the cap \(([^)]*)\); one fix does "
            r"not\s*compile under OPA 1\.20\.2 \(([^)]*)\)",
            (
                numbers("excluded: missing cell"),
                numbers("excluded: an object with"),
                numbers("does not compile"),
            ),
            "real faults: the other exclusions",
        ),
        (
            r"under the settings the suites test "
            r"\(([^)]*)\), in \\#(\d+) because its suites supply no "
            r"input",
            (
                numbers("no decision change"),
                str(
                    next(
                        r["number"]
                        for r in pooled
                        if r.get("status", "").startswith("no decision")
                        and r.get("authors_inputs") == 0
                    )
                ),
            ),
            "real faults: no decision change",
        ),
        (
            r"The difference set is a union of the policy's own quotient classes in (\d+) of the "
            r"(\d+)",
            (str(head["difference_is_a_union_of_classes"]), str(head["faults"])),
            "real faults: the unions, in the supporting information",
        ),
        (
            r"(\d+) of those (\d+) are exposed only by chance, between (\d+\.\d)\\% and "
            r"(\d+\.\d)\\% of "
            r"the time",
            (
                str(len(by_chance)),
                str(len(new_field)),
                _pct(min(r["exposure"]["quotient"] for r in by_chance)),
                _pct(max(r["exposure"]["quotient"] for r in by_chance)),
            ),
            "real faults: how often the quotient finds a new field's fix",
        ),
        (
            r"In expectation one witness per class exposes (\d+\.\d)\\%, a random suite of the "
            r"same size "
            r"(\d+\.\d)\\%, the decision proxy (\d+\.\d)\\%, and a random suite of the proxy's "
            r"size "
            r"(\d+\.\d)\\%",
            tuple(
                _pct(mean[s])
                for s in ("quotient", "random_quotient", "decision", "random_decision")
            ),
            "real faults: the means",
        ),
        (
            r"The quotient beats random testing by (\d\.\d+) \$\[(\d\.\d+), (\d\.\d+)\]\$, higher "
            r"on (\d+) "
            r"faults, tied on (\d+) and lower on (\d+) \(\$p = (0\.\d+)\$[;)]",
            (
                *interval(h1),
                str(h1["wins"]),
                str(h1["ties"]),
                str(h1["losses"]),
                f"{h1['p_value']:.4f}",
            ),
            "real faults: H1",
        ),
        (
            r"and the proxy by (\d\.\d+) \$\[(\d\.\d+), (\d\.\d+)\]\$, higher on (\d+) and lower "
            r"on none "
            r"\(\$p = (0\.\d+)\$; Holm (0\.\d+)\)",
            (*interval(h2), str(h2["wins"]), f"{h2['p_value']:.4f}", f"{h2['p_value_holm']:.4f}"),
            "real faults: H2",
        ),
    ]
    for record in scored:
        settings = record["per_setting"]
        kind = (
            "union"
            if record["difference_is_a_union_of_classes"]
            else ("contains" if record["quotient_exposes_with_certainty"] else "splits")
        )
        claims.append(
            (
                rf"(?<![\d.]){record['number']} & (GK|CV) & \\texttt\{{[^}}]*\}} & (\d+) & "
                rf"({_GROUPED}) & "
                rf"({_GROUPED}) & (\d+) & (union|contains|splits) & (yes|) ?& (\d+\.\d) & "
                rf"(\d+\.\d) & "
                r"(\d+\.\d) \\\\",
                (
                    "GK" if record["corpus"] == "gatekeeper" else "CV",
                    str(len(settings)),
                    _grouped(sum(s["cells"] for s in settings)),
                    _grouped(sum(s["quotient_classes"] for s in settings)),
                    str(sum(s["difference_cells"] for s in settings)),
                    kind,
                    "yes" if record["fix_reads_paths_the_policy_does_not"] else "",
                    _pct(record["exposure"]["quotient"]),
                    _pct(record["exposure"]["random_quotient"]),
                    _pct(record["exposure"]["decision"]),
                ),
                f"real faults: the row for #{record['number']}",
            )
        )
    return claims


def _cedar_symcc_claims(docs: Path) -> list[Claim]:
    """SymCC's check of the Cedar replication's verdicts, under the files' own schemas.

    The main texts share the sentence that states the result. What the prose rests on and
    does not print -- no verdict refuted, every control verified, every counterexample
    confirmed by the engine -- is asserted, so the sentence cannot outlive its evidence.
    """

    study = _load(docs, "cedar-symcc-crosscheck-v1")
    listed = _load(docs, "cedar-schema-candidates-v1")["summary"]
    files = study["files"]
    primary, secondary = study["summary"]["primary"], study["summary"]["secondary"]
    assert study["summary"]["files"] == {"checked": len(files)}
    assert all(set(r["control"]) == {"verified"} for r in files)
    assert primary["classes"]["refuted"] == 0 and not primary["refutations"]
    assert not primary["with_a_counterexample_the_engine_did_not_confirm"]
    assert set(secondary["counterexamples"]) == {"confirmed"}
    mutants = [m for r in files for m in r["mutants"]]
    equivalent = [m for m in mutants if m["study"] == "equivalent"]
    live = [m for m in mutants if m["study"] == "live"]
    assert all(m["study"] == "live" for m in mutants if m["counterexamples"])
    classes, live_classes = primary["classes"], secondary["classes"]
    every = classes["not refuted, every environment verified"]
    partly, nowhere = classes["not refuted, partly checked"], classes["unchecked"]
    untyped = [m for m in equivalent if m["class"] != "not refuted, every environment verified"]
    # "mutants the schema's type checker rejects in some environment"
    assert all(set(m["results"]) <= {"verified", "mutant does not compile"} for m in untyped)
    widen = sum(1 for m in untyped if m["operator"].startswith("widen_"))
    cut = sum(1 for m in untyped if m["operator"].startswith("keep_"))
    assert widen + cut == len(untyped)
    schema_equivalent = live_classes["equivalent under the schema"]
    neither = len(live) - live_classes["live under the schema"] - schema_equivalent
    # "The other ... live mutants are verified wherever they are well typed"
    assert live_classes["equivalent where checked"] == neither
    widened = sum(
        n
        for operator, n in secondary["equivalent_under_the_schema_by_operator"].items()
        if operator.startswith("widen_")
    )
    selves = sum(1 for m in mutants for c in m["counterexamples"] if c.get("principal_is_resource"))
    first = re.search(r"Its (\d+) such counterexamples", study["deviations"][0])
    assert first is not None
    found = listed["schema found"]
    return [
        (
            r"on (\d+) (?:Cedar )?files whose authors wrote a schema",
            (str(len(files)),),
            "cedar symcc: the files checked, as both main texts state it",
        ),
        (
            r"finds no request the schema admits that separates any of the (\d+) mutants the "
            r"study calls equivalent",
            (str(len(equivalent)),),
            "cedar symcc: no equivalent verdict refuted, as both main texts state it",
        ),
        (
            r"and verifies (\d+) of them in every request environment \(",
            (str(every),),
            "cedar symcc: verified in every environment, in the main text",
        ),
        (
            r"For each of the (\d+) files the replication scored",
            (str(listed["files"]),),
            "cedar symcc: the files the replication scored",
        ),
        (
            rf"({_GROUPED}) files in (\d+) repositories have one \((\d+) in the file's own "
            rf"directory, (\d+) in an ancestor and (\d+) elsewhere in the repository\), with "
            rf"({_GROUPED}) request environments",
            (
                _grouped(listed["with a schema"]),
                str(listed["repositories with a schema"]),
                str(found["same directory"]),
                str(found["ancestor"]),
                str(found["elsewhere"]),
                _grouped(listed["environments"]),
            ),
            "cedar symcc: the files with an author's schema, and where it was found",
        ),
        (
            r"the other (\d+) hold (\d+) equivalent and (\d+) live verdicts",
            (str(len(files)), str(len(equivalent)), str(len(live))),
            "cedar symcc: the population",
        ),
        (
            r"and all (\d+) reproduced the counts it recorded",
            (str(len(files)),),
            "cedar symcc: verdicts reproduced before they were checked",
        ),
        (
            r"Equivalent & (\d+) \\\\ \\quad refuted & (\d+) \\\\ \\quad verified in every request "
            r"environment & (\d+) \\\\ \\quad verified wherever it is well typed & (\d+) \\\\ "
            r"\\quad well typed in no environment & (\d+) \\\\ Live & (\d+) \\\\ \\quad confirmed "
            r"live & (\d+) \\\\ \\quad equivalent in every request environment & (\d+) \\\\ "
            r"\\quad neither & (\d+)",
            (
                str(len(equivalent)),
                str(classes["refuted"]),
                str(every),
                str(partly),
                str(nowhere),
                str(len(live)),
                str(live_classes["live under the schema"]),
                str(schema_equivalent),
                str(neither),
            ),
            "cedar symcc: the table",
        ),
        (
            r"it verifies (\d+) of them in every request environment\. The other (\d+) are "
            r"mutants the schema's type checker rejects in some environment --- (\d+) widen a "
            r"policy's scope to principals or actions its condition cannot be typed for, and "
            r"(\d+) cut a conjunction",
            (str(every), str(len(untyped)), str(widen), str(cut)),
            "cedar symcc: the verdicts not verified everywhere, and why",
        ),
        (
            r"it verifies (\d+) of them wherever they compile, and the remaining (\d+) compile "
            r"nowhere",
            (str(partly), str(nowhere)),
            "cedar symcc: verified where well typed, and well typed nowhere",
        ),
        (
            r"all (\d+) of them, every one against a live mutant, separate the mutant",
            (str(secondary["counterexamples"]["confirmed"]),),
            "cedar symcc: counterexamples the engine confirms",
        ),
        (
            r"Of those requests, (\d+) name one entity as both principal and resource",
            (str(selves),),
            "cedar symcc: counterexamples whose principal is the resource",
        ),
        (
            r"and (\d+) counterexamples went unreplayed",
            (first.group(1),),
            "cedar symcc: the first run's deviation",
        ),
        (
            r"Of the (\d+) live mutants, (\d+) \((\d+\.\d)\\%\) are equivalent under their "
            r"authors' schema",
            (str(len(live)), str(schema_equivalent), _share(schema_equivalent, len(live))),
            "cedar symcc: live mutants equivalent under the schema",
        ),
        (
            r"These include (\d+) that widen a policy's scope",
            (str(widened),),
            "cedar symcc: the schema-equivalent mutants that widen a scope",
        ),
        (
            r"The other (\d+) live mutants are verified wherever they are well typed",
            (str(neither),),
            "cedar symcc: the live mutants in neither class",
        ),
    ]


def _round2_claims(docs: Path) -> list[Claim]:
    """The second review round: re-analyses of artifacts the studies had already written."""

    analyses = _load(docs, "review-round-analyses-v1")
    families = analyses["guard_families"]
    rows = families["by_language"]
    azure, xacml, iam = rows["Azure Policy"], rows["XACML"], rows["AWS IAM"]
    unrecorded = families["rego_and_kyverno_inside_unrecorded"]
    cedar = families["cedar_inside_by_design"]
    literal = families["literal_operand_where_recorded"]
    operand_free = (
        azure["operand-free"]
        + xacml["operand-free"]
        + iam["operand-free"]
        + iam["pattern, literal by construction"]
        + cedar
    )
    line = analyses["line_coverage"]
    clustered = analyses["clustered"]
    rego_c = clustered["rego_payoff_by_module"]
    commit_c = clustered["real_faults_by_commit"]
    module_c = clustered["real_faults_by_module"]
    sensitivity = analyses["real_faults_no_change_sensitivity"]
    shares = analyses["equivalent_shares"]
    mcdc = _load(docs, "xacml-criteria-study-v1")["hypotheses"]["H1"]["MCDC"]

    # Every clustered interval stays above zero: the sentence that says so is checked here.
    for block in (rego_c, commit_c, module_c):
        for name in ("H1", "H2"):
            assert block[name]["cluster_bootstrap_95"][0] > 0, (name, block)

    def interval(entry: dict) -> tuple[str, str]:
        low, high = entry["cluster_bootstrap_95"]
        return f"{low:.3f}", f"{high:.3f}"

    def p(entry: dict) -> str:
        return f"{entry['cluster_sign_flip_p']:.4f}"

    population_shares = [
        shares[label]["share"]
        for label in (
            "generated (300)",
            "Cedar with an author schema (71)",
            "Gatekeeper, decided (13)",
            "XACML benchmark (11)",
        )
    ]
    claims: list[Claim] = [
        (
            rf"({_GROUPED}) inside verdicts use\s*only families",
            (_grouped(operand_free),),
            "families: verdicts on families decidable whatever their operands",
        ),
        (
            r"(\d+) in Azure Policy and XACML use",
            (str(literal),),
            "families: verdicts on a family that needs a literal operand",
        ),
        (
            r"the (\d+)\s*Rego and\s*Kyverno verdicts record no family per call",
            (str(unrecorded),),
            "families: verdicts that record no family",
        ),
        (
            r"for those (\d+) the share inside is an upper bound",
            (str(literal + unrecorded),),
            "families: the verdicts whose argument is not checked",
        ),
        (
            rf"and ({_GROUPED}) inside \(Section~\\ref\{{sec:membership\}}\), ({_GROUPED}) of them "
            r"through guard families",
            (
                _grouped(operand_free + literal + unrecorded),
                _grouped(operand_free),
            ),
            "contributions: inside verdicts by family",
        ),
        (
            rf"Total & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) \\\\",
            (
                _grouped(operand_free + literal + unrecorded),
                _grouped(operand_free),
                _grouped(literal),
                _grouped(unrecorded),
            ),
            "families: the table's totals",
        ),
        (
            r"Kendall's \$\\tau = (0\.\d+)\$(?:, | \()\$p = (0\.\d+)\$",
            (
                f"{line['kill_rate']['kendall_tau_b']:.2f}",
                f"{line['kill_rate']['permutation_p_two_sided']:.4f}",
            ),
            "line coverage tracks the kill rate",
        ),
        (
            r"weak and not significant \(\$\\tau = (0\.\d+)\$, \$p = (0\.\d+)\$\)",
            (
                f"{line['exact_score']['kendall_tau_b']:.2f}",
                f"{line['exact_score']['permutation_p_two_sided']:.2f}",
            ),
            "line coverage against the exact score",
        ),
        (
            r"or \$\[(\d\.\d+), (\d\.\d+)\]\$ resampling the (\d+) modules rather than the "
            r"(\d+) policies",
            (*interval(rego_c["H1"]), str(rego_c["clusters"]), str(rego_c["units"])),
            "rego payoff: H1 resampled by module",
        ),
        (
            r"with an exact\s*module-level sign-flip \$p = (0\.\d+)\$",
            (p(rego_c["H1"]),),
            "rego payoff: H1's module-level sign-flip",
        ),
        (
            r"[Tt]he (\d+) Rego policies share (\d+) modules and the (\d+)\s*faults (\d+) "
            r"commits; resampled by module and by commit, every interval stays above zero",
            (
                str(rego_c["units"]),
                str(rego_c["clusters"]),
                str(commit_c["units"]),
                str(commit_c["clusters"]),
            ),
            "threats: the clusters",
        ),
        (
            r"edge over random testing is (0\.\d+)\s*\$\[(0\.\d+), (0\.\d+)\]\$ by module \(exact "
            r"sign-flip \$p = (0\.\d+)\$\); on the faults it is (0\.\d+)\s*\$\[(0\.\d+), "
            r"(0\.\d+)\]\$ by commit \(\$p = (0\.\d+)\$\) and \$\[(0\.\d+), (0\.\d+)\]\$ by "
            r"module \(\$p = (0\.\d+)\$\)",
            (
                f"{rego_c['H1']['mean_difference']:.3f}",
                *interval(rego_c["H1"]),
                p(rego_c["H1"]),
                f"{commit_c['H1']['mean_difference']:.3f}",
                *interval(commit_c["H1"]),
                p(commit_c["H1"]),
                *interval(module_c["H1"]),
                p(module_c["H1"]),
            ),
            "threats: the clustered intervals",
        ),
        (
            r"or (\d+\.\d)\\%, (\d+\.\d)\\% and (\d+\.\d)\\% counting as unexposed the two "
            r"fixes",
            tuple(
                _pct(sensitivity["mean_exposure_counting_them_as_unexposed"][s])
                for s in ("quotient", "random_quotient", "decision")
            ),
            "real faults: counting the two unchanged fixes as unexposed",
        ),
        (
            r"(\d+\.\d)\\% of generated policies' mutants are\s*equivalent, (\d+\.\d)\\% of those "
            r"of the Cedar files with an author schema, (\d+\.\d)\\% on the decided\s*Gatekeeper "
            r"modules \((\d+\.\d)\\% outright\) and (\d+\.\d)\\% on Xu et al.'s XACML benchmark",
            (
                _pct(shares["generated (300)"]["share"]),
                _pct(shares["Cedar with an author schema (71)"]["share"]),
                _pct(shares["Gatekeeper, decided (13)"]["share"]),
                _pct(shares["Gatekeeper, decided (13)"]["outright_share"]),
                _pct(shares["XACML benchmark (11)"]["share"]),
            ),
            "equivalent shares beyond the reference policy",
        ),
        (
            r"worth (\d+) percentage points on one\s*small policy, and (\d+) to (\d+) on the "
            r"populations we scored",
            (
                str(round(100 * shares["reference policy"]["share"])),
                str(round(100 * min(population_shares))),
                str(round(100 * max(population_shares))),
            ),
            "conclusion: what decidability is worth",
        ),
        (
            r"Median sizes are (\d+) tests\s*for the proxy and (\d+), (\d+) and (\d+) for the "
            r"quotient",
            _median_sizes(docs),
            "the payoff figure's median suite sizes",
        ),
        (
            r"the shipped suite's exact (\d+\.\d)\\% reads as (\d+\.\d)\\%, and a coverage\s*"
            r"matrix witnessing every cell, complete by Corollary~\\ref\{cor:score\}, as "
            r"(\d+\.\d)\\%",
            _price_rows(docs),
            "the price of undecided equivalence, in prose",
        ),
        (
            r"Of its (\d+) files judged inside, (\d+)\s*parse under the",
            _cedar_funnel(docs)[:2],
            "cedar: inside and parsed",
        ),
        (
            rf"(\d+) exceed the cap of ({_GROUPED}) cells",
            _cedar_funnel(docs)[2:4],
            "cedar: over the cap",
        ),
        (
            r"failed (?:its|the) completeness check on (\d+)",
            _cedar_funnel(docs)[4:5],
            "cedar: failing the completeness check",
        ),
    ]
    claims.append(
        (
            r"comes within (\d+\.\d)\s*points (?:of the quotient )?with a (\w+) of (?:the|its) "
            r"requests",
            (f"{100 * mcdc['mean_difference']:.1f}", _ordinal_fraction(docs)),
            "xacml: MC/DC against the quotient, in brief",
        )
    )
    return claims


def _ordinal_fraction(docs: Path) -> str:
    """How many times MC/DC's requests the quotient's are, as a fraction word (16 -> sixteenth).

    Like for like, as the shared sentence is: both sizes over the policies where XPA built an
    MC/DC suite.
    """

    study = _load(docs, "xacml-criteria-study-v1")
    paired = [r for r in study["policies"] if r["suites"]["MCDC"]["status"] == "generated"]
    quotient = sum(r["quotient_classes"] for r in paired) / len(paired)
    mcdc = study["summary"]["mean_suite_size"]["MCDC"]
    ordinals = {14: "fourteenth", 15: "fifteenth", 16: "sixteenth", 17: "seventeenth"}
    return ordinals[round(quotient / mcdc)]


def _median_sizes(docs: Path) -> tuple[str, str, str, str]:
    generated = _load(docs, "suite-strategy-study-v1")["operator_sets"]["A"]["median_suite_size"]
    cedar = _load(docs, "cedar-suite-strategy-study-v1")["analyses"][
        "primary: files with a condition"
    ]["median_suite_size"]
    rego = _load(docs, "rego-suite-strategy-study-v1")
    classes = [
        policy["quotient_classes"]
        for module in rego["modules"].values()
        if not module["development"]
        for policy in module["policies"]
        if policy["status"] == "scored"
    ]
    return (
        str(int(generated["decision"])),
        str(int(generated["quotient"])),
        str(int(cedar["quotient"])),
        str(int(statistics.median(classes))),
    )


def _price_rows(docs: Path) -> tuple[str, str, str]:
    estimator = _load(docs, "estimator-comparison-v1")
    suites = {entry["suite"]: entry for entry in estimator["suites"]}
    default = suites["default-scenarios.json"]
    matrix = suites["coverage-matrix-scenarios.json"]
    return (
        _pct(default["exact_score"]),
        _pct(default["score_without_equivalence_detection"]),
        _pct(matrix["score_without_equivalence_detection"]),
    )


def _cedar_funnel(docs: Path) -> tuple[str, str, str, str, str]:
    study = _load(docs, "cedar-suite-strategy-study-v1")
    population = study["population"]
    statuses = study["file_statuses"]
    return (
        str(population["judged inside"]),
        str(population["judged inside"] - population["Cedar does not parse it"]),
        str(statuses.get("over the cell cap", statuses.get("over the cap", 0))),
        _grouped(study["max_cells"]),
        str(statuses["missing cells"]),
    )


def _half_up(value: float, places: str) -> str:
    return str(Decimal(str(value)).quantize(Decimal(places), rounding=ROUND_HALF_UP))


def _xacml_criteria_claims(docs: Path) -> list[Claim]:
    """Xu et al.'s criteria and the quotient, on Xu et al.'s own benchmark.

    The main texts share one sentence, and it states both halves of the result -- complete
    detection, at a size MC/DC does not need -- so neither can be quoted without the other. What
    the prose rests on and does not print is asserted: every policy scored, none unrunnable, no
    missing cell, the quotient at exactly 100%, and an oracle without a disagreement.
    """

    study = _load(docs, "xacml-criteria-study-v1")
    summary, hypotheses, policies = study["summary"], study["hypotheses"], study["policies"]
    assert summary["statuses"] == {"scored": len(policies)}
    assert summary["mutants"]["unrunnable"] == 0
    assert all(not r["missing_cells_for"] and r["requests_in_no_class"] == 0 for r in policies)
    assert study["oracle"]["disagree"] == 0
    mean, pooled, size = (
        summary["mean_over_policies"],
        summary["pooled_over_mutants"],
        summary["mean_suite_size"],
    )
    assert mean["quotient"] == 1.0 and pooled["quotient"] == 1.0

    def pct(value: float) -> str:
        exact = Decimal(str(value)) * 100
        return str(exact.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))

    def whole(value: float) -> str:
        return _half_up(value, "1")

    live = summary["mutants"]["live"]
    equivalent = summary["mutants"]["equivalent"]
    merged = sorted(
        (r for r in policies if r["quotient_classes"] < r["cells"]), key=lambda r: r["policy"]
    )
    h1, h2 = hypotheses["H1"], hypotheses["H2"]
    mc = h1["MCDC"]
    others = [h1[c] for c in ("RC", "DC", "NE-DC", "PC", "PD-PC")]
    assert len({v["holm_p"] for v in others}) == 1
    above = [h2[c] for c in ("RC", "DC", "NE-DC")]
    assert all(v["holm_p"] >= 0.05 and v["mean_difference"] > 0 for v in above)
    assert all(h2[c]["holm_p"] >= 0.05 for c in ("PC", "PD-PC"))
    assert h2["MCDC"]["holm_p"] == h2["NE-MCDC"]["holm_p"]
    big = sum(
        1
        for r in policies
        if r["policy"] in ("itrust3.xml", "pluto3.xml")
        for m in r["scored"]
        if m["status"] == "live"
    )
    rows = [
        ("One witness per quotient class", "quotient", "random_quotient"),
        ("MC/DC (XPA)$^{a}$", "MCDC", "random_MCDC"),
        ("MC/DC without errors (XPA)$^{a}$", "NE-MCDC", "random_NE-MCDC"),
        ("Decision coverage (XPA)", "DC", "random_DC"),
        ("Decision coverage without errors (XPA)", "NE-DC", "random_NE-DC"),
        ("Rule coverage (XPA)", "RC", "random_RC"),
        ("Rule-pair coverage (XPA)", "PC", "random_PC"),
        ("Permit--deny rule pairs (XPA)", "PD-PC", "random_PD-PC"),
        ("One witness per decision (the proxy)", "decision", "random_decision"),
    ]
    # Like for like: the quotient's size over the policies where XPA built an MC/DC suite, the
    # policies MC/DC's own figures are averaged over.
    paired = [r for r in policies if r["suites"]["MCDC"]["status"] == "generated"]
    paired_size = whole(sum(r["quotient_classes"] for r in paired) / len(paired))
    assert all(summary["by_policy"][r["policy"]]["quotient"] == 1.0 for r in paired)
    claims: list[Claim] = [
        (
            r"[Oo]n the (\w+) of Xu et al.'s benchmark policies where their tool built an MC/DC "
            r"suite, the quotient detects every live mutant with (\d+) requests on average, where "
            r"their MC/DC detects (\d+\.\d)\\% with (\d+)",
            (_word(len(paired)), paired_size, pct(mean["MCDC"]), whole(size["MCDC"])),
            "xacml criteria: both halves, like for like, as both main texts state them",
        ),
        (
            r"agrees with all (\d+) of Balana's own conformance cases",
            (str(study["oracle"]["agree"]),),
            "xacml criteria: the engine oracle",
        ),
        (
            r"Of XPA's (\d+) benchmark policies, (\d+) are at once inside the fragment",
            (
                str(len(study["population"]["eligible"]) + len(study["population"]["excluded"])),
                str(len(study["population"]["eligible"])),
            ),
            "xacml criteria: the population",
        ),
        (
            rf"XPA's operators make ({_GROUPED}) mutants: ({_GROUPED}) live and (\d+) equivalent, "
            r"(\d+) of the latter",
            (
                _grouped(live + equivalent),
                _grouped(live),
                str(equivalent),
                str(summary["equivalent_by_operator"]["ANR"]),
            ),
            "xacml criteria: the mutants",
        ),
        (
            r"in (\d+) of the 11 policies; only the three kmarket policies merge cells, (\d+) into "
            r"(\d+), (\d+) into (\d+) and (\d+) into (\d+)",
            (
                str(sum(1 for r in policies if r["quotient_classes"] == r["cells"])),
                *(str(v) for r in merged for v in (r["cells"], r["quotient_classes"])),
            ),
            "xacml criteria: where the quotient is the refinement",
        ),
        (
            r"Its completeness therefore costs (\d+) requests on average on the (\w+) policies "
            r"where XPA built an MC/DC suite \((\d+) over all (\w+)\), where MC/DC, the strongest "
            r"of Xu et al.'s criteria, detects (\d+\.\d)\\% with (\d+)",
            (
                paired_size,
                _word(len(paired)),
                whole(size["quotient"]),
                _word(len(policies)),
                pct(mean["MCDC"]),
                whole(size["MCDC"]),
            ),
            "xacml criteria: both halves, in the supporting information",
        ),
        (
            r"MC/DC by (\d+\.\d) points \[(\d+\.\d), (\d+\.\d)\], (\d+) wins and (\d+) ties over "
            r"(\d+) policies \(Holm \$p = ([\d.]+)\$\)",
            (
                pct(mc["mean_difference"]),
                pct(mc["bootstrap_95"][0]),
                pct(mc["bootstrap_95"][1]),
                str(mc["wins"]),
                str(mc["ties"]),
                str(mc["policies"]),
                str(mc["holm_p"]),
            ),
            "xacml criteria: H1 against MC/DC",
        ),
        (
            r"the rule, decision and pair criteria by (\d+\.\d) to (\d+\.\d) points \(Holm "
            r"\$p = ([\d.]+)\$ each\)",
            (
                pct(min(v["mean_difference"] for v in others)),
                pct(max(v["mean_difference"] for v in others)),
                str(others[0]["holm_p"]),
            ),
            "xacml criteria: H1 against the other criteria",
        ),
        (
            r"by (\d+\.\d) and (\d+\.\d) points \(Holm \$p = ([\d.]+)\$\); rule and decision",
            (
                pct(h2["MCDC"]["mean_difference"]),
                pct(h2["NE-MCDC"]["mean_difference"]),
                str(h2["MCDC"]["holm_p"]),
            ),
            "xacml criteria: H2 for MC/DC",
        ),
        (
            r"after Holm's correction \(\$p\$ from ([\d.]+) to ([\d.]+)\)",
            (str(min(v["holm_p"] for v in above)), str(max(v["holm_p"] for v in above))),
            "xacml criteria: H2 for rule and decision coverage",
        ),
        (
            r"A random suite as large as the quotient detects (\d+\.\d)\\%, so the quotient's edge "
            r"over random testing at equal size is (\d+\.\d) points",
            (pct(mean["random_quotient"]), pct(mean["quotient"] - mean["random_quotient"])),
            "xacml criteria: the quotient against random testing, described",
        ),
        (
            r"Xu et al.'s decision coverage, which detects (\d+\.\d)\\% with (\d+) requests, is "
            r"not the paper's decision proxy, which detects (\d+\.\d)\\% with (\d+)",
            (pct(mean["DC"]), whole(size["DC"]), pct(mean["decision"]), whole(size["decision"])),
            "xacml criteria: their decision coverage and the paper's proxy",
        ),
        (
            rf"which hold ({_GROUPED}) of the ({_GROUPED}) live mutants, and by one operator, "
            r"RPTE, with (\d+)",
            (_grouped(big), _grouped(live), str(summary["live_by_operator"]["RPTE"])),
            "xacml criteria: what dominates the pooled column",
        ),
        (
            r"one of the (\d+) equivalent mutants is separated by a request that gives an "
            r"attribute several values",
            (str(equivalent),),
            "xacml criteria: the bag check",
        ),
        (
            r"a first run stopped on the (\d+) such mutants",
            (str(sum(len(r["targets_restored"]) for r in policies)),),
            "xacml criteria: the deviation",
        ),
    ]
    assert summary["bag_check"]["equivalent_mutants_a_bag_request_separates"] == 1
    for label, key, random_key in rows:
        claims.append(
            (
                re.escape(label) + r" & (\d+\.\d) & (\d+\.\d) & (\d+\.\d) & (\d+\.\d) \\\\",
                (
                    pct(mean[key]),
                    pct(mean[random_key]),
                    pct(pooled[key]),
                    _half_up(size[key], "0.1"),
                ),
                f"xacml criteria: the table's row for {key}",
            )
        )
    return claims


def _rego_payoff_claims(docs: Path) -> list[Claim]:
    """The suite-strategy study replicated on real Rego policies, every decision OPA's.

    The 10-page article restates the result in the full version's own phrases, so each pin below
    reaches both texts; the abstract, the conclusion and the threats are shared word for word.
    """

    study = _load(docs, "rego-suite-strategy-study-v1")
    exact = _load(docs, "rego-exact-adequacy-v1")
    generated = _load(docs, "suite-strategy-study-v1")["operator_sets"]["A"]["hypotheses"]
    cedar = _load(docs, "cedar-suite-strategy-study-v1")["analyses"][
        "primary: files with a condition"
    ]["hypotheses"]
    head, by_module = study["headline"], study["by_module"]
    development = study["development_module"]
    policies = [
        (subject, policy)
        for subject, record in study["modules"].items()
        if subject != development
        for policy in record["policies"]
    ]
    scores = head["mean_expected_score"]
    first, second, third = (head["comparisons"][name] for name in ("H1", "H2", "H3"))

    # The population is the exact study's measured modules, and every policy in it was scored:
    # the decision constant on every class and no path left unmerged.
    assert study["witness_spaces"] == "rego-exact-adequacy-v1.json"
    modules = {subject for subject, _ in policies}
    assert len(modules) == by_module["policies"] == exact["headline"]["modules"]
    assert len(policies) == head["policies"]
    assert all(policy["status"] == "scored" for _, policy in policies)
    assert all(policy["unmerged_paths"] == 0 for _, policy in policies)
    # "All three comparisons reach the permutation floor", the module reading a single Holm p.
    floor = round(1 / (1 + study["resamples"]), 4)
    assert all(h["p_value"] == floor for h in head["comparisons"].values())
    holm = {h["p_value_holm"] for h in by_module["comparisons"].values()}
    assert len(holm) == 1, holm
    # "the ordering is the same" by module; the proxy's gap lies between the other populations'.
    ranked = [
        sorted(r["mean_expected_score"], key=r["mean_expected_score"].get)
        for r in (head, by_module)
    ]
    assert ranked[0] == ranked[1], ranked
    assert (
        generated["H2"]["mean_difference"]
        < second["mean_difference"]
        < cedar["H2"]["mean_difference"]
    )
    # "falls short of the quotient on every policy"
    assert second["wins"] == second["policies"]
    # "The two losses are one module ... under two of its settings"
    losses = [
        subject.split("/")[-2]
        for subject, policy in policies
        if policy["expected_score"]["quotient"] < policy["expected_score"]["random_quotient"]
    ]
    assert len(losses) == first["losses"] and len(set(losses)) == 1, losses

    def median(key: str) -> str:
        value = statistics.median(policy[key] for _, policy in policies)
        assert value == int(value), (key, value)
        return _grouped(int(value))

    def interval(hypothesis: dict[str, Any]) -> tuple[str, str, str]:
        low, high = hypothesis["bootstrap_95"]
        return (f"{hypothesis['mean_difference']:.3f}", f"{low:.3f}", f"{high:.3f}")

    def row(means: dict[str, float]) -> tuple[str, ...]:
        return tuple(_pct(means[strategy]) for strategy in PAYOFF_FIGURE_ORDER)

    live = [policy["live_mutants"] for _, policy in policies]
    lowest = min(policy["expected_score"]["quotient"] for _, policy in policies)
    decisions, classes, cells = (
        median("decision_classes"),
        median("quotient_classes"),
        median("cells"),
    )
    with_development = study["with_development_module"]["mean_expected_score"]
    return [
        (
            r"on (\d+) Gatekeeper Rego modules under the settings their suites "
            r"test, (\d+\.\d)\\%, (\d+\.\d)\\% and (\d+\.\d)\\%",
            (
                str(exact["headline"]["modules"]),
                _pct(scores["quotient"]),
                _pct(scores["random_quotient"]),
                _pct(scores["decision"]),
            ),
            "rego payoff: the abstract",
        ),
        (
            r"(\d+) Gatekeeper Rego modules under the (\d+) parameter settings their suites test,",
            (str(exact["headline"]["modules"]), str(head["policies"])),
            "rego payoff: the population, as the abstract and the 10-page article put it",
        ),
        (
            r"on real Rego under a protocol of its own and the Open Policy Agent \(OPA\), "
            r"(\d+\.\d)\\% against (\d+\.\d)\\% and (\d+\.\d)\\%",
            (_pct(scores["quotient"]), _pct(scores["random_quotient"]), _pct(scores["decision"])),
            "rego payoff: the contribution",
        ),
        (
            r"so the (\d+) modules whose spaces pass give (\d+) policies",
            (str(exact["headline"]["modules"]), str(head["policies"])),
            "rego payoff: modules and policies",
        ),
        (
            r"OPA (\d+\.\d+\.\d+), run with",
            (study["engine"].removeprefix("opa "),),
            "rego payoff: the engine",
        ),
        (
            r"and on all (\d+) policies it is, with no path left unmerged",
            (str(head["policies"]),),
            "rego payoff: the constancy check",
        ),
        (
            r"of which each policy has between (\d+) and (\d+)\s+live",
            (str(min(live)), str(max(live))),
            "rego payoff: live mutants per policy",
        ),
        (
            rf"Median size & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & "
            rf"({_GROUPED}) \\\\",
            (decisions, decisions, classes, classes, cells),
            "rego payoff: the table's sizes",
        ),
        (
            r"(\d+) policies & (\d+\.\d)\\% & (\d+\.\d)\\% & (\d+\.\d)\\% & (\d+\.\d)\\% & "
            r"(\d+\.\d)\\% \\\\",
            (str(head["policies"]), *row(scores)),
            "rego payoff: the table, by policy",
        ),
        (
            r"(\d+) modules, averaged & (\d+\.\d)\\% & (\d+\.\d)\\% & (\d+\.\d)\\% & "
            r"(\d+\.\d)\\% & (\d+\.\d)\\% \\\\",
            (str(by_module["policies"]), *row(by_module["mean_expected_score"])),
            "rego payoff: the table, by module",
        ),
        (
            r"on the (\d+) policies of (\d+) Gatekeeper library modules",
            (str(head["policies"]), str(by_module["policies"])),
            "rego payoff: the table's caption",
        ),
        (
            r"one witness per class detects (\d+\.\d)\\% of the live mutants in expectation",
            (_pct(scores["quotient"]),),
            "rego payoff: the quotient",
        ),
        (
            r"and no policy falls below (\d+\.\d)\\%",
            (f"{int(lowest * 1000) / 10:.1f}",),
            "rego payoff: the lowest quotient score",
        ),
        (
            r"[Aa] random suite of as many cells comes close, at (\d+\.\d)\\%",
            (_pct(scores["random_quotient"]),),
            "rego payoff: random at the quotient's size",
        ),
        (
            rf"at a median of ({_GROUPED}) classes in ({_GROUPED}) cells",
            (classes, cells),
            "rego payoff: the sizes that make the random suite large",
        ),
        (
            r"paired advantage (?:over it is|of) (\d\.\d+)\s+\$\[(\d\.\d+), (\d\.\d+)\]\$",
            interval(first),
            "rego payoff: H1",
        ),
        (
            r"higher on (\d+) of the (\d+) policies, tied on (\d+) and lower on (\d+)",
            tuple(str(first[key]) for key in ("wins", "policies", "ties", "losses")),
            "rego payoff: H1, policy by policy",
        ),
        (
            r"decision proxy, at (\d+\.\d)\\%, falls short of the quotient on every policy",
            (_pct(scores["decision"]),),
            "rego payoff: the proxy",
        ),
        (
            r"falls short of the quotient on every policy, by (\d\.\d+) "
            r"\$\[(\d\.\d+), (\d\.\d+)\]\$",
            interval(second),
            "rego payoff: H2",
        ),
        (
            r"beats random suites of its own size by (\d\.\d+) \$\[(\d\.\d+), (\d\.\d+)\]\$",
            interval(third),
            "rego payoff: H3",
        ),
        (
            rf"The ({_WORD_PATTERN}) losses are one module, \\texttt\{{(\w+)\}}, under "
            rf"({_WORD_PATTERN}) of its settings",
            (_word(first["losses"]), losses[0], _word(len(losses))),
            "rego payoff: where random testing wins",
        ),
        (
            r"each comparison holds at Holm-adjusted \$p = (0\.\d+)\$",
            (f"{holm.pop():.4f}",),
            "rego payoff: the module reading",
        ),
        (
            r"which the protocol reports apart, gives (\d+\.\d)\\%, (\d+\.\d)\\% and (\d+\.\d)\\%",
            (
                _pct(with_development["quotient"]),
                _pct(with_development["random_quotient"]),
                _pct(with_development["decision"]),
            ),
            "rego payoff: with the development module",
        ),
        (
            r"(\d+) real Rego policies,? decided by OPA",
            (str(head["policies"]),),
            "rego payoff: the figure's legend and caption",
        ),
        (
            r"(\d+) (?:Rego )?modules of one library",
            (str(by_module["policies"]),),
            "rego payoff: the threats",
        ),
        (
            r"is small, (\d\.\d) points with an interval of \$\[(\d\.\d), (\d\.\d)\]\$",
            tuple(
                f"{100 * value:.1f}" for value in (first["mean_difference"], *first["bootstrap_95"])
            ),
            "rego payoff: the threats, in points",
        ),
        (
            r"on real Rego, decided by OPA, (\d+\.\d)\\% where the proxy detects (\d+\.\d)\\%",
            (_pct(scores["quotient"]), _pct(scores["decision"])),
            "rego payoff: the conclusion",
        ),
    ]


def _rego_suite_claims(docs: Path) -> list[Claim]:
    """What a real suite's line coverage is worth against its mutation score (Gatekeeper Rego)."""

    suite = _load(docs, "rego-suite-adequacy-v1")
    head = suite["headline"]
    operators = suite["by_operator"]

    def rate(operator: str) -> str:
        counts = operators[operator]
        return str(round(100 * counts["killed"] / counts["total"]))

    return [
        (
            rf"on the ({_GROUPED}) Gatekeeper modules\s+that ship an author-written suite, one of",
            (_grouped(suite["population"]["modules_with_a_suite_and_a_decision"]),),
            "rego suite study: the population",
        ),
        (
            r"(\d+) (?:Gatekeeper modules that ship an author-written suite, besides|modules "
            r"outside) the one the harness was built on",
            (_grouped(suite["population"]["modules_with_a_suite_and_a_decision"] - 1),),
            "rego suite study: the population without the development module",
        ),
        (
            r"a mean of (\d+\.\d)\\% line coverage",
            (f"{head['mean_coverage']:.1f}",),
            "rego suite study: mean coverage",
        ),
        (
            r"killing\s+(\d+\.\d)\\% in the mean "
            rf"\(({_GROUPED}) of ({_GROUPED}) over the ({_GROUPED}) modules",
            (
                _pct(head["mean_mutation_score"]),
                _grouped(head["killed"]),
                _grouped(head["mutants"]),
                _grouped(head["modules"]),
            ),
            "rego suite study: mean mutation score and pool",
        ),
        (
            r"a per-module gap of (\d+\.\d) points with a 95\\% bootstrap interval of "
            r"\$\[(\d+\.\d), (\d+\.\d)\]\$",
            (
                _pct(head["mean_gap"]),
                _pct(head["gap_bootstrap_95"][0]),
                _pct(head["gap_bootstrap_95"][1]),
            ),
            "rego suite study: the gap",
        ),
        (
            r"the suites kill (\d+)\\% of deleted rules and (\d+)\\% of removed negations but "
            r"only (\d+)\\% of changed string literals, (\d+)\\% of changed comparisons and "
            r"(\d+)\\% of changed numbers",
            (
                rate("delete a rule"),
                rate("remove a negation"),
                rate("change a string literal"),
                rate("change a comparison"),
                rate("change a number literal"),
            ),
            "rego suite study: the uneven gap by operator",
        ),
        (
            r"[Aa]uthor-written Rego suites reach (\d+\.\d)\\% line coverage yet kill "
            r"(\d+\.\d)\\% of mutants",
            (f"{head['mean_coverage']:.1f}", _pct(head["mean_mutation_score"])),
            "rego suite study: the figures restated in the abstract and conclusion",
        ),
        (
            r"overstates adequacy by (\d+\.\d) points",
            (_pct(head["mean_gap"]),),
            "rego suite study: the gap, as the introduction restates it",
        ),
    ]


def _sample_oracle_claims(docs: Path) -> list[Claim]:
    """The sampled Rego modules against the engine's own dependency analysis."""

    oracle = _load(docs, "third-party-sample-rego-oracle-v1")
    # "all 6 are modules whose package other files of the repository share"
    assert oracle["disagreeing_modules_whose_package_is_shared"] == oracle["disagreements"]
    return [
        (
            rf"we put the ({_GROUPED}) sampled modules to the same check",
            (_grouped(oracle["modules"]),),
            "sample oracle: modules checked",
        ),
        (
            rf"Of the ({_GROUPED}), ({_GROUPED}) agree with the engine and ({_GROUPED}) do not, "
            rf"and all ({_GROUPED}) are modules whose package other files of the repository share",
            (
                _grouped(oracle["modules"]),
                _grouped(oracle["agreements"]),
                _grouped(oracle["disagreements"]),
                _grouped(oracle["disagreements"]),
            ),
            "sample oracle: agreement, and why the rest disagree",
        ),
        (
            rf"For the other ({_GROUPED}) modules the engine could not compile the repository",
            (_grouped(oracle["engine_could_not_load"]),),
            "sample oracle: modules the engine could not compile",
        ),
    ]


def _cedar_claims(docs: Path) -> list[Claim]:
    """The replication on real Cedar policies, and the real edits beside it."""

    cedar = _load(docs, "cedar-suite-strategy-study-v1")
    edits = _load(docs, "cedar-real-edits-v1")
    generated = _load(docs, "suite-strategy-study-v1")["operator_sets"]["A"]
    population, statuses = cedar["population"], cedar["file_statuses"]
    primary = cedar["analyses"]["primary: files with a condition"]
    secondary = cedar["analyses"]["secondary: every eligible file"]
    scores = primary["mean_expected_score"]
    first, second = primary["hypotheses"]["H1"], primary["hypotheses"]["H2"]
    floor = round(1 / (1 + cedar["resamples"]), 4)
    for analysis in (primary, secondary):
        assert all(h["p_value"] == floor for h in analysis["hypotheses"].values())
    ranked = [
        sorted(a["mean_expected_score"], key=a["mean_expected_score"].get)
        for a in (primary, secondary)
    ]
    assert ranked[0] == ranked[1], ranked
    decision_sizes = sorted(
        entry["decision_range"]
        for entry in cedar["files"].values()
        if entry["status"] == "scored" and entry.get("with_condition") and entry["expected_score"]
    )
    decision_median = str(int(statistics.median(decision_sizes)))
    sizes = {name: str(int(size)) for name, size in primary["median_suite_size"].items()}
    weakening_within_changes = all(
        pair["changes_a_decision"] for pair in edits["pairs"] if pair.get("weakens_a_decision")
    )
    assert weakening_within_changes
    # A scored file enters an analysis only if some mutant changes a decision, so the analyses
    # are smaller than the scored files by the files with nothing to detect. The paper names
    # the one such file with a condition, and says it gives every request the same decision.
    scored = [entry for entry in cedar["files"].values() if entry["status"] == "scored"]
    conditioned = [entry for entry in scored if entry["with_condition"]]
    nothing_to_detect = [entry for entry in conditioned if entry["expected_score"] is None]
    assert len(conditioned) - primary["files_scored"] == len(nothing_to_detect) == 1
    assert nothing_to_detect[0]["decision_range"] == 1
    assert set(nothing_to_detect[0]["mutants"]) == {"equivalent"}
    assert len(scored) - secondary["files_scored"] == sum(
        entry["expected_score"] is None for entry in scored
    )

    def interval(hypothesis: dict[str, Any]) -> tuple[str, str, str]:
        low, high = hypothesis["bootstrap_95"]
        return (f"{hypothesis['mean_difference']:.3f}", f"{low:.3f}", f"{high:.3f}")

    rows = (
        ("one witness per decision", "decision", decision_median),
        ("random, as many cells as decisions", "random_decision", decision_median),
        ("random, as many cells as quotient classes", "random_quotient", sizes["quotient"]),
        ("one witness per quotient class", "quotient", sizes["quotient"]),
        ("one witness per refinement cell", "refinement", sizes["refinement"]),
    )
    # Anchored on the row's end, because the same labels open the rows of the first table.
    claims: list[Claim] = [
        (
            rf"{re.escape(label)} & ({_GROUPED}) & (\d+\.\d)\\% \\\\",
            (size, _pct(scores[strategy])),
            f"cedar replication: {strategy} row",
        )
        for label, strategy, size in rows
    ]
    claims += [
        (
            rf"Of its ({_GROUPED}) files judged inside, ({_GROUPED}) parse under the Cedar engine",
            (
                _grouped(population["judged inside"]),
                _grouped(population["judged inside"] - population["Cedar does not parse it"]),
            ),
            "cedar replication: the population",
        ),
        (
            r"through its Python binding cedarpy (\d+\.\d+\.\d+)\.",
            (cedar["engine"].removeprefix("cedarpy "),),
            "cedar replication: the binding the artifact records",
        ),
        (
            rf"and ({_GROUPED}) are exact-eligible",
            (_grouped(population["exact-eligible"]),),
            "cedar replication: the eligible files",
        ),
        (
            rf"of which ({_GROUPED}) exceed the cap of ({_GROUPED}) cells",
            (_grouped(statuses["over the cell cap"]), _grouped(cedar["max_cells"])),
            "cedar replication: files over the cap",
        ),
        (
            rf"For each file, ({_GROUPED}) requests drawn",
            (_grouped(cedar["fuzz_requests_per_file"]),),
            "cedar replication: the completeness check's draws",
        ),
        (
            rf"and ({_GROUPED}) files failed and are excluded by name",
            (_grouped(statuses["missing cells"]),),
            "cedar replication: files failing completeness",
        ),
        (
            rf"Of the ({_GROUPED}) that remain, ({_GROUPED}) have at least one condition, and "
            rf"the ({_GROUPED}) of them with a mutant that changes a decision form the primary "
            r"analysis",
            (
                _grouped(statuses["scored"]),
                _grouped(len(conditioned)),
                _grouped(primary["files_scored"]),
            ),
            "cedar replication: the primary analysis",
        ),
        (
            r"Covering the quotient detects (\d+\.\d)\\% of the live mutants in expectation and a "
            r"random suite of the same size (\d+\.\d)\\%, a paired difference of (\d\.\d+) with a "
            r"95\\% bootstrap interval of \$\[(\d\.\d+), (\d\.\d+)\]\$, higher on "
            rf"({_GROUPED}) of the ({_GROUPED}) files and lower on ({_GROUPED})",
            (
                _pct(scores["quotient"]),
                _pct(scores["random_quotient"]),
                *interval(first),
                _grouped(first["wins"]),
                _grouped(first["policies"]),
                _grouped(first["losses"]),
            ),
            "cedar replication: H1",
        ),
        (
            r"Against the decision proxy, at (\d+\.\d)\\%, the difference is (\d\.\d+) "
            r"\$\[(\d\.\d+), (\d\.\d+)\]\$, higher on "
            rf"({_GROUPED}) files and lower on (none|{_GROUPED})",
            (
                _pct(scores["decision"]),
                *interval(second),
                _grouped(second["wins"]),
                "none" if second["losses"] == 0 else _grouped(second["losses"]),
            ),
            "cedar replication: H2",
        ),
        (
            rf"the secondary analysis, over the ({_GROUPED}) scored files with a mutant that "
            r"changes a decision, gives the same ordering",
            (_grouped(secondary["files_scored"]),),
            "cedar replication: the secondary analysis",
        ),
        (
            rf"a median of ({_GROUPED}) refinement cells against ({_GROUPED})",
            (sizes["refinement"], str(int(generated["median_suite_size"]["refinement"]))),
            "cedar replication: real policy is coarser than generated",
        ),
        (
            rf"Of the ({_GROUPED}) earlier-version pairs whose two versions are both eligible and "
            rf"under the cap, ({_GROUPED}) change a decision, and ({_GROUPED}) of those "
            rf"({_GROUPED}) weaken one",
            (
                _grouped(edits["pairs_measured"]),
                _grouped(edits["change_a_decision"]),
                _grouped(edits["weaken_a_decision"]),
                _grouped(edits["change_a_decision"]),
            ),
            "cedar real edits: what they do",
        ),
        (
            rf"would have caught those ({_GROUPED}) in expectation (\d+\.\d)\\% of the time, and "
            r"the decision proxy (\d+\.\d)\\%",
            (
                _grouped(edits["change_a_decision"]),
                _pct(edits["mean_detection_of_decision_changes"]["quotient"]),
                _pct(edits["mean_detection_of_decision_changes"]["decision"]),
            ),
            "cedar real edits: what a suite of the earlier version catches",
        ),
        (
            rf"On ({_GROUPED}) real Cedar files, (\d+\.\d)\\%, "
            r"(\d+\.\d)\\% and (\d+\.\d)\\%",
            (
                _grouped(primary["files_scored"]),
                _pct(scores["quotient"]),
                _pct(scores["random_quotient"]),
                _pct(scores["decision"]),
            ),
            "abstract: the Cedar replication",
        ),
        (
            r"replicated on real Cedar policy under a second protocol and the Cedar engine, "
            r"(\d+\.\d)\\% against (\d+\.\d)\\% and (\d+\.\d)\\%",
            (_pct(scores["quotient"]), _pct(scores["random_quotient"]), _pct(scores["decision"])),
            "contributions: the Cedar replication",
        ),
        (
            r"on real Cedar policy, decided by its engine, (\d+\.\d)\\% where the proxy detects "
            r"(\d+\.\d)\\%",
            (_pct(scores["quotient"]), _pct(scores["decision"])),
            "conclusion: the Cedar replication",
        ),
        (
            rf"failed the completeness check on ({_GROUPED}) files",
            (_grouped(statuses["missing cells"]),),
            "threats: Cedar files failing completeness",
        ),
    ]
    return claims


def _summary_claims(docs: Path) -> list[Claim]:
    """The new results as the abstract and the conclusion restate them."""

    suites = _load(docs, "suite-strategy-study-v1")["operator_sets"]["A"]
    review = _load(docs, "review-signal-study-v1")["operator_sets"]["A"]["generated"]
    summary = _load(docs, "third-party-sample-summary-v1")
    scores = suites["mean_expected_score"]
    weakenings = _pct(review["weakening"]["reviewers"]["trustweave_diff"]["recall"])
    assert len(summary["ecosystems"]) == 4
    # "parameterisation appears in all four": every sample holds at least one schema.
    assert all(row["sample"]["schemas"] for row in summary["ecosystems"].values())
    return [
        (
            rf"on ({_GROUPED}) generated policies, one witness per quotient class detects\s*"
            r"(\d+\.\d)\\% of seeded faults with a median of (\d+) tests, a random suite of the "
            r"same "
            r"size (\d+\.\d)\\%, and our\s*(\w+)-test decision proxy (\d+\.\d)\\%",
            (
                _grouped(suites["policies_scored"]),
                _pct(scores["quotient"]),
                str(int(suites["median_suite_size"]["quotient"])),
                _pct(scores["random_quotient"]),
                _word(int(suites["median_suite_size"]["decision"])),
                _pct(scores["decision"]),
            ),
            "abstract: the suite strategies",
        ),
        (
            r"it detects (\d+\.\d)\\% of seeded faults in expectation where the proxy detects "
            r"(\d+\.\d)\\%",
            (_pct(scores["quotient"]), _pct(scores["decision"])),
            "conclusion: the quotient against the proxy",
        ),
        (
            r"which the tool's own diff names for (\d+\.\d)\\% of them today",
            (weakenings,),
            "conclusion: the weakenings the diff names",
        ),
        (
            rf"({_GROUPED}) files from ({_GROUPED}) repositories in four languages, drawn by a "
            rf"recorded procedure and pinned file by file\. Each sits at or below its vendor's "
            rf"share, parameterisation appears in all four, and every one of their ({_GROUPED}) "
            rf"exclusions falls under the same three reasons",
            (
                _grouped(summary["sampled"]),
                _grouped(summary["repositories"]),
                _grouped(summary["exclusions"]),
            ),
            "contributions: the third-party samples",
        ),
    ]


def _third_party_claims(docs: Path) -> list[Claim]:
    """The samples of policy written outside the vendors, and the table beside the vendors."""

    summary = _load(docs, "third-party-sample-summary-v1")
    rows = summary["ecosystems"]
    manifests = {name: _load(docs, f"third-party-sample-{name}-corpus-v1") for name in rows}
    (repository_cap,) = {manifest["repository_cap"] for manifest in manifests.values()}
    (owner_cap,) = {manifest["owner_cap"] for manifest in manifests.values()}

    # The sentences that are claims about every case, checked as such.
    assert summary["taxonomy_holds"] and summary["exclusions_unclassified"] == 0
    assert all(rows[name]["vendor"]["schemas"] == 0 for name in ("kyverno", "iam", "cedar"))
    assert rows["rego"]["sample"]["schemas_outside_a_constraint_context"] == 0
    for name in ("kyverno", "rego", "cedar"):
        sample, vendor = rows[name]["sample"], rows[name]["vendor"]
        assert vendor["share_inside_of_policies"] > sample["share_inside_of_policies_wilson_95"][1]
    assert (
        rows["iam"]["sample"]["share_inside_of_policies"]
        == rows["iam"]["vendor"]["share_inside_of_policies"]
    )

    def share(name: str, side: str) -> str:
        # From the counts: a share stored at four places and formatted again at one rounds
        # twice, which turned 270 of 342 (78.947%) into 79.0.
        counts = rows[name][side]
        return _pct(counts["inside"] / counts["policies"])

    claims: list[Claim] = []
    for label, name in (
        ("Kyverno", "kyverno"),
        ("Rego", "rego"),
        ("AWS IAM", "iam"),
        ("Cedar", "cedar"),
    ):
        row, sample = rows[name], rows[name]["sample"]
        low, high = sample["share_inside_of_policies_wilson_95"]
        claims.append(
            (
                rf"{label} & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & "
                rf"({_GROUPED}) & ({_GROUPED}) & ({_GROUPED}) & (\d+\.\d)\\% "
                r"\[(\d+\.\d), (\d+\.\d)\] & (\d+\.\d)\\%",
                (
                    _grouped(row["frame"]),
                    _grouped(row["sampled"]),
                    _grouped(row["repositories"]),
                    _grouped(sample["inside"]),
                    _grouped(sample["outside"]),
                    _grouped(sample["undetermined"]),
                    _grouped(sample["schemas"]),
                    share(name, "sample"),
                    _pct(low),
                    _pct(high),
                    share(name, "vendor"),
                ),
                f"third-party sample: {name} row",
            )
        )
    schemas = {name: rows[name]["sample"]["schemas"] for name in rows}
    resting = rows["rego"]["sample"]["resting_on_an_undefined_data_document"]
    claims += [
        (
            rf"gives the result: ({_GROUPED}) files from ({_GROUPED}) repositories",
            (_grouped(summary["sampled"]), _grouped(summary["repositories"])),
            "third-party sample: files and repositories",
        ),
        (
            rf"under caps of ({_WORD_PATTERN}) and ({_WORD_PATTERN}) files",
            (_word(repository_cap), _word(owner_cap)),
            "third-party sample: the caps, in the procedure",
        ),
        (
            rf"under caps of ({_WORD_PATTERN}) files per repository and ({_WORD_PATTERN}) "
            r"per owner",
            (_word(repository_cap), _word(owner_cap)),
            "third-party sample: the caps, in the caption",
        ),
        (
            rf"({_GROUPED}) of the ({_GROUPED}) Kyverno files are Helm templates, ({_GROUPED}) of "
            rf"the IAM documents interpolate a Terraform or CloudFormation placeholder, "
            rf"({_GROUPED}) Cedar files are templates and ({_GROUPED}) Rego modules are "
            rf"constraint templates: ({_GROUPED}) policy schemas",
            (
                _grouped(schemas["kyverno"]),
                _grouped(rows["kyverno"]["sampled"]),
                _grouped(schemas["iam"]),
                _grouped(schemas["cedar"]),
                _grouped(schemas["rego"]),
                _grouped(sum(schemas.values())),
            ),
            "third-party sample: the schemas, by language",
        ),
        (
            r"Kyverno (\d+\.\d)\\% against (\d+\.\d)\\%, Rego (\d+\.\d)\\% against (\d+\.\d)\\%, "
            r"Cedar (\d+\.\d)\\% against (\d+\.\d)\\%, and IAM (\d+\.\d)\\% in both",
            (
                share("kyverno", "sample"),
                share("kyverno", "vendor"),
                share("rego", "sample"),
                share("rego", "vendor"),
                share("cedar", "sample"),
                share("cedar", "vendor"),
                share("iam", "sample"),
            ),
            "third-party sample: each share against its vendor",
        ),
        (
            rf"every one of the ({_GROUPED}) exclusions in\s*these samples falls under the same "
            r"three reasons",
            (_grouped(summary["exclusions"]),),
            "third-party sample: the taxonomy holds",
        ),
        (
            rf"({_GROUPED}) Rego verdicts rest on a \\texttt\{{data\}} document that no module "
            r"of the repository defines",
            (_grouped(resting),),
            "third-party sample: Rego verdicts resting on undefined data",
        ),
        (
            rf"The ({_GROUPED}) bound how far that reading could move the Rego row",
            (_grouped(resting),),
            "third-party sample: the bound on the Conftest reading",
        ),
    ]
    return claims


def _review_claims(docs: Path) -> list[Claim]:
    """The reviewer study: what each reviewer flags, and the two edits the diff never shows."""

    study = _load(docs, "review-signal-study-v1")["operator_sets"]["A"]
    change, weakening = study["generated"]["change"], study["generated"]["weakening"]

    def row(reviewer: str) -> tuple[str, ...]:
        first, second = change["reviewers"][reviewer], weakening["reviewers"][reviewer]
        return tuple(
            f"{value:.3f}"
            for value in (
                first["recall"],
                first["precision"],
                second["recall"],
                second["precision"],
            )
        )

    # "produce no signal at all" and "all of them a decision flipped towards permission or a
    # default changed to allow" are claims about every edit, so they are checked as such.
    silent = study["decision_edits_by_direction"]
    assert silent["flip_decision to a stricter decision"]["signalled"] == 0
    assert silent["default_decision to anything but allow"]["signalled"] == 0
    named = {
        operator
        for operator, entry in weakening["recall_by_operator"].items()
        if entry["trustweave_diff_recall"]
    }
    assert named == {"flip_decision", "default_decision"}, named

    labels = (
        (r"exact table comparison \(Theorem~\\ref\{thm:equivalence\}\)", "exact_table"),
        ("TrustWeave's diff signals", "trustweave_diff"),
        ("suite, one witness per quotient class", "suite_quotient"),
        ("suite, one witness per decision", "suite_decision"),
        ("text diff", "text_diff"),
    )
    claims: list[Claim] = [
        (
            rf"{label} & (\d\.\d+) & (\d\.\d+) & (\d\.\d+) & (\d\.\d+)",
            row(reviewer),
            f"reviewers: {reviewer} row",
        )
        for label, reviewer in labels
    ]
    tool = change["reviewers"]["trustweave_diff"]
    claims += [
        (
            rf"--- ({_GROUPED}) changes, of which ({_GROUPED}) are semantic and "
            rf"({_GROUPED}) weaken the policy ---",
            (
                _grouped(change["changes"]),
                _grouped(change["positives"]),
                _grouped(weakening["positives"]),
            ),
            "reviewers: the changes scored",
        ),
        (
            rf"pooled over ({_GROUPED}) proposed changes",
            (_grouped(change["changes"]),),
            "reviewers: the changes pooled in the table",
        ),
        (
            rf"The diff routes (\d+\.\d)\\% of semantic changes to a reviewer and raises "
            rf"({_GROUPED}) alarms on edits that change no decision",
            (_pct(tool["recall"]), _grouped(tool["false_alarms"])),
            "reviewers: what the diff routes and its false alarms",
        ),
        (
            r"It names (\d+\.\d)\\% of the weakenings as weakenings",
            (_pct(weakening["reviewers"]["trustweave_diff"]["recall"]),),
            "reviewers: weakenings the diff names",
        ),
        (
            rf"a median of ({_GROUPED}) cells per change",
            (_grouped(int(study["exact_table_cells_per_change_median"])),),
            "reviewers: what the exact comparison decides per change",
        ),
    ]
    return claims


def _payoff_claims(docs: Path) -> list[Claim]:
    """The suite-strategy study: the sample it ran on, the table, and the three comparisons."""

    sample = _load(docs, "generated-policy-sample-v1")
    study = _load(docs, "suite-strategy-study-v1")
    paper, extended = study["operator_sets"]["A"], study["operator_sets"]["B"]
    sizes = {name: str(int(size)) for name, size in paper["median_suite_size"].items()}
    first, second, third = (paper["hypotheses"][name] for name in ("H1", "H2", "H3"))

    def means(strategy: str) -> tuple[str, str]:
        return (
            _pct(paper["mean_expected_score"][strategy]),
            _pct(extended["mean_expected_score"][strategy]),
        )

    def interval(hypothesis: dict[str, Any]) -> tuple[str, str, str]:
        low, high = hypothesis["bootstrap_95"]
        return (f"{hypothesis['mean_difference']:.3f}", f"{low:.3f}", f"{high:.3f}")

    # Two sentences are checked rather than quoted: that every comparison hit the test's
    # floor, and that the extended operators order the strategies as the paper's do.
    floor = round(1 / (1 + study["resamples"]), 4)
    assert all(paper["hypotheses"][name]["p_value"] == floor for name in ("H1", "H2", "H3"))
    holm = {paper["hypotheses"][name]["p_value_holm"] for name in ("H1", "H2", "H3")}
    assert len(holm) == 1, holm
    ranked = [
        sorted(scores["mean_expected_score"], key=scores["mean_expected_score"].get)
        for scores in (paper, extended)
    ]
    assert ranked[0] == ranked[1], ranked

    rows = (
        ("one witness per decision", "decision", sizes["decision"]),
        ("random, as many cells as decisions", "random_decision", sizes["decision"]),
        ("random, as many cells as quotient classes", "random_quotient", sizes["quotient"]),
        ("one witness per quotient class", "quotient", sizes["quotient"]),
        ("one witness per refinement cell", "refinement", sizes["refinement"]),
    )
    claims: list[Claim] = [
        (
            rf"{re.escape(label)} & ({_GROUPED}) & (\d+\.\d)\\% & (\d+\.\d)\\%",
            (size, *means(strategy)),
            f"suite strategies: {strategy} row",
        )
        for label, strategy, size in rows
    ]
    claims += [
        (
            rf"at most ({_GROUPED}) cells, until it has ({_GROUPED}): it drew ({_GROUPED}) "
            rf"candidates, the parser refused ({_GROUPED}) and ({_GROUPED}) were over the cap",
            (
                _grouped(sample["max_cells"]),
                _grouped(len(sample["policies"])),
                _grouped(sample["candidates_drawn"]),
                _grouped(sample["rejected_by_parser"]),
                _grouped(sample["over_cell_cap"]),
            ),
            "suite strategies: the generated sample",
        ),
        (
            rf"averaged over the ({_GROUPED}) generated policies",
            (_grouped(paper["policies_scored"]),),
            "suite strategies: policies scored",
        ),
        (
            r"covering the quotient detects (\d+\.\d)\\% of the live mutants in expectation "
            r"against (\d+\.\d)\\% for a random suite of the same size: a paired difference of "
            r"(\d\.\d+), with a 95\\% bootstrap interval of \$\[(\d\.\d+), (\d\.\d+)\]\$, "
            rf"higher on ({_GROUPED}) of the ({_GROUPED}) policies and lower on ({_GROUPED})",
            (
                _pct(paper["mean_expected_score"]["quotient"]),
                _pct(paper["mean_expected_score"]["random_quotient"]),
                *interval(first),
                _grouped(first["wins"]),
                _grouped(first["policies"]),
                _grouped(first["losses"]),
            ),
            "suite strategies: H1, the quotient against random at equal size",
        ),
        (
            r"Against the\s*decision proxy the difference is (\d\.\d+) "
            r"\$\[(\d\.\d+), (\d\.\d+)\]\$, higher on "
            rf"({_GROUPED}) policies and lower on (none|{_GROUPED})",
            (
                *interval(second),
                _grouped(second["wins"]),
                "none" if second["losses"] == 0 else _grouped(second["losses"]),
            ),
            "suite strategies: H2, the quotient against the proxy",
        ),
        (
            r"by (\d\.\d+)\s*\$\[(\d\.\d+), (\d\.\d+)\]\$, so it is not worthless",
            interval(third),
            "suite strategies: H3, the proxy against random at equal size",
        ),
        (
            rf"at a median of ({_WORD_PATTERN}) test cases against ({_GROUPED})",
            (_word(int(paper["median_suite_size"]["decision"])), sizes["quotient"]),
            "suite strategies: the proxy's suite size against the quotient's",
        ),
        (
            rf"reach \$p = (\d\.\d+)\$, the smallest a ({_GROUPED})-permutation sign-flip test "
            r"can return, and \$p = (\d\.\d+)\$ after Holm's correction",
            (f"{floor:.4f}", _grouped(study["resamples"]), f"{holm.pop():.4f}"),
            "suite strategies: the permutation floor, raw and corrected",
        ),
        (
            rf"at a median of ({_GROUPED}) cells rather than ({_GROUPED})",
            (sizes["refinement"], sizes["quotient"]),
            "suite strategies: the refinement's suite size against the quotient's",
        ),
        (
            r"detects (\d+\.\d)\\% of seeded faults in expectation, against (\d+\.\d)\\% for a "
            r"random suite of the same size and (\d+\.\d)\\% for our decision proxy, "
            rf"across ({_GROUPED}) generated policies",
            (
                _pct(paper["mean_expected_score"]["quotient"]),
                _pct(paper["mean_expected_score"]["random_quotient"]),
                _pct(paper["mean_expected_score"]["decision"]),
                _grouped(paper["policies_scored"]),
            ),
            "suite strategies: the contribution as the introduction states it",
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
    # A paper split in two may state the decomposition in both files; every statement must
    # carry the same counts, and one copy must sum to the artifact's figure.
    for length in range(1, len(counts) + 1):
        if len(counts) % length == 0 and counts == counts[:length] * (len(counts) // length):
            if sum(counts[:length]) == equivalent:
                return []
            break
    return [
        f"the worked example's mechanisms account for {sum(counts)} equivalent mutants "
        f"({' + '.join(str(count) for count in counts)}) where the artifact reports "
        f"{equivalent}"
    ]


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


# --- figures ----------------------------------------------------------------------------
#
# A figure's data sits in `\addplot coordinates {...}` and no prose pin reaches it, so a
# plotted series can go on agreeing with a caption that agrees with an artifact while the
# series itself is a year out of date. These checks recompute each series from the artifact
# it claims to come from and compare the coordinates.

TAXONOMY_FIGURE_ORDER = (
    "AWS IAM",
    "Cedar",
    "XACML",
    "Kyverno (vendor)",
    "Kyverno (third-party)",
    "Rego (GCP library)",
    "Rego (four corpora)",
    "Azure Policy",
)
TAXONOMY_FIGURE_BANDS = (
    "inside",
    "not a policy",
    "the subject does not determine the guard",
    "reads evaluation-time state",
    "undetermined",
)


PAYOFF_FIGURE_ORDER = ("decision", "random_decision", "random_quotient", "quotient", "refinement")
# The graphical abstract draws three of those strategies, best first.
ABSTRACT_FIGURE_ORDER = ("quotient", "random_quotient", "decision")


def _axes(tex: str, name: str) -> list[list[list[tuple[str, str]]]]:
    """The `\addplot coordinates {...}` series of every pgfplots axis named `name`.

    A data figure is found by the axis it draws (`\begin{axis}[name=...]`) rather than by its
    figure label, because a paper with a condensed version and an extended one carries the same
    figure twice, sometimes as one panel of a larger figure, and every copy has to agree with the
    artifact, not only the first.
    """

    found = []
    for match in re.finditer(r"\\begin\{axis\}\[", tex):
        start, depth, index = match.end(), 0, match.end()
        while index < len(tex):
            char = tex[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == "]" and depth == 0:
                break
            index += 1
        options = tex[start:index]
        if not re.search(r"(?:^|,)\s*name\s*=\s*" + re.escape(name) + r"\s*(?:,|$)", options):
            continue
        end = tex.find(r"\end{axis}", index)
        body = tex[index:end]
        found.append(
            [
                re.findall(r"\(([-\d.e+]+)\s*,\s*([-\d.e+]+)\)", series)
                for series in re.findall(r"\\addplot[^{]*coordinates\s*\{([^}]*)\}", body)
            ]
        )
    return found


def _compare_figure(
    tex: str, name: str, what: str, bands: tuple[str, ...], expected: list[list[tuple[str, str]]]
) -> list[str]:
    problems: list[str] = []
    copies = _axes(tex, name)
    if not copies:
        return [f"the {what} figure states no data, or its axis is no longer named {name}"]
    for number, plotted in enumerate(copies, start=1):
        where = f"{what} figure" if len(copies) == 1 else f"{what} figure (copy {number})"
        for band, want, got in zip(bands, expected, plotted, strict=False):
            if want != got:
                problems.append(
                    f"{where}, {band!r} series: the manuscript plots "
                    f"{[value for value, _ in got]} where the artifact gives "
                    f"{[value for value, _ in want]}"
                )
        if len(plotted) != len(expected):
            problems.append(
                f"the {where} plots {len(plotted)} series where the artifact has {len(expected)}"
            )
    return problems


PAYOFF_SERIES = ("generated policies", "real Cedar policies", "real Rego policies")


def _payoff_series(
    docs: Path, order: tuple[str, ...], populations: int = 3
) -> list[list[tuple[str, str]]]:
    # The payoff figure plots the suite-strategy studies on one scale: the generated policies
    # under the paper's operators, the primary analysis of the real Cedar policies, and the real
    # Rego policies. The graphical abstract draws the first two.
    generated = _load(docs, "suite-strategy-study-v1")["operator_sets"]["A"]["mean_expected_score"]
    cedar = _load(docs, "cedar-suite-strategy-study-v1")["analyses"][
        "primary: files with a condition"
    ]["mean_expected_score"]
    rego = _load(docs, "rego-suite-strategy-study-v1")["headline"]["mean_expected_score"]
    return [
        [(_pct(scores[strategy]), str(index)) for index, strategy in enumerate(order)]
        for scores in (generated, cedar, rego)[:populations]
    ]


# The taxonomy figure places each exclusion by the obstruction that would survive supplying its
# parameters, and as a schema only when nothing else keeps it out: the bands of
# `exclusion_taxonomy.crosstab`, rounded so that every bar sums to exactly 100.0.
TAXONOMY_CROSSTAB_BANDS = {
    "inside": "inside",
    "not a policy": "schema only",
    "the subject does not determine the guard": "subject",
    "reads evaluation-time state": "evaluation time",
    "undetermined": "undetermined",
}


def figure_findings(tex: str, docs: Path) -> list[str]:
    crossed = _load(docs, "exclusion-crosstab-v1")
    rows = {row["corpus"]: row for row in crossed["rows"]}
    expected: list[list[tuple[str, str]]] = []
    for band in TAXONOMY_FIGURE_BANDS:
        series = []
        for index, corpus in enumerate(TAXONOMY_FIGURE_ORDER):
            value = rows[corpus]["band_shares"][TAXONOMY_CROSSTAB_BANDS[band]]
            series.append((f"{value:.1f}", str(index)))
        expected.append(series)
    problems = _compare_figure(tex, "taxonomy", "taxonomy", TAXONOMY_FIGURE_BANDS, expected)

    problems += _compare_figure(
        tex, "payoff", "payoff", PAYOFF_SERIES, _payoff_series(docs, PAYOFF_FIGURE_ORDER)
    )

    # `fig:cost` is not checked, for the reason recorded beside the withdrawn cost claims.
    return problems


def abstract_findings(paper: Path, docs: Path) -> list[str]:
    """The graphical abstract beside the manuscript, when there is one.

    A journal that asks for a graphical table-of-contents entry prints it on its contents
    page, away from the paper, so a number that drifts there is read without the table that
    would contradict it. Its bars are three of the payoff figure's, in the order it draws them.
    """

    figure = paper.with_name("graphical-abstract.tex")
    if not figure.is_file():
        return []
    return _compare_figure(
        figure.read_text(encoding="utf-8"),
        "abstract",
        "graphical abstract",
        PAYOFF_SERIES[:2],
        _payoff_series(docs, ABSTRACT_FIGURE_ORDER, populations=2),
    )


def with_supplement(tex: str, paper: Path) -> str:
    """The manuscript with its Supporting Information, when the paper is split in two.

    A journal that caps the main text sends the long measurement notes to a separate file,
    `supplement.tex` beside the manuscript. The claims are about the paper as a whole, so
    the supplement's body is read as if it followed the manuscript. A reference that
    crosses the file boundary is written `\\ref{S-label}` or `\\ref{M-label}` for the
    cross-document package; the prefix is dropped so the label resolves here.
    """

    supplement = paper.with_name("supplement.tex")
    if supplement.is_file():
        text = supplement.read_text(encoding="utf-8")
        start, end = "%%BODY-START", "%%BODY-END"
        if start in text and end in text:
            text = text.split(start, 1)[1].split(end, 1)[0]
        tex = tex + "\n" + text
    return re.sub(r"\\(ref|pageref|eqref)\{[SM]-", r"\\\1{", tex)


def check(paper: Path, docs: Path) -> list[str]:
    tex = with_supplement(paper.read_text(encoding="utf-8"), paper)
    bib = (paper.parent / "refs.bib").read_text(encoding="utf-8")
    flat = flatten(tex)
    problems = structural_findings(tex, bib)
    problems += claim_findings(flat, numeric_claims(docs))
    problems += decomposition_findings(flat, docs)
    problems += corpus_findings(bib, docs)
    problems += figure_findings(tex, docs)
    problems += abstract_findings(paper, docs)
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
