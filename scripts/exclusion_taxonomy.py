"""Why a policy is outside the fragment, across every language measured.

The membership measurements answer "how much is inside". This answers the question that
turns out to be more interesting: of everything outside, *what put it there*. Across six
policy languages and eight corpora the answer is three things, and only three.

**The artifact is not a policy.** A parameterised Azure Policy definition or a Gatekeeper
constraint template is a policy *schema* -- a function from parameter bindings to policies
-- so it determines no decision function and the question cannot be put to it until an
assignment or a Constraint supplies the bindings. This is the largest category, and it
recurs in two ecosystems that share no design lineage, which is the evidence that it is a
fact about how policy languages are built rather than an artefact of one of them. Azure
sharpens it: a definition whose every parameter carries a `defaultValue` *does* determine a
decision function, so the line falls between "parameterised" and "parameterised without
defaults" rather than at parameterisation itself.

**The subject does not determine the guard.** This is the category whose name matters,
because the obvious name for it is wrong. It is tempting to say "the policy reads state the
evaluator was not handed", and that is false of the largest member: Gatekeeper *does* hand
OPA its cached cluster inventory, injected as `data.inventory` before evaluation. What is
true, and what the fragment actually requires, is that the guard's value be determined by
the subject the decision is about together with literals in the policy.

That criterion sorts the cases consistently where "was it handed over" does not. Cedar's
entity hierarchy is part of the authorization request, so it is the subject, and a hierarchy
of unbounded depth stays inside. Azure's `subscription()` and `resourceGroup()` are
derivable from the resource under evaluation, so they too are the subject. But Gatekeeper's
inventory is ambient cluster state rather than the admission request; an ARM `reference()`
names a resource other than the one being evaluated; a Kyverno `context` entry or CEL call
queries the API server; `verifyImages` fetches a signature from a registry; an XACML
`AttributeSelector` ranges over an arbitrary document. In each of those the guard's value
turns on something the subject does not fix, so no witness is constructible from the policy
text and the partition is not the policy's to determine.

**A guard reads state that exists only at evaluation time.** The clock, in two policies,
and the network, in one -- a library helper that calls `http.send`. Worth keeping separate
from the category above rather than folded into it: this is not state that some other
subject could have carried, it is state that does not exist until evaluation, so no choice
of subject fixes it. The row was named for the clock alone until the differential check
against `opa deps` found the network call the adapter had missed, and a row that cannot
take a fourth member honestly is a row that was named too narrowly.

    python scripts/exclusion_taxonomy.py [--json out.json]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

# (corpus label, artifact stem). One row per measured corpus, in size order.
CORPORA: tuple[tuple[str, str], ...] = (
    ("AWS IAM", "fragment-membership-iam-wide-v1"),
    ("Azure Policy", "fragment-membership-azure-wide-v1"),
    ("XACML", "fragment-membership-xacml-wide-v1"),
    ("Kyverno (vendor)", "fragment-membership-kyverno-wide-v1"),
    ("Rego (four corpora)", "fragment-membership-rego-wide-v1"),
    ("Rego (GCP library)", "fragment-membership-rego-gcp-v1"),
    ("Kyverno (third-party)", "fragment-membership-kyverno-thirdparty-v1"),
    ("Cedar", "fragment-membership-cedar-wide-v1"),
)

# The three kinds, each matched by phrases the adapters actually emit. A reason matching
# none of them is reported rather than silently bucketed: the claim is that the taxonomy is
# exhaustive, and a claim like that is only worth making if its instrument can refute it.
KINDS: dict[str, tuple[str, ...]] = {
    "not a policy": ("policy schema",),
    "the subject does not determine the guard": (
        "the host injects",
        "context entry fetches",
        "reads a data document",
        "reaches outside",
        "runtime state of a resource",
        "whether a related resource exists",
        "verifies an image",
        "selects over request content",
        "selects on Namespace labels",
        "reads outside the policy",
        "reads something outside the admission request",
    ),
    "reads evaluation-time state": ("reads the clock", "not a function of its arguments"),
}


def classify(reason: str) -> str | None:
    for kind, needles in KINDS.items():
        if any(needle in reason for needle in needles):
            return kind
    return None


def kind_of(entry: dict[str, Any]) -> str | None:
    """Which row an exclusion belongs in, over every obstruction it carries.

    The verdict *reports* the obstruction that survives instantiation, so an artifact that is
    a schema and also reads state the subject does not carry is reported under the read. That
    is the right thing to tell a reader about one artifact and the wrong thing to count by:
    it made the size of the "not a policy" row depend on which other obstruction happened to
    outrank it, and the row moved by 649 Azure definitions when a second guard region was
    read for the first time without any artifact changing its schema status. So the row is
    decided over all the reasons an adapter recorded, and being a schema decides it: an
    artifact that determines no decision function is not a policy, whatever else is also true
    of it, which is the argument the row is named for.
    """

    reasons = entry.get("reasons") or [entry["reason"]]
    if any(classify(reason) == "not a policy" for reason in reasons):
        return "not a policy"
    return classify(entry["reason"])


def measure(docs: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    totals: Counter[str] = Counter()
    unclassified: Counter[str] = Counter()
    considered = inside = 0

    for label, stem in CORPORA:
        findings = json.loads((docs / f"{stem}.json").read_text(encoding="utf-8"))
        counts = findings["counts"]
        by_kind: Counter[str] = Counter()
        for entry in findings["policies"]:
            if entry["verdict"] != "outside":
                continue
            kind = kind_of(entry)
            if kind is None:
                unclassified[entry["reason"][:120]] += 1
            else:
                by_kind[kind] += 1
                totals[kind] += 1
        total = sum(counts.values())
        considered += total
        inside += counts["inside"]
        rows.append(
            {
                "corpus": label,
                "artifact": stem,
                "policies_considered": total,
                "inside": counts["inside"],
                "outside": counts["outside"],
                "undetermined": counts["undetermined"],
                "share_inside": round(counts["inside"] / total, 4) if total else None,
                "exclusions_by_kind": dict(sorted(by_kind.items())),
            }
        )

    schemas = totals["not a policy"]
    policies = considered - schemas
    return {
        "schema_version": "v1",
        "corpora": len(CORPORA),
        "artifacts_considered": considered,
        "artifacts_inside": inside,
        "policy_schemas": schemas,
        "policies_considered": policies,
        "share_inside_of_policies": round(inside / policies, 4) if policies else None,
        "exclusions": sum(totals.values()) + sum(unclassified.values()),
        "exclusions_by_kind": dict(sorted(totals.items())),
        "exclusions_unclassified": dict(unclassified),
        "taxonomy_is_exhaustive": not unclassified,
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docs", type=Path, default=DOCS)
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)

    findings = measure(arguments.docs)
    print(
        f"{findings['corpora']} corpora, {findings['artifacts_considered']} artifacts, "
        f"{findings['artifacts_inside']} inside"
    )
    for row in findings["rows"]:
        print(
            f"  {row['corpus']:24s} {row['policies_considered']:5d}  "
            f"inside {row['inside']:5d}  outside {row['outside']:4d}  "
            f"undetermined {row['undetermined']}"
        )
    print()
    print(f"{findings['exclusions']} exclusions, by kind:")
    for kind, count in findings["exclusions_by_kind"].items():
        print(f"  {count:5d}  {kind}")
    if findings["exclusions_unclassified"]:
        print("  UNCLASSIFIED:")
        for reason, count in findings["exclusions_unclassified"].items():
            print(f"    {count:4d}  {reason}")
    print()
    print(
        f"policy schemas {findings['policy_schemas']}; of the "
        f"{findings['policies_considered']} artifacts that are policies, "
        f"{findings['artifacts_inside']} are inside "
        f"({100 * (findings['share_inside_of_policies'] or 0):.1f}%)"
    )

    if arguments.json:
        arguments.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
