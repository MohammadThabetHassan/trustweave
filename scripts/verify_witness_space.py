"""Certify the witness construction with an SMT solver instead of an argument.

Theorem 1 bounds the policy-relative quotient by a product, and two of its terms are over
set-valued components whose predicates are existential: purpose tags, matched by non-empty
intersection with a named set, and capabilities, matched by a named pattern that may be
exact or a final namespace wildcard. Those two terms are where the proof was wrong. It
claimed each of the `2^|K_P|` capability subsets is occupied by some subject, and nothing
matching `net.http` fails to match `net.*`, so on a policy naming both there is a subset
occupied by nothing at all.

So the construction is checked rather than argued. For a set of named patterns this asks
Z3, for every candidate signature, whether any capability set realises it, and compares the
answer against what `witness_space()` enumerates. Agreement in both directions is what is
wanted: the construction must produce every achievable signature (or the quotient is
incomplete and Corollary 4's premise is unreachable) and no unachievable one (or it invents
classes no subject occupies).

The same is done for purpose tags, where the collapse has a different cause -- the predicate
is coarser than the subsets rather than the values subsuming one another.

Usage:
    python scripts/verify_witness_space.py [--json out.json]
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    import z3
except ImportError:  # pragma: no cover - the checker is optional tooling
    z3 = None  # type: ignore[assignment]

from trustweave.policy_predicates import capability_matches  # noqa: E402

# The literal the harness used as its fixed outsider sentinel. The two cases below name it on
# purpose: it is a legal capability and a legal namespace tail, so a policy is free to use it,
# and while the sentinel was a constant the construction lost a class when one did. The string
# is spelled out here rather than imported so that the cross-check keeps testing the case even
# if the harness renames its stem.
FORMER_SENTINEL = "trustweave-witness-outsider"

# Pattern sets chosen to cover the shapes that decide the question: nested, disjoint, exact,
# a chain of three, a mix, and the two that collide with the outsider witness. Every one is a
# policy a reviewer could write.
CAPABILITY_CASES: tuple[tuple[str, ...], ...] = (
    (),
    ("net.*",),
    ("net.*", "net.http"),
    ("net.*", "fs.*"),
    ("net.http", "net.https"),
    ("net.*", "net.http", "net.http.get"),
    ("net.*", "fs.*", "net.http"),
    ("a", "b", "c"),
    # The witness for `net.*` was `net.` followed by the sentinel, so this pair produced two
    # classes where three are achievable, and the missing one -- matches `net.*`, not the
    # exact literal -- is where an unnamed capability belongs.
    ("net.*", f"net.{FORMER_SENTINEL}"),
    # The bare sentinel as a capability of its own, the shape that collides in every
    # component the outsider stands in for.
    (FORMER_SENTINEL,),
)
# (named tags, the tag sets successive rules name)
PURPOSE_CASES: tuple[tuple[tuple[str, ...], tuple[tuple[str, ...], ...]], ...] = (
    (("a", "b"), (("a", "b"),)),
    (("a", "b"), (("a",), ("b",))),
    (("a", "b", "c"), (("a", "b"), ("b", "c"))),
    (("a",), (("a",),)),
)


def _matches(pattern: str, capability: Any) -> Any:
    """The engine's matching rule, as an SMT constraint over a string variable."""

    if pattern.endswith(".*"):
        return z3.PrefixOf(z3.StringVal(pattern[:-1]), capability)
    return capability == z3.StringVal(pattern)


def capability_signature_achievable(patterns: tuple[str, ...], signature: tuple[bool, ...]) -> bool:
    """Whether any capability set matches exactly the patterns the signature marks true.

    One string variable per pattern the signature marks true is enough. Every true pattern
    needs a witness, and adding capabilities can only turn further patterns true, so a
    signature realisable by any set is realisable by one of that size.
    """

    wanted = [pattern for pattern, held in zip(patterns, signature, strict=True) if held]
    unwanted = [pattern for pattern, held in zip(patterns, signature, strict=True) if not held]
    if not wanted:
        # The empty capability set matches nothing, so the all-false signature always holds.
        return True
    solver = z3.Solver()
    capabilities = [z3.String(f"c{index}") for index in range(len(wanted))]
    for pattern in wanted:
        solver.add(z3.Or([_matches(pattern, capability) for capability in capabilities]))
    for pattern in unwanted:
        for capability in capabilities:
            solver.add(z3.Not(_matches(pattern, capability)))
    return solver.check() == z3.sat


def purpose_signature_achievable(
    tags: tuple[str, ...], rule_sets: tuple[tuple[str, ...], ...], signature: tuple[bool, ...]
) -> bool:
    """Whether any set of carried tags answers each rule's intersection test as given."""

    solver = z3.Solver()
    carried = {tag: z3.Bool(f"has_{tag}") for tag in tags}
    for rule_set, held in zip(rule_sets, signature, strict=True):
        intersects = z3.Or(
            [carried[tag] for tag in rule_set if tag in carried] or [z3.BoolVal(False)]
        )
        solver.add(intersects if held else z3.Not(intersects))
    return solver.check() == z3.sat


def dominates(broad: str, narrow: str) -> bool:
    """Whether every capability matching `narrow` matches `broad` as well.

    A final-wildcard pattern matches every string carrying its stem as a prefix, so it
    dominates any pattern whose own stem or literal extends that prefix. A literal matches
    one string, so it dominates only itself and never a wildcard, whose witness is its stem
    followed by a tail no literal ends with.
    """

    if broad.endswith(".*"):
        stem = broad[:-1]
        return (narrow[:-1] if narrow.endswith(".*") else narrow).startswith(stem)
    return not narrow.endswith(".*") and broad == narrow


def capability_signature_achievable_by_criterion(
    patterns: tuple[str, ...], signature: tuple[bool, ...]
) -> bool:
    """The closed form the paper states: no pattern marked false dominates one marked true.

    Matching is monotone in the capability set, so a signature is realised by some set
    exactly when each true pattern has a single witness that no false pattern matches, and
    for wildcard and literal patterns such a witness exists exactly when no false pattern
    dominates the true one. The solver check above decides the same question by search;
    this decides it by the criterion, and `check()` records whether the two agree.
    """

    return not any(
        dominates(unwanted, wanted)
        for wanted, held in zip(patterns, signature, strict=True)
        if held
        for unwanted, denied in zip(patterns, signature, strict=True)
        if not denied
    )


def purpose_signature_achievable_by_criterion(
    rule_sets: tuple[tuple[str, ...], ...], signature: tuple[bool, ...]
) -> bool:
    """A true intersection test needs a tag no false test names: each named set marked true
    must contain a tag outside the union of the sets marked false."""

    denied = {
        tag
        for rule_set, held in zip(rule_sets, signature, strict=True)
        if not held
        for tag in rule_set
    }
    return all(
        not set(rule_set) <= denied
        for rule_set, held in zip(rule_sets, signature, strict=True)
        if held
    )


def _constructed_capability_signatures(patterns: tuple[str, ...]) -> set[tuple[bool, ...]]:
    """What `witness_space()` produces for a policy naming exactly these patterns.

    The classes are read off a real policy document rather than off the class-building helper,
    so the outsider the harness derives for that policy is part of what is checked. That is
    the step the cross-check used to skip, and skipping it is why a fixed sentinel colliding
    with a named capability went unnoticed through eight agreeing cases.
    """

    import importlib.util

    specification = importlib.util.spec_from_file_location(
        "policy_mutation", ROOT / "scripts" / "policy_mutation.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["policy_mutation"] = module
    specification.loader.exec_module(module)
    document = {"rules": [{"tool_capabilities": list(patterns)}]}
    return {
        tuple(
            any(capability_matches(pattern, capability) for capability in witness)
            for pattern in patterns
        )
        for witness in module.witness_space(document)["tool_capabilities"]
    }


def check() -> dict[str, Any]:
    findings: dict[str, Any] = {"schema_version": "v1", "capabilities": [], "purposes": []}

    for patterns in CAPABILITY_CASES:
        achievable = {
            signature
            for signature in itertools.product((False, True), repeat=len(patterns))
            if capability_signature_achievable(patterns, signature)
        }
        constructed = _constructed_capability_signatures(patterns)
        by_criterion = {
            signature
            for signature in itertools.product((False, True), repeat=len(patterns))
            if capability_signature_achievable_by_criterion(patterns, signature)
        }
        findings["capabilities"].append(
            {
                "patterns": list(patterns),
                "candidate_signatures": 2 ** len(patterns),
                "achievable_by_solver": len(achievable),
                "achievable_by_criterion": len(by_criterion),
                "produced_by_construction": len(constructed),
                "agree": achievable == constructed,
                "criterion_agrees": by_criterion == achievable,
                "unachievable_but_produced": sorted(str(s) for s in constructed - achievable),
                "achievable_but_missing": sorted(str(s) for s in achievable - constructed),
            }
        )

    for tags, rule_sets in PURPOSE_CASES:
        achievable = {
            signature
            for signature in itertools.product((False, True), repeat=len(rule_sets))
            if purpose_signature_achievable(tags, rule_sets, signature)
        }
        by_criterion = {
            signature
            for signature in itertools.product((False, True), repeat=len(rule_sets))
            if purpose_signature_achievable_by_criterion(rule_sets, signature)
        }
        findings["purposes"].append(
            {
                "named_tags": list(tags),
                "rule_sets": [list(entry) for entry in rule_sets],
                "candidate_signatures": 2 ** len(rule_sets),
                "achievable_by_solver": len(achievable),
                "achievable_by_criterion": len(by_criterion),
                "subsets_enumerated": 2 ** len(tags),
                "criterion_agrees": by_criterion == achievable,
            }
        )

    findings["capability_cases"] = len(findings["capabilities"])
    findings["capability_cases_agreeing"] = sum(
        1 for entry in findings["capabilities"] if entry["agree"]
    )
    findings["cases_where_the_criterion_agrees_with_the_solver"] = sum(
        1
        for entry in (*findings["capabilities"], *findings["purposes"])
        if entry["criterion_agrees"]
    )
    findings["cases"] = len(findings["capabilities"]) + len(findings["purposes"])
    findings["solver"] = z3.get_version_string() if z3 is not None else None
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    if z3 is None:
        raise SystemExit("z3 is not installed; install z3-solver to run this check")

    findings = check()
    print(f"solver: {findings['solver']}")
    print("\ncapability pattern sets:")
    for entry in findings["capabilities"]:
        mark = "ok " if entry["agree"] else "MISMATCH"
        print(
            f"  {mark} {str(entry['patterns']):44s} "
            f"candidates={entry['candidate_signatures']:3d} "
            f"achievable={entry['achievable_by_solver']:3d} "
            f"constructed={entry['produced_by_construction']:3d}"
        )
        if not entry["agree"]:
            print(f"        produced but unachievable: {entry['unachievable_but_produced']}")
            print(f"        achievable but missing:    {entry['achievable_but_missing']}")
    print("\npurpose tag predicates:")
    for entry in findings["purposes"]:
        print(
            f"  tags={str(entry['named_tags']):18s} rules={str(entry['rule_sets']):26s} "
            f"subsets={entry['subsets_enumerated']:2d} "
            f"achievable signatures={entry['achievable_by_solver']:2d}"
        )
    print(
        f"\n{findings['capability_cases_agreeing']} of {findings['capability_cases']} "
        "capability cases agree with the solver"
    )
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(
        f"{findings['cases_where_the_criterion_agrees_with_the_solver']} of {findings['cases']} "
        "cases: the closed-form criterion agrees with the solver"
    )
    complete = findings["capability_cases_agreeing"] == findings["capability_cases"]
    criterion = findings["cases_where_the_criterion_agrees_with_the_solver"] == findings["cases"]
    return 0 if complete and criterion else 1


if __name__ == "__main__":
    raise SystemExit(main())
