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

# Pattern sets chosen to cover the shapes that decide the question: nested, disjoint, exact,
# a chain of three, and a mix. Every one is a policy a reviewer could write.
CAPABILITY_CASES: tuple[tuple[str, ...], ...] = (
    (),
    ("net.*",),
    ("net.*", "net.http"),
    ("net.*", "fs.*"),
    ("net.http", "net.https"),
    ("net.*", "net.http", "net.http.get"),
    ("net.*", "fs.*", "net.http"),
    ("a", "b", "c"),
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


def _constructed_capability_signatures(patterns: tuple[str, ...]) -> set[tuple[bool, ...]]:
    """What `witness_space()` produces, expressed as signatures."""

    import importlib.util

    specification = importlib.util.spec_from_file_location(
        "policy_mutation", ROOT / "scripts" / "policy_mutation.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["policy_mutation"] = module
    specification.loader.exec_module(module)
    return {
        tuple(
            any(capability_matches(pattern, capability) for capability in witness)
            for pattern in patterns
        )
        for witness in module._capability_classes(patterns)
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
        findings["capabilities"].append(
            {
                "patterns": list(patterns),
                "candidate_signatures": 2 ** len(patterns),
                "achievable_by_solver": len(achievable),
                "produced_by_construction": len(constructed),
                "agree": achievable == constructed,
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
        findings["purposes"].append(
            {
                "named_tags": list(tags),
                "rule_sets": [list(entry) for entry in rule_sets],
                "candidate_signatures": 2 ** len(rule_sets),
                "achievable_by_solver": len(achievable),
                "subsets_enumerated": 2 ** len(tags),
            }
        )

    findings["capability_cases"] = len(findings["capabilities"])
    findings["capability_cases_agreeing"] = sum(
        1 for entry in findings["capabilities"] if entry["agree"]
    )
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
    return 0 if findings["capability_cases_agreeing"] == findings["capability_cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
