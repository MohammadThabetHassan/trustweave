"""Check the decision map the theory is stated over against the engine that ships.

`scripts/policy_mutation.py` enumerates a policy's subject classes and decides each class
with its own first-match loop over the engine's predicates. Every exactness claim rests on
that map: equivalence is a comparison of two maps, the kill criterion is a difference of
maps, and the abstraction theorem says a subject decides as the witness of its class does.
The engine users run is `trustweave.engine.evaluate_flow`, reached through a manifest by
`trustweave scan`. The harness never called it. Its own tests compared the harness with
itself -- a function documented as "the engine's own first-match evaluation" called the
harness's re-implementation -- and so the evaluation order, the default, the wildcard and
the classification bounds were checked against a reading of the engine rather than against
the engine.

This closes that gap the plain way. For the shipped policy, a richer variant and a seeded
run of generated policies that the parser accepts, every class witness and a sample of
concrete subjects is decided twice, once by the harness's map and once by building the
`Source`, `Tool` and `Flow` the engine takes and calling `evaluate_flow`. The two must
agree on every subject, and a subject must decide as the witness of the class the harness
places it in. The artifact records the seed, the policies, the subjects, and the
disagreements, which are expected to be none and are listed rather than counted so that a
future one is a specific policy and subject and not a statistic.

Usage:
    python scripts/interpreter_oracle.py [--policies N] [--subjects M] [--seed S] [--json out]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trustweave.engine import evaluate_flow  # noqa: E402
from trustweave.models import (  # noqa: E402
    DECLARED_CONTROL_CATALOG,
    DEFAULT_CLASSIFICATION_TAXONOMY,
    Flow,
    Source,
    Tool,
    ValidationError,
    parse_policy,
)


def _policy_mutation() -> Any:
    specification = importlib.util.spec_from_file_location(
        "policy_mutation_oracle", ROOT / "scripts" / "policy_mutation.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


harness = _policy_mutation()

DEFAULT_SEED = 20260909
SHIPPED_POLICY = ROOT / "policies" / "default-policy.json"

# Pools the generator draws from. Capabilities nest on purpose -- `net.*` covers `net.http`
# covers nothing narrower than itself -- because the nesting is where the witness
# construction was once wrong, and identifiers include names no policy will mention so the
# outsider class is occupied.
CAPABILITY_PATTERNS = ("net.*", "net.http", "net.http.get", "fs.read", "fs.*", "db.write")
CONCRETE_CAPABILITIES = (
    "net.http",
    "net.http.get",
    "net.smtp",
    "fs.read",
    "fs.write",
    "db.write",
    "unrelated.capability",
)
IDENTIFIERS = ("alice", "bob", "mailer", "search", "crm", "ledger")
PURPOSES = ("support", "billing", "audit", "marketing")
# The largest quotient the oracle will enumerate. Every class of a policy under the cap is
# decided twice, so the cap is the only thing that keeps a generated policy out of the check
# -- and a cap that silently drops the large quotients would leave the check biased towards
# small ones. It is therefore an argument, the sizes of what it excludes are recorded, and
# the default is high enough that the excluded candidates are the ones whose quotients run to
# millions of classes rather than merely thousands.
MAX_CELLS = 200_000


def engine_decision(policy: Any, subject: tuple[Any, ...]) -> str:
    """The shipped engine's decision for one concrete subject, through its real entry point."""

    trust, action, classification, source_id, tool_id, purposes, capabilities = subject
    source = Source(
        name=source_id, trust=trust, data_classification=classification, description="oracle"
    )
    tool = Tool(name=tool_id, action_class=action, capabilities=capabilities, description="oracle")
    flow = Flow(source=source.name, tool=tool.name, purpose="oracle", purpose_tags=purposes)
    return str(evaluate_flow(flow, source, tool, policy).decision)


def _subset(generator: random.Random, pool: tuple[str, ...], at_most: int) -> list[str]:
    size = generator.randint(0, min(at_most, len(pool)))
    return sorted(generator.sample(pool, size))


def generate_policy(generator: random.Random) -> dict[str, Any] | None:
    """One random policy document on the schema that admits every predicate, or None if the
    parser rejects it -- rejections are counted, not retried into silence."""

    taxonomy = list(DEFAULT_CLASSIFICATION_TAXONOMY)
    with_approval = generator.random() < 0.7
    document: dict[str, Any] = {
        "schema_version": "trustweave.dev/policy/v1alpha2",
        "name": "oracle-policy",
        "default_decision": generator.choice(harness.DECISIONS),
        "rules": [],
    }
    if with_approval:
        document["approval_control"] = {
            "mechanism": "human-review-queue",
            "binds_to": ["actor", "tool"],
            "fail_closed": generator.random() < 0.5,
        }
    for index in range(generator.randint(1, 5)):
        rule: dict[str, Any] = {
            "id": f"R-{index}",
            "description": "generated",
            "source_trust": _subset(generator, harness.TRUST_LEVELS, 3) or ["trusted"],
            "tool_action_classes": _subset(generator, harness.ACTION_CLASSES, 4) or ["read"],
            "decision": generator.choice(harness.DECISIONS),
            "rationale": "generated",
        }
        if generator.random() < 0.35:
            rule["source_data_classifications"] = _subset(generator, tuple(taxonomy), 3) or [
                "public"
            ]
        if generator.random() < 0.3:
            low, high = sorted(generator.sample(range(len(taxonomy)), 2))
            if generator.random() < 0.5:
                rule["source_data_classification_at_least"] = taxonomy[low]
            if generator.random() < 0.5:
                rule["source_data_classification_at_most"] = taxonomy[high]
        if generator.random() < 0.4:
            rule["tool_capabilities"] = _subset(generator, CAPABILITY_PATTERNS, 3) or ["fs.read"]
        if generator.random() < 0.3:
            rule["source_identifiers"] = _subset(generator, IDENTIFIERS[:3], 2) or ["alice"]
        if generator.random() < 0.3:
            rule["tool_identifiers"] = _subset(generator, IDENTIFIERS[2:], 2) or ["mailer"]
        if generator.random() < 0.35:
            rule["purpose_tags"] = _subset(generator, PURPOSES, 2) or ["support"]
        if with_approval and generator.random() < 0.25:
            rule["required_controls"] = _subset(
                generator, tuple(sorted(DECLARED_CONTROL_CATALOG)), 2
            ) or ["approval"]
        document["rules"].append(rule)
    try:
        parse_policy(document)
    except ValidationError:
        return None
    return document


def random_subject(generator: random.Random, space: dict[str, tuple[Any, ...]]) -> tuple[Any, ...]:
    """A concrete subject, drawn so that named values, outsiders and nesting all occur."""

    named_purposes = tuple(sorted({tag for subset in space["purpose_tags"] for tag in subset}))
    classifications = (*DEFAULT_CLASSIFICATION_TAXONOMY, "unspecified", "zzz-not-in-taxonomy")
    return (
        generator.choice(harness.TRUST_LEVELS),
        generator.choice(harness.ACTION_CLASSES),
        generator.choice(classifications),
        generator.choice((*IDENTIFIERS[:3], "synthetic-source", "nobody")),
        generator.choice((*IDENTIFIERS[2:], "synthetic-tool", "nothing")),
        tuple(
            _subset(
                generator, tuple(dict.fromkeys((*named_purposes, *PURPOSES, "unnamed-purpose"))), 3
            )
        ),
        tuple(_subset(generator, CONCRETE_CAPABILITIES, 3)),
    )


def check_policy(
    label: str, document: dict[str, Any], generator: random.Random, subjects: int
) -> dict[str, Any]:
    policy = parse_policy(document)
    space = harness.witness_space(document)
    reference = harness.decision_map(document)
    disagreements: list[dict[str, Any]] = []

    # Every class witness: the harness's map against the engine on the same subject.
    for cell, decided in reference.items():
        engine = engine_decision(policy, cell)
        if engine != decided:
            disagreements.append(
                {"kind": "witness", "subject": list(cell), "harness": decided, "engine": engine}
            )

    # Concrete subjects: the engine against the witness of the class the harness places
    # them in, which is the abstraction theorem checked against the interpreter rather than
    # against the harness's own evaluator.
    for _ in range(subjects):
        subject = random_subject(generator, space)
        witness = harness.abstract_cell(space, *subject)
        engine = engine_decision(policy, subject)
        via_class = reference.get(witness)
        if via_class is None or engine != via_class:
            disagreements.append(
                {
                    "kind": "subject",
                    "subject": list(subject),
                    "class_witness": list(witness),
                    "engine": engine,
                    "harness": via_class,
                }
            )
    return {
        "policy": label,
        "rules": len(document["rules"]),
        "cells": len(reference),
        "subjects": subjects,
        "disagreements": disagreements,
    }


def richer_policy(document: dict[str, Any]) -> dict[str, Any]:
    """The shipped policy with the predicates the shipped rules do not use, as the tests do."""

    richer = json.loads(json.dumps(document))
    richer["schema_version"] = "trustweave.dev/policy/v1alpha2"
    richer["rules"][0]["source_data_classification_at_least"] = "confidential"
    richer["rules"][1]["tool_capabilities"] = ["net.*", "fs.read"]
    richer["rules"][2]["purpose_tags"] = ["support", "billing"]
    return richer


def measure(policies: int, subjects: int, seed: int, max_cells: int = MAX_CELLS) -> dict[str, Any]:
    generator = random.Random(seed)
    shipped = json.loads(SHIPPED_POLICY.read_text(encoding="utf-8"))
    checks = [
        check_policy("policies/default-policy.json", shipped, generator, subjects),
        check_policy(
            "default-policy.json with the richer guards",
            richer_policy(shipped),
            generator,
            subjects,
        ),
    ]
    rejected = skipped = 0
    generated = 0
    skipped_sizes: list[int] = []
    while generated < policies:
        document = generate_policy(generator)
        if document is None:
            rejected += 1
            continue
        space = harness.witness_space(document)
        total = 1
        for values in space.values():
            total *= len(values)
        if total > max_cells:
            skipped += 1
            skipped_sizes.append(total)
            continue
        generated += 1
        checks.append(check_policy(f"generated-{generated}", document, generator, subjects))
    disagreements = [
        {"policy": check["policy"], **entry} for check in checks for entry in check["disagreements"]
    ]
    return {
        "schema_version": "v1",
        "engine_entry_point": "trustweave.engine.evaluate_flow",
        "seed": seed,
        "policies_checked": len(checks),
        "generated_policies": generated,
        "generated_rejected_by_parser": rejected,
        "generated_skipped_as_too_large": skipped,
        "max_cells": max_cells,
        "largest_quotient_checked": max(check["cells"] for check in checks),
        "smallest_quotient_skipped": min(skipped_sizes, default=0),
        "median_quotient_skipped": (
            sorted(skipped_sizes)[len(skipped_sizes) // 2] if skipped_sizes else 0
        ),
        "cells_checked": sum(check["cells"] for check in checks),
        "subjects_checked": sum(check["subjects"] for check in checks),
        "disagreements": disagreements,
        "policies": [{k: v for k, v in check.items() if k != "disagreements"} for check in checks],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policies", type=int, default=200)
    parser.add_argument("--subjects", type=int, default=40)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--max-cells", type=int, default=MAX_CELLS)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    findings = measure(args.policies, args.subjects, args.seed, args.max_cells)
    print(
        f"{findings['policies_checked']} policies ({findings['generated_policies']} generated, "
        f"{findings['generated_rejected_by_parser']} rejected by the parser, "
        f"{findings['generated_skipped_as_too_large']} over {findings['max_cells']:,} "
        f"classes, the smallest of them {findings['smallest_quotient_skipped']:,}): "
        f"{findings['cells_checked']} class witnesses and {findings['subjects_checked']} "
        f"concrete subjects decided by the engine and the harness; "
        f"{len(findings['disagreements'])} disagreements"
    )
    for entry in findings["disagreements"][:10]:
        print(
            f"  {entry['policy']}: {entry['kind']} {entry['subject']} -> "
            f"engine {entry['engine']}, harness {entry['harness']}"
        )
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 1 if findings["disagreements"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
