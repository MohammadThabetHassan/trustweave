"""Rego equivalence under every Constraint the library ships.

Under `docs/SHIPPED_CONSTRAINTS_PROTOCOL_REGO.md` (hashed below). The exact study decides
equivalence under the parameter settings each suite tests; this decides the same mutants again
under every Constraint the Gatekeeper library ships for the template. Every step is the exact
study's (`scripts/rego_exact_study.py`): the same mutants, kills, witness space and engine
decisions. On the tested settings alone each module must first reproduce its record in
`docs/rego-exact-adequacy-v1.json`, or it is reported and not scored.

CLI:
    python scripts/rego_shipped_constraints_study.py study --corpus <gatekeeper-library> \
        --json docs/rego-shipped-constraints-v1.json [--only SUBJECT ...] [--workers 6]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import multiprocessing
import random
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PROTOCOL = DOCS / "SHIPPED_CONSTRAINTS_PROTOCOL_REGO.md"
# Fixed when the protocol was committed (0b98050), before any module was decided under a new
# setting.
PROTOCOL_SHA256 = "0ef10f141e18c19a88eb85c17aa3685c69353b536c2449bd0bf031991b306016"
EXACT_ARTIFACT = DOCS / "rego-exact-adequacy-v1.json"
CORPUS_COMMIT = "e034212e94e666ab3ba69108d96222bffc8ef671"

# The protocol's table: every shipped Constraint per module, by its sample directory, with its
# parameters as canonical JSON ("absent" when it has none) and whether the setting is new.
FROZEN: dict[str, list[tuple[str, str, bool]]] = {
    "src/general/automount-serviceaccount-token/src.rego": [
        ("automount-serviceaccount-token", "absent", False)
    ],
    "src/general/block-loadbalancer-services/src.rego": [("block-load-balancer", "absent", False)],
    "src/general/block-nodeport-services/src.rego": [("block-node-port", "absent", False)],
    "src/general/block-wildcard-ingress/src.rego": [("block-wildcard-ingress", "absent", False)],
    "src/general/disallowanonymous/src.rego": [
        ("no-anonymous-bindings", '{"allowedRoles": ["cluster-role-1"]}', True),
        ("no-authenticated", '{"disallowAuthenticated": true}', True),
    ],
    "src/general/disallowinteractive/src.rego": [("no-interactive-containers", "absent", False)],
    "src/general/httpsonly/src.rego": [
        ("ingress-https-only", "absent", False),
        ("ingress-https-only-tls-optional", '{"tlsOptional": true}', False),
    ],
    "src/general/imagedigests/src.rego": [("container-image-must-have-digest", "absent", False)],
    "src/pod-security-policy/allow-privilege-escalation/src.rego": [
        ("psp-allow-privilege-escalation-container", '{"exemptImages": ["safeimages.com/*"]}', True)
    ],
    "src/pod-security-policy/host-namespaces/src.rego": [("psp-host-namespace", "absent", False)],
    "src/pod-security-policy/host-process/src.rego": [("psp-host-process", "absent", False)],
    "src/pod-security-policy/privileged-containers/src.rego": [
        ("psp-privileged-container", '{"exemptImages": ["safeimages.com/*"]}', True)
    ],
    "src/pod-security-policy/proc-mount/src.rego": [
        (
            "psp-proc-mount",
            '{"exemptImages": ["safeimages.com/*"], "procMount": "Default"}',
            True,
        )
    ],
    "src/pod-security-policy/read-only-root-filesystem/src.rego": [
        ("full_wildcard", '{"exemptImages": ["*"]}', True),
        ("psp-readonlyrootfilesystem", '{"exemptImages": ["specialprogram"]}', True),
        ("wildcard-prefix", '{"exemptImages": ["safe-images.com/*"]}', True),
    ],
}

# What the reproduction gate compares with the exact study's record.
REPRODUCED = (
    "mutants",
    "killed",
    "stillborn",
    "live",
    "suite_equivalent",
    "distinguishable",
    "killed_through_decision",
    "killed_without_a_decision_change",
)

# What changed after the first population run, kept so the record is whole. None changes the
# protocol: it fixes the settings and their cells, not the order they are read in.
NOTES = (
    "The first population run compared each module's tested settings with the committed record "
    "as an ordered list. OPA's test runner prints a suite's inputs in an order that differs from "
    "run to run, and the settings are read in that order, so four modules -- disallowanonymous, "
    "disallowinteractive, proc-mount and the development module -- failed the gate on order "
    "alone, with every count, every survivor and every setting's cells the same. The gate now "
    "compares each setting's cells whatever the order. That run separated no equivalent under "
    "any shipped Constraint in any module.",
)


def protocol_digest(path: Path = PROTOCOL) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def require_protocol() -> None:
    found = protocol_digest()
    if found != PROTOCOL_SHA256:
        raise SystemExit(
            f"{PROTOCOL.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the "
            "study ran; a changed protocol is a different study, so this one refuses to run"
        )


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def canonical(params: Any, absent: Any) -> str:
    return "absent" if params is absent else json.dumps(params, sort_keys=True)


def shipped_constraints(corpus: Path, subject: str) -> list[tuple[str, str]]:
    """Every Constraint the library ships for a module: (sample directory, canonical parameters)."""

    group_name = Path(subject).parent.relative_to("src")
    found = []
    for manifest in sorted((corpus / "library" / group_name / "samples").glob("*/constraint.yaml")):
        document = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        spec = document.get("spec") or {}
        params = (
            json.dumps(spec["parameters"], sort_keys=True) if "parameters" in spec else "absent"
        )
        found.append((manifest.parent.name, params))
    return found


# --- one module --------------------------------------------------------------------------------


def settle(task: tuple[str, str, str, list[str], str, list[tuple[str, str]]]) -> dict[str, Any]:
    """One module under its tested settings and its shipped ones.

    The tested part is the exact study's `study_module` step for step, the random draws
    included, so its counts can be compared with the committed record. Each shipped setting
    that is new follows, on the same generator, with every review the suite's inputs carry
    paired with the new parameters among the off-cell checks.
    """

    subject, source, test_path, lib_paths, opa, shipped = task
    exact = _load("rego_exact_study")
    space = _load("rego_witness_space")
    suite = _load("rego_suite_study")
    mutation = _load("rego_source_mutation")
    test = Path(test_path)
    libs = [Path(p) for p in lib_paths]
    lib_sources = [
        f for p in libs for f in sorted(p.rglob("*.rego")) if not f.name.endswith("_test.rego")
    ]
    absent = space.ABSENT
    record: dict[str, Any] = {"subject": subject, "development": subject == exact.DEVELOPMENT}

    inputs = exact.authors_inputs(opa, source, test, libs)
    tested: list[Any] = []
    seen: set[str] = set()
    for item in inputs:
        params = item.get("parameters", absent) if isinstance(item, dict) else absent
        key = canonical(params, absent)
        if key not in seen:
            seen.add(key)
            tested.append(params)
    if not tested:
        tested = [absent]
    record["tested_settings"] = ["absent" if p is absent else p for p in tested]

    found = mutation.mutants(source)
    killed: list[bool] = []
    with tempfile.TemporaryDirectory() as directory:
        module = Path(directory) / Path(subject).name
        for mutant in found:
            module.write_text(mutant.source, encoding="utf-8")
            killed.append(not suite._passes(suite._run_test([module, test, *libs], coverage=False)))
    stillborn = [not exact.compiles(opa, mutant.source, libs) for mutant in found]
    live = [i for i in range(len(found)) if not stillborn[i]]

    asts = [space.opa_parse(opa, f.read_text(encoding="utf-8")) for f in lib_sources]
    module_ast = space.opa_parse(opa, source)
    mutant_asts = {i: space.opa_parse(opa, found[i].source) for i in live}
    package = space.package_of(module_ast)
    shapes = space.shapes_from(inputs)
    generator = random.Random(f"{exact.SEED}:{subject}")
    reviews: list[Any] = []
    review_keys: set[str] = set()
    for item in inputs:
        if isinstance(item, dict) and "review" in item:
            key = json.dumps(item["review"], sort_keys=True)
            if key not in review_keys:
                review_keys.add(key)
                reviews.append(item["review"])

    def under(params: Any, authors: list[Any]) -> dict[str, Any]:
        """The exact study's witness space and decisions under one setting."""

        merged = space.Analyzer([module_ast, *asts], package, params)
        merged.run()
        for ast in mutant_asts.values():
            other = space.Analyzer([ast, *asts], package, params)
            try:
                other.run()
            except space.Unsupported:
                continue
            for segs, hints in other.hints.items():
                merged.hints[segs] |= hints
            merged.read |= other.read
            merged.links |= other.links
        cells = space.build(merged, shapes, exact.MAX_CELLS)
        pool = space.leaf_pool(cells)
        drawn = [
            space.perturb(generator.choice(cells), pool, generator) for _ in range(exact.DRAWS)
        ]
        authors_drawn = (
            [space.perturb(generator.choice(authors), pool, generator) for _ in range(exact.DRAWS)]
            if authors
            else []
        )
        checks = drawn + authors + authors_drawn
        everything = [exact._wrap(r, params, absent) for r in cells + checks]
        base = exact.decide(opa, source, libs, everything)
        separated: dict[int, tuple[Any, Any]] = {}
        missing: list[int] = []
        for i in live:
            got = exact.decide(opa, found[i].source, libs, everything)
            on_cells = next((c for c in range(len(cells)) if got[c] != base[c]), None)
            if on_cells is not None:
                separated[i] = (everything[on_cells], base[on_cells])
                continue
            if any(got[c] != base[c] for c in range(len(cells), len(everything))):
                missing.append(i)
        return {
            "cells": len(cells),
            "cells_where_the_module_errors": sum(1 for d in base[: len(cells)] if d == "error"),
            "drawn": len(drawn),
            "authors_reviews": len(authors),
            "authors_drawn": len(authors_drawn),
            "separated": separated,
            "missing": missing,
        }

    # The tested settings, exactly as the exact study ran them.
    distinguishable: dict[int, tuple[Any, Any]] = {}
    checked = []
    for params in tested:
        wanted = canonical(params, absent)
        authors = [
            item["review"]
            for item in inputs
            if isinstance(item, dict)
            and "review" in item
            and ("absent" if "parameters" not in item else canonical(item["parameters"], absent))
            == wanted
        ]
        result = under(params, authors)
        for i, witness in result["separated"].items():
            distinguishable.setdefault(i, witness)
        checked.append(
            {
                "parameters": "absent" if params is absent else params,
                **{k: v for k, v in result.items() if k not in ("separated", "missing")},
                "missing_cells": len(result["missing"]),
            }
        )
    equivalents = [i for i in live if i not in distinguishable]
    counts = {
        "mutants": len(found),
        "killed": sum(killed),
        "stillborn": sum(stillborn),
        "live": len(live),
        "suite_equivalent": len(equivalents),
        "distinguishable": len(distinguishable),
        "killed_through_decision": sum(killed[i] for i in distinguishable),
        "killed_without_a_decision_change": sum(killed[i] for i in equivalents),
    }
    survivors = sorted(i for i in distinguishable if not killed[i])
    record.update(counts)
    record["survivors"] = survivors
    record["tested_settings_checked"] = checked
    record["equivalents_tested"] = equivalents

    # The reproduction gate. A module the exact study did not measure (a test's synthetic
    # template) has no record to reproduce.
    committed = json.loads(EXACT_ARTIFACT.read_text(encoding="utf-8"))["modules"].get(subject)
    if committed is None:
        committed = {}
        record["no_committed_record"] = True
    differences: dict[str, Any] = {
        key: {"now": counts[key], "committed": committed.get(key)}
        for key in REPRODUCED
        if counts[key] != committed.get(key)
    }
    if survivors != [s["mutant"] for s in committed.get("survivors", [])]:
        differences["survivors"] = {
            "now": survivors,
            "committed": [s["mutant"] for s in committed.get("survivors", [])],
        }

    # Each setting with its cells, whatever the order: the engine's test runner prints the
    # suite's inputs in an order that differs from run to run, and the settings are read in
    # the order they are printed.
    def by_setting(rows: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "absent"
            if row["parameters"] == "absent"
            else json.dumps(row["parameters"], sort_keys=True): row["cells"]
            for row in rows
        }

    cells_now = by_setting(checked)
    cells_then = by_setting(committed.get("instantiations_checked", []))
    if cells_now != cells_then or len(checked) != len(committed.get("instantiations", [])):
        differences["settings_and_cells"] = {"now": cells_now, "committed": cells_then}
    if any(row["missing_cells"] for row in checked):
        differences["missing_cells"] = [row["missing_cells"] for row in checked]
    record["reproduces"] = None if record.get("no_committed_record") else not differences
    record["reproduction_differences"] = {} if record.get("no_committed_record") else differences

    # Every shipped Constraint; the new settings are decided, the others were tested.
    shipped_rows = []
    newly: dict[int, dict[str, Any]] = {}
    undecided: list[str] = []
    tested_keys = {canonical(p, absent) for p in tested}
    for name, params_json in shipped:
        row: dict[str, Any] = {
            "constraint": name,
            "parameters": "absent" if params_json == "absent" else json.loads(params_json),
            "new": params_json not in tested_keys,
        }
        if not row["new"]:
            row["status"] = "a tested setting"
            shipped_rows.append(row)
            continue
        params = absent if params_json == "absent" else json.loads(params_json)
        try:
            result = under(params, reviews)
        except space.Unsupported as reason:
            row["status"] = f"undecided: {reason}"
            undecided.append(name)
            shipped_rows.append(row)
            continue
        row.update({k: v for k, v in result.items() if k not in ("separated", "missing")})
        if result["missing"]:
            row["status"] = "undecided: missing cell"
            row["missing_cells"] = result["missing"]
            undecided.append(name)
            shipped_rows.append(row)
            continue
        row["status"] = "decided"
        row["separates_equivalents"] = sorted(i for i in result["separated"] if i in equivalents)
        row["separates_any"] = len(result["separated"])
        for i in row["separates_equivalents"]:
            if i not in newly:
                witness, decision = result["separated"][i]
                newly[i] = {
                    "mutant": i,
                    "operator": found[i].operator,
                    "detail": found[i].detail,
                    "constraint": name,
                    "input": witness,
                    "module_decision": decision,
                    "killed_by_the_suite": killed[i],
                }
        shipped_rows.append(row)
    record["shipped"] = shipped_rows
    record["undecided_under"] = undecided
    record["newly_separated"] = [newly[i] for i in sorted(newly)]
    record["equivalents_under_every_shipped_constraint"] = (
        None if undecided else [i for i in equivalents if i not in newly]
    )
    return record


# --- the population ----------------------------------------------------------------------------


def _share(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def headline(records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The 13 headline modules pooled, the development module left out."""

    group = {s: r for s, r in records.items() if not r["development"]}
    scored = {s: r for s, r in group.items() if r["reproduces"]}
    decided = {s: r for s, r in scored.items() if not r["undecided_under"]}
    total = lambda key, rows: sum(r[key] for r in rows.values())  # noqa: E731
    distinguishable = total("distinguishable", scored)
    killed = total("killed_through_decision", scored)
    outright = sum(
        r["suite_equivalent"] for r in scored.values() if r["tested_settings"] == ["absent"]
    )
    relative = total("suite_equivalent", scored) - outright
    newly = [n for r in decided.values() for n in r["newly_separated"]]
    newly_killed = sum(1 for n in newly if n["killed_by_the_suite"])
    with_new = sum(
        r["suite_equivalent"] for r in scored.values() if any(row["new"] for row in r["shipped"])
    )
    undecided_equivalents = sum(
        r["suite_equivalent"] for s, r in scored.items() if s not in decided
    )
    left_out = {s: r for s, r in scored.items() if s in decided}
    return {
        "modules": len(group),
        "reproduced": len(scored),
        "not_reproduced": sorted(s for s in group if s not in scored),
        "undecided": sorted(s for s in scored if s not in decided),
        "equivalents_tested": total("suite_equivalent", scored),
        "parameter_relative": relative,
        "in_modules_with_a_new_setting": with_new,
        "newly_separated": len(newly),
        "newly_separated_killed_by_the_suite": newly_killed,
        "equivalents_under_every_shipped_constraint": (
            total("suite_equivalent", scored) - len(newly) - undecided_equivalents
        ),
        "distinguishable_tested": distinguishable,
        "killed_through_decision": killed,
        "pooled_exact_score_tested": _share(killed, distinguishable),
        "worst_case_tested": _share(killed, distinguishable + relative),
        "pooled_exact_score_shipped": _share(
            killed + newly_killed, distinguishable + len(newly) + undecided_equivalents
        ),
        "pooled_exact_score_shipped_undecided_left_out": _share(
            total("killed_through_decision", left_out) + newly_killed,
            total("distinguishable", left_out) + len(newly),
        ),
    }


def study(corpus: Path, workers: int, only: list[str] | None) -> dict[str, Any]:
    require_protocol()
    exact = _load("rego_exact_study")
    suite = _load("rego_suite_study")
    opa = suite._opa()
    libs = suite._lib_dirs(corpus)
    commit = suite._git_commit(corpus)
    if commit != CORPUS_COMMIT:
        raise SystemExit(f"the corpus is at {commit}, not the {CORPUS_COMMIT} the protocol fixes")
    committed = json.loads(EXACT_ARTIFACT.read_text(encoding="utf-8"))["modules"]
    subjects = sorted(s for s, r in committed.items() if r.get("status") == "measured")
    frozen_match = all(
        [(n, p) for n, p, _ in FROZEN[s]] == shipped_constraints(corpus, s) for s in subjects
    ) and set(FROZEN) == set(subjects)
    if not frozen_match:
        raise SystemExit("the shipped Constraints differ from the protocol's table")
    if only:
        subjects = [s for s in subjects if s in only]
    tasks = []
    for subject in subjects:
        module = corpus / subject
        test = module.with_name(module.name.replace(".rego", "_test.rego"))
        shipped = [(n, p) for n, p, _ in FROZEN[subject]]
        tasks.append(
            (subject, module.read_text("utf-8"), str(test), [str(p) for p in libs], opa, shipped)
        )
    records: dict[str, dict[str, Any]] = {}
    # Spawned, not forked, as the exact study's pool is.
    context = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(workers, mp_context=context) as pool:
        pending = {pool.submit(settle, task): task[0] for task in tasks}
        for future in concurrent.futures.as_completed(pending):
            record = future.result()
            records[record["subject"]] = record
            print(
                f"{len(records)}/{len(tasks)} {record['subject']}: reproduces "
                f"{record['reproduces']}, newly separated {len(record['newly_separated'])}, "
                f"undecided {record['undecided_under']}",
                file=sys.stderr,
                flush=True,
            )
    # A new setting must be new against the settings the run re-derived, as the table says.
    for subject, record in records.items():
        flags = [row["new"] for row in record["shipped"]]
        if flags != [new for _, _, new in FROZEN[subject]]:
            raise SystemExit(f"{subject}: which settings are new differs from the protocol")
    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "engine": suite._engine_version(),
        "corpus": {"name": corpus.name, "commit": commit},
        "seed": exact.SEED,
        "draws": exact.DRAWS,
        "max_cells": exact.MAX_CELLS,
        "development_module": exact.DEVELOPMENT,
        "shipped_constraints_match_the_protocol": frozen_match,
        "every_module_reproduces": all(r["reproduces"] for r in records.values()),
        "headline": headline(records) if not only else None,
        "modules": dict(sorted(records.items())),
        "deviations": [],
        "notes": list(NOTES),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("study")
    run.add_argument("--corpus", type=Path, required=True)
    run.add_argument("--json", type=Path, required=True)
    run.add_argument("--only", nargs="*")
    run.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    result = study(args.corpus.resolve(), args.workers, args.only)
    args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["headline"]:
        print(json.dumps(result["headline"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
