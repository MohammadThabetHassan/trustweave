"""The hosted mutation gate cannot regress below the required score and parity contract.

The gate logic itself lives in scripts/mutation_gate.py so it can run locally. This
module checks two things: that the workflow really invokes that script, and that the
script still enforces every acceptance condition the project claims it does. The
conditions are asserted behaviourally rather than by matching source text, so the gate
cannot pass this test while having lost an enforcement path.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts" / "mutation_gate.py"


def _load_gate() -> ModuleType:
    """Load the gate by path.

    ``scripts`` is not a package and nothing puts the repository root on ``sys.path``
    under a bare ``pytest`` invocation, which is how CI runs the suite. The rest of the
    suite loads ``scripts/reality_check.py`` the same way.
    """

    specification = importlib.util.spec_from_file_location("mutation_gate", GATE_PATH)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules["mutation_gate"] = module
    specification.loader.exec_module(module)
    return module


gate = _load_gate()
GATE_SCRIPT = "scripts/mutation_gate.py"

ALLOWED_CLASSIFICATIONS = gate.ALLOWED_CLASSIFICATIONS
DEFAULT_TRIAGE = gate.DEFAULT_TRIAGE
THRESHOLD_PERCENT = gate.THRESHOLD_PERCENT
GateFailure = gate.GateFailure
check_diff_parity = gate.check_diff_parity
check_identifier_parity = gate.check_identifier_parity
check_records = gate.check_records
parse_totals = gate.parse_totals
check_gated_threshold = gate.check_gated_threshold
run_gate = gate.run_gate


def _job() -> dict[str, object]:
    workflow = yaml.safe_load((ROOT / ".github/workflows/mutation.yml").read_text(encoding="utf-8"))
    return workflow["jobs"]["mutation-quality"]


def _step(name: str) -> dict[str, object]:
    return next(step for step in _job()["steps"] if step["name"] == name)  # type: ignore[index]


def test_hosted_job_runs_the_mutation_scope_with_a_neutral_sha() -> None:
    """GITHUB_SHA is unset so mutmut cannot restrict mutants to a commit's diff."""

    assert _job()["name"] == "Mutation quality and survivor gate"
    assert "env -u GITHUB_SHA mutmut run" in _step("Run selected mutation scope")["run"]
    assert "mutmut results --all true" in _step("Run selected mutation scope")["run"]


def test_hosted_job_delegates_the_gate_to_the_runnable_script() -> None:
    """The workflow must run the same gate a contributor can run before pushing."""

    run = _step("Mutation quality and survivor gate")["run"]
    assert GATE_SCRIPT in run
    for argument in (
        "--run-log mutation-run.log",
        "--results mutation-results.txt",
        "--ratchet docs/mutation-ratchet-v1.json",
    ):
        assert argument in run
    assert (ROOT / GATE_SCRIPT).is_file()


def test_hosted_job_publishes_the_gate_evidence() -> None:
    upload = _step("Upload mutation evidence")
    assert upload["if"] == "always()"
    for artifact in (
        "mutation-run.log",
        "mutation-results.txt",
        "mutation-quality.json",
        "docs/mutation-survivor-triage-v1.json",
        "docs/mutation-ratchet-v1.json",
    ):
        assert artifact in upload["with"]["path"]  # type: ignore[index]


def test_gate_defaults_match_the_published_contract() -> None:
    assert THRESHOLD_PERCENT == 95
    assert Path("docs/mutation-survivor-triage-v1.json") == DEFAULT_TRIAGE
    assert {"equivalent", "defensive", "needs_regression"} == ALLOWED_CLASSIFICATIONS


def test_gate_rejects_a_score_below_the_threshold() -> None:
    """The threshold applies to the gated scope, not to the whole run."""

    gated = {"trustweave.chain": Counter({"killed": 949, "survived": 51})}
    with pytest.raises(GateFailure, match="Mutation quality gate failed"):
        check_gated_threshold(gated)


def test_gate_rejects_an_incomplete_or_inconsistent_run() -> None:
    with pytest.raises(GateFailure, match="did not complete"):
        parse_totals("⠋ 999/1000  🎉 999  🙁 0")
    with pytest.raises(GateFailure, match="inconsistent"):
        parse_totals("⠋ 1000/1000  🎉 999  🙁 2")


def test_gate_refuses_an_uncovered_mutant_in_the_gated_scope() -> None:
    """The survivor triage cannot account for a mutant no test reaches."""

    gated = {"trustweave.chain": Counter({"killed": 999, "no tests": 1})}
    with pytest.raises(GateFailure, match="no covering test"):
        check_gated_threshold(gated)


def test_gate_holds_a_ratcheted_module_to_its_recorded_floor() -> None:
    """The module the gate does not cover is still under a control that can fail."""

    ratcheted = {"trustweave.code_analysis": Counter({"killed": 70, "survived": 30})}
    failures, _ = gate.check_ratchet(
        ratcheted, {"trustweave.code_analysis": {"score_percent": 80.0}}
    )

    assert failures and "below the recorded" in failures[0]


def _inventory(records: list[dict[str, object]]) -> dict[str, object]:
    counts = Counter(str(record["classification"]) for record in records)
    return {
        "schema_version": 1,
        "mutation_run": {"tool": "mutmut"},
        "survivor_count": len(records),
        "untriaged_count": 0,
        "classification_counts": {
            label: counts.get(label, 0) for label in sorted(ALLOWED_CLASSIFICATIONS)
        },
        "survivors": records,
    }


def _record(identifier: str, **overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "id": identifier,
        "classification": "equivalent",
        "rationale": "Reordering is unobservable.",
        "diff": f"# {identifier}: survived\n-    a = 1\n+    a = 2\n",
    }
    record.update(overrides)
    return record


def test_gate_enforces_exact_survivor_identifier_parity() -> None:
    inventory = _inventory([_record("x_a__mutmut_1")])
    with pytest.raises(GateFailure, match="exact identifier parity failed"):
        check_identifier_parity(inventory, ["x_a__mutmut_1", "x_b__mutmut_2"])
    with pytest.raises(GateFailure, match="exact identifier parity failed"):
        check_identifier_parity(inventory, ["x_b__mutmut_2"])


def test_gate_enforces_zero_untriaged_records() -> None:
    inventory = _inventory([_record("x_a__mutmut_1")]) | {"untriaged_count": 1}
    with pytest.raises(GateFailure, match="unresolved entries"):
        check_identifier_parity(inventory, ["x_a__mutmut_1"])


def test_gate_requires_a_rationale_for_every_resolved_classification() -> None:
    for classification in ("equivalent", "defensive"):
        inventory = _inventory([_record("x_a__mutmut_1", classification=classification)])
        inventory["survivors"][0]["rationale"] = ""  # type: ignore[index]
        with pytest.raises(GateFailure, match="rationale is empty"):
            check_records(inventory)


def test_gate_enforces_exact_normalized_diff_parity() -> None:
    digests, _ = check_records(_inventory([_record("x_a__mutmut_1")]))
    with pytest.raises(GateFailure, match="exact diff parity failed"):
        check_diff_parity(digests, Counter({"0" * 64: 1}))


def test_gate_blocks_publication_while_a_survivor_needs_regression(tmp_path: Path) -> None:
    """A survivor that should have been killed must fail the gate, not be reported."""

    identifiers = [f"trustweave.chain.x_a__mutmut_{index}" for index in range(1, 5)]
    records = [_record(identifier) for identifier in identifiers]
    records[0]["classification"] = "needs_regression"
    run_log = tmp_path / "run.log"
    run_log.write_text("⠋ 100/100  🎉 96  🙁 4", encoding="utf-8")
    results = tmp_path / "results.txt"
    killed = "".join(f"trustweave.chain.x_k__mutmut_{index}: killed\n" for index in range(96))
    results.write_text(
        killed + "".join(f"{name}: survived\n" for name in identifiers), encoding="utf-8"
    )
    triage = tmp_path / "triage.json"
    triage.write_text(json.dumps(_inventory(records)), encoding="utf-8")

    def fake_show(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        identifier = argv[2]
        return subprocess.CompletedProcess(argv, 0, stdout=_record(identifier)["diff"], stderr="")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("mutation_gate.subprocess.run", fake_show)
    try:
        with pytest.raises(GateFailure, match="needs_regression classifications remain"):
            run_gate(run_log, results, triage, "mutmut")
    finally:
        monkeypatch.undo()


def test_published_triage_inventory_is_well_formed() -> None:
    """The committed inventory must satisfy the record-level gate on its own."""

    inventory = json.loads((ROOT / DEFAULT_TRIAGE).read_text(encoding="utf-8"))
    _, counts = check_records(inventory)
    assert counts["needs_regression"] == 0
    assert inventory["untriaged_count"] == 0
    assert inventory["survivor_count"] == len(inventory["survivors"])
