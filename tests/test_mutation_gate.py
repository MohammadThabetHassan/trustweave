"""Tests for the mutation quality and survivor-triage parity gate.

The gate decides whether the discovery layer's mutation evidence may be published, so
each rejection reason is asserted individually rather than through the exit code alone.
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

GateFailure = gate.GateFailure
check_diff_parity = gate.check_diff_parity
check_identifier_parity = gate.check_identifier_parity
check_records = gate.check_records
diff_digest = gate.diff_digest
load_inventory = gate.load_inventory
check_gated_threshold = gate.check_gated_threshold
partition = gate.partition
module_of = gate.module_of
main = gate.main
normalized_diff = gate.normalized_diff
parse_survivors = gate.parse_survivors
parse_totals = gate.parse_totals
run_gate = gate.run_gate

PROGRESS = "⠋ Running mutation testing 100/100  🎉 96  🫥 0  ⏰ 0  🤔 0  🙁 4  🔇 0"
DIFF = """# x_probe__mutmut_1: survived

--- probe.py
+++ probe.py
@@ -1,2 +1,2 @@
-    return value > 0
+    return value >= 0
"""


def _record(identifier: str, classification: str = "equivalent") -> dict[str, object]:
    return {
        "id": identifier,
        "classification": classification,
        "rationale": "Boundary is unobservable to callers.",
        "diff": DIFF,
    }


def _inventory(identifiers: list[str], **overrides: object) -> dict[str, object]:
    records = [_record(identifier) for identifier in identifiers]
    inventory: dict[str, object] = {
        "schema_version": 1,
        "mutation_run": {"tool": "mutmut"},
        "survivor_count": len(records),
        "untriaged_count": 0,
        "classification_counts": {
            "defensive": 0,
            "equivalent": len(records),
            "needs_regression": 0,
        },
        "survivors": records,
    }
    inventory.update(overrides)
    return inventory


class TestParseTotals:
    def test_reads_the_final_progress_line(self) -> None:
        assert parse_totals(f"earlier noise\n{PROGRESS}\n") == (100, 96, 4)

    def test_prefers_the_last_line_when_progress_is_repeated(self) -> None:
        early = "⠋ 10/100  🎉 9  🙁 1"
        assert parse_totals(f"{early}\n{PROGRESS}") == (100, 96, 4)

    def test_carriage_returns_do_not_hide_the_totals(self) -> None:
        assert parse_totals(f"spinner\r{PROGRESS}") == (100, 96, 4)

    def test_rejects_output_without_totals(self) -> None:
        with pytest.raises(GateFailure, match="did not contain final"):
            parse_totals("mutmut crashed before reporting\n")

    def test_rejects_an_incomplete_run(self) -> None:
        with pytest.raises(GateFailure, match="did not complete: 40/100"):
            parse_totals("⠋ 40/100  🎉 38  🙁 2")

    def test_allows_mutants_that_are_neither_killed_nor_survived(self) -> None:
        """A mutant can also be reported as having no covering test."""

        assert parse_totals("⠋ 100/100  🎉 90  🙁 4") == (100, 90, 4)

    def test_rejects_totals_that_exceed_the_generated_count(self) -> None:
        with pytest.raises(GateFailure, match="totals are inconsistent"):
            parse_totals("⠋ 100/100  🎉 98  🙁 6")

    def test_does_not_judge_the_score(self) -> None:
        """The threshold is over the gated modules, which the run totals do not identify."""

        assert parse_totals("⠋ 100/100  🎉 10  🙁 90") == (100, 10, 90)


class TestGatedThreshold:
    def test_a_score_below_the_threshold_is_refused(self) -> None:
        gated = {"trustweave.chain": Counter({"killed": 94, "survived": 6})}
        with pytest.raises(GateFailure, match=r"94\.00%\) < 95%"):
            check_gated_threshold(gated)

    def test_a_score_exactly_at_the_threshold_is_accepted(self) -> None:
        gated = {"trustweave.chain": Counter({"killed": 95, "survived": 5})}

        assert check_gated_threshold(gated)["score_percent"] == 95.0

    def test_a_gated_module_with_an_uncovered_mutant_is_refused(self) -> None:
        """The triage cannot describe a mutant no test reaches, so it must not exist here."""

        gated = {"trustweave.chain": Counter({"killed": 99, "no tests": 1})}
        with pytest.raises(GateFailure, match="no covering test"):
            check_gated_threshold(gated)

    def test_an_empty_gated_scope_is_refused(self) -> None:
        with pytest.raises(GateFailure, match="No gated module"):
            check_gated_threshold({})


class TestPartition:
    def test_the_module_is_read_from_the_identifier(self) -> None:
        assert module_of("trustweave.chain.x_render__mutmut_4") == "trustweave.chain"

    def test_ratcheted_modules_are_separated_from_gated_ones(self) -> None:
        results = (
            "trustweave.chain.x_a__mutmut_1: killed\n"
            "trustweave.chain.x_a__mutmut_2: survived\n"
            "trustweave.code_analysis.x_b__mutmut_1: survived\n"
            "trustweave.code_analysis.x_b__mutmut_2: no tests\n"
        )
        gated, ratcheted = partition(results)

        assert set(gated) == {"trustweave.chain"}
        assert set(ratcheted) == {"trustweave.code_analysis"}
        assert ratcheted["trustweave.code_analysis"]["no tests"] == 1


class TestParseSurvivors:
    def test_extracts_identifiers(self) -> None:
        results = "x_a__mutmut_1: survived\nx_b__mutmut_2: killed\nx_c__mutmut_3: survived\n"
        assert parse_survivors(results, survived=2) == ["x_a__mutmut_1", "x_c__mutmut_3"]

    def test_rejects_a_count_that_disagrees_with_the_run(self) -> None:
        with pytest.raises(GateFailure, match="does not equal final run total"):
            parse_survivors("x_a__mutmut_1: survived\n", survived=2)

    def test_rejects_duplicate_identifiers(self) -> None:
        results = "x_a__mutmut_1: survived\nx_a__mutmut_1: survived\n"
        with pytest.raises(GateFailure, match="duplicate survivor identifiers"):
            parse_survivors(results, survived=2)


class TestDiffNormalisation:
    def test_strips_the_survivor_banner(self) -> None:
        assert not normalized_diff(DIFF).startswith("#")

    def test_leaves_a_diff_without_a_banner_alone(self) -> None:
        body = "--- a\n+++ b\n"
        assert normalized_diff(body) == body

    def test_a_renamed_mutant_with_the_same_diff_has_the_same_digest(self) -> None:
        renamed = DIFF.replace("x_probe__mutmut_1", "x_probe__mutmut_9")
        assert diff_digest(renamed) == diff_digest(DIFF)

    def test_a_changed_diff_body_changes_the_digest(self) -> None:
        assert diff_digest(DIFF.replace(">= 0", "> 1")) != diff_digest(DIFF)


class TestLoadInventory:
    def test_reports_a_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(GateFailure, match="Missing survivor triage inventory"):
            load_inventory(tmp_path / "absent.json")

    def test_reports_missing_fields(self, tmp_path: Path) -> None:
        path = tmp_path / "triage.json"
        path.write_text(json.dumps({"survivors": []}), encoding="utf-8")
        with pytest.raises(GateFailure, match="missing fields"):
            load_inventory(path)

    def test_requires_survivors_to_be_a_list(self, tmp_path: Path) -> None:
        path = tmp_path / "triage.json"
        path.write_text(json.dumps(_inventory([]) | {"survivors": {}}), encoding="utf-8")
        with pytest.raises(GateFailure, match="must be a list"):
            load_inventory(path)


class TestIdentifierParity:
    def test_accepts_an_exact_match(self) -> None:
        inventory = _inventory(["x_a__mutmut_1"])
        assert check_identifier_parity(inventory, ["x_a__mutmut_1"]) == ["x_a__mutmut_1"]

    def test_rejects_a_survivor_absent_from_the_inventory(self) -> None:
        with pytest.raises(GateFailure, match=r"missing=\['x_b__mutmut_2'\]"):
            check_identifier_parity(
                _inventory(["x_a__mutmut_1"]), ["x_a__mutmut_1", "x_b__mutmut_2"]
            )

    def test_rejects_a_stale_inventory_entry(self) -> None:
        with pytest.raises(GateFailure, match=r"stale=\['x_b__mutmut_2'\]"):
            check_identifier_parity(
                _inventory(["x_a__mutmut_1", "x_b__mutmut_2"]), ["x_a__mutmut_1"]
            )

    def test_rejects_a_record_without_a_string_id(self) -> None:
        inventory = _inventory(["x_a__mutmut_1"])
        inventory["survivors"][0].pop("id")  # type: ignore[index]
        with pytest.raises(GateFailure, match="string id"):
            check_identifier_parity(inventory, ["x_a__mutmut_1"])

    def test_rejects_duplicate_inventory_ids(self) -> None:
        inventory = _inventory(["x_a__mutmut_1"])
        inventory["survivors"].append(_record("x_a__mutmut_1"))  # type: ignore[attr-defined]
        with pytest.raises(GateFailure, match="duplicate mutant ids"):
            check_identifier_parity(inventory, ["x_a__mutmut_1"])

    def test_rejects_a_miscounted_inventory(self) -> None:
        inventory = _inventory(["x_a__mutmut_1"], survivor_count=7)
        with pytest.raises(GateFailure, match="count is inconsistent"):
            check_identifier_parity(inventory, ["x_a__mutmut_1"])

    def test_rejects_a_nonzero_untriaged_count(self) -> None:
        inventory = _inventory(["x_a__mutmut_1"], untriaged_count=1)
        with pytest.raises(GateFailure, match="unresolved entries"):
            check_identifier_parity(inventory, ["x_a__mutmut_1"])


class TestRecords:
    def test_returns_digests_and_counts(self) -> None:
        digests, counts = check_records(_inventory(["x_a__mutmut_1", "x_b__mutmut_2"]))
        assert digests == Counter({diff_digest(DIFF): 2})
        assert counts == {"defensive": 0, "equivalent": 2, "needs_regression": 0}

    @pytest.mark.parametrize("diff", ["", "   \n"])
    def test_rejects_an_empty_diff(self, diff: str) -> None:
        inventory = _inventory(["x_a__mutmut_1"])
        inventory["survivors"][0]["diff"] = diff  # type: ignore[index]
        with pytest.raises(GateFailure, match="diff is empty"):
            check_records(inventory)

    def test_rejects_an_unknown_classification(self) -> None:
        inventory = _inventory(["x_a__mutmut_1"])
        inventory["survivors"][0]["classification"] = "wont_fix"  # type: ignore[index]
        with pytest.raises(GateFailure, match="Invalid survivor classification"):
            check_records(inventory)

    def test_rejects_an_empty_rationale(self) -> None:
        inventory = _inventory(["x_a__mutmut_1"])
        inventory["survivors"][0]["rationale"] = "  "  # type: ignore[index]
        with pytest.raises(GateFailure, match="rationale is empty"):
            check_records(inventory)

    def test_rejects_declared_counts_that_disagree(self) -> None:
        inventory = _inventory(["x_a__mutmut_1"])
        inventory["survivors"][0]["classification"] = "defensive"  # type: ignore[index]
        with pytest.raises(GateFailure, match="classification counts are inconsistent"):
            check_records(inventory)


class TestDiffParity:
    def test_accepts_matching_multisets(self) -> None:
        check_diff_parity(Counter({"a": 2}), Counter({"a": 2}))

    def test_rejects_a_changed_diff(self) -> None:
        with pytest.raises(GateFailure, match="missing_diff_digests"):
            check_diff_parity(Counter({"a": 1}), Counter({"b": 1}))

    def test_rejects_a_multiplicity_change(self) -> None:
        with pytest.raises(GateFailure, match="exact diff parity failed"):
            check_diff_parity(Counter({"a": 1}), Counter({"a": 2}))


class TestRunGate:
    @staticmethod
    def _fixtures(tmp_path: Path, identifiers: list[str]) -> tuple[Path, Path, Path]:
        run_log = tmp_path / "run.log"
        run_log.write_text(PROGRESS, encoding="utf-8")
        results = tmp_path / "results.txt"
        # 96 killed and 4 survived, all in one gated module, so the scope clears 95%.
        killed = "".join(f"trustweave.chain.x_k__mutmut_{index}: killed\n" for index in range(96))
        survived = "".join(f"{name}: survived\n" for name in identifiers)
        results.write_text(killed + survived, encoding="utf-8")
        triage = tmp_path / "triage.json"
        triage.write_text(json.dumps(_inventory(identifiers)), encoding="utf-8")
        return run_log, results, triage

    @pytest.fixture
    def stub_show(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            banner = f"# {argv[2]}: survived\n"
            return subprocess.CompletedProcess(
                argv, 0, stdout=banner + DIFF.split("\n", 1)[1], stderr=""
            )

        monkeypatch.setattr("mutation_gate.subprocess.run", fake_run)

    def test_passes_and_reports_evidence(self, tmp_path: Path, stub_show: None) -> None:
        identifiers = [f"trustweave.chain.x_a__mutmut_{index}" for index in range(1, 5)]
        run_log, results, triage = self._fixtures(tmp_path, identifiers)
        evidence = run_gate(run_log, results, triage, "mutmut")
        assert evidence["killed"] == 96
        assert evidence["score_percent"] == 96.0
        assert evidence["survivor_identifier_parity"] == "exact"
        assert evidence["triage_survivor_count"] == 4
        assert evidence["triage_untriaged_count"] == 0

    def test_needs_regression_blocks_the_gate(self, tmp_path: Path, stub_show: None) -> None:
        identifiers = [f"trustweave.chain.x_a__mutmut_{index}" for index in range(1, 5)]
        run_log, results, triage = self._fixtures(tmp_path, identifiers)
        inventory = _inventory(identifiers)
        inventory["survivors"][0]["classification"] = "needs_regression"  # type: ignore[index]
        inventory["classification_counts"] = {
            "defensive": 0,
            "equivalent": 3,
            "needs_regression": 1,
        }
        triage.write_text(json.dumps(inventory), encoding="utf-8")
        with pytest.raises(GateFailure, match="1 needs_regression classifications remain"):
            run_gate(run_log, results, triage, "mutmut")

    def test_main_writes_no_evidence_when_the_gate_fails(self, tmp_path: Path) -> None:
        run_log = tmp_path / "run.log"
        run_log.write_text("⠋ 100/100  🎉 90  🙁 10", encoding="utf-8")
        results = tmp_path / "results.txt"
        results.write_text("", encoding="utf-8")
        evidence = tmp_path / "evidence.json"
        exit_code = main(
            [
                "--run-log",
                str(run_log),
                "--results",
                str(results),
                "--triage",
                str(tmp_path / "triage.json"),
                "--evidence",
                str(evidence),
            ]
        )
        assert exit_code == 1
        assert not evidence.exists()

    def test_main_writes_evidence_when_the_gate_passes(
        self, tmp_path: Path, stub_show: None
    ) -> None:
        identifiers = [f"trustweave.chain.x_a__mutmut_{index}" for index in range(1, 5)]
        run_log, results, triage = self._fixtures(tmp_path, identifiers)
        evidence = tmp_path / "evidence.json"
        # The ratchet path is passed explicitly. Its default is relative, so leaving it
        # out made the result depend on the working directory: from the repository root
        # the real record loads and demands mutants this fixture does not produce.
        exit_code = main(
            [
                "--run-log",
                str(run_log),
                "--results",
                str(results),
                "--triage",
                str(triage),
                "--evidence",
                str(evidence),
                "--ratchet",
                str(tmp_path / "absent-ratchet.json"),
            ]
        )
        assert exit_code == 0
        assert json.loads(evidence.read_text(encoding="utf-8"))["threshold_percent"] == 95


class TestRatchet:
    """A module held to a floor rather than to the survivor-triage gate."""

    def test_a_rate_above_the_floor_passes(self) -> None:
        ratcheted = {"trustweave.code_analysis": Counter({"killed": 85, "survived": 15})}
        floors = {"trustweave.code_analysis": {"score_percent": 80.0}}

        failures, measured = gate.check_ratchet(ratcheted, floors)

        assert failures == []
        assert measured["trustweave.code_analysis"]["score_percent"] == 85.0

    def test_a_rate_exactly_at_the_floor_passes(self) -> None:
        ratcheted = {"trustweave.code_analysis": Counter({"killed": 80, "survived": 20})}
        floors = {"trustweave.code_analysis": {"score_percent": 80.0}}

        assert gate.check_ratchet(ratcheted, floors)[0] == []

    def test_a_rate_below_the_floor_fails(self) -> None:
        ratcheted = {"trustweave.code_analysis": Counter({"killed": 79, "survived": 21})}
        floors = {"trustweave.code_analysis": {"score_percent": 80.0}}

        failures, _ = gate.check_ratchet(ratcheted, floors)

        assert failures and "below the recorded" in failures[0]

    def test_uncovered_mutants_count_against_the_rate(self) -> None:
        """A mutant no test reaches is not killed, so it must not be quietly dropped."""

        ratcheted = {
            "trustweave.code_analysis": Counter({"killed": 80, "survived": 10, "no tests": 10})
        }
        failures, measured = gate.check_ratchet(
            ratcheted, {"trustweave.code_analysis": {"score_percent": 80.0}}
        )

        assert measured["trustweave.code_analysis"]["generated"] == 100
        assert measured["trustweave.code_analysis"]["score_percent"] == 80.0
        assert failures == []

    def test_a_recorded_floor_with_no_mutants_is_refused(self) -> None:
        """Silence would hide the module dropping out of the mutation scope."""

        failures, _ = gate.check_ratchet({}, {"trustweave.code_analysis": {"score_percent": 80.0}})

        assert failures and "produced no mutants" in failures[0]

    def test_mutants_with_no_recorded_floor_are_refused(self) -> None:
        ratcheted = {"trustweave.code_analysis": Counter({"killed": 80, "survived": 20})}

        failures, _ = gate.check_ratchet(ratcheted, {})

        assert failures and "no recorded floor" in failures[0]

    def test_the_committed_record_names_every_ratcheted_module(self) -> None:
        record = json.loads(
            (ROOT / "docs" / "mutation-ratchet-v1.json").read_text(encoding="utf-8")
        )

        assert set(record["modules"]) == set(gate.RATCHETED_MODULES)
        for entry in record["modules"].values():
            assert 0 < entry["score_percent"] <= 100
            assert entry["reason"].strip()


def test_a_ratcheted_survivor_is_not_expected_in_the_triage_inventory() -> None:
    """Its survivors are counted, never excused, and no proof is claimed for them."""

    inventory = json.loads(
        (ROOT / "docs" / "mutation-survivor-triage-v1.json").read_text(encoding="utf-8")
    )
    ratcheted = [
        record["id"]
        for record in inventory["survivors"]
        if gate.module_of(record["id"]) in gate.RATCHETED_MODULES
    ]

    assert ratcheted == []
