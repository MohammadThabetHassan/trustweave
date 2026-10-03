"""The two studies that score suites and reviewers against exact ground truth.

Their figures are only as good as three things this file holds them to: the protocol the
studies were fixed under has not moved, every closed-form detection probability agrees with
enumerating what it summarises, and the committed artifacts are what the script computes.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import math
import random
import sys
from fractions import Fraction
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "exact_evaluation_study", ROOT / "scripts" / "exact_evaluation_study.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["exact_evaluation_study"] = module
    specification.loader.exec_module(module)
    return module


study = _module()


def _artifact(name: str) -> dict:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


class TestProtocol:
    def test_the_protocol_is_the_one_the_studies_were_fixed_under(self) -> None:
        study.require_protocol()

    def test_a_changed_protocol_is_refused(self, tmp_path: Path) -> None:
        changed = tmp_path / "protocol.md"
        changed.write_bytes(study.PROTOCOL.read_bytes() + b"\nA late hypothesis.\n")

        with pytest.raises(SystemExit, match="refuses to run"):
            study.require_protocol(changed)

    def test_a_crlf_checkout_hashes_the_same_text(self, tmp_path: Path) -> None:
        crlf = tmp_path / "protocol.md"
        crlf.write_bytes(
            study.PROTOCOL.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        )

        assert study.protocol_digest(crlf) == study.PROTOCOL_SHA256

    def test_every_artifact_records_the_protocol(self) -> None:
        for name in (
            "generated-policy-sample-v1.json",
            "suite-strategy-study-v1.json",
            "review-signal-study-v1.json",
        ):
            assert _artifact(name)["protocol_sha256"] == study.PROTOCOL_SHA256, name


class TestClosedForms:
    def test_one_witness_per_group_agrees_with_every_choice_of_witnesses(self) -> None:
        generator = random.Random(1)
        for _ in range(300):
            cells = list(range(generator.randint(2, 9)))
            generator.shuffle(cells)
            groups_count = generator.randint(1, len(cells))
            cuts = sorted(generator.sample(range(1, len(cells)), groups_count - 1))
            groups = [cells[a:b] for a, b in zip([0, *cuts], [*cuts, len(cells)], strict=True)]
            hits = set(generator.sample(cells, generator.randint(0, len(cells))))
            choices = list(itertools.product(*groups))
            expected = Fraction(sum(1 for c in choices if hits & set(c)), len(choices))

            assert study._detection(groups, hits) == expected

    @pytest.mark.parametrize("cells", range(1, 9))
    def test_a_random_suite_agrees_with_every_sample(self, cells: int) -> None:
        for hits in range(cells + 1):
            for size in range(1, cells + 1):
                samples = list(itertools.combinations(range(cells), size))
                expected = Fraction(
                    sum(1 for s in samples if set(s) & set(range(hits))), math.comb(cells, size)
                )

                assert study._random_detection(cells, hits, size) == expected


class TestFaults:
    def test_set_a_is_the_papers_operator_set_unchanged(self) -> None:
        reference = json.loads((ROOT / "policies" / "default-policy.json").read_text("utf-8"))

        assert [name for name, _ in study.operators_a(reference)] == [
            name for name, _ in study.harness._mutants(reference)
        ]
        assert len(study.operators_a(reference)) == 38

    def test_set_b_names_no_literal_the_policy_does_not(self) -> None:
        """So the pooled space is the policy's own, as the protocol states."""

        sample = _artifact("generated-policy-sample-v1.json")
        for document in sample["policies"][:40]:
            own = study.harness.witness_space(document)
            pooled = study.harness.witness_space(
                document, *(m for _, m in study.operators_b(document))
            )
            assert study.space_size(pooled) == study.space_size(own)


class TestRecordedStudies:
    def test_the_sample_is_the_seeded_draw(self) -> None:
        recorded = _artifact("generated-policy-sample-v1.json")

        assert study.draw_sample() == recorded
        assert len(recorded["policies"]) == study.POLICIES

    @pytest.mark.parametrize("operator_set", ["A", "B"])
    def test_per_policy_scores_match_a_fresh_analysis(self, operator_set: str) -> None:
        sample = _artifact("generated-policy-sample-v1.json")
        recorded = _artifact("suite-strategy-study-v1.json")["operator_sets"][operator_set]
        by_policy = {entry["policy"]: entry for entry in recorded["per_policy"]}
        for index in range(6):
            analysis = study.analyse_policy(sample["policies"][index], operator_set)
            scores = study.expected_scores(analysis)
            assert scores is not None
            assert by_policy[index]["expected_score"] == {
                strategy: study._round(value) for strategy, value in scores.items()
            }

    def test_covering_the_refinement_detected_every_live_mutant(self) -> None:
        """Corollary 4, checked on every scored policy rather than assumed."""

        recorded = _artifact("suite-strategy-study-v1.json")
        for operator_set in recorded["operator_sets"].values():
            for entry in operator_set["per_policy"]:
                assert entry["expected_score"]["refinement"] == 1.0

    def test_no_deviation_from_the_protocol_was_needed(self) -> None:
        assert _artifact("suite-strategy-study-v1.json")["deviations"] == []
        assert _artifact("review-signal-study-v1.json")["deviations"] == []


class TestReviewers:
    def test_a_flip_to_a_stricter_decision_raises_no_diff_signal(self) -> None:
        """The miss the study measures, shown on the reference policy."""

        reference = json.loads((ROOT / "policies" / "default-policy.json").read_text("utf-8"))
        mutants = dict(study.operators_a(reference))

        assert study.tool_signals(reference, mutants["flip_decision[TW-001->deny]"]) == []
        assert study.tool_signals(reference, mutants["delete_rule[TW-001]"]) == ["TW-DIFF-011"]

    def test_precision_and_recall_are_counted_over_the_right_sets(self) -> None:
        one = Fraction(1)
        records = [
            {
                "operator": "x",
                "change": True,
                "weakening": True,
                "signals": ["TW-DIFF-008"],
                "change_detection": {"decision": one, "quotient": one},
                "weakening_detection": {"decision": one, "quotient": one},
            },
            {
                "operator": "x",
                "change": True,
                "weakening": False,
                "signals": [],
                "change_detection": {"decision": Fraction(1, 2), "quotient": one},
                "weakening_detection": {"decision": Fraction(0), "quotient": Fraction(0)},
            },
            {
                "operator": "y",
                "change": False,
                "weakening": False,
                "signals": ["TW-DIFF-011"],
                "change_detection": {"decision": Fraction(0), "quotient": Fraction(0)},
                "weakening_detection": {"decision": Fraction(0), "quotient": Fraction(0)},
            },
        ]

        scored = study.score_reviewers(records)
        change = scored["change"]["reviewers"]
        weakening = scored["weakening"]["reviewers"]

        assert change["trustweave_diff"] == {
            "recall": 0.5,
            "precision": 0.5,
            "false_alarms": 1,
            "missed": 1,
        }
        assert change["text_diff"]["precision"] == round(2 / 3, 6)
        assert change["suite_decision"]["recall"] == 0.75
        assert weakening["trustweave_diff"] == {
            "recall": 1.0,
            "precision": 1.0,
            "false_alarms": 0,
            "missed": 0,
        }
