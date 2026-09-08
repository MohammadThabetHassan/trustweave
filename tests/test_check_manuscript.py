"""The manuscript's figures are pinned to the artifacts, and the pin is tested.

Prose is not executed, so a wrong number in the paper is invisible to every other test
in this repository. `scripts/check_manuscript.py` closes that gap, and this file checks
the closure the only way that means anything: by perturbing a figure and requiring the
guard to fail. A guard that has only ever been seen to pass is not evidence.

The perturbations are the two that revision actually produces -- a number changed in one
section and left alone in another, and a phrasing rewritten so the pin no longer matches
anything.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _repository_root() -> Path | None:
    """The tree holding both the manuscript and the artifacts, or None if there is none.

    The mutation runner copies `src`, `tests` and `scripts` into a `mutants/` directory
    and runs the suite from there, so the root this file computes is not always the
    repository: under mutmut it is `mutants/`, which carries no `paper/`. Walking up finds
    the real tree in that case, and returning None lets these tests skip rather than fail
    in a checkout that legitimately has no manuscript.
    """

    for candidate in (ROOT, *ROOT.parents):
        if (candidate / "paper" / "main.tex").is_file() and (candidate / "docs").is_dir():
            return candidate
    return None


REPOSITORY = _repository_root()
PAPER = (REPOSITORY / "paper" / "main.tex") if REPOSITORY else ROOT / "paper" / "main.tex"
DOCS = (REPOSITORY / "docs") if REPOSITORY else ROOT / "docs"

pytestmark = pytest.mark.skipif(REPOSITORY is None, reason="no manuscript in this tree to check")


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "check_manuscript", ROOT / "scripts" / "check_manuscript.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["check_manuscript"] = module
    specification.loader.exec_module(module)
    return module


checker = _module()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A copy of the paper and its artifacts that a test may edit."""
    paper_directory = tmp_path / "paper"
    paper_directory.mkdir()
    shutil.copy(PAPER, paper_directory / "main.tex")
    shutil.copy(PAPER.parent / "refs.bib", paper_directory / "refs.bib")
    documents = tmp_path / "docs"
    documents.mkdir()
    for artifact in DOCS.glob("*.json"):
        shutil.copy(artifact, documents / artifact.name)
    return tmp_path


def test_the_shipped_manuscript_agrees_with_its_artifacts() -> None:
    assert checker.check(PAPER, DOCS) == []


def test_the_manuscript_pins_a_substantial_number_of_claims() -> None:
    """A guard over three figures would pass while saying almost nothing."""
    assert len(checker.numeric_claims(DOCS)) >= 20


def test_a_figure_changed_in_one_section_only_is_caught(workspace: Path) -> None:
    """The failure substring search cannot see, because the old value survives.

    The pooled membership count is stated in the abstract, in the conclusion and in the
    total row of the membership table, so editing the first occurrence leaves the correct
    value present elsewhere in the file. A substring search passes that paper. This must
    not.
    """
    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    assert text.count("753") >= 2, "the fixture needs the figure stated more than once"
    paper.write_text(text.replace("753", "750", 1), encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")
    assert any("pooled membership" in problem for problem in problems), problems


def test_an_edited_phrasing_fails_rather_than_passing_silently(
    workspace: Path,
) -> None:
    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    paper.write_text(text.replace("flags all 88 subjects", "flags every subject"), encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")
    assert any("no longer states" in problem for problem in problems), problems


def test_a_perturbed_artifact_disagrees_with_the_manuscript(workspace: Path) -> None:
    """The guard is symmetric: it does not assume the artifact is the wrong side."""
    artifact = workspace / "docs" / "estimator-comparison-v1.json"
    findings = json.loads(artifact.read_text(encoding="utf-8"))
    findings["equivalent_share"] = 0.4311
    artifact.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    problems = checker.check(workspace / "paper" / "main.tex", workspace / "docs")
    assert any("equivalent share" in problem for problem in problems), problems


def test_a_citation_without_a_bibliography_entry_is_caught(workspace: Path) -> None:
    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    paper.write_text(text.replace(r"\cite{z3}", r"\cite{z3,absent2026}"), "utf-8")

    problems = checker.check(paper, workspace / "docs")
    assert any("absent2026" in problem for problem in problems), problems


def test_a_dangling_cross_reference_is_caught(workspace: Path) -> None:
    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    paper.write_text(text.replace(r"\ref{thm:kill}", r"\ref{thm:absent}", 1), encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")
    assert any("thm:absent" in problem for problem in problems), problems


def test_flatten_sees_through_emphasis_and_line_breaks() -> None:
    """The pins match phrasing, so they must survive bold and a wrapped line."""
    flattened = checker.flatten("carries \\textbf{0.000 bits}\n--- exactly none.")
    assert flattened == "carries 0.000 bits --- exactly none."


def test_the_worked_example_accounts_for_every_equivalent_mutant() -> None:
    """The paper's explanation is arithmetic, so it can be checked as arithmetic."""

    assert (
        checker.decomposition_findings(checker.flatten(PAPER.read_text(encoding="utf-8")), DOCS)
        == []
    )


def test_a_decomposition_that_no_longer_sums_is_caught(workspace: Path) -> None:
    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    paper.write_text(text.replace("(13 mutants)", "(12 mutants)"), encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")
    assert any("account for 15 equivalent mutants" in problem for problem in problems), problems


def test_a_removed_decomposition_is_caught_rather_than_passing(workspace: Path) -> None:
    """Dropping one mechanism fails on the sum; dropping both must not pass silently."""
    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    both_gone = text.replace(" is unobservable} (13 mutants)", "}").replace(
        " is unobservable} (3 mutants)", "}"
    )
    assert "mutants)" not in both_gone or "is unobservable}" not in both_gone
    paper.write_text(both_gone, encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")
    assert any("no longer decomposes" in problem for problem in problems), problems
