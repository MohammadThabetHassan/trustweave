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
import os
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _artifacts() -> Path:
    """The `docs/` directory holding the JSON the manuscript's claims are pinned to.

    The mutation runner copies `src`, `tests` and `scripts` into a `mutants/` directory
    and runs the suite from there, so the root this file computes is not always the
    repository. Walking up finds the real tree in that case.
    """

    for candidate in (ROOT, *ROOT.parents):
        if (candidate / "docs" / "estimator-comparison-v1.json").is_file():
            return candidate / "docs"
    return ROOT / "docs"


def _paper() -> Path | None:
    """The manuscript, which is deliberately not in this repository.

    A journal reads a publicly posted full text as prior dissemination, so the paper is
    kept outside the working tree and located through TRUSTWEAVE_PAPER. These tests skip
    when it is not set, because a checkout without the paper is the normal case -- but
    they must still run wherever the paper does live, since a guard nobody exercises is
    not a guard.
    """

    from_environment = os.environ.get("TRUSTWEAVE_PAPER")
    if from_environment and Path(from_environment).is_file():
        return Path(from_environment)
    for candidate in (ROOT, *ROOT.parents):
        in_tree = candidate / "paper" / "main.tex"
        if in_tree.is_file():
            return in_tree
    return None


PAPER_OR_NONE = _paper()
DOCS = _artifacts()
PAPER = PAPER_OR_NONE if PAPER_OR_NONE is not None else ROOT / "paper" / "main.tex"

pytestmark = pytest.mark.skipif(
    PAPER_OR_NONE is None,
    reason="the manuscript is kept outside the repository; set TRUSTWEAVE_PAPER to check it",
)


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

    The figure is derived from the artifacts rather than written here. Hard-coding it went
    stale twice as the corpus grew, and summing four ecosystems by hand went stale a third
    time when IAM and Azure joined the table; the taxonomy artifact sums every corpus.
    """

    inside = checker._load(DOCS, "exclusion-taxonomy-v1")["artifacts_inside"]
    pooled = checker._grouped(inside)
    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    assert text.count(pooled) >= 2, f"the fixture needs the pooled count {pooled} stated twice"
    paper.write_text(text.replace(pooled, checker._grouped(inside - 3), 1), encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")

    assert any("policies inside" in problem for problem in problems), problems


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
    """Lower one mechanism's count by one and the sum no longer meets the artifact.

    The counts are read from the paper rather than written here: they changed once when
    the worked example was corrected, and a test carrying the old ones tested nothing.
    """

    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    counts = [int(found) for found in checker.MECHANISM_COUNT.findall(checker.flatten(text))]
    assert len(counts) >= 2, "the worked example must decompose the equivalent mutants"
    first = counts[0]
    paper.write_text(
        text.replace(f"({first} mutants)", f"({first - 1} mutants)", 1), encoding="utf-8"
    )

    problems = checker.check(paper, workspace / "docs")

    expected = f"account for {sum(counts) - 1} equivalent mutants"
    assert any(expected in problem for problem in problems), problems


def test_a_removed_decomposition_is_caught_rather_than_passing(workspace: Path) -> None:
    """Dropping one mechanism fails on the sum; dropping them all must not pass silently."""

    import re

    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    all_gone = re.sub(r" is unobservable\} \(\d+ mutants\)", "}", text)
    assert not checker.MECHANISM_COUNT.findall(checker.flatten(all_gone))
    paper.write_text(all_gone, encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")

    assert any("no longer decomposes" in problem for problem in problems), problems


def test_the_bibliography_cites_the_commits_the_artifacts_measured() -> None:
    assert (
        checker.corpus_findings((PAPER.parent / "refs.bib").read_text(encoding="utf-8"), DOCS) == []
    )


def test_a_cited_corpus_commit_no_artifact_measured_is_caught(workspace: Path) -> None:
    """The failure a reader would actually hit: a corpus they cannot reconstruct."""
    bibliography = workspace / "paper" / "refs.bib"
    text = bibliography.read_text(encoding="utf-8")
    bibliography.write_text(text.replace("ab73ad39", "ab73ad38"), encoding="utf-8")

    problems = checker.check(workspace / "paper" / "main.tex", workspace / "docs")

    assert any("no artifact measured" in problem for problem in problems), problems


def test_a_measured_corpus_the_bibliography_omits_is_caught(workspace: Path) -> None:
    """The other direction: a corpus that was read but never named."""
    artifact = workspace / "docs" / "fragment-membership-rego-wide-v1.json"
    findings = json.loads(artifact.read_text(encoding="utf-8"))
    findings["corpus"].append(
        {"name": "extra", "remote": "https://example.com/extra.git", "commit": "0" * 40}
    )
    artifact.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    problems = checker.check(workspace / "paper" / "main.tex", workspace / "docs")

    assert any("does not cite" in problem for problem in problems), problems


def test_a_figure_whose_series_drifts_from_its_artifact_is_caught(workspace: Path) -> None:
    """A plotted series is the one number in a paper no prose pin reaches.

    The caption, the surrounding text and the artifact can all agree while the coordinates
    a reader actually looks at are a measurement out of date, because nothing compares them.
    """

    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    series = re.search(r"\\addplot coordinates \{\(([\d.]+),0\)", text)
    assert series, "the taxonomy figure no longer plots a first coordinate"
    perturbed = text.replace(
        f"\\addplot coordinates {{({series.group(1)},0)",
        f"\\addplot coordinates {{({float(series.group(1)) - 1.1:.1f},0)",
        1,
    )
    paper.write_text(perturbed, encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")

    assert any("taxonomy figure" in problem for problem in problems), problems


def test_a_cost_figure_series_that_drifts_is_caught(workspace: Path) -> None:
    """The same check on the figure that had carried unpinned coordinates for a release."""

    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    assert "(4,0." in text, "the cost figure no longer plots a four-cell share"
    paper.write_text(text.replace("(4,0.", "(4,0.1", 1), encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")

    assert any("cost figure" in problem for problem in problems), problems


def test_a_figure_whose_label_moves_is_reported_rather_than_skipped(workspace: Path) -> None:
    """A guard that quietly finds nothing to check is worse than no guard."""

    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    paper.write_text(text.replace("\\label{fig:taxonomy}", "\\label{fig:elsewhere}"), "utf-8")

    problems = checker.check(paper, workspace / "docs")

    assert any("taxonomy figure states no data" in problem for problem in problems), problems
