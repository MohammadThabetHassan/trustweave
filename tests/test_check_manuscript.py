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
    for companion in ("supplement.tex", "graphical-abstract.tex"):
        if (PAPER.parent / companion).is_file():
            shutil.copy(PAPER.parent / companion, paper_directory / companion)
    documents = tmp_path / "docs"
    documents.mkdir()
    for artifact in DOCS.glob("*.json"):
        shutil.copy(artifact, documents / artifact.name)
    # Protocols too: the real-faults claims are read against the protocol's frozen table.
    for protocol in DOCS.glob("*PROTOCOL*.md"):
        shutil.copy(protocol, documents / protocol.name)
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

    assert any("artifacts inside" in problem for problem in problems), problems


def _holding(workspace: Path, phrase: str) -> Path:
    """The file of the split manuscript that states `phrase`: material moves between them."""

    for name in ("main.tex", "supplement.tex"):
        candidate = workspace / "paper" / name
        if candidate.is_file() and phrase in candidate.read_text(encoding="utf-8"):
            return candidate
    raise AssertionError(f"neither file of the manuscript states {phrase!r}")


def test_an_edited_phrasing_fails_rather_than_passing_silently(
    workspace: Path,
) -> None:
    paper = workspace / "paper" / "main.tex"
    holder = _holding(workspace, "flags all 88 subjects")
    text = holder.read_text(encoding="utf-8")
    holder.write_text(
        text.replace("flags all 88 subjects", "flags every subject"), encoding="utf-8"
    )

    problems = checker.check(paper, workspace / "docs")
    assert any("no longer states" in problem for problem in problems), problems


def test_a_figure_changed_in_the_supplement_is_caught(workspace: Path) -> None:
    """The claims are about the paper as a whole, so the supporting file is read too.

    A manuscript split to meet a page limit keeps its measurement notes in `supplement.tex`;
    a guard that read only the main file would pass a wrong number moved there.
    """

    supplement = workspace / "paper" / "supplement.tex"
    if not supplement.is_file():
        pytest.skip("the manuscript is not split into a main file and a supplement")
    text = supplement.read_text(encoding="utf-8")
    assert "reproduces all 7 of them" in text
    supplement.write_text(
        text.replace("reproduces all 7 of them", "reproduces all 6 of them"), "utf-8"
    )

    problems = checker.check(workspace / "paper" / "main.tex", workspace / "docs")

    assert any("provenance" in problem for problem in problems), problems


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
    whole = checker.with_supplement(text, paper)
    counts = [int(found) for found in checker.MECHANISM_COUNT.findall(checker.flatten(whole))]
    assert len(counts) >= 2, "the worked example must decompose the equivalent mutants"
    first = [int(found) for found in checker.MECHANISM_COUNT.findall(checker.flatten(text))][0]
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
    for name in ("main.tex", "supplement.tex"):
        part = workspace / "paper" / name
        if not part.is_file():
            continue
        all_gone = re.sub(
            r"\s+is\s+unobservable(\}?)\s+\(\d+\s+mutants\)",
            r"\1",
            part.read_text(encoding="utf-8"),
        )
        assert not checker.MECHANISM_COUNT.findall(checker.flatten(all_gone))
        part.write_text(all_gone, encoding="utf-8")

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
    series = re.search(r"\\addplot\[tw inside\] coordinates \{\(([\d.]+),0\)", text)
    assert series, "the taxonomy figure no longer plots a first coordinate"
    perturbed = text.replace(
        f"\\addplot[tw inside] coordinates {{({series.group(1)},0)",
        f"\\addplot[tw inside] coordinates {{({float(series.group(1)) - 1.1:.1f},0)",
        1,
    )
    paper.write_text(perturbed, encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")

    assert any("taxonomy figure" in problem for problem in problems), problems


@pytest.mark.parametrize("population", ["cedar", "rego"])
def test_a_payoff_figure_whose_series_drifts_from_its_artifact_is_caught(
    workspace: Path, population: str
) -> None:
    """The payoff figure restates three pinned tables on one scale, so it is pinned too."""

    paper = workspace / "paper" / "main.tex"
    holder = _holding(workspace, "\\begin{axis}[name=payoff")
    text = holder.read_text(encoding="utf-8")
    series = re.search(rf"\\addplot\[tw {population}\] coordinates \{{\(([\d.]+),0\)", text)
    assert series, f"the payoff figure no longer plots a first {population} coordinate"
    perturbed = text.replace(
        f"\\addplot[tw {population}] coordinates {{({series.group(1)},0)",
        f"\\addplot[tw {population}] coordinates {{({float(series.group(1)) + 2.0:.1f},0)",
        1,
    )
    holder.write_text(perturbed, encoding="utf-8")

    problems = checker.check(paper, workspace / "docs")

    assert any("payoff figure" in problem for problem in problems), problems


def test_a_rego_payoff_score_that_drifts_from_its_artifact_is_caught(workspace: Path) -> None:
    """The Rego replication's table is read across, so its rows are pinned by their own shape."""

    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    row = re.search(r"\d+ policies & ([\d.]+)\\%", text)
    assert row, "the Rego payoff table no longer has its row by policy"
    start, end = row.span(1)
    paper.write_text(text[:start] + f"{float(row.group(1)) + 0.1:.1f}" + text[end:], "utf-8")

    problems = checker.check(paper, workspace / "docs")

    assert any("rego payoff: the table, by policy" in problem for problem in problems), problems


def test_a_graphical_abstract_whose_bars_drift_from_their_artifact_is_caught(
    workspace: Path,
) -> None:
    """The table-of-contents figure is read apart from the paper, so it is pinned too."""

    figure = workspace / "paper" / "graphical-abstract.tex"
    if not figure.is_file():
        pytest.skip("the manuscript has no graphical abstract beside it")
    text = figure.read_text(encoding="utf-8")
    series = re.search(r"\\addplot\[[^]{]*\] coordinates \{\(([\d.]+),0\)", text)
    assert series, "the graphical abstract no longer plots a first coordinate"
    start, end = series.span(1)
    figure.write_text(text[:start] + f"{float(series.group(1)) - 3.0:.1f}" + text[end:], "utf-8")

    problems = checker.check(workspace / "paper" / "main.tex", workspace / "docs")

    assert any("graphical abstract figure" in problem for problem in problems), problems


def test_a_figure_whose_axis_is_renamed_is_reported_rather_than_skipped(workspace: Path) -> None:
    """A guard that quietly finds nothing to check is worse than no guard."""

    paper = workspace / "paper" / "main.tex"
    text = paper.read_text(encoding="utf-8")
    assert "name=taxonomy" in text
    paper.write_text(text.replace("name=taxonomy", "name=elsewhere"), "utf-8")
    supplement = workspace / "paper" / "supplement.tex"
    if supplement.is_file():
        supplement.write_text(
            supplement.read_text(encoding="utf-8").replace("name=taxonomy", "name=elsewhere"),
            "utf-8",
        )

    problems = checker.check(paper, workspace / "docs")

    assert any("taxonomy figure states no data" in problem for problem in problems), problems
