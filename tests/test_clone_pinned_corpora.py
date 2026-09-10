"""The corpus cloner is the instrument a reproduction starts from, so it is tested.

`scripts/clone_pinned_corpora.py` reads the commits the measurement artifacts record and
puts each corpus on disk at that commit, laid out so `verify_corpus_provenance.py` can find
it. What it must not do is report success on a tree that is not the recorded one, because
that is precisely the failure the whole provenance check exists for: a blobless clone whose
checkout stopped part-way still answers `git rev-parse HEAD` correctly.

These tests use a repository made here and cloned over `file://`, so they need no network.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


cloner = _load("clone_pinned_corpora")


def _git(*arguments: str, cwd: Path) -> str:
    finished = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *arguments],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
    )
    return finished.stdout.strip()


def _origin(tmp_path: Path, files: int = 6) -> tuple[Path, str]:
    """A small repository with a known commit, to be cloned over file://."""

    source = tmp_path / "origin"
    (source / "policies").mkdir(parents=True)
    for index in range(files):
        (source / "policies" / f"p{index}.cedar").write_text(
            f"permit(principal, action, resource) when {{ {index} == {index} }};\n"
        )
    _git("init", "--quiet", cwd=source)
    _git("add", "-A", cwd=source)
    _git("commit", "--quiet", "-m", "policies", cwd=source)
    return source, _git("rev-parse", "HEAD", cwd=source)


def test_the_plan_comes_from_the_artifacts_rather_than_a_list_beside_them() -> None:
    """A hardcoded corpus list is one more thing that can drift from the measurement."""

    plan = cloner.pinned(ROOT / "docs")

    assert plan, "no whole-corpus artifact names a corpus"
    for stem, entries in plan.items():
        assert stem.startswith("fragment-membership-")
        for entry in entries:
            assert entry["remote"].startswith("https://"), entry
            assert len(entry["commit"]) == 40, entry
    # A pooled row's repositories all land in one directory, which is what lets
    # verify_corpus_provenance.py measure that row from the directory holding them.
    pooled = plan["fragment-membership-rego-wide-v1"]
    assert len(pooled) == 4
    assert len({entry["name"] for entry in pooled}) == 4


def test_a_complete_clone_at_the_recorded_commit_is_reported_ok(tmp_path: Path) -> None:
    source, commit = _origin(tmp_path)

    outcome = cloner.clone(
        {"name": "corpus", "remote": source.as_uri(), "commit": commit}, tmp_path / "into"
    )

    assert outcome["ok"], outcome
    assert outcome["head"] == commit
    assert outcome["tracked_files"] == outcome["files_present"] == 6


def test_an_unfinished_checkout_is_refused_rather_than_reported_ok(tmp_path: Path) -> None:
    """The failure the provenance check exists for, reproduced deliberately.

    `rev-parse HEAD` still answers correctly on a tree missing most of its files, so a
    checkout that stopped part-way is invisible to every check that asks only for the commit.
    """

    source, commit = _origin(tmp_path)
    into = tmp_path / "into"
    assert cloner.clone({"name": "corpus", "remote": source.as_uri(), "commit": commit}, into)["ok"]
    working = into / "corpus"
    for path in sorted((working / "policies").glob("*.cedar"))[:4]:
        path.unlink()

    # Reading the tree as it stands must refuse it...
    tracked, present = cloner._complete(working)
    assert (tracked, present) == (6, 2)

    # ...and re-running must repair it rather than only complaining, so that a reproduction
    # can be resumed instead of restarted.
    repaired = cloner.clone({"name": "corpus", "remote": source.as_uri(), "commit": commit}, into)
    assert repaired["ok"], repaired
    assert repaired["files_present"] == 6


def test_a_tree_at_another_commit_is_refused(tmp_path: Path) -> None:
    source, first = _origin(tmp_path)
    (source / "policies" / "later.cedar").write_text("permit(principal, action, resource);\n")
    _git("add", "-A", cwd=source)
    _git("commit", "--quiet", "-m", "one more", cwd=source)
    second = _git("rev-parse", "HEAD", cwd=source)
    assert first != second

    outcome = cloner.clone(
        {"name": "corpus", "remote": source.as_uri(), "commit": first}, tmp_path / "into"
    )

    assert outcome["ok"], "the earlier commit is a legitimate target"
    assert outcome["head"] == first
    assert outcome["tracked_files"] == 6, "the later file is not in the recorded commit"


def test_a_file_count_the_artifact_disagrees_with_is_refused(tmp_path: Path) -> None:
    """The artifact records how many files the commit held; a mismatch is a moved corpus."""

    source, commit = _origin(tmp_path)

    outcome = cloner.clone(
        {
            "name": "corpus",
            "remote": source.as_uri(),
            "commit": commit,
            "tracked_files": 999,
        },
        tmp_path / "into",
    )

    assert not outcome["ok"]
    assert "999" in outcome["why"]


def test_the_command_reports_a_failure_in_its_exit_code(tmp_path: Path) -> None:
    """A cloner that fails quietly would hand the verifier a corpus it cannot trust."""

    documents = tmp_path / "docs"
    documents.mkdir()
    (documents / "fragment-membership-nowhere-wide-v1.json").write_text(
        json.dumps(
            {
                "corpus_scope": "wide",
                "corpus": [
                    {
                        "name": "missing",
                        "remote": (tmp_path / "no-such-repository").as_uri(),
                        "commit": "0" * 40,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    code = cloner.main(["--into", str(tmp_path / "into"), "--docs", str(documents)])

    assert code == 1
