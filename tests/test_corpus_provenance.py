"""The recorded provenance is checked by re-measuring, and that check is tested.

`scripts/verify_corpus_provenance.py` re-runs each adapter over the corpora at the commits
their artifacts record and diffs the counts. It needs the corpora on disk, so it cannot run
here; what runs here is the report it last produced, held to what the paper says of it, plus
the parts of the instrument that need no corpus at all -- which is where its own mistakes
would be, since a verifier that silently checks nothing reports success.
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


verifier = _load("verify_corpus_provenance")


def _report() -> dict:
    for candidate in (ROOT, *ROOT.parents):
        path = candidate / "docs" / "corpus-provenance-verification-v1.json"
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    raise AssertionError("docs/corpus-provenance-verification-v1.json is missing")


def test_every_whole_corpus_artifact_was_re_measured_and_reproduced() -> None:
    """The claim in the paper: seven of the corpora reproduce from their recorded commits."""

    report = _report()

    assert report["differing"] == []
    assert report["checked"] == report["reproduced"] == 7
    for row in report["rows"]:
        if row["verdict"] == "reproduced":
            assert row["recorded"] == row["measured"]


def test_the_report_covers_every_membership_artifact_and_says_why_when_it_cannot() -> None:
    """A verifier that quietly skips what it cannot do would report success either way."""

    report = _report()
    docs = sorted(path.stem for path in (ROOT / "docs").glob("fragment-membership-*.json"))

    assert sorted(row["artifact"] for row in report["rows"]) == docs
    assert report["artifacts"] == len(docs)
    for row in report["rows"]:
        assert row["verdict"] in ("reproduced", "differs", "skipped", "not checked")
        if row["verdict"] in ("skipped", "not checked"):
            assert row["why"], row["artifact"]
    assert len(report["not_checked"]) == len(docs) - report["checked"]


def test_a_corpus_at_the_wrong_commit_is_reported_rather_than_measured(tmp_path: Path) -> None:
    """The failure the instrument exists for: a tree that is not the one recorded."""

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "fragment-membership-cedar-wide-v1.json").write_text(
        json.dumps(
            {
                "ecosystem": "cedar",
                "corpus_scope": "wide",
                "corpus": [
                    {"name": "cedar-integration-tests", "commit": "f" * 40, "remote": "https://x"}
                ],
                "policies_considered": 22,
                "counts": {"inside": 22, "outside": 0, "undetermined": 0},
            }
        ),
        encoding="utf-8",
    )

    findings = verifier.verify(tmp_path / "no-corpora-here", docs)
    row = findings["rows"][0]

    assert row["verdict"] == "not checked"
    assert "cedar-integration-tests" in row["why"]
    assert findings["checked"] == 0
    assert findings["differing"] == []
    assert row["corpus"][0]["remote"] == "https://x", "the report says where to get it"


def test_a_recorded_count_that_no_longer_holds_is_reported_as_differing(tmp_path: Path) -> None:
    """The Azure case, in miniature: the tree is the recorded one and the count is not."""

    corpus = tmp_path / "corpora" / "one"
    (corpus / "policies").mkdir(parents=True)
    (corpus / "policies" / "a.cedar").write_text("permit(principal, action, resource);\n")
    subprocess.run(["git", "-C", str(corpus), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(corpus), "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(corpus),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "one policy",
        ],
        check=True,
    )
    commit = verifier._head(corpus)
    assert commit

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "fragment-membership-cedar-wide-v1.json").write_text(
        json.dumps(
            {
                "ecosystem": "cedar",
                "corpus_scope": "wide",
                "corpus": [{"name": "one", "commit": commit, "remote": "https://x"}],
                "policies_considered": 99,
                "counts": {"inside": 99, "outside": 0, "undetermined": 0},
            }
        ),
        encoding="utf-8",
    )

    findings = verifier.verify(tmp_path / "corpora", docs)
    row = findings["rows"][0]

    assert row["verdict"] == "differs"
    assert findings["differing"] == ["fragment-membership-cedar-wide-v1"]
    assert row["measured"]["policies_considered"] != 99
    assert verifier.main(["--corpora", str(tmp_path / "corpora"), "--docs", str(docs)]) == 1


def test_a_pooled_row_is_measured_from_the_directory_that_holds_its_corpora() -> None:
    """The Rego row pools four checkouts, and measuring one of them is a different study."""

    root = Path("/corpora/rego")

    assert verifier._measurement_root([root / "a"]) == root / "a"
    assert verifier._measurement_root([root / "a", root / "b"]) == root


def test_the_provenance_records_how_much_of_the_commit_was_on_disk() -> None:
    """The field whose absence let a measurement over a fifth of a repository look complete.

    Two Azure artifacts recorded commit `9780ba64`, one reporting 3,659 definitions and the
    other 3,769. The commit was right both times; the working tree was not -- the first had
    only `built-in-policies/` on disk, a blobless clone whose checkout did not finish -- and
    no field in either artifact could tell them apart.
    """

    stems = sorted((ROOT / "docs").glob("fragment-membership-*-wide-v1.json"))
    stems.append(ROOT / "docs" / "fragment-membership-rego-gcp-v1.json")

    assert stems, "no whole-corpus artifacts to check"
    for path in stems:
        artifact = json.loads(path.read_text(encoding="utf-8"))
        for entry in artifact["corpus"]:
            assert entry["tracked_files"] > 0, (path.name, entry["name"])
            assert entry["files_present"] == entry["tracked_files"], (
                f"{path.name}: {entry['name']} was measured over an incomplete checkout "
                f"({entry['files_present']} of {entry['tracked_files']} files present)"
            )


def test_the_report_says_whether_each_checkout_was_complete() -> None:
    report = _report()

    for row in report["rows"]:
        if row["verdict"] not in ("reproduced", "differs"):
            continue
        assert row["corpus_recorded_a_complete_checkout"] is True, row["artifact"]
        for entry in row["corpus"]:
            assert entry["checkout_was_complete"] is True, (row["artifact"], entry["name"])


def test_the_third_party_corpus_was_refetched_and_its_decay_recorded() -> None:
    """A corpus collected by code search does not stay fetchable, and that is a finding.

    Re-fetching the 49 files at the commits the manifest records found 18 gone three weeks
    later. Every one that could be fetched still hashed to its recorded sha256 and was
    judged identically, so the corrected Kyverno adapter leaves the third-party verdicts as
    measured; the 18 rest on the verification done when they were collected.
    """

    for candidate in (ROOT, *ROOT.parents):
        path = candidate / "docs" / "third-party-kyverno-revalidation-v1.json"
        if path.is_file():
            break
    else:  # pragma: no cover - the artifact is committed
        raise AssertionError("docs/third-party-kyverno-revalidation-v1.json is missing")
    revalidation = json.loads(path.read_text(encoding="utf-8"))
    measured = json.loads(
        (ROOT / "docs" / "fragment-membership-kyverno-thirdparty-v1.json").read_text("utf-8")
    )

    assert revalidation["verdicts_changed_among_those_refetched"] == []
    assert revalidation["files_in_manifest"] == measured["policies_considered"] == 49
    assert (
        revalidation["files_still_fetchable_at_their_commit"]
        + revalidation["files_no_longer_available"]
        == 49
    )
    assert revalidation["files_no_longer_available"] == 18
