"""Drawing and pinning third-party samples, without the network.

The samples' figures rest on a procedure: what leaves the pool before the frame, which files
the seeded walk keeps under its caps, how a fetched file is verified, and how a failed fetch
is reported. Each is held here with the network replaced, so the tests run anywhere.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def _load(name: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


sample = _load("third_party_sample")
measure = _load("measure_third_party_policies")


def _candidate(repository: str, path: str, blob: str, **extra: object) -> dict:
    return {
        "repository": repository,
        "owner": repository.split("/")[0],
        "path": path,
        "blob_sha1": blob,
        "commit": "c" * 40,
        "fork": False,
        "vendor": False,
        **extra,
    }


class TestPolicyDocuments:
    @pytest.mark.parametrize(
        ("ecosystem", "text", "is_policy"),
        [
            ("kyverno", "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n", True),
            ("kyverno", "apiVersion: kyverno.io/v1\nkind: PolicyException\n", False),
            ("kyverno", "apiVersion: apps/v1\nkind: Deployment\n", False),
            ("iam", '{"Version": "2012-10-17", "Statement": []}', True),
            ("iam", '{"Resources": {"Role": {"Properties": {}}}}', False),
            ("iam", "not json", False),
            ("cedar", "permit(principal, action, resource);", True),
            ("cedar", '// permit(principal, action, resource);\n@id("x")', False),
            ("rego", "package main\n\ndeny[msg] { false }\n", True),
            ("rego", "# no package here\n", False),
        ],
    )
    def test_only_a_policy_document_of_the_ecosystem_is_kept(
        self, ecosystem: str, text: str, is_policy: bool
    ) -> None:
        assert (sample.not_a_policy(ecosystem, text) is None) is is_policy

    @pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
    def test_the_blob_hash_is_the_one_git_and_code_search_report(self, tmp_path: Path) -> None:
        content = b'package main\r\n\ndeny[msg] { msg := "x" }\n'
        path = tmp_path / "policy.rego"
        path.write_bytes(content)
        expected = subprocess.run(
            ["git", "hash-object", "--no-filters", str(path)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        assert sample.git_blob_sha1(content) == expected


class TestFrame:
    def test_vendor_forks_copies_tests_and_repeats_leave_the_pool(self) -> None:
        pool = [
            _candidate("kept/a", "p.rego", "1"),
            _candidate("vendor/a", "p.rego", "2", vendor=True),
            _candidate("fork/a", "p.rego", "3", fork=True),
            _candidate("copy/a", "p.rego", "v"),
            _candidate("already/a", "p.rego", "4"),
            _candidate("test/a", "p_test.rego", "5"),
            _candidate("repeat/a", "q.rego", "1"),
        ]

        frame, removed = sample.frame("rego", pool, {"v"}, {("already/a", "p.rego")})

        assert [c["repository"] for c in frame] == ["kept/a"]
        assert sum(removed.values()) == len(pool) - len(frame)
        assert removed["already in the 49 third-party Kyverno policies"] == 1
        assert removed["a byte-for-byte copy of a vendor corpus file"] == 1
        assert removed["a Rego test module"] == 1
        assert removed["the same content as an earlier file"] == 1

    def test_the_walk_is_seeded_and_respects_both_caps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        contents = {
            f"r{i}/{j}.cedar": f"permit(principal, action, resource); // {i} {j}".encode()
            for i in range(6)
            for j in range(6)
        }
        candidates = []
        for key, content in contents.items():
            repository, path = key.split("/")
            owner = "same-owner" if repository in {"r0", "r1"} else repository
            candidates.append(
                {
                    **_candidate(f"{owner}/{repository}", path, sample.git_blob_sha1(content)),
                    "owner": owner,
                }
            )

        def fake_fetch(entry: dict) -> tuple[bytes, str]:
            repository = entry["repo"].split("/")[1]
            return contents[f"{repository}/{entry['path']}"], "fetched"

        monkeypatch.setattr(measure, "fetch_bytes", fake_fetch)
        first, skipped, examined = sample.select("cedar", candidates, target=12)
        second, _, _ = sample.select("cedar", candidates, target=12)

        assert first == second
        assert len(first) == 12
        per_repository: dict[str, int] = {}
        per_owner: dict[str, int] = {}
        for entry in first:
            per_repository[entry["repo"]] = per_repository.get(entry["repo"], 0) + 1
            owner = entry["repo"].split("/")[0]
            per_owner[owner] = per_owner.get(owner, 0) + 1
        assert max(per_repository.values()) <= sample.REPOSITORY_CAP
        assert max(per_owner.values()) <= sample.OWNER_CAP
        assert examined == len(first) + sum(skipped.values())

    def test_a_file_that_changed_since_it_was_indexed_is_not_kept(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        candidates = [_candidate("o/r", "p.cedar", "0" * 40)]
        monkeypatch.setattr(
            measure, "fetch_bytes", lambda entry: (b"permit(principal, action, resource);", "ok")
        )

        kept, skipped, _ = sample.select("cedar", candidates, target=1)

        assert kept == []
        assert skipped == {"content differs from what the search indexed": 1}


class TestFetching:
    def test_the_first_manifest_hashes_text_and_later_ones_hash_bytes(self) -> None:
        crlf = b"a: 1\r\nb: 2\r\n"

        assert (
            measure.digest(crlf, measure.TEXT_DIGEST) == hashlib.sha256(b"a: 1\nb: 2\n").hexdigest()
        )
        assert measure.digest(crlf, measure.BYTES_DIGEST) == hashlib.sha256(crlf).hexdigest()

    def test_a_failed_request_says_how_it_failed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Completed:
            def __init__(self, returncode: int, stderr: bytes) -> None:
                self.returncode, self.stderr, self.stdout = returncode, stderr, b""

        monkeypatch.setattr(
            measure.subprocess, "run", lambda *a, **k: Completed(22, b"error: 404 Not Found")
        )
        assert measure.fetch_bytes({"repo": "o/r", "commit": "c", "path": "p"})[1].startswith(
            "HTTP error"
        )
        monkeypatch.setattr(measure.subprocess, "run", lambda *a, **k: Completed(28, b""))
        assert measure.fetch_bytes({"repo": "o/r", "commit": "c", "path": "p"})[1] == (
            "network error (curl exit 28)"
        )

    def test_revalidation_reports_each_failure_and_each_changed_verdict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        corpus = {
            "ecosystem": "cedar",
            "digest": measure.BYTES_DIGEST,
            "files": [
                {"repo": "o/r", "path": "a.cedar", "commit": "c", "sha256": "x"},
                {"repo": "o/r", "path": "b.cedar", "commit": "c", "sha256": "y"},
            ],
        }
        measured = {
            "policies": [
                {"subject": "o/r/a.cedar", "verdict": "undetermined"},
                {"subject": "o/r/b.cedar", "verdict": "inside"},
            ]
        }

        def fake(entry: dict, method: str) -> tuple[str | None, str]:
            if entry["path"] == "a.cedar":
                return "permit(principal, action, resource);", "verified"
            return None, "network error (curl exit 28)"

        monkeypatch.setattr(measure, "fetch_verified", fake)
        report = measure.revalidate(corpus, measured, "2026-10-03")

        assert report["files_still_fetchable_at_their_commit"] == 1
        assert report["unavailable"] == [
            {"subject": "o/r/b.cedar", "failure": "network error (curl exit 28)"}
        ]
        assert report["verdicts_changed_among_those_refetched"] == ["o/r/a.cedar"]


@pytest.mark.parametrize("ecosystem", sorted(sample.TARGETS))
def test_each_recorded_manifest_is_internally_consistent(ecosystem: str) -> None:
    path = DOCS / f"third-party-sample-{ecosystem}-corpus-v1.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))

    assert manifest["ecosystem"] == ecosystem
    assert manifest["digest"] == measure.BYTES_DIGEST
    assert manifest["policies"] == len(manifest["files"])
    assert manifest["examined"] == manifest["policies"] + sum(manifest["skipped"].values())
    assert manifest["frame"] == manifest["pool"] - sum(manifest["removed_from_pool"].values())
    repositories: dict[str, int] = {}
    for entry in manifest["files"]:
        assert len(entry["commit"]) == 40 and len(entry["sha256"]) == 64
        repositories[entry["repo"]] = repositories.get(entry["repo"], 0) + 1
        assert entry["repo"].split("/")[0].lower() not in manifest["excluded_owners"]
    assert max(repositories.values()) <= manifest["repository_cap"]


@pytest.mark.parametrize("ecosystem", sorted(sample.TARGETS))
def test_each_measurement_judges_exactly_its_manifest(ecosystem: str) -> None:
    """Every pinned file is judged or reported unavailable, and nothing else is judged."""

    manifest = json.loads(
        (DOCS / f"third-party-sample-{ecosystem}-corpus-v1.json").read_text(encoding="utf-8")
    )
    measured = json.loads(
        (DOCS / f"third-party-sample-{ecosystem}-membership-v1.json").read_text(encoding="utf-8")
    )
    pinned = {f"{entry['repo']}/{entry['path']}" for entry in manifest["files"]}
    judged = {entry["subject"] for entry in measured["policies"]}
    missing = {
        entry["subject"] if isinstance(entry, dict) else entry
        for entry in measured["policies_unavailable"]
    }

    assert judged | missing == pinned
    assert not judged & missing
    assert sum(measured["counts"].values()) == measured["policies_considered"] == len(judged)


def test_the_recorded_summary_is_what_the_samples_say() -> None:
    recorded = json.loads((DOCS / "third-party-sample-summary-v1.json").read_text("utf-8"))

    assert sample.summarise() == recorded
    # The taxonomy was derived from vendor corpora; it is held to policy written outside them.
    assert recorded["taxonomy_holds"] is True
    assert recorded["exclusions_unclassified"] == 0


def test_the_cedar_replication_adds_up_and_records_its_protocol() -> None:
    """Checked without the engine's bindings: the study script imports them only to run."""

    cedar_study = _load("cedar_exact_study")
    cedar_study.require_protocol()
    recorded = json.loads((DOCS / "cedar-suite-strategy-study-v1.json").read_text("utf-8"))
    population = recorded["population"]

    assert recorded["protocol_sha256"] == cedar_study.PROTOCOL_SHA256
    assert population["judged inside"] == (
        population["Cedar does not parse it"]
        + population["exact-eligible"]
        + population["not exact-eligible"]
    )
    assert sum(recorded["file_statuses"].values()) == population["exact-eligible"]
    # Deviations from the protocol are on the record, not in a footnote.
    assert len(recorded["deviations"]) == 3
    for entry in recorded["files"].values():
        if entry["status"] == "scored" and entry["expected_score"]:
            assert entry["expected_score"]["refinement"] == 1.0
            assert entry["decision_range"] <= 2


def test_the_cedar_real_edits_are_pinned_and_consistent() -> None:
    recorded = json.loads((DOCS / "cedar-real-edits-v1.json").read_text("utf-8"))
    measured = [pair for pair in recorded["pairs"] if pair["status"] == "measured"]

    assert len(measured) == recorded["pairs_measured"]
    assert recorded["change_a_decision"] == sum(1 for p in measured if p["changes_a_decision"])
    for pair in measured:
        assert len(pair["before"]["sha256"]) == len(pair["after"]["sha256"]) == 64
        if pair["weakens_a_decision"]:
            assert pair["changes_a_decision"]


def test_the_rego_engine_check_accounts_for_every_sampled_module() -> None:
    recorded = json.loads((DOCS / "third-party-sample-rego-oracle-v1.json").read_text("utf-8"))

    assert recorded["modules"] == 300
    assert (
        recorded["agreements"] + recorded["disagreements"] + recorded["engine_could_not_load"]
        == recorded["modules"]
    )
    assert len(recorded["disagreeing_modules"]) == recorded["disagreements"]
