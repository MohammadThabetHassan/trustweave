"""Measure fragment membership on policy written by organisations that run the engine.

Every other corpus in this study is published by the vendor that ships the engine, which
is the external-validity limitation the study reports. This one is not: it is Kyverno
policy found in the repositories of unaffiliated organisations, with the vendor's own
organisations excluded.

It is a convenience sample and says so. GitHub code search surfaced it, code search results
are not stable, and 49 policies from 28 owners is not a random sample of anything. What the
corpus is good for is a comparison: the same instrument, the same language, policy written
by different people. It answers "does the fragment cover only what vendors write?" and not
"what share of deployed Kyverno policy is inside?".

Reproducibility does not depend on search. `docs/third-party-kyverno-corpus-v1.json` pins
every file by repository, path and commit, with a SHA-256 of the content measured, so a
reader re-fetches exactly what was classified and this script refuses anything that has
changed underneath it. The same holds for every `docs/third-party-sample-*-corpus-v1.json`
manifest, which name their ecosystem; this script measures any ecosystem whose policies are
judged one file at a time.

A fetch that fails says why. An earlier version counted every failed request as a file that
no longer exists, and reported 18 of the 49 Kyverno policies gone three weeks after they were
collected; re-fetched with retries, every one of the 18 was still there. `--revalidate`
re-fetches a manifest and records, per file, whether it verified, and if not, how it failed.

    python scripts/measure_third_party_policies.py --json out.json
    python scripts/measure_third_party_policies.py --corpus MANIFEST --json out.json
    python scripts/measure_third_party_policies.py --revalidate --json out.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import sys
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "docs" / "third-party-kyverno-corpus-v1.json"
MEASURED = ROOT / "docs" / "fragment-membership-kyverno-thirdparty-v1.json"
RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"
# Fail on an HTTP error rather than hashing its error page, bound every attempt, and retry
# the transient failures curl recognises, so a slow server is not reported as a deleted file.
CURL = [
    "curl",
    "--silent",
    "--show-error",
    "--location",
    "--fail",
    "--max-time",
    "30",
    "--retry",
    "3",
    "--retry-delay",
    "2",
]
# How a manifest's digests were taken. The first manifest hashed the text after decoding,
# which folds CRLF into LF; every later one hashes the bytes the server returns.
TEXT_DIGEST = "sha256 of the decoded text, CRLF folded to LF"
BYTES_DIGEST = "sha256 of the bytes"
ADAPTERS = {
    "kyverno": "fragment_membership_kyverno",
    "iam": "fragment_membership_iam",
    "cedar": "fragment_membership_cedar",
}


def _adapter(ecosystem: str = "kyverno") -> Any:
    """The ecosystem's adapter, loaded by path because these scripts are not a package."""

    if ecosystem not in ADAPTERS:
        raise SystemExit(f"{ecosystem} policies are not judged one file at a time")
    for name in ("fragment_membership", ADAPTERS[ecosystem]):
        specification = importlib.util.spec_from_file_location(
            name, Path(__file__).resolve().parent / f"{name}.py"
        )
        if specification is None or specification.loader is None:  # pragma: no cover
            raise SystemExit(f"cannot load {name}")
        module = importlib.util.module_from_spec(specification)
        sys.modules.setdefault(name, module)
        specification.loader.exec_module(module)
    return sys.modules[ADAPTERS[ecosystem]]


def digest(content: bytes, method: str) -> str:
    if method == TEXT_DIGEST:
        return hashlib.sha256(content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()
    return hashlib.sha256(content).hexdigest()


def fetch_bytes(entry: dict[str, str]) -> tuple[bytes | None, str]:
    """The bytes at the pinned commit, or None and why they could not be had."""

    url = RAW.format(
        repo=entry["repo"], commit=entry["commit"], path=urllib.parse.quote(entry["path"])
    )
    try:
        completed = subprocess.run([*CURL, url], capture_output=True, timeout=180, check=False)
    except subprocess.TimeoutExpired:
        return None, "timed out"
    except OSError as error:
        return None, f"could not run curl: {error}"
    if completed.returncode == 22:
        return None, "HTTP error: " + completed.stderr.decode("utf-8", "replace").strip()[-80:]
    if completed.returncode != 0:
        return None, f"network error (curl exit {completed.returncode})"
    return completed.stdout, "fetched"


def fetch_verified(entry: dict[str, str], method: str) -> tuple[str | None, str]:
    """The pinned content as text, or None and why: unreachable, changed, or undecodable."""

    content, status = fetch_bytes(entry)
    if content is None:
        return None, status
    if digest(content, method) != entry["sha256"]:
        return None, "content differs from the recorded digest"
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None, "content is not UTF-8"
    return text.replace("\r\n", "\n").replace("\r", "\n"), "verified"


def fetch(entry: dict[str, str]) -> str | None:
    """The pinned content of the first manifest's entries, or None when it cannot be had."""

    text, _ = fetch_verified(entry, TEXT_DIGEST)
    return text


def measure(corpus: dict[str, Any]) -> dict[str, Any]:
    ecosystem = corpus.get("ecosystem", "kyverno")
    method = corpus.get("digest", TEXT_DIGEST)
    adapter = _adapter(ecosystem)
    policies: list[dict[str, Any]] = []
    unavailable: list[str] = []
    for entry in corpus["files"]:
        subject = f"{entry['repo']}/{entry['path']}"
        text, _ = fetch_verified(entry, method)
        if text is None:
            unavailable.append(subject)
            continue
        outcome = adapter.classify(text)
        policies.append(
            {
                "subject": subject,
                "commit": entry["commit"],
                "verdict": outcome.verdict,
                "reason": outcome.reason,
                **outcome.detail,
            }
        )
    policies.sort(key=lambda entry: entry["subject"])
    counts = Counter(entry["verdict"] for entry in policies)
    judged = len(policies)
    return {
        "schema_version": "v1",
        "ecosystem": ecosystem,
        "provenance": "third-party",
        "corpus_scope": "third-party",
        "how_collected": corpus["how_collected"],
        "excluded_owners": corpus["excluded_owners"],
        "policies_considered": judged,
        "policies_unavailable": sorted(unavailable),
        # A subject is `owner/repo/path/to/file.yaml`, so the repository is its first two
        # segments -- splitting on the last separator counts directories as repositories.
        "repositories": len({"/".join(entry["subject"].split("/")[:2]) for entry in policies}),
        "owners": len({entry["subject"].split("/")[0] for entry in policies}),
        "counts": {
            "inside": counts["inside"],
            "outside": counts["outside"],
            "undetermined": counts["undetermined"],
        },
        "share_inside": round(counts["inside"] / judged, 4) if judged else None,
        "policies": policies,
    }


SUPERSEDED_REVALIDATION = {
    "revalidated_on": "2026-09-09",
    "files_no_longer_available": 18,
    "why_it_was_wrong": (
        "its fetch did not fail on an HTTP error, retried nothing, and counted every request "
        "that did not return the recorded digest as a file that no longer exists; re-fetched "
        "with retries, every one of the 18 verified against its recorded digest"
    ),
}


def revalidate(corpus: dict[str, Any], measured: dict[str, Any], today: str) -> dict[str, Any]:
    """Re-fetch every pinned file, say how each one that failed failed, and re-judge the rest."""

    method = corpus.get("digest", TEXT_DIGEST)
    adapter = _adapter(corpus.get("ecosystem", "kyverno"))
    recorded = {entry["subject"]: entry["verdict"] for entry in measured["policies"]}
    unavailable: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    changed: list[str] = []
    for entry in corpus["files"]:
        subject = f"{entry['repo']}/{entry['path']}"
        text, status = fetch_verified(entry, method)
        if text is None:
            unavailable.append({"subject": subject, "failure": status})
            continue
        verdict = adapter.classify(text).verdict
        counts[verdict] += 1
        if verdict != recorded.get(subject):
            changed.append(subject)
    fetched = len(corpus["files"]) - len(unavailable)
    return {
        "schema_version": "v1",
        "revalidated_on": today,
        "what_this_is": (
            "every file of the third-party manifest re-fetched at its recorded commit, checked "
            "against its recorded digest, and judged again by the current adapter"
        ),
        "fetch": {"command": CURL, "digest": method},
        "files_in_manifest": len(corpus["files"]),
        "files_still_fetchable_at_their_commit": fetched,
        "files_no_longer_available": len(unavailable),
        "unavailable": sorted(unavailable, key=lambda item: item["subject"]),
        "counts_among_those_refetched": {
            "inside": counts["inside"],
            "outside": counts["outside"],
            "undetermined": counts["undetermined"],
        },
        "verdicts_changed_among_those_refetched": sorted(changed),
        "supersedes": SUPERSEDED_REVALIDATION,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--revalidate",
        action="store_true",
        help="re-fetch and re-judge the manifest against its measured artifact",
    )
    parser.add_argument("--measured", type=Path, default=MEASURED)
    arguments = parser.parse_args(argv)

    corpus = json.loads(arguments.corpus.read_text(encoding="utf-8"))
    if arguments.revalidate:
        measured = json.loads(arguments.measured.read_text(encoding="utf-8"))
        today = dt.datetime.now(dt.UTC).date().isoformat()
        report = revalidate(corpus, measured, today)
        print(
            f"re-fetched {report['files_still_fetchable_at_their_commit']} of "
            f"{report['files_in_manifest']}; verdicts changed: "
            f"{len(report['verdicts_changed_among_those_refetched'])}"
        )
        for item in report["unavailable"]:
            print(f"  {item['subject']}: {item['failure']}")
        if arguments.json:
            arguments.json.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        return 0
    findings = measure(corpus)

    print(f"third-party {findings['ecosystem']} policies: {findings['policies_considered']}")
    print(f"  repositories: {findings['repositories']}  owners: {findings['owners']}")
    for verdict, count in sorted(findings["counts"].items()):
        print(f"  {verdict:14s} {count}")
    if findings["policies_unavailable"]:
        print(f"  unavailable at their pinned commit: {len(findings['policies_unavailable'])}")
    print(f"  share inside: {findings['share_inside']}")

    if arguments.json:
        arguments.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
