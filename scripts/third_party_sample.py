"""Draw, pin and measure samples of policy written by organisations that use an engine.

Every other corpus in the study is published by a vendor whose engine reads it, and the one
exception -- 49 Kyverno policies found by code search -- answers "does the fragment cover
only what vendors write?" rather than estimating anything. This script builds larger samples
for four ecosystems, by a procedure fixed in advance and recorded in each manifest:

1. ``harvest``: GitHub code search for each ecosystem's policy files, every query split by
   file size because the search returns at most 1,000 results per query. The candidate pool
   and every request's ``total_count`` go to a working directory. Search results are not
   stable, so nothing downstream depends on repeating this step.
2. ``select``: the pool becomes a sampling frame by removing, in this order, files owned by
   the vendor or by the authors of a corpus the study already measures, forks, byte-for-byte
   copies of a vendor corpus file (by git blob hash), files already in the 49, Rego test
   modules, and repeated content. The frame is shuffled with a fixed seed and walked in that
   order, keeping a file when its repository and owner are under their caps, it fetches at
   the commit the search recorded, its git blob hash matches the search's, and it is a
   policy document of the ecosystem. Every skip is counted by reason. The kept files are
   written to ``docs/third-party-sample-<ecosystem>-corpus-v1.json``, each pinned by
   repository, path, commit and the SHA-256 of its bytes.
3. Measurement. Kyverno, IAM and Cedar policies are judged one file at a time, by
   ``measure_third_party_policies.py --corpus <manifest>``. A Rego policy is judged with the
   rule graph of the bundle it is evaluated in, so ``measure-rego`` fetches every module of
   each sampled repository at the pinned commit -- what OPA loads when pointed at the
   repository -- and judges the sampled modules against it.

Usage:
    python scripts/third_party_sample.py harvest kyverno --work W
    python scripts/third_party_sample.py select kyverno --work W --corpora C \\
        --json docs/third-party-sample-kyverno-corpus-v1.json
    python scripts/third_party_sample.py measure-rego \\
        --corpus docs/third-party-sample-rego-corpus-v1.json --work W \\
        --json docs/third-party-sample-rego-membership-v1.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import importlib.util
import json
import random
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SEED = 20261003
REPOSITORY_CAP = 3
OWNER_CAP = 5
TARGETS = {"kyverno": 400, "iam": 400, "cedar": 400, "rego": 300}
SHARDS = (
    "size:<300",
    "size:300..600",
    "size:600..1000",
    "size:1000..1500",
    "size:1500..2500",
    "size:2500..4000",
    "size:4000..7000",
    "size:>7000",
)
QUERIES = {
    "kyverno": (
        '"kyverno.io/v1" "kind: ClusterPolicy" extension:yaml',
        '"kyverno.io/v1" "kind: ClusterPolicy" extension:yml',
        '"kyverno.io/v1" "kind: Policy" extension:yaml',
    ),
    "rego": (
        '"package" "deny" extension:rego',
        '"package" "violation" extension:rego',
        '"package" "allow" extension:rego',
    ),
    "iam": ('"2012-10-17" "Statement" "Effect" "Action" extension:json',),
    "cedar": ('"permit" extension:cedar', '"forbid" extension:cedar'),
}
# Owners that write or ship the engine, or wrote a corpus the study already measures.
VENDOR_OWNERS = {
    "kyverno": ("kyverno", "nirmata"),
    "rego": (
        "open-policy-agent",
        "styrainc",
        "instrumenta",
        "redhat-cop",
        "googlecloudplatform",
        "forseti-security",
    ),
    "iam": ("aws", "awslabs", "awsdocs", "amzn", "amazon-archives", "iann0036"),
    "cedar": ("cedar-policy", "aws", "awslabs", "awsdocs", "amzn", "amazon-archives"),
}
VENDOR_PREFIXES = {
    "kyverno": (),
    "rego": (),
    "iam": ("aws-", "amazon-"),
    "cedar": ("aws-", "amazon-"),
}
# The pinned checkouts of the vendor corpora, by ecosystem, under the corpora root.
VENDOR_CORPORA = {
    "kyverno": ("kyverno",),
    "rego": ("rego", "gcp"),
    "iam": ("iam",),
    "cedar": ("cedar",),
}

KYVERNO_API = re.compile(r"^\s*apiVersion:\s*['\"]?kyverno\.io/", re.MULTILINE)
KYVERNO_KIND = re.compile(r"^\s*kind:\s*['\"]?(?:ClusterPolicy|Policy)['\"]?\s*$", re.MULTILINE)
CEDAR_POLICY = re.compile(r"\b(?:permit|forbid)\s*\(")
CEDAR_COMMENT = re.compile(r'("(?:[^"\\]|\\.)*")|//[^\n]*')
REGO_PACKAGE = re.compile(r"^\s*package\s+\S", re.MULTILINE)


def _load(name: str) -> Any:
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules.setdefault(name, module)
    specification.loader.exec_module(module)
    return sys.modules[name]


def is_vendor(ecosystem: str, owner: str) -> bool:
    lowered = owner.lower()
    return lowered in VENDOR_OWNERS[ecosystem] or lowered.startswith(VENDOR_PREFIXES[ecosystem])


def git_blob_sha1(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content, usedforsecurity=False).hexdigest()


def not_a_policy(ecosystem: str, text: str) -> str | None:
    """Why a fetched file is not a policy document of this ecosystem, or None if it is one."""

    if ecosystem == "kyverno":
        if KYVERNO_API.search(text) and KYVERNO_KIND.search(text):
            return None
        return "declares no kyverno.io ClusterPolicy or Policy"
    if ecosystem == "iam":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return "is not JSON"
        if isinstance(parsed, dict) and "Statement" in parsed:
            return None
        return "is not a bare IAM policy document"
    if ecosystem == "cedar":
        code = CEDAR_COMMENT.sub(lambda found: found.group(1) or "", text)
        return None if CEDAR_POLICY.search(code) else "states no permit or forbid"
    return None if REGO_PACKAGE.search(text) else "declares no package"


# ---------------------------------------------------------------------------------------
# harvest
# ---------------------------------------------------------------------------------------


def _search(query: str, page: int) -> dict[str, Any]:
    for attempt in range(6):
        completed = subprocess.run(
            [
                "gh",
                "api",
                "-X",
                "GET",
                "search/code",
                "-f",
                f"q={query}",
                "-f",
                "per_page=100",
                "-f",
                f"page={page}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0:
            result: dict[str, Any] = json.loads(completed.stdout)
            return result
        message = (completed.stderr + completed.stdout).lower()
        if "rate limit" in message or "403" in message or "abuse" in message:
            time.sleep(60 * (attempt + 1))
            continue
        if "422" in message:
            return {"total_count": None, "items": [], "error": message.strip()[:300]}
        time.sleep(15)
    return {"total_count": None, "items": [], "error": "exhausted retries"}


def harvest(ecosystem: str, work: Path, max_pages: int = 4) -> None:
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    requests: list[dict[str, Any]] = []
    for query in QUERIES[ecosystem]:
        for shard in SHARDS:
            full = f"{query} {shard}"
            for page in range(1, max_pages + 1):
                result = _search(full, page)
                items = result.get("items", [])
                requests.append(
                    {
                        "query": full,
                        "page": page,
                        "total_count": result.get("total_count"),
                        "returned": len(items),
                        "error": result.get("error"),
                    }
                )
                for item in items:
                    repository = item["repository"]
                    key = (repository["full_name"], item["path"])
                    record = candidates.setdefault(
                        key,
                        {
                            "ecosystem": ecosystem,
                            "repository": repository["full_name"],
                            "owner": repository["owner"]["login"],
                            "fork": bool(repository.get("fork")),
                            "vendor": is_vendor(ecosystem, repository["owner"]["login"]),
                            "path": item["path"],
                            "blob_sha1": item["sha"],
                            "commit": parse_qs(urlparse(item["url"]).query).get("ref", [None])[0],
                            "matched_queries": [],
                        },
                    )
                    if full not in record["matched_queries"]:
                        record["matched_queries"].append(full)
                time.sleep(6.5)  # code search allows ten requests a minute
                total = result.get("total_count") or 0
                if len(items) < 100 or page * 100 >= min(total, 1000):
                    break
    work.mkdir(parents=True, exist_ok=True)
    (work / f"candidates-{ecosystem}.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in candidates.values()),
        "utf-8",
    )
    (work / f"harvest-{ecosystem}.json").write_text(
        json.dumps(
            {
                "ecosystem": ecosystem,
                "harvested_at": dt.datetime.now(dt.UTC).isoformat(),
                "shards": list(SHARDS),
                "queries": list(QUERIES[ecosystem]),
                "max_pages": max_pages,
                "requests": requests,
                "pool_size": len(candidates),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        "utf-8",
    )


# ---------------------------------------------------------------------------------------
# select
# ---------------------------------------------------------------------------------------


def vendor_blobs(ecosystem: str, corpora: Path) -> set[str]:
    """Git blob hashes of every file in the pinned vendor corpora of this ecosystem."""

    blobs: set[str] = set()
    for directory in VENDOR_CORPORA[ecosystem]:
        root = corpora / directory
        repositories = (
            [root]
            if (root / ".git").exists()
            else sorted(path for path in root.iterdir() if (path / ".git").exists())
        )
        for repository in repositories:
            listing = subprocess.run(
                ["git", "-C", str(repository), "ls-tree", "-r", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            for line in listing.splitlines():
                mode_type_sha, _ = line.split("\t", 1)
                _, kind, sha = mode_type_sha.split()
                if kind == "blob":
                    blobs.add(sha)
    return blobs


def frame(
    ecosystem: str, pool: list[dict[str, Any]], vendor: set[str], already: set[tuple[str, str]]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    removed: Counter[str] = Counter()
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []
    for candidate in sorted(pool, key=lambda item: (item["repository"], item["path"])):
        if candidate["vendor"]:
            removed["owned by the vendor or a measured corpus's author"] += 1
        elif candidate["fork"]:
            removed["a fork"] += 1
        elif candidate["blob_sha1"] in vendor:
            removed["a byte-for-byte copy of a vendor corpus file"] += 1
        elif (candidate["repository"], candidate["path"]) in already:
            removed["already in the 49 third-party Kyverno policies"] += 1
        elif ecosystem == "rego" and candidate["path"].endswith("_test.rego"):
            removed["a Rego test module"] += 1
        elif candidate["blob_sha1"] in seen:
            removed["the same content as an earlier file"] += 1
        else:
            seen.add(candidate["blob_sha1"])
            kept.append(candidate)
    return kept, dict(sorted(removed.items()))


def select(
    ecosystem: str, candidates: list[dict[str, Any]], target: int, seed: int = SEED
) -> tuple[list[dict[str, Any]], dict[str, int], int]:
    """Walk the shuffled frame, keeping verified policy documents under the caps."""

    measure = _load("measure_third_party_policies")
    order = list(candidates)
    random.Random(seed).shuffle(order)
    kept: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    per_repository: Counter[str] = Counter()
    per_owner: Counter[str] = Counter()
    examined = 0
    position = 0
    with concurrent.futures.ThreadPoolExecutor(12) as pool:
        pending: dict[int, concurrent.futures.Future[tuple[bytes | None, str]]] = {}
        while len(kept) < target and position < len(order):
            # Keep a window of fetches in flight, in frame order, so the order decides.
            for ahead in range(position, min(position + 24, len(order))):
                if ahead not in pending:
                    entry = order[ahead]
                    pending[ahead] = pool.submit(
                        measure.fetch_bytes,
                        {
                            "repo": entry["repository"],
                            "commit": entry["commit"],
                            "path": entry["path"],
                        },
                    )
            candidate = order[position]
            future = pending.pop(position)
            position += 1
            examined += 1
            if per_repository[candidate["repository"]] >= REPOSITORY_CAP:
                skipped["its repository already has the cap"] += 1
                continue
            if per_owner[candidate["owner"]] >= OWNER_CAP:
                skipped["its owner already has the cap"] += 1
                continue
            content, status = future.result()
            if content is None:
                skipped[f"could not be fetched ({status.split(':')[0]})"] += 1
                continue
            if git_blob_sha1(content) != candidate["blob_sha1"]:
                skipped["content differs from what the search indexed"] += 1
                continue
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                skipped["is not UTF-8"] += 1
                continue
            reason = not_a_policy(ecosystem, text)
            if reason:
                skipped[reason] += 1
                continue
            kept.append(
                {
                    "repo": candidate["repository"],
                    "path": candidate["path"],
                    "commit": candidate["commit"],
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "blob_sha1": candidate["blob_sha1"],
                }
            )
            per_repository[candidate["repository"]] += 1
            per_owner[candidate["owner"]] += 1
        for future in pending.values():
            future.cancel()
    return kept, dict(sorted(skipped.items())), examined


def manifest(
    ecosystem: str, work: Path, corpora: Path, target: int, seed: int = SEED
) -> dict[str, Any]:
    harvested = json.loads((work / f"harvest-{ecosystem}.json").read_text("utf-8"))
    pool = [
        json.loads(line)
        for line in (work / f"candidates-{ecosystem}.jsonl").read_text("utf-8").splitlines()
    ]
    already: set[tuple[str, str]] = set()
    if ecosystem == "kyverno":
        earlier = json.loads((DOCS / "third-party-kyverno-corpus-v1.json").read_text("utf-8"))
        already = {(entry["repo"], entry["path"]) for entry in earlier["files"]}
    candidates, removed = frame(ecosystem, pool, vendor_blobs(ecosystem, corpora), already)
    files, skipped, examined = select(ecosystem, candidates, target, seed)
    population: dict[str, int] = {}
    for request in harvested["requests"]:
        if request["page"] == 1 and request["total_count"] is not None:
            query = request["query"].rsplit(" size:", 1)[0]
            population[query] = population.get(query, 0) + request["total_count"]
    measure = _load("measure_third_party_policies")
    return {
        "schema_version": "v1",
        "ecosystem": ecosystem,
        "provenance": "third-party",
        "digest": measure.BYTES_DIGEST,
        "how_collected": (
            "GitHub code search, each query split into eight size shards and read to at most "
            f"{harvested['max_pages'] * 100} results per shard; the pool filtered to a frame and "
            "the frame shuffled with the recorded seed and walked under the recorded caps, as "
            "scripts/third_party_sample.py states"
        ),
        "harvested_at": harvested["harvested_at"],
        "queries": harvested["queries"],
        "shards": harvested["shards"],
        "search_total_count_by_query": dict(sorted(population.items())),
        "excluded_owners": sorted(VENDOR_OWNERS[ecosystem]),
        "excluded_owner_prefixes": sorted(VENDOR_PREFIXES[ecosystem]),
        "seed": seed,
        "repository_cap": REPOSITORY_CAP,
        "owner_cap": OWNER_CAP,
        "target": target,
        "pool": len(pool),
        "removed_from_pool": removed,
        "frame": len(candidates),
        "frame_repositories": len({c["repository"] for c in candidates}),
        "frame_owners": len({c["owner"] for c in candidates}),
        "examined": examined,
        "skipped": skipped,
        "policies": len(files),
        "repositories": len({entry["repo"] for entry in files}),
        "owners": len({entry["repo"].split("/")[0] for entry in files}),
        "files": sorted(files, key=lambda entry: (entry["repo"], entry["path"])),
    }


# ---------------------------------------------------------------------------------------
# measure-rego
# ---------------------------------------------------------------------------------------


def _checkout(repository: str, commit: str, into: Path) -> str | None:
    """The repository's modules and YAML at `commit`, or why they could not be had."""

    if (into / ".git").exists():
        head = subprocess.run(
            ["git", "-C", str(into), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        if head == commit:
            return None
    into.mkdir(parents=True, exist_ok=True)
    steps = (
        ["git", "init", "-q"],
        ["git", "remote", "add", "origin", f"https://github.com/{repository}.git"],
        ["git", "sparse-checkout", "set", "--no-cone", "*.rego", "*.yaml", "*.yml"],
        ["git", "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit],
        ["git", "checkout", "-q", "FETCH_HEAD"],
    )
    for step in steps:
        completed = subprocess.run(
            step, cwd=into, capture_output=True, text=True, timeout=600, check=False
        )
        if completed.returncode != 0 and step[1] != "remote":
            return f"{' '.join(step[:2])} failed: {completed.stderr.strip()[-120:]}"
    return None


_REGO: Any = None


def _measure_repository(
    task: tuple[str, str, list[dict[str, str]], Path],
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, Any] | None]:
    """One repository's sampled modules, judged against that repository's whole bundle.

    Run in a worker process: the adapter keeps the bundle's rule graph in module-level
    tables that `discover` resets, so one process judges one repository at a time.
    """

    global _REGO
    if _REGO is None:
        _load("fragment_membership")
        _REGO = _load("fragment_membership_rego")
    repository, commit, entries, work = task
    into = work / "bundles" / repository.replace("/", "__") / commit[:12]
    failure = _checkout(repository, commit, into)
    if failure:
        return (
            [],
            [{"subject": f"{repository}/{e['path']}", "failure": failure} for e in entries],
            None,
        )
    modules = _REGO.discover(into)
    policies: list[dict[str, Any]] = []
    unavailable: list[dict[str, str]] = []
    for entry in entries:
        path = into / entry["path"]
        subject = f"{repository}/{entry['path']}"
        try:
            content = path.read_bytes()
        except OSError:
            unavailable.append({"subject": subject, "failure": "not in the checkout"})
            continue
        if hashlib.sha256(content).hexdigest() != entry["sha256"]:
            unavailable.append({"subject": subject, "failure": "content differs"})
            continue
        text = content.decode("utf-8")
        outcome = _REGO.classify(text)
        policies.append(
            {
                "subject": subject,
                "commit": commit,
                "verdict": outcome.verdict,
                "reason": outcome.reason,
                **outcome.detail,
                # Recorded beside the verdict, not used by it: the adapter reads
                # `input.parameters` as a Gatekeeper constraint's, which would be wrong for a
                # Conftest policy over a configuration whose own field is called that. Whether
                # the module reads an admission review or a constraint says which it is.
                "reads_admission_review": "input.review" in text,
                "reads_constraint": "input.constraint" in text,
            }
        )
    return policies, unavailable, {"repo": repository, "commit": commit, "modules": len(modules)}


def measure_rego(corpus: dict[str, Any], work: Path, workers: int = 8) -> dict[str, Any]:
    by_repository: dict[tuple[str, str], list[dict[str, str]]] = {}
    for entry in corpus["files"]:
        by_repository.setdefault((entry["repo"], entry["commit"]), []).append(entry)
    tasks = [
        (repository, commit, entries, work)
        for (repository, commit), entries in sorted(by_repository.items())
    ]
    policies: list[dict[str, Any]] = []
    unavailable: list[dict[str, str]] = []
    bundles: list[dict[str, Any]] = []
    with concurrent.futures.ProcessPoolExecutor(workers) as pool:
        for judged, missing, bundle in pool.map(_measure_repository, tasks):
            policies.extend(judged)
            unavailable.extend(missing)
            if bundle is not None:
                bundles.append(bundle)
    bundles.sort(key=lambda entry: (entry["repo"], entry["commit"]))
    policies.sort(key=lambda entry: entry["subject"])
    counts = Counter(entry["verdict"] for entry in policies)
    judged = len(policies)
    return {
        "schema_version": "v1",
        "ecosystem": "rego",
        "provenance": "third-party",
        "corpus_scope": "third-party",
        "bundle": "every module of the repository at the pinned commit",
        "how_collected": corpus["how_collected"],
        "excluded_owners": corpus["excluded_owners"],
        "policies_considered": judged,
        "policies_unavailable": sorted(unavailable, key=lambda item: item["subject"]),
        "repositories": len(
            {
                entry["subject"].split("/")[0] + "/" + entry["subject"].split("/")[1]
                for entry in policies
            }
        ),
        "owners": len({entry["subject"].split("/")[0] for entry in policies}),
        "bundles": bundles,
        "counts": {
            "inside": counts["inside"],
            "outside": counts["outside"],
            "undetermined": counts["undetermined"],
        },
        "share_inside": round(counts["inside"] / judged, 4) if judged else None,
        "policies": policies,
    }


# ---------------------------------------------------------------------------------------
# oracle-rego: the sampled Rego modules against the engine's own dependency analysis
# ---------------------------------------------------------------------------------------

_ORACLE: Any = None
_PACKAGE_LINE = re.compile(r"^\s*package\s+([\w.]+)", re.MULTILINE)


def _declared_package(path: Path) -> str:
    found = _PACKAGE_LINE.search(path.read_text(encoding="utf-8", errors="ignore"))
    return found.group(1) if found else ""


def _oracle_repository(
    task: tuple[str, str, list[dict[str, str]], Path, frozenset[str]],
) -> list[dict[str, Any]]:
    """`opa deps` on each sampled module, compiled with its repository's whole bundle.

    The same comparison `oracle_rego.py` makes for the vendor corpora, restricted to the
    sampled modules: the adapter's verdict, from syntax, against what the engine's compiler
    says the module's package depends on. One process judges one repository at a time,
    because the adapter keeps the bundle's rule graph in module-level tables.
    """

    global _ORACLE
    if _ORACLE is None:
        _ORACLE = _load("oracle_rego")
    rego = _ORACLE.rego
    repository, commit, entries, work, nondeterministic = task
    into = work / "bundles" / repository.replace("/", "__") / commit[:12]
    rego.discover(into)
    declared = set(rego._DECLARED_PACKAGES)
    bundle_path = work / "oracle" / f"{repository.replace('/', '__')}-{commit[:12]}.tar.gz"
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _ORACLE.build_bundle(into, bundle_path)
    except subprocess.TimeoutExpired:
        return [
            {
                "subject": f"{repository}/{entry['path']}",
                "package": "",
                "adapter": {"kind": "not compared"},
                "engine": {"error": "opa build did not finish within its time limit"},
                "agree": None,
            }
            for entry in entries
        ]
    results: list[dict[str, Any]] = []
    for entry in entries:
        text = (into / entry["path"]).read_text(encoding="utf-8")
        outcome = rego.classify(text)
        ast = rego.parse(text)
        package = rego.package_of(ast) if ast else ""
        record: dict[str, Any] = {
            "subject": f"{repository}/{entry['path']}",
            "package": package,
            "adapter": _ORACLE.adapter_view(outcome),
            # `opa deps` answers for a package, and a Conftest repository often puts many files
            # in one (`package main`); the adapter judges the file. Recorded so a disagreement
            # can be told apart from a difference in what the two are judging.
            "files_sharing_its_package": sum(
                1
                for other in into.rglob("*.rego")
                if ".git" not in other.parts
                and not other.name.endswith("_test.rego")
                and other != into / entry["path"]
                and _declared_package(other) == package
            ),
        }
        try:
            dependencies = _ORACLE.dependencies(bundle_path, package)
        except subprocess.TimeoutExpired:
            # The engine did not answer within the oracle's budget: no verdict either way.
            dependencies = "opa deps did not finish within its time limit"
        if isinstance(dependencies, str):
            record["engine"] = {"error": dependencies}
            record["agree"] = None
        else:
            base, virtual = dependencies
            record["engine"] = _ORACLE.engine_view(
                base, virtual, declared, text, nondeterministic, package
            )
            record["agree"] = _ORACLE.agree(record["adapter"], record["engine"])
        results.append(record)
    return results


def oracle_rego(corpus: dict[str, Any], work: Path, workers: int = 8) -> dict[str, Any]:
    oracle = _load("oracle_rego")
    nondeterministic = oracle.engine_nondeterministic_builtins()
    by_repository: dict[tuple[str, str], list[dict[str, str]]] = {}
    for entry in corpus["files"]:
        by_repository.setdefault((entry["repo"], entry["commit"]), []).append(entry)
    tasks = [
        (repository, commit, entries, work, nondeterministic)
        for (repository, commit), entries in sorted(by_repository.items())
    ]
    modules: list[dict[str, Any]] = []
    with concurrent.futures.ProcessPoolExecutor(workers) as pool:
        for judged in pool.map(_oracle_repository, tasks):
            modules.extend(judged)
    modules.sort(key=lambda entry: entry["subject"])
    unloaded = sum(1 for entry in modules if entry["agree"] is None)
    return {
        "schema_version": "v1",
        "what_this_is": (
            "every sampled third-party Rego module's adapter verdict against `opa deps` on "
            "the package, compiled with the module's whole repository at the pinned commit"
        ),
        "modules": len(modules),
        "engine_could_not_load": unloaded,
        "agreements": sum(1 for entry in modules if entry["agree"] is True),
        "disagreements": sum(1 for entry in modules if entry["agree"] is False),
        "disagreeing_modules": [entry for entry in modules if entry["agree"] is False],
        "disagreeing_modules_whose_package_is_shared": sum(
            1 for e in modules if e["agree"] is False and e.get("files_sharing_its_package")
        ),
        "could_not_load": [
            {"subject": entry["subject"], "error": entry["engine"]["error"][-200:]}
            for entry in modules
            if entry["agree"] is None
        ],
        "by_adapter_kind": dict(sorted(Counter(e["adapter"]["kind"] for e in modules).items())),
    }


# ---------------------------------------------------------------------------------------
# summarise
# ---------------------------------------------------------------------------------------

# The vendor artifacts each sample is compared with: the rows of the membership table.
VENDOR_ARTIFACTS = {
    "kyverno": ("fragment-membership-kyverno-wide-v1",),
    "iam": ("fragment-membership-iam-wide-v1",),
    "cedar": ("fragment-membership-cedar-wide-v1",),
    "rego": ("fragment-membership-rego-wide-v1", "fragment-membership-rego-gcp-v1"),
}


def wilson(successes: int, trials: int, z: float = 1.959964) -> list[float] | None:
    """The 95% Wilson interval for a binomial share, which treats the sample as simple random.

    The caps on repositories and owners make that approximately rather than exactly true.
    """

    if not trials:
        return None
    share = successes / trials
    denominator = 1 + z * z / trials
    centre = (share + z * z / (2 * trials)) / denominator
    half = z * (share * (1 - share) / trials + z * z / (4 * trials * trials)) ** 0.5 / denominator
    return [round(centre - half, 6), round(centre + half, 6)]


UNDEFINED_DATA = "data document the bundle does not define"


def _shares(policies: list[dict[str, Any]], kind_of: Any) -> dict[str, Any]:
    """Counts and shares over artifacts, and over the artifacts that are policies."""

    counts = Counter(entry["verdict"] for entry in policies)
    kinds = Counter(kind_of(entry) for entry in policies if entry["verdict"] == "outside")
    schemas = kinds.get("not a policy", 0)
    considered = len(policies)
    inside = counts["inside"]
    return {
        "artifacts": considered,
        "inside": inside,
        "outside": counts["outside"],
        "undetermined": counts["undetermined"],
        "schemas": schemas,
        "policies": considered - schemas,
        "share_inside": round(inside / considered, 6) if considered else None,
        "share_inside_of_policies": (
            round(inside / (considered - schemas), 6) if considered - schemas else None
        ),
        "exclusions_by_kind": {
            str(kind): count for kind, count in sorted(kinds.items(), key=lambda item: str(item[0]))
        },
    }


def summarise(docs: Path = DOCS) -> dict[str, Any]:
    """One record per ecosystem: the sample, its verdicts, and the vendor row beside it."""

    taxonomy = _load("exclusion_taxonomy")
    rows: dict[str, Any] = {}
    for ecosystem in sorted(TARGETS):
        manifest = json.loads(
            (docs / f"third-party-sample-{ecosystem}-corpus-v1.json").read_text("utf-8")
        )
        measured = json.loads(
            (docs / f"third-party-sample-{ecosystem}-membership-v1.json").read_text("utf-8")
        )
        vendor = [
            entry
            for stem in VENDOR_ARTIFACTS[ecosystem]
            for entry in json.loads((docs / f"{stem}.json").read_text("utf-8"))["policies"]
        ]
        sample_shares = _shares(measured["policies"], taxonomy.kind_of)
        sample_shares["share_inside_of_policies_wilson_95"] = wilson(
            sample_shares["inside"], sample_shares["policies"]
        )
        schema_records = [
            entry
            for entry in measured["policies"]
            if entry["verdict"] == "outside" and taxonomy.kind_of(entry) == "not a policy"
        ]
        sample_shares["schemas_outside_a_constraint_context"] = (
            sum(
                1
                for entry in schema_records
                if not entry["reads_admission_review"] and not entry["reads_constraint"]
            )
            if ecosystem == "rego"
            else None
        )
        sample_shares["resting_on_an_undefined_data_document"] = sum(
            1
            for entry in measured["policies"]
            if UNDEFINED_DATA in entry["reason"]
            or any(UNDEFINED_DATA in reason for reason in entry.get("reasons") or ())
        )
        reasons = Counter(
            entry["reason"].split(":")[0]
            for entry in measured["policies"]
            if entry["verdict"] != "inside"
        )
        rows[ecosystem] = {
            "pool": manifest["pool"],
            "frame": manifest["frame"],
            "frame_repositories": manifest["frame_repositories"],
            "examined": manifest["examined"],
            "sampled": manifest["policies"],
            "repositories": manifest["repositories"],
            "owners": manifest["owners"],
            "unavailable_when_measured": len(measured["policies_unavailable"]),
            "sample": sample_shares,
            "reasons": dict(sorted(reasons.items())),
            "vendor": _shares(vendor, taxonomy.kind_of),
        }
    exclusions = sum(sum(row["sample"]["exclusions_by_kind"].values()) for row in rows.values())
    unclassified = sum(row["sample"]["exclusions_by_kind"].get("None", 0) for row in rows.values())
    return {
        "schema_version": "v1",
        "ecosystems": rows,
        "sampled": sum(row["sampled"] for row in rows.values()),
        "measured": sum(row["sample"]["artifacts"] for row in rows.values()),
        "repositories": sum(row["repositories"] for row in rows.values()),
        "exclusions": exclusions,
        "exclusions_unclassified": unclassified,
        "taxonomy_holds": unclassified == 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    harvest_command = commands.add_parser("harvest")
    harvest_command.add_argument("ecosystem", choices=sorted(QUERIES))
    harvest_command.add_argument("--work", type=Path, required=True)
    harvest_command.add_argument("--max-pages", type=int, default=4)
    select_command = commands.add_parser("select")
    select_command.add_argument("ecosystem", choices=sorted(QUERIES))
    select_command.add_argument("--work", type=Path, required=True)
    select_command.add_argument("--corpora", type=Path, required=True)
    select_command.add_argument("--json", type=Path, required=True)
    rego_command = commands.add_parser("measure-rego")
    rego_command.add_argument("--corpus", type=Path, required=True)
    rego_command.add_argument("--work", type=Path, required=True)
    rego_command.add_argument("--json", type=Path, required=True)
    summary_command = commands.add_parser("summarise")
    summary_command.add_argument("--json", type=Path, required=True)
    oracle_command = commands.add_parser("oracle-rego")
    oracle_command.add_argument("--corpus", type=Path, required=True)
    oracle_command.add_argument("--work", type=Path, required=True)
    oracle_command.add_argument("--json", type=Path, required=True)
    arguments = parser.parse_args(argv)

    if arguments.command == "harvest":
        harvest(arguments.ecosystem, arguments.work, arguments.max_pages)
        return 0
    if arguments.command == "summarise":
        findings = summarise()
    elif arguments.command == "oracle-rego":
        corpus = json.loads(arguments.corpus.read_text("utf-8"))
        findings = oracle_rego(corpus, arguments.work)
    elif arguments.command == "select":
        findings = manifest(
            arguments.ecosystem, arguments.work, arguments.corpora, TARGETS[arguments.ecosystem]
        )
    else:
        corpus = json.loads(arguments.corpus.read_text("utf-8"))
        findings = measure_rego(corpus, arguments.work)
    arguments.json.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", "utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
