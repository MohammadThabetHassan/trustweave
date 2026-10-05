"""The schemas the authors of the scored Cedar files wrote, found before they are used.

SymCC, Cedar's symbolic compiler, decides whether two policy sets are equivalent over the
requests a schema admits. The cross-check of the Cedar exact study
(`docs/CEDAR_SYMCC_CROSSCHECK_PROTOCOL.md`) therefore needs a schema for every file it checks,
and this project writes none: it uses the one the file's authors wrote, or skips the file.

For every file the study scored, this script lists the schema candidates in the file's own
repository at the commit the corpus records -- every `*.cedarschema` or `*.cedarschema.json`
file, and every `.json` or `.cedar` file whose name contains "schema" -- nearest first: the
file's own directory, then its ancestors from the nearest, then the rest of the repository,
by path within each group. The file's schema is the first candidate under which Cedar's
validator accepts the file in strict mode. A JSON candidate that wraps its schema as
`{"cedarJson": "..."}`, the form Amazon Verified Permissions exports, is read unwrapped. The
request environments are the (principal type, action, resource type) triples the schema's
actions apply to, in the order the schema declares them.

Usage:
    python scripts/cedar_schema_candidates.py --cedar PATH/TO/cedar --cache DIR \\
        --json docs/cedar-schema-candidates-v1.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SCHEMA_NAME = re.compile(r"\.cedarschema(\.json)?$", re.I)
SCHEMA_LIKE = re.compile(r"(^|/)[^/]*schema[^/]*\.(json|cedar)$", re.I)
KINDS = ("same directory", "ancestor", "elsewhere")
TREES = "https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1"


def _load(name: str) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def git_blob_sha1(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()


def tree(repo: str, commit: str, cache: Path) -> dict[str, Any]:
    """The repository's recursive tree at the commit, as GitHub's API returns it."""

    stored = cache / "trees" / f"{repo.replace('/', '__')}__{commit}.json"
    if not stored.exists():
        command = ["curl", "--silent", "--show-error", "--fail", "--max-time", "120"]
        if os.environ.get("GITHUB_TOKEN"):
            command += ["--header", f"Authorization: Bearer {os.environ['GITHUB_TOKEN']}"]
        completed = subprocess.run(
            [*command, TREES.format(repo=repo, commit=commit)], capture_output=True, check=False
        )
        stored.parent.mkdir(parents=True, exist_ok=True)
        if completed.returncode != 0:
            return {"error": completed.stderr.decode("utf-8", "replace").strip()[-200:]}
        stored.write_bytes(completed.stdout)
    return json.loads(stored.read_text("utf-8"))


def blob(repo: str, commit: str, path: str, sha1: str, cache: Path) -> bytes | None:
    """The file's bytes at the commit, checked against the tree's blob id, or None."""

    stored = cache / "blobs" / sha1
    if not stored.exists():
        measure = _load("measure_third_party_policies")
        content, _ = measure.fetch_bytes({"repo": repo, "commit": commit, "path": path})
        if content is None or git_blob_sha1(content) != sha1:
            return None
        stored.parent.mkdir(parents=True, exist_ok=True)
        stored.write_bytes(content)
    content = stored.read_bytes()
    return content if git_blob_sha1(content) == sha1 else None


def ordered(policy_path: str, paths: list[str]) -> list[tuple[str, str]]:
    """The candidates nearest first, each with where it sits relative to the policy file."""

    here = posixpath.dirname(policy_path)
    chain = [here]
    while chain[-1]:
        chain.append(posixpath.dirname(chain[-1]))

    def rank(path: str) -> tuple[int, int, str]:
        directory = posixpath.dirname(path)
        if directory == here:
            return (0, 0, path)
        if directory in chain:
            return (1, chain.index(directory), path)
        return (2, 0, path)

    return [(path, KINDS[rank(path)[0]]) for path in sorted(paths, key=rank)]


def schema_source(content: bytes, path: str) -> tuple[str, str]:
    """The candidate's format, `json` or `cedar`, and its text."""

    text = content.decode("utf-8-sig", "replace")
    if path.lower().endswith(".json") or text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return "json", text
        if isinstance(data, dict) and isinstance(data.get("cedarJson"), str):
            return "json", data["cedarJson"]
        return "json", text
    return "cedar", text


def _cedar(cedar: str, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [cedar, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        input=stdin,
        timeout=300,
        check=False,
    )


def validate(cedar: str, schema: Path, schema_format: str, policies: Path) -> str:
    done = _cedar(
        cedar,
        "validate",
        "--schema",
        str(schema),
        "--schema-format",
        schema_format,
        "--policies",
        str(policies),
        "--validation-mode",
        "strict",
    )
    if done.returncode == 0:
        return "validates"
    if "failed to parse schema" in (done.stderr + done.stdout).lower():
        return "not a schema"
    return "does not validate"


def environments(cedar: str, schema_format: str, text: str) -> list[list[str]]:
    """Every (principal type, action, resource type) the schema's actions apply to."""

    if schema_format == "json":
        done = _cedar(cedar, "translate-schema", "--direction", "json-to-cedar", stdin=text)
        if done.returncode != 0:
            raise RuntimeError(done.stderr.strip()[:300])
        text = done.stdout
    done = _cedar(
        cedar, "translate-schema", "--direction", "cedar-to-json-with-resolved-types", stdin=text
    )
    if done.returncode != 0:
        raise RuntimeError(done.stderr.strip()[:300])
    found: list[list[str]] = []
    for namespace, body in json.loads(done.stdout).items():
        prefix = f"{namespace}::" if namespace else ""
        for action, specification in (body.get("actions") or {}).items():
            applies = specification.get("appliesTo") or {}
            for principal in applies.get("principalTypes") or []:
                for resource in applies.get("resourceTypes") or []:
                    found.append(
                        [
                            principal if "::" in principal else prefix + principal,
                            f"{prefix}Action::{json.dumps(action)}",
                            resource if "::" in resource else prefix + resource,
                        ]
                    )
    return found


def examine(entry: dict[str, str], cedar: str, cache: Path) -> dict[str, Any]:
    subject = f"{entry['repo']}/{entry['path']}"
    record: dict[str, Any] = {
        "subject": subject,
        "repo": entry["repo"],
        "commit": entry["commit"],
        "path": entry["path"],
        "sha256": entry["sha256"],
        "candidates": [],
        "schema": None,
        "environments": [],
    }
    listing = tree(entry["repo"], entry["commit"], cache)
    if "error" in listing:
        record["tree"] = "unavailable: " + listing["error"]
        return record
    record["tree"] = "truncated" if listing.get("truncated") else "complete"
    shas = {item["path"]: item["sha"] for item in listing["tree"] if item["type"] == "blob"}
    named = [path for path in shas if SCHEMA_NAME.search(path) or SCHEMA_LIKE.search(path)]
    policy = blob(entry["repo"], entry["commit"], entry["path"], entry["blob_sha1"], cache)
    if policy is None or hashlib.sha256(policy).hexdigest() != entry["sha256"]:
        record["tree"] += "; the policy file could not be had at its recorded digest"
        return record
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "policies.cedar").write_bytes(policy)
        for path, kind in ordered(entry["path"], named):
            content = blob(entry["repo"], entry["commit"], path, shas[path], cache)
            if content is None:
                record["candidates"].append({"path": path, "kind": kind, "result": "unfetchable"})
                continue
            schema_format, text = schema_source(content, path)
            (root / "schema").write_text(text, encoding="utf-8")
            result = validate(cedar, root / "schema", schema_format, root / "policies.cedar")
            candidate = {
                "path": path,
                "kind": kind,
                "blob_sha1": shas[path],
                "sha256": hashlib.sha256(content).hexdigest(),
                "format": schema_format,
                "result": result,
            }
            record["candidates"].append(candidate)
            if result == "validates":
                record["schema"] = {k: v for k, v in candidate.items() if k != "result"}
                record["environments"] = environments(cedar, schema_format, text)
                break
    return record


def candidates(cedar: str, cache: Path) -> dict[str, Any]:
    study = json.loads((DOCS / "cedar-suite-strategy-study-v1.json").read_text("utf-8"))
    manifest = json.loads((DOCS / "third-party-sample-cedar-corpus-v1.json").read_text("utf-8"))
    index = {f"{entry['repo']}/{entry['path']}": entry for entry in manifest["files"]}
    scored = sorted(k for k, v in study["files"].items() if v["status"] == "scored")
    version = _cedar(cedar, "--version").stdout.strip()
    files = [examine(index[subject], cedar, cache) for subject in scored]
    with_schema = [f for f in files if f["schema"]]
    return {
        "schema_version": "v1",
        "made_with": version,
        "files_from": "docs/cedar-suite-strategy-study-v1.json (status scored)",
        "candidate_names": "*.cedarschema, *.cedarschema.json, and *.json or *.cedar whose "
        "name contains 'schema'",
        "order": "same directory, then ancestors nearest first, then elsewhere; by path within",
        "rule": "the first candidate under which `cedar validate --validation-mode strict` "
        "accepts the file; candidates after it are not listed",
        "summary": {
            "files": len(files),
            "with a candidate": sum(1 for f in files if f["candidates"]),
            "with a schema": len(with_schema),
            "schema found": dict(sorted(Counter(f["schema"]["kind"] for f in with_schema).items())),
            "repositories with a schema": len({f["repo"] for f in with_schema}),
            "environments": sum(len(f["environments"]) for f in with_schema),
        },
        "files": files,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cedar", default=os.environ.get("CEDAR_CLI", "cedar"))
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    result = candidates(args.cedar, args.cache)
    text = json.dumps(result, indent=1, ensure_ascii=False)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
