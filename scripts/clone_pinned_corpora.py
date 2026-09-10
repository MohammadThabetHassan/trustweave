"""Clone every corpus a measurement artifact names, at the commit it names.

The membership artifacts under `docs/` each record the repositories they read and the commit
each was at. Reconstructing that from the artifacts -- rather than from a list kept beside
them -- is the point: a hardcoded list is one more thing that can drift away from the
measurement it is supposed to reproduce, and this study has already been bitten once by a
recorded commit that did not describe what was actually read.

Two things this does that a plain `git clone` does not.

It lays the corpora out the way `verify_corpus_provenance.py` expects. That script finds a
repository by matching `git rev-parse HEAD` against a recorded commit, and measures a pooled
row from the directory that holds all of its repositories. So the layout is one directory per
artifact: a row naming four repositories gets a directory containing exactly those four, and
a row naming one gets that repository on its own.

And it checks the checkout finished. A blobless clone fetches file contents lazily, so an
interrupted checkout leaves a working tree that is a strict subset of its commit while
`rev-parse HEAD` still answers correctly. That is how an Azure measurement came to read a
fifth of its repository and record the commit for all of it. Every clone here is compared
against `git ls-tree` before it is called done.

Usage:
    python scripts/clone_pinned_corpora.py --into <dir> [--only <artifact-stem>]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def pinned(docs: Path = DOCS) -> dict[str, list[dict[str, str]]]:
    """{artifact stem: the repositories it read}, for the whole-corpus measurements."""

    found: dict[str, list[dict[str, str]]] = {}
    for path in sorted(docs.glob("fragment-membership-*.json")):
        artifact = json.loads(path.read_text(encoding="utf-8"))
        corpus = artifact.get("corpus")
        if artifact.get("corpus_scope") != "wide" or not isinstance(corpus, list) or not corpus:
            continue
        found[path.stem] = [
            {
                "name": str(entry["name"]),
                "remote": str(entry["remote"]),
                "commit": str(entry["commit"]),
                "tracked_files": entry.get("tracked_files"),
            }
            for entry in corpus
        ]
    return found


def _git(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
        timeout=3600,
    )


def _complete(repository: Path) -> tuple[int, int]:
    """(files the commit contains, files present on disk) -- the incomplete-checkout check."""

    listed = _git("ls-tree", "-r", "--name-only", "HEAD", cwd=repository)
    if listed.returncode != 0:
        return (0, 0)
    names = [line for line in listed.stdout.splitlines() if line]
    return (len(names), sum(1 for name in names if (repository / name).exists()))


def clone(entry: dict[str, Any], into: Path) -> dict[str, Any]:
    """Clone one corpus at its recorded commit, and report what arrived."""

    destination = into / entry["name"]
    result: dict[str, Any] = {"name": entry["name"], "commit": entry["commit"]}
    if not (destination / ".git").exists():
        into.mkdir(parents=True, exist_ok=True)
        cloned = _git(
            "clone",
            "--quiet",
            "--filter=blob:none",
            "--no-checkout",
            entry["remote"],
            str(destination),
        )
        if cloned.returncode != 0:
            return {**result, "ok": False, "why": f"clone failed: {cloned.stderr.strip()[:200]}"}

    # `--force`, so that re-running repairs a tree rather than only reporting on it: a
    # checkout that stopped part-way leaves files missing, and a plain `git checkout` of the
    # commit already at HEAD will not put them back.
    checked = _git("checkout", "--force", "--quiet", entry["commit"], cwd=destination)
    if checked.returncode != 0:
        return {**result, "ok": False, "why": f"checkout failed: {checked.stderr.strip()[:200]}"}

    head = _git("rev-parse", "HEAD", cwd=destination).stdout.strip()
    tracked, present = _complete(destination)
    result |= {"head": head, "tracked_files": tracked, "files_present": present}
    if head != entry["commit"]:
        return {**result, "ok": False, "why": f"HEAD is {head[:12]}, not the recorded commit"}
    if tracked == 0:
        return {**result, "ok": False, "why": "the commit lists no files"}
    if present != tracked:
        return {
            **result,
            "ok": False,
            "why": (
                f"the checkout is incomplete: {present} of {tracked} files present. This is the "
                "failure the study hit once already -- a blobless clone whose checkout did not "
                "finish still answers rev-parse correctly."
            ),
        }
    expected = entry.get("tracked_files")
    if expected is not None and expected != tracked:
        return {
            **result,
            "ok": False,
            "why": f"the commit lists {tracked} files where the artifact recorded {expected}",
        }
    return {**result, "ok": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--into", type=Path, required=True)
    parser.add_argument("--docs", type=Path, default=DOCS)
    parser.add_argument("--only", help="one artifact stem, for reproducing a single row")
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)

    plan = pinned(arguments.docs)
    if arguments.only:
        plan = {stem: entries for stem, entries in plan.items() if stem == arguments.only}
        if not plan:
            raise SystemExit(f"no whole-corpus artifact named {arguments.only!r}")

    rows: list[dict[str, Any]] = []
    for stem, entries in plan.items():
        for entry in entries:
            outcome = clone(entry, arguments.into / stem)
            rows.append({"artifact": stem, **outcome})
            status = "ok" if outcome["ok"] else "FAILED"
            print(f"{status:6} {stem}/{outcome['name']} {outcome['commit'][:12]}", flush=True)
            if not outcome["ok"]:
                print(f"       {outcome['why']}", flush=True)

    failed = [row for row in rows if not row["ok"]]
    print(f"\n{len(rows) - len(failed)} of {len(rows)} corpora cloned complete at their commits")
    if arguments.json:
        arguments.json.write_text(
            json.dumps({"corpora": rows, "failed": len(failed)}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
