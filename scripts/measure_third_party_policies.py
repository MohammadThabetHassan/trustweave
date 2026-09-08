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
changed underneath it.

    python scripts/measure_third_party_policies.py --json out.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "docs" / "third-party-kyverno-corpus-v1.json"
RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"


def _adapter() -> Any:
    """The Kyverno adapter, loaded by path because these scripts are not a package."""

    for name in ("fragment_membership", "fragment_membership_kyverno"):
        specification = importlib.util.spec_from_file_location(
            name, Path(__file__).resolve().parent / f"{name}.py"
        )
        if specification is None or specification.loader is None:  # pragma: no cover
            raise SystemExit(f"cannot load {name}")
        module = importlib.util.module_from_spec(specification)
        sys.modules.setdefault(name, module)
        specification.loader.exec_module(module)
    return sys.modules["fragment_membership_kyverno"]


def fetch(entry: dict[str, str]) -> str | None:
    """The pinned content, or None when it cannot be fetched or has changed."""

    url = RAW.format(repo=entry["repo"], commit=entry["commit"], path=entry["path"])
    try:
        completed = subprocess.run(
            ["curl", "-sSL", url], capture_output=True, text=True, timeout=90
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or not completed.stdout:
        return None
    text = completed.stdout
    if hashlib.sha256(text.encode()).hexdigest() != entry["sha256"]:
        return None
    return text


def measure(corpus: dict[str, Any]) -> dict[str, Any]:
    adapter = _adapter()
    policies: list[dict[str, Any]] = []
    unavailable: list[str] = []
    for entry in corpus["files"]:
        subject = f"{entry['repo']}/{entry['path']}"
        text = fetch(entry)
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
        "ecosystem": "kyverno",
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args(argv)

    corpus = json.loads(arguments.corpus.read_text(encoding="utf-8"))
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
