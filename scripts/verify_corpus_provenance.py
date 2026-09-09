"""Re-measure every corpus at the commit its artifact records, and diff the counts.

Each membership artifact under `docs/` carries a `corpus` block naming the repositories it
read and the commit each was at. That is provenance, and provenance is not a reproduction: a
commit recorded beside a result says which tree was *meant*, and only re-measuring says which
tree was *read*. The difference is not hypothetical. The Azure artifact recorded
`9780ba64` and reported 3,659 definitions; re-cloning that commit and re-running the same
adapter finds 3,769, because the tree measured had been an earlier one and 110 definitions
added later were missing from it. Nothing in the repository could have caught that, because
every check compared the artifact with itself.

This is that check. Point it at a directory holding the corpora, already cloned at the
recorded commits, and for every whole-corpus membership artifact it

  1. finds the repositories the artifact names, by matching `git rev-parse HEAD` against the
     commits recorded, and reports a corpus it cannot find or that sits at another commit;
  2. re-runs the same adapter over the same root with the same scope; and
  3. diffs `policies_considered` and `counts` against what the artifact says.

It does not clone. Fetching seven repositories is slow, needs the network, and would make the
result depend on a remote still serving a commit, so the corpora are an input. Re-clone them
from the `remote` and `commit` fields the report prints when a corpus is missing.

Usage:
    python scripts/verify_corpus_provenance.py --corpora <dir> [--json out.json]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def _membership() -> Any:
    # The adapters are imported by name, which needs `scripts/` importable. Running this file
    # as a script puts it there and importing this module does not, so it goes in explicitly:
    # a verifier that works only when invoked one way is a verifier its own tests cannot run.
    if str(ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(ROOT / "scripts"))
    specification = importlib.util.spec_from_file_location(
        "fragment_membership_provenance", ROOT / "scripts" / "fragment_membership.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _head(repository: Path) -> str | None:
    if not (repository / ".git").exists():
        return None
    try:
        finished = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - git absent or wedged
        return None
    return finished.stdout.strip() or None


def checkouts(corpora: Path) -> dict[str, Path]:
    """Every git checkout under `corpora`, keyed by the commit it is at."""

    found: dict[str, Path] = {}
    if not corpora.is_dir():
        return found
    for candidate in sorted(corpora.rglob(".git")):
        repository = candidate.parent
        commit = _head(repository)
        if commit:
            found.setdefault(commit, repository)
    return found


def _measurement_root(repositories: list[Path]) -> Path:
    """The directory to measure from: the checkout itself, or the parent that holds them all.

    An artifact naming one repository was measured over that repository. The Rego row pools
    four and the XACML row two, and those were measured over the directory holding them, so
    reproducing the number means measuring from the same place.
    """

    if len(repositories) == 1:
        return repositories[0]
    return Path(os.path.commonpath([str(path) for path in repositories]))


def verify(corpora: Path, docs: Path = DOCS) -> dict[str, Any]:
    membership = _membership()
    available = checkouts(corpora)
    rows: list[dict[str, Any]] = []

    for path in sorted(docs.glob("fragment-membership-*.json")):
        artifact = json.loads(path.read_text(encoding="utf-8"))
        row: dict[str, Any] = {"artifact": path.stem, "ecosystem": artifact.get("ecosystem")}
        recorded = artifact.get("corpus")

        if not isinstance(recorded, list) or not recorded:
            rows.append({**row, "verdict": "skipped", "why": "the artifact records no corpus"})
            continue
        if artifact.get("corpus_scope") != "wide":
            rows.append(
                {
                    **row,
                    "verdict": "skipped",
                    "why": "measured over the subjects of a study, not the whole corpus",
                }
            )
            continue

        row["corpus"] = [
            {
                "name": entry.get("name"),
                "commit": entry.get("commit"),
                "remote": entry.get("remote"),
                "found": entry.get("commit") in available,
            }
            for entry in recorded
        ]
        missing = [entry for entry in row["corpus"] if not entry["found"]]
        if missing:
            rows.append(
                {
                    **row,
                    "verdict": "not checked",
                    "why": "no checkout at the recorded commit: "
                    + ", ".join(str(entry["name"]) for entry in missing),
                }
            )
            continue

        repositories = [available[entry["commit"]] for entry in row["corpus"]]
        root = _measurement_root(repositories)
        fresh = membership.measure(
            membership.load_adapter(str(artifact["ecosystem"])), root, None, wide=True
        )
        row["measured_from"] = root.name
        row["recorded"] = {
            "policies_considered": artifact["policies_considered"],
            "counts": artifact["counts"],
        }
        row["measured"] = {
            "policies_considered": fresh["policies_considered"],
            "counts": fresh["counts"],
        }
        row["verdict"] = "reproduced" if row["recorded"] == row["measured"] else "differs"
        rows.append(row)

    checked = [row for row in rows if row["verdict"] in ("reproduced", "differs")]
    return {
        "schema_version": "v1",
        "verified_on": datetime.now(UTC).strftime("%Y-%m-%d"),
        "python": platform.python_version(),
        "opa": _opa_version(),
        "artifacts": len(rows),
        "checked": len(checked),
        "reproduced": sum(row["verdict"] == "reproduced" for row in checked),
        "differing": [row["artifact"] for row in checked if row["verdict"] == "differs"],
        "not_checked": [
            {"artifact": row["artifact"], "why": row["why"]}
            for row in rows
            if row["verdict"] in ("skipped", "not checked")
        ],
        "rows": rows,
    }


def _opa_version() -> str | None:
    if shutil.which("opa") is None:
        return None
    try:
        finished = subprocess.run(
            ["opa", "version"], capture_output=True, text=True, check=False, timeout=60
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return None
    for line in finished.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def render(findings: dict[str, Any]) -> str:
    lines = [
        f"{findings['checked']} of {findings['artifacts']} membership artifacts re-measured "
        f"from their recorded provenance: {findings['reproduced']} reproduced, "
        f"{len(findings['differing'])} differ"
    ]
    for row in findings["rows"]:
        if row["verdict"] in ("skipped", "not checked"):
            lines.append(f"  {row['verdict']:12} {row['artifact']}: {row['why']}")
            continue
        lines.append(f"  {row['verdict']:12} {row['artifact']}: {row['measured']['counts']}")
        if row["verdict"] == "differs":
            lines.append(f"               recorded {row['recorded']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpora",
        type=Path,
        required=True,
        help="a directory holding the corpora, cloned at the commits the artifacts record",
    )
    parser.add_argument("--docs", type=Path, default=DOCS)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    findings = verify(args.corpora, args.docs)
    print(render(findings))
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 1 if findings["differing"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
