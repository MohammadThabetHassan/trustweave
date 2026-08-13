#!/usr/bin/env python3
"""Validate that TrustWeave documentation and local repository contracts are real and connected."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as error:  # pragma: no cover - CI installs the optional dev dependency.
    raise SystemExit("PyYAML is required for repository reality checks.") from error

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)\s]+)(?:\s+[^)]*)?\)")
EXPECTED_COMMANDS = (
    "scan",
    "test",
    "explain",
    "attest",
    "report",
    "verify",
    "diff",
    "policy-check",
    "trace-review",
    "mcp-profile-check",
    "framework-import",
    "mcp-import",
    "sarif",
)


def _check_json_documents() -> list[str]:
    failures: list[str] = []
    for path in sorted((ROOT / "schemas").glob("*.json")):
        try:
            parsed: Any = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            failures.append(f"Invalid JSON schema {path.relative_to(ROOT)}: {error}")
            continue
        if not isinstance(parsed, dict) or "$schema" not in parsed:
            failures.append(f"Schema {path.relative_to(ROOT)} lacks a top-level $schema field")
    return failures


def _check_markdown_links() -> list[str]:
    failures: list[str] = []
    for document in sorted(ROOT.rglob("*.md")):
        if any(part in {".git", "dist", "build", ".wheel-check"} for part in document.parts):
            continue
        for target in MARKDOWN_LINK.findall(document.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            relative_target = target.split("#", maxsplit=1)[0]
            if not relative_target:
                continue
            destination = (document.parent / relative_target).resolve()
            if not destination.exists():
                failures.append(
                    f"Broken local Markdown link in {document.relative_to(ROOT)}: {target}"
                )
    return failures


def _check_workflows() -> list[str]:
    failures: list[str] = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        try:
            parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            failures.append(f"Invalid workflow YAML {path.relative_to(ROOT)}: {error}")
            continue
        if not isinstance(parsed, dict) or not isinstance(parsed.get("jobs"), dict):
            failures.append(f"Workflow {path.relative_to(ROOT)} lacks a jobs mapping")
    return failures


def _check_cli() -> list[str]:
    completed = subprocess.run(
        ["trustweave", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return [f"trustweave --help failed: {completed.stderr.strip()}"]
    return [
        f"Documented CLI command missing from help: {command}"
        for command in EXPECTED_COMMANDS
        if command not in completed.stdout
    ]


def main() -> int:
    """Print actionable repository reality-check failures and return an appropriate code."""

    failures = _check_json_documents() + _check_markdown_links() + _check_workflows() + _check_cli()
    if failures:
        print("Repository reality check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(
        "Repository reality check passed: schemas, local documentation links, workflows, "
        "and CLI commands are connected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
