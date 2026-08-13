#!/usr/bin/env python3
"""Validate that TrustWeave documentation and local repository contracts are real and connected."""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
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
    "framework-import",
    "mcp-scaffold",
    "mcp-import",
    "mcp-profile-check",
    "statement",
    "sarif",
)
PUBLIC_ASSETS = (
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "CODE_OF_CONDUCT.md",
    "GOVERNANCE.md",
    "LICENSE",
    "CITATION.cff",
    ".github/CODEOWNERS",
)
REQUIRED_ISSUE_FORMS = (
    ".github/ISSUE_TEMPLATE/01-bug-report.yml",
    ".github/ISSUE_TEMPLATE/02-feature-request.yml",
)
REQUIRED_README_MARKERS = (
    "python -m pip install --upgrade trustweave",
    "[SUPPORT.md](SUPPORT.md)",
    "[SECURITY.md](SECURITY.md)",
    "[CONTRIBUTING.md](CONTRIBUTING.md)",
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


def _check_issue_templates() -> list[str]:
    failures: list[str] = []
    config_path = ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml"
    if not config_path.exists():
        return ["Missing .github/ISSUE_TEMPLATE/config.yml"]

    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        return [f"Invalid issue-template config YAML: {error}"]
    if not isinstance(config, dict):
        failures.append("Issue-template config must be a YAML mapping")
    elif config.get("blank_issues_enabled") is not False:
        failures.append("Issue-template config must disable blank public issues")

    for relative_path in REQUIRED_ISSUE_FORMS:
        path = ROOT / relative_path
        if not path.exists():
            failures.append(f"Missing required issue form: {relative_path}")
            continue
        try:
            form = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            failures.append(f"Invalid issue-form YAML {relative_path}: {error}")
            continue
        if not isinstance(form, dict):
            failures.append(f"Issue form {relative_path} must be a YAML mapping")
            continue
        for key in ("name", "description", "body"):
            if key not in form:
                failures.append(f"Issue form {relative_path} lacks required key: {key}")
        if not isinstance(form.get("name"), str) or len(form.get("name", "")) <= 3:
            failures.append(f"Issue form {relative_path} needs a name longer than three characters")
        if not isinstance(form.get("description"), str) or not form.get("description", "").strip():
            failures.append(f"Issue form {relative_path} needs a non-empty description")
        if not isinstance(form.get("body"), list) or not form.get("body"):
            failures.append(f"Issue form {relative_path} needs a non-empty body list")
    return failures


def _check_public_documents() -> list[str]:
    failures: list[str] = []
    for relative_path in PUBLIC_ASSETS:
        if not (ROOT / relative_path).exists():
            failures.append(f"Missing public project asset: {relative_path}")

    readme_path = ROOT / "README.md"
    if readme_path.exists():
        readme = readme_path.read_text(encoding="utf-8")
        for marker in REQUIRED_README_MARKERS:
            if marker not in readme:
                failures.append(f"README.md lacks required public-readiness marker: {marker}")
        if "repository remains private" in readme.casefold():
            failures.append("README.md still claims that the repository remains private")

    security_path = ROOT / "SECURITY.md"
    if security_path.exists():
        security = security_path.read_text(encoding="utf-8").casefold()
        if "pre-release software" in security:
            failures.append(
                "SECURITY.md still describes the released project as pre-release software"
            )
        if "report a vulnerability" not in security:
            failures.append("SECURITY.md lacks a private vulnerability-reporting route")

    project_path = ROOT / "pyproject.toml"
    release_path = ROOT / "docs" / "RELEASE.md"
    if project_path.exists() and release_path.exists():
        with project_path.open("rb") as project_file:
            project = tomllib.load(project_file)
        version = project.get("project", {}).get("version")
        if isinstance(version, str):
            release = release_path.read_text(encoding="utf-8")
            if f"TrustWeave `{version}`" not in release:
                failures.append("docs/RELEASE.md does not name the declared package version")

            citation_path = ROOT / "CITATION.cff"
            if citation_path.exists():
                try:
                    citation = yaml.safe_load(citation_path.read_text(encoding="utf-8"))
                except yaml.YAMLError as error:
                    failures.append(f"Invalid CITATION.cff YAML: {error}")
                else:
                    if not isinstance(citation, dict):
                        failures.append("CITATION.cff must be a YAML mapping")
                    elif citation.get("title") != "TrustWeave":
                        failures.append("CITATION.cff must use the TrustWeave title")
                    elif citation.get("type") != "software":
                        failures.append("CITATION.cff must identify the project as software")
                    elif citation.get("version") != version:
                        failures.append("CITATION.cff version does not match pyproject.toml")
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

    failures = (
        _check_json_documents()
        + _check_markdown_links()
        + _check_workflows()
        + _check_issue_templates()
        + _check_public_documents()
        + _check_cli()
    )
    if failures:
        print("Repository reality check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(
        "Repository reality check passed: schemas, local documentation links, workflows, "
        "issue forms, public documentation, release metadata, and CLI commands are connected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
