"""Run discovery over third-party agent repositories nobody here wrote.

docs/classifier-evaluation-v1.json measures the analyzer against a benchmark this project
authored and annotated. That is the right instrument for precision on labelled cases and
the wrong one for coverage: a registration form nobody here thought of is not reported as
a gap, it is simply absent, and a benchmark cannot contain a case for a form its authors
did not know about.

This survey is the other half. It runs `trustweave discover` over real agent code from
projects with no connection to this one and records what came back: how many tools, under
which registration forms, in which classes, and with which refusals. It cannot say whether
a verdict is right, because the code is unlabelled. It says whether the tool surface was
seen at all, which is the failure the benchmark is blind to.

It found two, and they were the largest coverage gaps in the analyzer:
the OpenAI Agents SDK's `@function_tool` was recognised by nothing, so 328 tools were
invisible, and CrewAI's `BaseTool` subclasses were not either, so a repository reporting
75 tools -- every one of them `read`, at high confidence -- actually exposes 207.

Corpora are not vendored. They are fetched at the commits the artifact pins.

Usage:
    python scripts/wild_discovery_survey.py <name>=<path> [<name>=<path> ...] [--json out]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Final

ROOT = Path(__file__).resolve().parents[1]

# What was surveyed, at the commit it was surveyed at. The corpora are large and belong to
# other projects, so they are fetched rather than vendored, and the artifact carries this
# so a reader can fetch exactly what was read.
CORPUS_PROVENANCE: dict[str, dict[str, str]] = {
    "modelcontextprotocol_servers": {
        "remote": "https://github.com/modelcontextprotocol/servers.git",
        "commit": "d73f99efbfd40c3aa1b61e88728b3d49fb52608f",
        "path": "src",
    },
    "openai_agents_examples": {
        "remote": "https://github.com/openai/openai-agents-python.git",
        "commit": "d3761b3e7b55b147610991bf736ce5ea0161cc82",
        "path": "examples",
    },
    "openai_agents_tests": {
        "remote": "https://github.com/openai/openai-agents-python.git",
        "commit": "d3761b3e7b55b147610991bf736ce5ea0161cc82",
        "path": "tests",
    },
    "crewai": {
        "remote": "https://github.com/crewAIInc/crewAI.git",
        "commit": "1b855b4ff97d3fc8bf6dc0981fed5f0999a7cd81",
        "path": "lib",
    },
    "smolagents_examples": {
        "remote": "https://github.com/huggingface/smolagents.git",
        "commit": "30bb1161095dbae2271e6bc3cc4c219cc3897a57",
        "path": "examples",
    },
    "smolagents_tests": {
        "remote": "https://github.com/huggingface/smolagents.git",
        "commit": "30bb1161095dbae2271e6bc3cc4c219cc3897a57",
        "path": "tests",
    },
    "pydantic_ai_examples": {
        "remote": "https://github.com/pydantic/pydantic-ai.git",
        "commit": "377f4c2315d225ead8f58c6e4abb8277b7be9bce",
        "path": "examples",
    },
    "pydantic_ai_tests": {
        "remote": "https://github.com/pydantic/pydantic-ai.git",
        "commit": "377f4c2315d225ead8f58c6e4abb8277b7be9bce",
        "path": "tests",
    },
    "autogen": {
        "remote": "https://github.com/microsoft/autogen.git",
        "commit": "027ecf0a379bcc1d09956d46d12d44a3ad9cee14",
        "path": "python",
    },
}


def discover(source: Path, output: Path) -> dict[str, Any]:
    """Run the published command, the way a user would."""

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustweave",
            "discover",
            "--source",
            str(source),
            "--output-dir",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    artifact = output / "code-discovery.json"
    if completed.returncode != 0 or not artifact.is_file():
        raise SystemExit(f"discovery failed for {source}: {completed.stderr.strip()[:300]}")
    return json.loads(artifact.read_text(encoding="utf-8"))


# Verbs whose presence in a registered name would be odd for a tool that only reads. This
# is a screen for finding candidate misses in unlabelled code, never a classification
# signal: the analyzer's own rule is that a name is not behaviour, and a tool called
# `delete_stale_cache` that only formats a string is correctly a read. What the screen says
# is "look at this one", and every hit is either a naming choice worth nothing or an effect
# the analyzer did not see.
EFFECTFUL_NAME_VERBS: Final = (
    "delete",
    "remove",
    "write",
    "update",
    "upload",
    "publish",
    "send",
    "post",
    "create",
    "insert",
    "drop",
    "execute",
    "run",
)


def name_screen(tools: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Tools whose registered name suggests an effect the verdict does not report."""

    flagged = []
    for tool in tools:
        if tool["proposed_action_class"] != "read":
            continue
        name = tool["name"].casefold().replace("-", "_").replace(" ", "_")
        head = name.split("_", 1)[0]
        if head in EFFECTFUL_NAME_VERBS:
            flagged.append(
                {
                    "name": tool["name"],
                    "file": tool["location"]["file"],
                    "line": tool["location"]["line"],
                }
            )
    return flagged


def summarise(name: str, artifact: dict[str, Any]) -> dict[str, Any]:
    tools = artifact.get("tools", [])
    reasons: Counter[str] = Counter()
    for tool in tools:
        reasons.update(tool.get("reasons") or [])
    return {
        "corpus": name,
        "tools": len(tools),
        "frameworks": dict(Counter(tool["framework"] for tool in tools).most_common()),
        "action_classes": dict(
            Counter(tool["proposed_action_class"] for tool in tools).most_common()
        ),
        "confidence": dict(Counter(tool["confidence"] for tool in tools).most_common()),
        "refusal_reasons": dict(reasons.most_common()),
        "name_screen": name_screen(tools),
    }


def run(sources: dict[str, Path]) -> dict[str, Any]:
    surveys = []
    with tempfile.TemporaryDirectory() as workspace:
        for name, source in sorted(sources.items()):
            surveys.append(summarise(name, discover(source, Path(workspace) / name)))
    frameworks: Counter[str] = Counter()
    screened = 0
    for survey in surveys:
        frameworks.update(survey["frameworks"])
        screened += len(survey["name_screen"])
    return {
        "schema_version": "v1",
        "corpus": {
            name: CORPUS_PROVENANCE[name] for name in sorted(sources) if name in CORPUS_PROVENANCE
        },
        "corpora_surveyed": len(surveys),
        "tools_discovered": sum(survey["tools"] for survey in surveys),
        "name_screen_hits": screened,
        "frameworks": dict(frameworks.most_common()),
        "surveys": surveys,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+", metavar="NAME=PATH")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    sources: dict[str, Path] = {}
    for entry in args.sources:
        if "=" not in entry:
            raise SystemExit(f"expected NAME=PATH, got {entry!r}")
        name, _, path = entry.partition("=")
        resolved = Path(path)
        if not resolved.exists():
            raise SystemExit(f"corpus not found: {resolved}")
        sources[name] = resolved

    findings = run(sources)
    print(f"corpora surveyed: {findings['corpora_surveyed']}")
    print(f"tools discovered: {findings['tools_discovered']}")
    for survey in findings["surveys"]:
        print(f"\n  {survey['corpus']}: {survey['tools']} tools")
        print(f"      frameworks: {survey['frameworks']}")
        print(f"      classes:    {survey['action_classes']}")
        if survey["refusal_reasons"]:
            print(f"      refusals:   {survey['refusal_reasons']}")
    print(f"\nframeworks across all corpora: {findings['frameworks']}")
    print(
        f"tools whose name suggests an effect the verdict does not report: "
        f"{findings['name_screen_hits']}"
    )
    for survey in findings["surveys"]:
        for hit in survey["name_screen"]:
            print(f"    {survey['corpus']}: {hit['name']} ({hit['file']}:{hit['line']})")
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
