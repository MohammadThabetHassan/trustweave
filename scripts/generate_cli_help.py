#!/usr/bin/env python3
"""Generate the top-level TrustWeave CLI help reference from the authoritative parser."""

from __future__ import annotations

import argparse
from pathlib import Path

from trustweave.cli import _parser

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "site" / "CLI_HELP.md"


def _canonical_help(text: str) -> str:
    """Normalize formatter line wrapping while preserving parser-derived paragraph content."""

    return "\n\n".join(" ".join(paragraph.split()) for paragraph in text.strip().split("\n\n"))


def render() -> str:
    """Render parser-derived CLI help as a Markdown reference without clocks or I/O inputs."""

    help_text = _canonical_help(_parser().format_help())
    return (
        "# Generated CLI Help\n\n"
        "> This reference is generated from TrustWeave's authoritative argument parser. "
        "Regenerate it with `python scripts/generate_cli_help.py`; do not edit the fenced help "
        "block manually.\n\n"
        "```text\n"
        f"{help_text}\n"
        "```\n"
    )


def main() -> int:
    """Write or verify the deterministic generated CLI help reference."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="Fail when the tracked generated reference is stale."
    )
    arguments = parser.parse_args()
    expected = render()
    if arguments.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            print(f"Generated CLI help is stale: {OUTPUT}")
            return 1
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
