"""Static review of a local Python source tree's tool surface."""

from __future__ import annotations

import argparse
from pathlib import Path

from trustweave.code_discovery import review_code_discovery
from trustweave.code_sources import collect_python_sources
from trustweave.commands._shared import (
    CODE_DISCOVERY_FILE,
    CODE_DISCOVERY_REPORT_FILE,
    EXIT_REVIEW,
)
from trustweave.io import load_document, write_json, write_text
from trustweave.models import parse_manifest
from trustweave.report import render_code_discovery_report


def register(subcommands: argparse.Namespace) -> None:
    """Register the local source discovery command."""

    discover = subcommands.add_parser(
        "discover",
        help=(
            "Statically analyze local Python source for its tool surface without "
            "importing or executing it."
        ),
    )
    discover.add_argument(
        "--source", type=Path, required=True, help="Local Python file or directory to parse."
    )
    discover.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Optional agent manifest, for declaration drift and coverage.",
    )
    discover.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )
    discover.add_argument(
        "--exit-on-review",
        action="store_true",
        help="Return status 1 when the discovery produces findings.",
    )


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Review one local Python source tree without importing or executing it."""

    manifest = parse_manifest(load_document(args.manifest)) if args.manifest else None
    collection = collect_python_sources(args.source)
    review = review_code_discovery(collection, manifest, generated_at)
    json_path = write_json(args.output_dir / CODE_DISCOVERY_FILE, review)
    markdown_path = write_text(
        args.output_dir / CODE_DISCOVERY_REPORT_FILE, render_code_discovery_report(review)
    )
    has_findings = int(review["summary"]["review_findings"]) > 0
    code = EXIT_REVIEW if args.exit_on_review and has_findings else 0
    return f"Wrote local code discovery: {json_path} and {markdown_path}", code
